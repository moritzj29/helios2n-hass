import asyncio
import logging
import re
from urllib.parse import unquote, urlsplit

from homeassistant.core import HomeAssistant, ServiceCall, callback, ServiceResponse, SupportsResponse
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_PROTOCOL, CONF_VERIFY_SSL, Platform
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from py2n import Py2NDevice
from py2n.exceptions import Py2NError

_LOGGER = logging.getLogger(__name__)

from .const import DOMAIN, ATTR_METHOD, DEFAULT_METHOD, ATTR_ENDPOINT, ATTR_TIMEOUT, DEFAULT_TIMEOUT, ATTR_DATA, ATTR_JSON, ATTR_ENTRY, CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD
from .coordinator import Helios2nPortDataUpdateCoordinator, Helios2nSwitchDataUpdateCoordinator, Helios2nSensorDataUpdateCoordinator
from .log import LOG_POLL_TASK, poll_log
from .utils import sanitize_connection_data, create_connection_data, normalize_auth_method

platforms = [Platform.BUTTON, Platform.LOCK, Platform.SWITCH, Platform.BINARY_SENSOR, Platform.SENSOR, Platform.EVENT]
ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"}
ENDPOINT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _validate_api_endpoint(endpoint: object | None) -> str:
    """Validate and normalize manual API endpoint.

    Accepts both `service/function` and `/api/service/function` formats.
    """
    if not endpoint:
        raise ServiceValidationError("Endpoint is required")
    if not isinstance(endpoint, str):
        raise ServiceValidationError("Endpoint must be a string")
    endpoint = endpoint.strip()
    if not endpoint:
        raise ServiceValidationError("Endpoint is required")

    split_result = urlsplit(endpoint)
    if split_result.scheme or split_result.netloc:
        raise ServiceValidationError("Endpoint must not include a URL scheme or hostname")
    if split_result.fragment:
        raise ServiceValidationError("Endpoint must not include URL fragments")

    path = split_result.path.lstrip("/")
    if path.startswith("api/"):
        path = path[4:]

    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        raise ServiceValidationError(
            "Endpoint must include service and function, e.g. system/info"
        )
    for segment in segments:
        decoded_segment = unquote(segment)
        if decoded_segment in {".", ".."}:
            raise ServiceValidationError("Endpoint path traversal is not allowed")
        if not ENDPOINT_SEGMENT_PATTERN.fullmatch(decoded_segment):
            raise ServiceValidationError(
                "Endpoint path segments may only contain letters, numbers, '_' or '-'"
            )

    normalized_path = "/".join(segments)
    if split_result.query:
        return f"{normalized_path}?{split_result.query}"
    return normalized_path


def _validate_payload_consistency(data, json_payload) -> None:
    """Prevent ambiguous request bodies where both `data` and `json` are set."""
    if data is not None and json_payload is not None:
        raise ServiceValidationError("Provide either data or json, not both")


def _validate_http_method(method: str) -> str:
    """Validate and normalize HTTP method for the manual API service call."""
    if not isinstance(method, str):
        raise ServiceValidationError("HTTP method must be a string")
    normalized_method = method.upper()
    if normalized_method not in ALLOWED_HTTP_METHODS:
        raise ServiceValidationError(
            f"Invalid HTTP method: {method}. Supported: GET, POST, PUT, DELETE"
        )
    return normalized_method


def _validate_timeout(timeout: int | str) -> int:
    """Validate timeout range and convert to int."""
    try:
        timeout_int = int(timeout)
    except (ValueError, TypeError) as err:
        raise ServiceValidationError("Timeout must be a valid integer") from err
    if timeout_int < 0 or timeout_int > 3600:
        raise ServiceValidationError("Timeout must be between 0 and 3600 seconds")
    return timeout_int

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    
    @callback
    async def api_call(call: ServiceCall) -> ServiceResponse:
        domain = hass.data.get(DOMAIN, {})
        if not domain:
            raise ServiceValidationError("helios2n is not set up.")
        entry = call.data.get(ATTR_ENTRY, list(domain)[0])
        if entry not in domain:
            raise ServiceValidationError(f"Entry {entry} not set up.")
        device = domain[entry]["_device"]

        # Validate input parameters
        method = _validate_http_method(call.data.get(ATTR_METHOD, DEFAULT_METHOD))

        endpoint = call.data.get(ATTR_ENDPOINT)
        endpoint = _validate_api_endpoint(endpoint)

        timeout_int = _validate_timeout(call.data.get(ATTR_TIMEOUT, DEFAULT_TIMEOUT))

        data = call.data.get(ATTR_DATA)
        json = call.data.get(ATTR_JSON)
        _validate_payload_consistency(data, json)
        result = {}
        try:
            result = await device.api_request(endpoint, timeout_int, method, data, json)
        except Py2NError as err:
            raise HomeAssistantError(f"Error from API call: {err}") from err

        if result is None:
            result = {}

        return result if call.return_response else None

    hass.services.async_register(DOMAIN, "api_call", api_call, supports_response=SupportsResponse.OPTIONAL)

    # Return boolean to indicate that initialization was successful.
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and cleanup resources."""
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    log_task = entry_data.pop(LOG_POLL_TASK, None) if entry_data else None
    if log_task:
        log_task.cancel()
        try:
            await log_task
        except asyncio.CancelledError:
            pass

    unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)

    if unload_ok:
        # Clean up hass.data
        hass.data[DOMAIN].pop(entry.entry_id)

        # Unregister services if this was the last entry
        if len(hass.data[DOMAIN]) == 0:
            hass.services.async_remove(DOMAIN, "api_call")

    return unload_ok

async def async_setup_entry(hass: HomeAssistant, config: ConfigEntry) -> bool:
    try:
        aiohttp_session = async_get_clientsession(hass)
        auth_method = normalize_auth_method(config.data.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD))
        connection_data = create_connection_data(
            host=config.data[CONF_HOST],
            username=config.options.get(CONF_USERNAME, config.data.get(CONF_USERNAME, "")),
            password=config.options.get(CONF_PASSWORD, config.data.get(CONF_PASSWORD, "")),
            protocol=config.data[CONF_PROTOCOL],
            auth_method=auth_method,
            ssl_verify=config.data.get(CONF_VERIFY_SSL, True),
        )
        _LOGGER.debug(
            "Connecting to device: %s",
            sanitize_connection_data(connection_data) | {CONF_AUTH_METHOD: auth_method},
        )
        device = await Py2NDevice.create(aiohttp_session, connection_data)
    except Exception as err:
        raise HomeAssistantError(f"Failed to connect to Helios/2N device: {err}") from err

    entry_data = hass.data.setdefault(DOMAIN, {}).setdefault(config.entry_id, {})
    entry_data["_device"] = device
    for platform in platforms:
        entry_data.setdefault(platform, {})
    # Create coordinators
    port_coordinator = Helios2nPortDataUpdateCoordinator(hass, device)
    switch_coordinator = Helios2nSwitchDataUpdateCoordinator(hass, device)
    sensor_coordinator = Helios2nSensorDataUpdateCoordinator(hass, device)
    entry_data[Platform.LOCK]["coordinator"] = switch_coordinator
    entry_data[Platform.SWITCH]["coordinator"] = port_coordinator
    entry_data[Platform.SENSOR]["coordinator"] = sensor_coordinator
    entry_data[Platform.BINARY_SENSOR]["coordinator"] = port_coordinator

    await asyncio.gather(
        port_coordinator.async_config_entry_first_refresh(),
        switch_coordinator.async_config_entry_first_refresh(),
        sensor_coordinator.async_config_entry_first_refresh(),
    )

    hass.async_create_task(
        hass.config_entries.async_forward_entry_setups(
            config, platforms
        )
    )

    try:
        logid = await device.log_subscribe()
        entry_data[LOG_POLL_TASK] = hass.async_create_task(
            poll_log(device, logid, hass, config.entry_id)
        )
    except Exception as err:
        _LOGGER.warning("Failed to subscribe to device logs: %s", err)

    return True

