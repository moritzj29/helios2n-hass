import asyncio
import logging
import re
from urllib.parse import unquote, urlsplit

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PROTOCOL, CONF_USERNAME, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType
from py2n import Py2NDevice
from py2n.exceptions import Py2NError

from .const import (
    ATTR_DATA,
    ATTR_ENDPOINT,
    ATTR_ENTRY,
    ATTR_JSON,
    ATTR_LOG_SUBSCRIPTION,
    ATTR_METHOD,
    ATTR_TIMEOUT,
    CONF_AUTH_METHOD,
    DEFAULT_AUTH_METHOD,
    DEFAULT_METHOD,
    DEFAULT_TIMEOUT,
    DOMAIN,
)
from .coordinator import (
    Helios2nPortDataUpdateCoordinator,
    Helios2nSensorDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)
from .log import LOG_POLL_TASK, async_get_supported_log_events, poll_log
from .utils import create_connection_data, normalize_auth_method, sanitize_connection_data, utc_now_iso

_LOGGER = logging.getLogger(__name__)

platforms = [Platform.BUTTON, Platform.LOCK, Platform.SWITCH, Platform.BINARY_SENSOR, Platform.SENSOR, Platform.EVENT]
ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"}
ENDPOINT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
LOG_WATCHDOG_TASK = "_log_watchdog_task"
LOG_UNLOADING = "_log_unloading"
# Small cooldown to avoid tight restart loops if device/API is briefly unavailable.
LOG_WATCHDOG_DELAY_SECONDS = 5


def _mark_log_subscription_unhealthy(entry_data: dict, reason: str) -> None:
    """Expose watchdog-detected task failure in diagnostics state."""
    state = entry_data.get(ATTR_LOG_SUBSCRIPTION)
    if not isinstance(state, dict):
        state = {}
        entry_data[ATTR_LOG_SUBSCRIPTION] = state
    state["healthy"] = False
    state["last_error"] = reason
    state["last_error_at"] = utc_now_iso()


def _mark_log_watchdog_resubscribe(entry_data: dict) -> None:
    state = entry_data.get(ATTR_LOG_SUBSCRIPTION)
    if not isinstance(state, dict):
        state = {}
        entry_data[ATTR_LOG_SUBSCRIPTION] = state
    state["resubscribe_count"] = int(state.get("resubscribe_count", 0)) + 1
    state["last_resubscribe_at"] = utc_now_iso()


async def _async_start_log_poll_task(
    hass: HomeAssistant, entry_id: str, device: Py2NDevice, logid: str
) -> None:
    """Start poll task and attach watchdog callback for unexpected exits."""
    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict) or entry_data.get(LOG_UNLOADING):
        return
    task = hass.async_create_task(poll_log(device, logid, hass, entry_id))
    entry_data[LOG_POLL_TASK] = task

    def _on_done(done_task: asyncio.Task) -> None:
        hass.async_create_task(
            _async_handle_log_poll_task_done(hass, entry_id, device, done_task)
        )

    task.add_done_callback(_on_done)


async def _async_handle_log_poll_task_done(
    hass: HomeAssistant, entry_id: str, device: Py2NDevice, done_task: asyncio.Task
) -> None:
    """Done-callback for the ``poll_log`` background task.

    Detects three exit modes:
    - ``cancelled``: unexpected cancellation during shutdown or reload.
    - ``exception()``: the loop crashed (logged with ``exc_info``).
    - clean exit: the subscription ended or returned empty without error.

    Marks the subscription unhealthy and schedules a delayed watchdog
    resubscribe, unless another watchdog restart is already pending.
    """
    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict):
        return
    if entry_data.get(LOG_UNLOADING):
        return
    if entry_data.get(LOG_POLL_TASK) is not done_task:
        return

    reason = "log polling task exited"
    if done_task.cancelled():
        reason = "log polling task cancelled unexpectedly"
        _LOGGER.warning("%s for entry %s; scheduling restart", reason, entry_id)
    else:
        exc = done_task.exception()
        if exc is not None:
            reason = f"log polling task crashed: {exc}"
            _LOGGER.error(
                "Log polling task crashed for entry %s; scheduling restart",
                entry_id,
                exc_info=exc,
            )
        else:
            _LOGGER.warning("Log polling task ended for entry %s; scheduling restart", entry_id)

    _mark_log_subscription_unhealthy(entry_data, reason)
    if entry_data.get(LOG_WATCHDOG_TASK) is not None:
        return
    entry_data[LOG_WATCHDOG_TASK] = hass.async_create_task(
        _async_restart_log_polling(hass, entry_id, device)
    )


async def _async_restart_log_polling(
    hass: HomeAssistant, entry_id: str, device: Py2NDevice
) -> None:
    """Delayed restart prevents hot-looping when device is briefly unavailable."""
    await asyncio.sleep(LOG_WATCHDOG_DELAY_SECONDS)
    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict):
        return
    if entry_data.get(LOG_UNLOADING):
        return
    try:
        logid = await device.log_subscribe()
        _mark_log_watchdog_resubscribe(entry_data)
        await _async_start_log_poll_task(hass, entry_id, device, logid)
    except asyncio.CancelledError:
        raise
    except Exception as err:
        _mark_log_subscription_unhealthy(entry_data, f"watchdog resubscribe failed: {err}")
        _LOGGER.warning("Log polling watchdog resubscribe failed for entry %s: %s", entry_id, err)
    finally:
        latest_entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
        if isinstance(latest_entry_data, dict):
            latest_entry_data[LOG_WATCHDOG_TASK] = None


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
    """Domain-level setup.

    No config entry is involved at this stage. The only action is registering
    the ``helios2n.api_call`` service, which allows arbitrary device API calls
    once at least one entry is loaded.
    """

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
    if isinstance(entry_data, dict):
        entry_data[LOG_UNLOADING] = True
    log_task = entry_data.pop(LOG_POLL_TASK, None) if entry_data else None
    if log_task:
        log_task.cancel()
        try:
            await log_task
        except asyncio.CancelledError:
            pass
    watchdog_task = entry_data.pop(LOG_WATCHDOG_TASK, None) if entry_data else None
    if watchdog_task:
        watchdog_task.cancel()
        try:
            await watchdog_task
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
    """Set up a single device config entry.

    Wiring order:
    1. Create the ``Py2NDevice`` using HA's shared aiohttp session.
    2. Query ``/api/log/caps`` to detect supported log event types; fall back
       to a known set for older firmware that does not expose capabilities.
    3. Create three coordinators and map them to platforms:
       - LOCK reads from the switch coordinator (bistable switches).
       - SWITCH / BINARY_SENSOR read from the port coordinator (I/O ports).
       - SENSOR reads from the sensor coordinator (uptime).
    4. Run initial refresh on each coordinator, then forward platform setup.
    5. Subscribe to device logs and start the ``poll_log`` loop under
        watchdog supervision.
    """
    try:
        aiohttp_session = async_get_clientsession(hass)
        auth_method = normalize_auth_method(config.data.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD))
        connection_data = create_connection_data(
            host=config.data[CONF_HOST],
            username=config.data.get(CONF_USERNAME, ""),
            password=config.data.get(CONF_PASSWORD, ""),
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

    # Fetch supported log events from device capabilities
    supported_log_events = await async_get_supported_log_events(device)
    if not supported_log_events:
        # Fallback to known events for backward compatibility with older firmware
        supported_log_events = {"SwitchStateChanged", "UserAuthenticated", "InputChanged", "OutputChanged"}
        _LOGGER.warning(
            "Device %s did not report supported log events or /api/log/caps unavailable; "
            "assuming default event support",
            config.data[CONF_HOST],
        )
    entry_data["supported_log_events"] = supported_log_events
    _LOGGER.info(
        "Device %s supports log events: %s",
        config.data[CONF_HOST],
        ", ".join(sorted(supported_log_events)),
    )

    for platform in platforms:
        entry_data.setdefault(platform, {})
    # Create coordinators: nomenclature follows underlying py2n library / API
    port_coordinator = Helios2nPortDataUpdateCoordinator(hass, device)
    switch_coordinator = Helios2nSwitchDataUpdateCoordinator(hass, device)
    sensor_coordinator = Helios2nSensorDataUpdateCoordinator(hass, device)

    # Map platforms to their coordinators:
    # - LOCK uses the switch coordinator because locks are controlled via bistable switches. (switch endpoint)
    # - SWITCH uses the port coordinator because switch entities represent output ports. (io endpoint)
    # - BINARY_SENSOR uses the port coordinator for port status sensors. (io endpoint)
    # - SENSOR uses the sensor coordinator for uptime and other system sensors.
    entry_data[Platform.LOCK]["coordinator"] = switch_coordinator
    entry_data[Platform.SWITCH]["coordinator"] = port_coordinator
    entry_data[Platform.SENSOR]["coordinator"] = sensor_coordinator
    entry_data[Platform.BINARY_SENSOR]["coordinator"] = port_coordinator

    await asyncio.gather(
        port_coordinator.async_config_entry_first_refresh(),
        switch_coordinator.async_config_entry_first_refresh(),
        sensor_coordinator.async_config_entry_first_refresh(),
    )

    await hass.config_entries.async_forward_entry_setups(
        config, platforms
    )

    try:
        logid = await device.log_subscribe()
        await _async_start_log_poll_task(hass, config.entry_id, device, logid)
    except Exception as err:
        _LOGGER.warning("Failed to subscribe to device logs: %s", err)

    return True
