import asyncio
import logging
from asyncio import TimeoutError

from homeassistant.core import HomeAssistant, ServiceCall, callback, ServiceResponse, SupportsResponse, ConfigEntry
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_PROTOCOL, Platform
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from py2n import Py2NDevice, Py2NConnectionData
from py2n.exceptions import DeviceConnectionError, DeviceUnsupportedError, DeviceApiError, ApiError, Py2NError

_LOGGER = logging.getLogger(__name__)

from .const import DOMAIN, ATTR_METHOD, DEFAULT_METHOD, ATTR_ENDPOINT, ATTR_TIMEOUT, DEFAULT_TIMEOUT, ATTR_DATA, ATTR_JSON, ATTR_ENTRY
from .coordinator import Helios2nPortDataUpdateCoordinator, Helios2nSwitchDataUpdateCoordinator, Helios2nSensorDataUpdateCoordinator
from .utils import sanitize_connection_data

platforms = [Platform.BUTTON, Platform.LOCK, Platform.SWITCH, Platform.BINARY_SENSOR, Platform.SENSOR]

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
	
	@callback
	async def api_call(call: ServiceCall) -> ServiceResponse:
		domain = hass.data.get(DOMAIN,{})
		if(len(domain) < 1):
			raise ServiceValidationError("helios2n is not set up.")
		entry = call.data.get(ATTR_ENTRY, list(domain)[0])
		if(entry not in domain):
			raise ServiceValidationError(f"Entry {entry} not set up.")
		device = domain[entry]["_device"]

		# Validate input parameters
		method = call.data.get(ATTR_METHOD, DEFAULT_METHOD)
		if method not in ["GET", "POST", "PUT", "DELETE"]:
			raise ServiceValidationError(f"Invalid HTTP method: {method}. Supported: GET, POST, PUT, DELETE")

		endpoint = call.data.get(ATTR_ENDPOINT)
		if not endpoint:
			raise ServiceValidationError("Endpoint is required")

		# Validate timeout is within reasonable range
		timeout = call.data.get(ATTR_TIMEOUT, DEFAULT_TIMEOUT)
		try:
			timeout_int = int(timeout)
			if timeout_int < 0 or timeout_int > 3600:
				raise ServiceValidationError("Timeout must be between 0 and 3600 seconds")
		except (ValueError, TypeError):
			raise ServiceValidationError("Timeout must be a valid integer")

		data = call.data.get(ATTR_DATA)
		json = call.data.get(ATTR_JSON)
		result = {}
		try: 
			result = await device.api_request(endpoint, timeout_int, method, data, json)
		except Py2NError as err:
			raise HomeAssistantError("error from api call:", err) from err

		if result is None:
			result = {}

		if call.return_response:
			return result
		else:
			return None

	hass.services.async_register(DOMAIN, "api_call", api_call, supports_response=SupportsResponse.OPTIONAL)

	# Return boolean to indicate that initialization was successful.
	return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
	"""Unload a config entry and cleanup resources."""
	unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)

	if unload_ok:
		# Clean up hass.data
		hass.data[DOMAIN].pop(entry.entry_id)
		
		# Unregister services if this was the last entry
		if len(hass.data[DOMAIN]) == 0:
			hass.services.async_remove(DOMAIN, "api_call")

	return unload_ok

async def async_setup_entry(hass: HomeAssistant, config: ConfigType) -> bool:
	try:
		aiohttp_session = async_get_clientsession(hass)
		connection_data = Py2NConnectionData(
			host=config.data[CONF_HOST],
			username=config.options.get(CONF_USERNAME, config.data.get(CONF_USERNAME, "")),
			password=config.options.get(CONF_PASSWORD, config.data.get(CONF_PASSWORD, "")),
			protocol=config.data[CONF_PROTOCOL]
		)
		_LOGGER.debug("Connecting to device: %s", sanitize_connection_data(connection_data))
		device = await Py2NDevice.create(aiohttp_session, connection_data)
	except Exception as err:
		raise HomeAssistantError(f"Failed to connect to Helios/2N device: {err}") from err

	entry_data = hass.data.setdefault(DOMAIN, {}).setdefault(config.entry_id, {})
	entry_data["_device"] = device
	for platform in platforms:
		entry_data.setdefault(platform, {})
	entry_data[Platform.LOCK]["coordinator"] = Helios2nSwitchDataUpdateCoordinator(hass, device)
	entry_data[Platform.SWITCH]["coordinator"] = Helios2nPortDataUpdateCoordinator(hass, device)
	entry_data[Platform.SENSOR]["coordinator"] = Helios2nSensorDataUpdateCoordinator(hass, device)
	entry_data[Platform.BINARY_SENSOR]["coordinator"] = Helios2nPortDataUpdateCoordinator(hass, device)
	hass.async_create_task(
		hass.config_entries.async_forward_entry_setups(
		config, platforms
		)
	)

	logid = await device.log_subscribe()

	hass.loop.create_task(poll_log(device, logid, hass))

	return True

async def poll_log(device, logid, hass):
	try:
		for event in await device.log_pull(logid,timeout=30):
			hass.bus.async_fire(DOMAIN+"_event", event)
	except (DeviceConnectionError, DeviceUnsupportedError) as err:
		await asyncio.sleep(5)
	except DeviceApiError as err:
		if err.error == ApiError.INVALID_PARAMETER_VALUE:
			logid = await device.log_subscribe()

	hass.loop.create_task(poll_log(device, logid, hass))
