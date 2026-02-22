from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_PROTOCOL, Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback, ServiceResponse, SupportsResponse
from homeassistant.helpers.typing import ConfigType
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from py2n import Py2NDevice, Py2NConnectionData
from py2n.exceptions import DeviceConnectionError, DeviceUnsupportedError, DeviceApiError, ApiError, Py2NError

import asyncio
from asyncio import TimeoutError

from .const import DOMAIN, ATTR_METHOD, DEFAULT_METHOD, ATTR_ENDPOINT, ATTR_TIMEOUT, DEFAULT_TIMEOUT, ATTR_DATA, ATTR_JSON, ATTR_ENTRY
from .coordinator import Helios2nPortDataUpdateCoordinator, Helios2nSwitchDataUpdateCoordinator, Helios2nSensorDataUpdateCoordinator

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

		method = call.data.get(ATTR_METHOD, DEFAULT_METHOD)
		endpoint = call.data.get(ATTR_ENDPOINT)
		timeout = call.data.get(ATTR_TIMEOUT,DEFAULT_TIMEOUT)
		data = call.data.get(ATTR_DATA)
		json = call.data.get(ATTR_JSON)
		result = {}
		try: 
			result = await device.api_request(endpoint, timeout, method, data, json)
		except Py2NError as err:
			raise HomeAssistantError("error from api call:", err) from err

		if result is None:
			result = {}

		if call.return_response:
			return result
		else:
			return None

	hass.services.async_register(DOMAIN, "api_call", api_call,supports_response=SupportsResponse.OPTIONAL)

	# Return boolean to indicate that initialization was successful.
	return True

async def async_setup_entry(hass: HomeAssistant, config: ConfigType) -> bool:
	aiohttp_session = async_get_clientsession(hass)
	connection_data = Py2NConnectionData(host= config.data[CONF_HOST], username=config.data[CONF_USERNAME], password=config.data[CONF_PASSWORD], protocol=config.data[CONF_PROTOCOL])
	device = await Py2NDevice.create(aiohttp_session, connection_data)
	entry_data = hass.data.setdefault(DOMAIN,{}).setdefault(config.entry_id,{})
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
