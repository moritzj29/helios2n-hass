import logging
from typing import Any
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PROTOCOL
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.selector import selector
import aiohttp
import voluptuous as vol
from py2n import Py2NDevice, Py2NConnectionData
from py2n.exceptions import DeviceApiError
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class Helios2nOptionsFlow(config_entries.OptionsFlow):
	"""Handle options for Helios2n."""

	def __init__(self, config_entry):
		"""Initialize options flow."""
		self.config_entry = config_entry

	async def async_step_init(self, user_input=None):
		"""Manage the options."""
		if user_input is not None:
			return self.async_abort_and_create_entry(
				title="",
				data=user_input
			)

		options_schema = vol.Schema({
			vol.Required(
				CONF_USERNAME,
				default=self.config_entry.options.get(CONF_USERNAME, ""),
			): cv.string,
			vol.Required(
				CONF_PASSWORD,
				default=self.config_entry.options.get(CONF_PASSWORD, ""),
			): cv.string,
		})

		return self.async_show_form(
			step_id="init",
			data_schema=options_schema
		)


class Helios2nConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
	"""Helios/2n config flow"""
	VERSION = 1

	async def async_step_user(self, user_input: dict[str, Any] | None = None) -> config_entries.FlowResult:
		errors = {}
		if user_input is not None:
			connect_options = Py2NConnectionData(user_input[CONF_HOST], user_input[CONF_USERNAME], user_input[CONF_PASSWORD], user_input[CONF_PROTOCOL])
			_LOGGER.error(connect_options)
			try:
				async with aiohttp.ClientSession() as session:
					device = await Py2NDevice.create(session, connect_options)
			except TimeoutError:
				errors["base"] = "timeout_error"
			except DeviceApiError:
				errors["base"] = "api_error"
			
			if not errors:
				await self.async_set_unique_id(device.data.serial)
				self._abort_if_unique_id_configured()

				return self.async_create_entry(
					title=device.data.name,
					data={
						CONF_HOST: user_input[CONF_HOST],
						CONF_PROTOCOL: user_input[CONF_PROTOCOL],
					},
					options={
						CONF_USERNAME: user_input[CONF_USERNAME],
						CONF_PASSWORD: user_input[CONF_PASSWORD],
					}
				)

		return self.async_show_form(
			step_id="user",
			data_schema=vol.Schema({
				vol.Required(CONF_HOST): cv.string,
				vol.Required(CONF_USERNAME): cv.string,
				vol.Required(CONF_PASSWORD): cv.string,
				vol.Required(CONF_PROTOCOL, default="http"):
					selector({
						"select": {
							"options": ["http", "https"],
							"mode": "dropdown",
						},
					}),
			}),
			errors=errors
		)

	@staticmethod
	def async_get_options_flow(config_entry):
		"""Get options flow for this integration."""
		return Helios2nOptionsFlow(config_entry)
	
