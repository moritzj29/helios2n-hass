import asyncio
import logging
from typing import Any
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PROTOCOL, CONF_VERIFY_SSL
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.selector import selector
import aiohttp
import voluptuous as vol
from py2n import Py2NDevice, Py2NConnectionData
from py2n.exceptions import ApiError, DeviceApiError, DeviceConnectionError
from .const import DOMAIN, CONF_CERTIFICATE_FINGERPRINT, DEFAULT_VERIFY_SSL
from .utils import sanitize_connection_data, async_get_ssl_certificate_fingerprint

_LOGGER = logging.getLogger(__name__)
SUPPORTED_PROTOCOLS = {"http", "https"}
DEFAULT_PROTOCOL = "https"
API_ERROR_TO_FLOW_ERROR: dict[ApiError, str] = {
    ApiError.INVALID_CONNECTION_TYPE: "invalid_connection_type",
    ApiError.AUTHORIZATION_REQUIRED: "authorization_required",
    ApiError.INSUFFICIENT_PRIVILEGES: "insufficient_privileges",
    ApiError.INVALID_AUTHENTICATION_METHOD: "invalid_authentication_method",
}


def _normalize_protocol(protocol_raw: object | None) -> str:
    """Normalize protocol value from config flow user input."""
    if protocol_raw is None:
        return DEFAULT_PROTOCOL
    protocol = str(protocol_raw).strip().lower()
    if protocol in SUPPORTED_PROTOCOLS:
        return protocol
    raise ValueError(f"Unsupported protocol: {protocol_raw}")


def _map_api_error_to_flow_error(error: ApiError) -> str:
    """Map API error codes to user-facing config flow errors."""
    return API_ERROR_TO_FLOW_ERROR.get(error, "api_error")


class Helios2nOptionsFlow(config_entries.OptionsFlow):
    """Handle options for Helios2n."""

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

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
            host = user_input[CONF_HOST]
            verify_ssl = user_input[CONF_VERIFY_SSL]
            protocol = DEFAULT_PROTOCOL
            try:
                protocol = _normalize_protocol(user_input.get(CONF_PROTOCOL))
            except ValueError:
                errors["base"] = "invalid_protocol"

            connect_options = Py2NConnectionData(
                host=host,
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                protocol=protocol,
            )
            sanitized_payload = sanitize_connection_data(connect_options) | {
                CONF_VERIFY_SSL: verify_ssl,
            }
            if errors:
                sanitized_payload[CONF_PROTOCOL] = user_input.get(CONF_PROTOCOL)
                _LOGGER.error(
                    "Connection test aborted: invalid protocol %r; payload=%s",
                    user_input.get(CONF_PROTOCOL),
                    sanitized_payload,
                )

            if not errors:
                _LOGGER.debug("Testing connection with payload=%s", sanitized_payload)
                try:
                    async with aiohttp.ClientSession() as session:
                        device = await Py2NDevice.create(session, connect_options)
                except (TimeoutError, asyncio.TimeoutError):
                    _LOGGER.error(
                        "Connection test failed: timeout; payload=%s",
                        sanitized_payload,
                    )
                    errors["base"] = "timeout_error"
                except DeviceApiError as err:
                    _LOGGER.error(
                        "Connection test failed: device API error %s; payload=%s",
                        err.error.name,
                        sanitized_payload,
                    )
                    errors["base"] = _map_api_error_to_flow_error(err.error)
                except (DeviceConnectionError, aiohttp.ClientError, OSError) as err:
                    _LOGGER.error(
                        "Connection test failed: network/client error %s; payload=%s",
                        err,
                        sanitized_payload,
                    )
                    errors["base"] = "cannot_connect"
                except Exception:
                    _LOGGER.exception(
                        "Unexpected error during device validation; payload=%s",
                        sanitized_payload,
                    )
                    errors["base"] = "unknown"

            if not errors:
                _LOGGER.info(
                    "Connection test succeeded; payload=%s",
                    sanitized_payload,
                )
                await self.async_set_unique_id(device.data.serial)
                self._abort_if_unique_id_configured()

                # Get certificate fingerprint if using HTTPS with verify_ssl disabled
                cert_fingerprint = None
                if protocol == "https" and not verify_ssl:
                    cert_fingerprint = await async_get_ssl_certificate_fingerprint(
                        self.hass, host
                    )

                return self.async_create_entry(
                    title=device.data.name,
                    data={
                        CONF_HOST: user_input[CONF_HOST],
                        CONF_PROTOCOL: protocol,
                        CONF_VERIFY_SSL: verify_ssl,
                        CONF_CERTIFICATE_FINGERPRINT: cert_fingerprint,
                    },
                    options={
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_HOST): cv.string,
                vol.Required(CONF_USERNAME): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
                vol.Required(CONF_PROTOCOL, default=DEFAULT_PROTOCOL):
                    selector({
                        "select": {
                            "options": ["https", "http"],
                            "mode": "dropdown",
                        },
                    }),
                vol.Required(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL):
                    selector({
                        "boolean": {},
                    }),
            }),
            errors=errors
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        """Get options flow for this integration."""
        return Helios2nOptionsFlow()
    
