import asyncio
import logging
from typing import Any
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PROTOCOL, CONF_VERIFY_SSL
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.selector import selector
import aiohttp
import voluptuous as vol
from py2n import Py2NDevice
from py2n.exceptions import ApiError, DeviceApiError, DeviceConnectionError
from .const import (
    CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
    CONF_DISABLE_CONTROL_ENTITIES,
    DOMAIN,
    CONF_AUTH_METHOD,
    CONF_CERTIFICATE_FINGERPRINT,
    DEFAULT_AUTH_METHOD,
    DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
    DEFAULT_DISABLE_CONTROL_ENTITIES,
    DEFAULT_VERIFY_SSL,
    SUPPORTED_AUTH_METHODS,
)
from .utils import (
    sanitize_connection_data,
    async_get_ssl_certificate_fingerprint,
    create_connection_data,
    normalize_auth_method,
)

_LOGGER = logging.getLogger(__name__)
SUPPORTED_PROTOCOLS = {"http", "https"}
DEFAULT_PROTOCOL = "https"
API_ERROR_TO_FLOW_ERROR: dict[ApiError, str] = {
    ApiError.INVALID_CONNECTION_TYPE: "invalid_connection_type",
    ApiError.AUTHORIZATION_REQUIRED: "authorization_required",
    ApiError.INSUFFICIENT_PRIVILEGES: "insufficient_privileges",
    ApiError.INVALID_AUTHENTICATION_METHOD: "invalid_authentication_method",
}


def _build_user_form_schema(
    *,
    host_default: str = "",
    username_default: str = "",
    password_default: str = "",
    protocol_default: str = DEFAULT_PROTOCOL,
    auth_method_default: str = DEFAULT_AUTH_METHOD,
    verify_ssl_default: bool = DEFAULT_VERIFY_SSL,
    create_read_only_status_entities_default: bool = DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
    disable_control_entities_default: bool = DEFAULT_DISABLE_CONTROL_ENTITIES,
) -> vol.Schema:
    """Build schema for connection settings forms."""
    return vol.Schema({
        vol.Required(CONF_HOST, default=host_default): cv.string,
        vol.Required(CONF_USERNAME, default=username_default): cv.string,
        vol.Required(CONF_PASSWORD, default=password_default): cv.string,
        vol.Required(CONF_PROTOCOL, default=protocol_default):
            selector({
                "select": {
                    "options": ["https", "http"],
                    "mode": "dropdown",
                },
            }),
        vol.Required(CONF_AUTH_METHOD, default=auth_method_default):
            selector({
                "select": {
                    "options": list(SUPPORTED_AUTH_METHODS),
                    "mode": "dropdown",
                },
            }),
        vol.Required(CONF_VERIFY_SSL, default=verify_ssl_default):
            selector({
                "boolean": {},
            }),
        vol.Required(
            CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
            default=create_read_only_status_entities_default,
        ): selector({"boolean": {}}),
        vol.Required(
            CONF_DISABLE_CONTROL_ENTITIES,
            default=disable_control_entities_default,
        ): selector({"boolean": {}}),
    })


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


async def _async_validate_connection(
    user_input: dict[str, Any],
) -> tuple[Py2NDevice | None, str | None, str, dict[str, Any]]:
    """Validate connection data against the device API."""
    host = user_input[CONF_HOST]
    verify_ssl = user_input[CONF_VERIFY_SSL]
    auth_method = user_input.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD)
    protocol = DEFAULT_PROTOCOL
    try:
        auth_method = normalize_auth_method(auth_method)
    except ValueError:
        sanitized_payload = {
            CONF_HOST: host,
            CONF_USERNAME: "***" if user_input.get(CONF_USERNAME) else None,
            CONF_PASSWORD: "***" if user_input.get(CONF_PASSWORD) else None,
            CONF_PROTOCOL: user_input.get(CONF_PROTOCOL),
            CONF_AUTH_METHOD: user_input.get(CONF_AUTH_METHOD),
            CONF_VERIFY_SSL: verify_ssl,
        }
        _LOGGER.error(
            "Connection test aborted: invalid auth method %r; payload=%s",
            user_input.get(CONF_AUTH_METHOD),
            sanitized_payload,
        )
        return None, "invalid_auth_method", protocol, sanitized_payload
    try:
        protocol = _normalize_protocol(user_input.get(CONF_PROTOCOL))
    except ValueError:
        sanitized_payload = {
            CONF_HOST: host,
            CONF_USERNAME: "***" if user_input.get(CONF_USERNAME) else None,
            CONF_PASSWORD: "***" if user_input.get(CONF_PASSWORD) else None,
            CONF_PROTOCOL: user_input.get(CONF_PROTOCOL),
            CONF_AUTH_METHOD: auth_method,
            CONF_VERIFY_SSL: verify_ssl,
        }
        _LOGGER.error(
            "Connection test aborted: invalid protocol %r; payload=%s",
            user_input.get(CONF_PROTOCOL),
            sanitized_payload,
        )
        return None, "invalid_protocol", protocol, sanitized_payload

    try:
        connect_options = create_connection_data(
            host=host,
            username=user_input[CONF_USERNAME],
            password=user_input[CONF_PASSWORD],
            protocol=protocol,
            auth_method=auth_method,
            ssl_verify=verify_ssl,
        )
    except ValueError as err:
        sanitized_payload = {
            CONF_HOST: host,
            CONF_USERNAME: "***" if user_input.get(CONF_USERNAME) else None,
            CONF_PASSWORD: "***" if user_input.get(CONF_PASSWORD) else None,
            CONF_PROTOCOL: protocol,
            CONF_AUTH_METHOD: auth_method,
            CONF_VERIFY_SSL: verify_ssl,
        }
        _LOGGER.error("Connection test aborted: %s; payload=%s", err, sanitized_payload)
        return None, "unsupported_auth_method", protocol, sanitized_payload

    sanitized_payload = sanitize_connection_data(connect_options) | {
        CONF_AUTH_METHOD: auth_method,
        CONF_VERIFY_SSL: verify_ssl,
    }

    _LOGGER.debug("Testing connection with payload=%s", sanitized_payload)
    try:
        async with aiohttp.ClientSession() as session:
            device = await Py2NDevice.create(session, connect_options)
    except (TimeoutError, asyncio.TimeoutError):
        _LOGGER.error(
            "Connection test failed: timeout; payload=%s",
            sanitized_payload,
        )
        return None, "timeout_error", protocol, sanitized_payload
    except DeviceConnectionError as err:
        inner_error = err.args[0] if err.args else None
        if isinstance(inner_error, (TimeoutError, asyncio.TimeoutError)):
            _LOGGER.error(
                "Connection test failed: timeout via DeviceConnectionError (%r); payload=%s",
                inner_error,
                sanitized_payload,
            )
            return None, "timeout_error", protocol, sanitized_payload
        _LOGGER.error(
            "Connection test failed: device connection error (%s: %r); payload=%s",
            type(inner_error).__name__ if inner_error is not None else type(err).__name__,
            inner_error if inner_error is not None else err,
            sanitized_payload,
        )
        return None, "cannot_connect", protocol, sanitized_payload
    except DeviceApiError as err:
        _LOGGER.error(
            "Connection test failed: device API error %s; payload=%s",
            err.error.name,
            sanitized_payload,
        )
        return None, _map_api_error_to_flow_error(err.error), protocol, sanitized_payload
    except (aiohttp.ClientError, OSError) as err:
        _LOGGER.error(
            "Connection test failed: network/client error (%s: %r); payload=%s",
            type(err).__name__,
            err,
            sanitized_payload,
        )
        return None, "cannot_connect", protocol, sanitized_payload
    except Exception:
        _LOGGER.exception(
            "Unexpected error during device validation; payload=%s",
            sanitized_payload,
        )
        return None, "unknown", protocol, sanitized_payload

    _LOGGER.info(
        "Connection test succeeded; payload=%s",
        sanitized_payload,
    )
    return device, None, protocol, sanitized_payload


class Helios2nOptionsFlow(config_entries.OptionsFlow):
    """Handle options for Helios2n."""

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            device, error_key, protocol, _ = await _async_validate_connection(user_input)
            if error_key:
                return self.async_show_form(
                    step_id="init",
                    data_schema=_build_user_form_schema(
                        host_default=user_input[CONF_HOST],
                        username_default=user_input[CONF_USERNAME],
                        password_default=user_input[CONF_PASSWORD],
                        protocol_default=user_input.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
                        auth_method_default=user_input.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD),
                        verify_ssl_default=user_input[CONF_VERIFY_SSL],
                        create_read_only_status_entities_default=user_input.get(
                            CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
                            DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
                        ),
                        disable_control_entities_default=user_input.get(
                            CONF_DISABLE_CONTROL_ENTITIES,
                            DEFAULT_DISABLE_CONTROL_ENTITIES,
                        ),
                    ),
                    errors={"base": error_key},
                )
            auth_method = normalize_auth_method(user_input.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD))

            cert_fingerprint = None
            if protocol == "https" and not user_input[CONF_VERIFY_SSL]:
                cert_fingerprint = await async_get_ssl_certificate_fingerprint(
                    self.hass, user_input[CONF_HOST]
                )

            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data={
                    **self.config_entry.data,
                    CONF_HOST: user_input[CONF_HOST],
                    CONF_PROTOCOL: protocol,
                    CONF_AUTH_METHOD: auth_method,
                    CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                    CONF_CREATE_READ_ONLY_STATUS_ENTITIES: user_input[
                        CONF_CREATE_READ_ONLY_STATUS_ENTITIES
                    ],
                    CONF_DISABLE_CONTROL_ENTITIES: user_input[CONF_DISABLE_CONTROL_ENTITIES],
                    CONF_CERTIFICATE_FINGERPRINT: cert_fingerprint,
                },
                options={
                    **self.config_entry.options,
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                },
            )
            await self.hass.config_entries.async_reload(self.config_entry.entry_id)
            assert device is not None
            return self.async_create_entry(
                title=device.data.name,
                data={
                    **self.config_entry.options,
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                },
            )

        return self.async_show_form(
            step_id="init",
            data_schema=_build_user_form_schema(
                host_default=self.config_entry.data.get(CONF_HOST, ""),
                username_default=self.config_entry.options.get(
                    CONF_USERNAME, self.config_entry.data.get(CONF_USERNAME, "")
                ),
                password_default=self.config_entry.options.get(
                    CONF_PASSWORD, self.config_entry.data.get(CONF_PASSWORD, "")
                ),
                protocol_default=self.config_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
                auth_method_default=self.config_entry.data.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD),
                verify_ssl_default=self.config_entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                create_read_only_status_entities_default=self.config_entry.data.get(
                    CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
                    DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
                ),
                disable_control_entities_default=self.config_entry.data.get(
                    CONF_DISABLE_CONTROL_ENTITIES,
                    DEFAULT_DISABLE_CONTROL_ENTITIES,
                ),
            ),
        )


class Helios2nConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Helios/2n config flow"""
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors = {}
        if user_input is not None:
            host = user_input[CONF_HOST]
            auth_method = user_input.get(CONF_AUTH_METHOD, DEFAULT_AUTH_METHOD)
            verify_ssl = user_input[CONF_VERIFY_SSL]
            device, error_key, protocol, _ = await _async_validate_connection(user_input)
            if error_key:
                errors["base"] = error_key

            if not errors:
                auth_method = normalize_auth_method(auth_method)
                assert device is not None
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
                        CONF_AUTH_METHOD: auth_method,
                        CONF_VERIFY_SSL: verify_ssl,
                        CONF_CREATE_READ_ONLY_STATUS_ENTITIES: user_input[
                            CONF_CREATE_READ_ONLY_STATUS_ENTITIES
                        ],
                        CONF_DISABLE_CONTROL_ENTITIES: user_input[CONF_DISABLE_CONTROL_ENTITIES],
                        CONF_CERTIFICATE_FINGERPRINT: cert_fingerprint,
                    },
                    options={
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_build_user_form_schema(),
            errors=errors
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        """Get options flow for this integration."""
        return Helios2nOptionsFlow()
    
