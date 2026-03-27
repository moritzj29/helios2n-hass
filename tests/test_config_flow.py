"""Tests for config flow behavior and error handling."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from py2n.exceptions import ApiError, DeviceApiError, DeviceConnectionError, DeviceUnsupportedError

from custom_components.helios2n import config_flow as flow_module
from custom_components.helios2n.config_flow import Helios2nConfigFlow, Helios2nOptionsFlow
from homeassistant.const import (
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_PROTOCOL,
    CONF_VERIFY_SSL,
)
from custom_components.helios2n.const import (
    CONF_AUTH_METHOD,
    CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
    CONF_DISABLE_CONTROL_ENTITIES,
)


@pytest.fixture(autouse=True)
def mock_async_get_clientsession():
    """Mock async_get_clientsession to avoid needing real HA infrastructure."""
    with patch('custom_components.helios2n.config_flow.async_get_clientsession') as mock:
        # Return a MagicMock that can be used as an aiohttp session
        mock.return_value = MagicMock()
        yield mock


VALID_USER_INPUT = {
    "host": "192.168.1.25",
    "username": "homeassistant",
    "password": "secret",
    "protocol": "https",
    "auth_method": "basic",
    "verify_ssl": False,
    "create_read_only_status_entities": False,
    "disable_control_entities": False,
}


def _new_flow(mock_hass) -> Helios2nConfigFlow:
    flow = Helios2nConfigFlow()
    flow.hass = mock_hass
    flow.async_set_unique_id = AsyncMock()
    flow._abort_if_unique_id_configured = MagicMock()
    return flow


def _new_options_flow(mock_hass) -> tuple[Helios2nOptionsFlow, MagicMock]:
    config_entry = MagicMock()
    config_entry.entry_id = "entry-1"
    config_entry.domain = "helios2n"
    config_entry.data = {
        "host": "192.168.1.10",
        "username": "old_user",
        "password": "old_pass",
        "protocol": "https",
        "auth_method": "basic",
        "verify_ssl": True,
        "create_read_only_status_entities": False,
        "disable_control_entities": False,
    }
    config_entry.options = {}
    mock_hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    mock_hass.config_entries.async_update_entry = MagicMock()
    mock_hass.config_entries.async_reload = AsyncMock(return_value=True)

    flow = Helios2nOptionsFlow()
    flow.hass = mock_hass
    flow.handler = config_entry.entry_id
    return flow, config_entry


@pytest.mark.asyncio
async def test_async_step_user_returns_timeout_error(mock_hass):
    """Timeout errors should be mapped to timeout_error."""
    flow = _new_flow(mock_hass)

    with patch.object(flow_module.Py2NDevice, "create", new=AsyncMock(side_effect=asyncio.TimeoutError)):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "timeout_error"


@pytest.mark.asyncio
async def test_async_step_user_returns_cannot_connect_for_client_error(mock_hass):
    """Network errors should be mapped to cannot_connect."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=aiohttp.ClientError("network")),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_async_step_user_returns_api_error(mock_hass):
    """API errors should be mapped to api_error."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=DeviceApiError(error=ApiError.AUTHORIZATION_REQUIRED)),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "authorization_required"


@pytest.mark.asyncio
async def test_async_step_user_maps_invalid_connection_type_error(mock_hass):
    """INVALID_CONNECTION_TYPE should map to a specific UI error."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=DeviceApiError(error=ApiError.INVALID_CONNECTION_TYPE)),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_connection_type"


@pytest.mark.asyncio
async def test_async_step_user_returns_unknown_for_unexpected_error(mock_hass):
    """Unexpected exceptions should be mapped to unknown."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "unknown"


@pytest.mark.asyncio
async def test_async_step_user_returns_cannot_connect_for_unsupported_device_response(mock_hass):
    """Malformed/unsupported device responses should map to cannot_connect."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=DeviceUnsupportedError("response malformed")),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_async_step_user_normalizes_protocol_before_connect(mock_hass):
    """Protocol should be normalized to lowercase before connecting."""
    flow = _new_flow(mock_hass)
    mock_device = SimpleNamespace(data=SimpleNamespace(serial="SER123", name="Door Intercom"))
    user_input = {**VALID_USER_INPUT, "protocol": "HTTPS", "verify_ssl": True}

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(return_value=mock_device),
    ) as create_mock:
        result = await flow.async_step_user(user_input)

    assert result["type"] == "create_entry"
    assert result["data"]["protocol"] == "https"
    connect_options = create_mock.await_args.args[1]
    assert connect_options.protocol == "https"


@pytest.mark.asyncio
async def test_async_step_user_uses_invalid_protocol_error(mock_hass):
    """Invalid protocol values should be rejected with explicit error."""
    flow = _new_flow(mock_hass)
    user_input = {**VALID_USER_INPUT, "protocol": "ftp"}

    result = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_protocol"


@pytest.mark.asyncio
async def test_async_step_user_logs_error_on_failure(mock_hass):
    """Failed connection attempts should log at error level."""
    flow = _new_flow(mock_hass)
    expected_payload = {
        "host": VALID_USER_INPUT["host"],
        "username": "***",
        "password": "***",
        "protocol": VALID_USER_INPUT["protocol"],
        "auth_method": VALID_USER_INPUT["auth_method"],
        "verify_ssl": VALID_USER_INPUT["verify_ssl"],
    }

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=aiohttp.ClientError("network")),
    ), patch.object(flow_module._LOGGER, "error") as error_log:
        await flow.async_step_user(VALID_USER_INPUT)

    assert error_log.call_count == 1
    assert error_log.call_args.args[0] == "Connection test failed: network/client error (%s: %r); payload=%s"
    assert error_log.call_args.args[1] == "ClientError"
    assert isinstance(error_log.call_args.args[2], aiohttp.ClientError)
    assert str(error_log.call_args.args[2]) == "network"
    assert error_log.call_args.args[3] == expected_payload


@pytest.mark.asyncio
async def test_async_step_user_maps_wrapped_timeout_to_timeout_error(mock_hass):
    """Wrapped timeout in DeviceConnectionError should map to timeout_error."""
    flow = _new_flow(mock_hass)

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(side_effect=DeviceConnectionError(asyncio.TimeoutError())),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "timeout_error"


@pytest.mark.asyncio
async def test_async_step_user_logs_info_on_success(mock_hass):
    """Successful connection attempts should log at info level."""
    flow = _new_flow(mock_hass)
    mock_device = SimpleNamespace(data=SimpleNamespace(serial="SER123", name="Door Intercom"))
    user_input = {**VALID_USER_INPUT, "verify_ssl": True}
    expected_payload = {
        "host": user_input["host"],
        "username": "***",
        "password": "***",
        "protocol": user_input["protocol"],
        "auth_method": user_input["auth_method"],
        "verify_ssl": True,
    }

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(return_value=mock_device),
    ), patch.object(flow_module._LOGGER, "info") as info_log:
        await flow.async_step_user(user_input)

    assert info_log.call_count == 1
    assert info_log.call_args.args == (
        "Connection test succeeded; payload=%s",
        expected_payload,
    )


@pytest.mark.asyncio
async def test_async_step_user_logs_invalid_protocol_with_sanitized_payload(mock_hass):
    """Invalid protocol path should log sanitized payload for diagnostics."""
    flow = _new_flow(mock_hass)
    user_input = {**VALID_USER_INPUT, "protocol": "ftp"}
    expected_payload = {
        "host": user_input["host"],
        "username": "***",
        "password": "***",
        "protocol": "ftp",
        "auth_method": user_input["auth_method"],
        "verify_ssl": user_input["verify_ssl"],
    }

    with patch.object(flow_module._LOGGER, "error") as error_log:
        result = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_protocol"
    assert error_log.call_count == 1
    assert error_log.call_args.args == (
        "Connection test aborted: invalid protocol %r; payload=%s",
        "ftp",
        expected_payload,
    )


@pytest.mark.asyncio
async def test_options_flow_updates_all_connection_parameters(mock_hass):
    """Options flow should update host/protocol/verify_ssl and credentials."""
    flow, config_entry = _new_options_flow(mock_hass)
    user_input = {
        "host": "192.168.1.55",
        "username": "new_user",
        "password": "new_pass",
        "protocol": "HTTPS",
        "auth_method": "basic",
        "verify_ssl": False,
        "create_read_only_status_entities": True,
        "disable_control_entities": True,
    }
    mock_device = SimpleNamespace(data=SimpleNamespace(name="Door Intercom"))

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(return_value=mock_device),
    ):
        result = await flow.async_step_init(user_input)

    assert result["type"] == "create_entry"
    assert result["title"] == "Door Intercom"
    assert result["data"] == {}
    mock_hass.config_entries.async_update_entry.assert_called_once_with(
        config_entry,
        data={
            **config_entry.data,
            "host": "192.168.1.55",
            "username": "new_user",
            "password": "new_pass",
            "protocol": "https",
            "auth_method": "basic",
            "verify_ssl": False,
            "create_read_only_status_entities": True,
            "disable_control_entities": True,
        },
        options={},
    )
    mock_hass.config_entries.async_reload.assert_awaited_once_with(config_entry.entry_id)


@pytest.mark.asyncio
async def test_options_flow_returns_invalid_protocol_error(mock_hass):
    """Options flow should reject invalid protocol values."""
    flow, _ = _new_options_flow(mock_hass)
    user_input = {
        "host": "192.168.1.55",
        "username": "new_user",
        "password": "new_pass",
        "protocol": "ftp",
        "auth_method": "basic",
        "verify_ssl": True,
    }

    result = await flow.async_step_init(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == "init"
    assert result["errors"]["base"] == "invalid_protocol"


@pytest.mark.asyncio
async def test_async_step_user_rejects_invalid_auth_method(mock_hass):
    """Invalid auth method values should be rejected with explicit error."""
    flow = _new_flow(mock_hass)
    user_input = {**VALID_USER_INPUT, "auth_method": "token"}

    result = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth_method"


@pytest.mark.asyncio
async def test_async_step_user_creates_entry_successfully(mock_hass):
    """Successful validation should create entry."""
    flow = _new_flow(mock_hass)
    mock_device = SimpleNamespace(data=SimpleNamespace(serial="SER123", name="Door Intercom"))

    with patch.object(
        flow_module.Py2NDevice,
        "create",
        new=AsyncMock(return_value=mock_device),
    ):
        result = await flow.async_step_user(VALID_USER_INPUT)

    assert result["type"] == "create_entry"
    assert result["title"] == "Door Intercom"
    assert result["data"]["host"] == VALID_USER_INPUT["host"]
    assert result["data"]["username"] == VALID_USER_INPUT["username"]
    assert result["data"]["password"] == VALID_USER_INPUT["password"]
    assert result["data"]["protocol"] == "https"
    assert result["data"]["auth_method"] == "basic"
    assert result["data"]["verify_ssl"] is False
    assert result["data"]["create_read_only_status_entities"] is False
    assert result["data"]["disable_control_entities"] is False
    assert result["options"] == {}
    assert flow.async_set_unique_id.await_count == 1
    assert flow.async_set_unique_id.await_args.args == ("SER123",)
    assert flow._abort_if_unique_id_configured.call_count == 1


@pytest.mark.asyncio
async def test_async_step_user_retains_values_on_validation_error(mock_hass):
    """When validation fails, the form should retain entered values as defaults."""
    flow = _new_flow(mock_hass)
    # Trigger a validation error (invalid protocol)
    user_input = {
        "host": "192.168.1.25",
        "username": "homeassistant",
        "password": "secret",
        "protocol": "ftp",  # Invalid
        "auth_method": "basic",
        "verify_ssl": False,
        "create_read_only_status_entities": True,
        "disable_control_entities": True,
    }
    result = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "invalid_protocol"

    # Verify that the entered values are passed as defaults to the schema builder.
    with patch.object(flow_module, '_build_user_form_schema', wraps=flow_module._build_user_form_schema) as mock_build:
        # Need to re-invoke the flow since we already consumed the first call
        flow2 = _new_flow(mock_hass)
        result2 = await flow2.async_step_user(user_input)
        assert mock_build.called
        kwargs = mock_build.call_args.kwargs
        assert kwargs['host_default'] == user_input[CONF_HOST]
        assert kwargs['username_default'] == user_input[CONF_USERNAME]
        assert kwargs['password_default'] == user_input[CONF_PASSWORD]
        assert kwargs['protocol_default'] == user_input["protocol"]  # 'ftp'
        assert kwargs['auth_method_default'] == user_input[CONF_AUTH_METHOD]
        assert kwargs['verify_ssl_default'] == user_input[CONF_VERIFY_SSL]
        assert kwargs['create_read_only_status_entities_default'] == user_input[CONF_CREATE_READ_ONLY_STATUS_ENTITIES]
        assert kwargs['disable_control_entities_default'] == user_input[CONF_DISABLE_CONTROL_ENTITIES]
