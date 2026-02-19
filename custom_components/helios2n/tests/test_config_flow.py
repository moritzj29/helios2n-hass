"""Tests for config flow behavior and error handling."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from py2n.exceptions import ApiError, DeviceApiError

from .. import config_flow as flow_module
from ..config_flow import Helios2nConfigFlow

VALID_USER_INPUT = {
	"host": "192.168.1.25",
	"username": "homeassistant",
	"password": "secret",
	"protocol": "https",
	"verify_ssl": False,
}


def _new_flow(mock_hass) -> Helios2nConfigFlow:
	flow = Helios2nConfigFlow()
	flow.hass = mock_hass
	flow.async_set_unique_id = AsyncMock()
	flow._abort_if_unique_id_configured = MagicMock()
	return flow


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
async def test_async_step_user_creates_entry_and_stores_fingerprint(mock_hass):
	"""Successful validation should create entry and persist SSL fingerprint."""
	flow = _new_flow(mock_hass)
	mock_device = SimpleNamespace(data=SimpleNamespace(serial="SER123", name="Door Intercom"))

	with patch.object(
		flow_module.Py2NDevice,
		"create",
		new=AsyncMock(return_value=mock_device),
	), patch.object(
		flow_module,
		"async_get_ssl_certificate_fingerprint",
		new=AsyncMock(return_value="deadbeef"),
	) as fingerprint_mock:
		result = await flow.async_step_user(VALID_USER_INPUT)

	assert result["type"] == "create_entry"
	assert result["title"] == "Door Intercom"
	assert result["data"]["host"] == VALID_USER_INPUT["host"]
	assert result["data"]["protocol"] == "https"
	assert result["data"]["verify_ssl"] is False
	assert result["data"]["certificate_fingerprint"] == "deadbeef"
	assert result["options"]["username"] == VALID_USER_INPUT["username"]
	assert result["options"]["password"] == VALID_USER_INPUT["password"]
	assert flow.async_set_unique_id.await_count == 1
	assert flow.async_set_unique_id.await_args.args == ("SER123",)
	assert flow._abort_if_unique_id_configured.call_count == 1
	assert fingerprint_mock.await_count == 1


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
		"verify_ssl": VALID_USER_INPUT["verify_ssl"],
	}

	with patch.object(
		flow_module.Py2NDevice,
		"create",
		new=AsyncMock(side_effect=aiohttp.ClientError("network")),
	), patch.object(flow_module._LOGGER, "error") as error_log:
		await flow.async_step_user(VALID_USER_INPUT)

	assert error_log.call_count == 1
	assert error_log.call_args.args[0] == "Connection test failed: network/client error %s; payload=%s"
	assert isinstance(error_log.call_args.args[1], aiohttp.ClientError)
	assert str(error_log.call_args.args[1]) == "network"
	assert error_log.call_args.args[2] == expected_payload


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
