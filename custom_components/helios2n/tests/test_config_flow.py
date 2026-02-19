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
	assert result["errors"]["base"] == "api_error"


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
