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


