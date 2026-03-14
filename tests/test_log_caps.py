"""Tests for log capabilities detection."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from custom_components.helios2n.log import async_get_supported_log_events


@pytest.mark.asyncio
async def test_async_get_supported_log_events_success():
    """Fetching supported events returns a set from a valid response."""
    device = MagicMock()
    device.api_request = AsyncMock(return_value={
        "success": True,
        "result": {
            "events": ["KeyPressed", "InputChanged", "OutputChanged", "UserAuthenticated"]
        }
    })
    result = await async_get_supported_log_events(device)
    assert result == {"KeyPressed", "InputChanged", "OutputChanged", "UserAuthenticated"}


@pytest.mark.asyncio
async def test_async_get_supported_log_events_empty_events():
    """Empty events list returns empty set."""
    device = MagicMock()
    device.api_request = AsyncMock(return_value={
        "success": True,
        "result": {"events": []}
    })
    result = await async_get_supported_log_events(device)
    assert result == set()


@pytest.mark.asyncio
async def test_async_get_supported_log_events_missing_result():
    """Missing result key returns empty set."""
    device = MagicMock()
    device.api_request = AsyncMock(return_value={"success": True})
    result = await async_get_supported_log_events(device)
    assert result == set()


@pytest.mark.asyncio
async def test_async_get_supported_log_events_invalid_response_type():
    """Non-dict response returns empty set."""
    device = MagicMock()
    device.api_request = AsyncMock(return_value=None)
    result = await async_get_supported_log_events(device)
    assert result == set()


@pytest.mark.asyncio
async def test_async_get_supported_log_events_events_not_list():
    """Non-list events value returns empty set."""
    device = MagicMock()
    device.api_request = AsyncMock(return_value={
        "success": True,
        "result": {"events": "not a list"}
    })
    result = await async_get_supported_log_events(device)
    assert result == set()


@pytest.mark.asyncio
async def test_async_get_supported_log_events_api_request_exception():
    """Exception from api_request returns empty set."""
    device = MagicMock()
    device.api_request = AsyncMock(side_effect=Exception("Connection error"))
    result = await async_get_supported_log_events(device)
    assert result == set()
