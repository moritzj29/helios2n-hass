"""Tests for __init__.py async_setup_entry and related functions."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from py2n import Py2NDevice

from custom_components.helios2n import (
    async_setup_entry,
    platforms as ALL_PLATFORMS,
)
from custom_components.helios2n.const import DOMAIN
from custom_components.helios2n.coordinator import (
    Helios2nPortDataUpdateCoordinator,
    Helios2nSensorDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)


@pytest.fixture
def mock_hass():
    """Mock HomeAssistant core."""
    hass = MagicMock()
    hass.data = {}
    hass.async_create_task = MagicMock()
    hass.config_entries = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.services = MagicMock()
    hass.services.async_register = MagicMock()
    hass.services.async_remove = MagicMock()
    hass.bus = MagicMock()
    hass.bus.async_fire = MagicMock()
    return hass


@pytest.fixture
def mock_entry():
    """Create a mock ConfigEntry."""
    entry = MagicMock(spec=ConfigEntry)
    entry.entry_id = "test-entry-id"
    entry.domain = DOMAIN
    entry.data = {
        "host": "192.168.1.100",
        "username": "admin",
        "password": "pass",
        "protocol": "https",
        "auth_method": "basic",
        "verify_ssl": False,
    }
    return entry


@pytest.fixture
def mock_device():
    """Create a mock Py2NDevice."""
    device = AsyncMock(spec=Py2NDevice)
    device.data = MagicMock(
        serial="SN123",
        name="Test Intercom",
        uptime=None,
        ports=[],
        switches=[],
    )
    device.log_subscribe = AsyncMock(return_value="logid123")
    device.api_request = AsyncMock(return_value={"result": {"events": ["SwitchStateChanged"]}})
    return device


@pytest.mark.asyncio
async def test_async_setup_entry_success(mock_hass, mock_entry, mock_device):
    """Test successful setup creates device, coordinators, forwards platforms, and starts log polling."""
    # Patch dependencies
    with (
        patch("custom_components.helios2n.async_get_clientsession", return_value=MagicMock()),
        patch("custom_components.helios2n.Py2NDevice.create", new=AsyncMock(return_value=mock_device)),
        patch("custom_components.helios2n.poll_log", new=AsyncMock()),  # prevent real polling loop
        patch("custom_components.helios2n.Helios2nPortDataUpdateCoordinator") as MockPortCoord,
        patch("custom_components.helios2n.Helios2nSwitchDataUpdateCoordinator") as MockSwitchCoord,
        patch("custom_components.helios2n.Helios2nSensorDataUpdateCoordinator") as MockSensorCoord,
        patch("custom_components.helios2n.async_get_supported_log_events", return_value={"SwitchStateChanged"}),
    ):
        # Prepare mock coordinators
        port_coord = AsyncMock()
        port_coord.async_config_entry_first_refresh = AsyncMock()
        MockPortCoord.return_value = port_coord

        switch_coord = AsyncMock()
        switch_coord.async_config_entry_first_refresh = AsyncMock()
        MockSwitchCoord.return_value = switch_coord

        sensor_coord = AsyncMock()
        sensor_coord.async_config_entry_first_refresh = AsyncMock()
        MockSensorCoord.return_value = sensor_coord

        # Run setup
        result = await async_setup_entry(mock_hass, mock_entry)

    assert result is True
    # Device stored
    assert mock_hass.data[DOMAIN][mock_entry.entry_id]["_device"] is mock_device
    # Supported log events stored (fallback not used)
    assert mock_hass.data[DOMAIN][mock_entry.entry_id]["supported_log_events"] == {"SwitchStateChanged"}

    # Coordinator assignments
    entry_data = mock_hass.data[DOMAIN][mock_entry.entry_id]
    assert isinstance(entry_data[Platform.LOCK]["coordinator"], type(switch_coord))
    assert isinstance(entry_data[Platform.SWITCH]["coordinator"], type(port_coord))
    assert isinstance(entry_data[Platform.SENSOR]["coordinator"], type(sensor_coord))
    assert isinstance(entry_data[Platform.BINARY_SENSOR]["coordinator"], type(port_coord))

    # First refresh called on each
    port_coord.async_config_entry_first_refresh.assert_awaited_once()
    switch_coord.async_config_entry_first_refresh.assert_awaited_once()
    sensor_coord.async_config_entry_first_refresh.assert_awaited_once()

    # Platform forwarding scheduled and awaited
    mock_hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(mock_entry, ALL_PLATFORMS)

    # Log subscription started
    mock_device.log_subscribe.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_device_creation_fails(mock_hass, mock_entry):
    """Test that if Py2NDevice.create raises, HomeAssistantError is raised."""
    with (
        patch("custom_components.helios2n.async_get_clientsession", return_value=MagicMock()),
        patch("custom_components.helios2n.Py2NDevice.create", new=AsyncMock(side_effect=RuntimeError("boom"))),
    ):
        from homeassistant.exceptions import HomeAssistantError
        with pytest.raises(HomeAssistantError):
            await async_setup_entry(mock_hass, mock_entry)
    # Nothing stored
    assert DOMAIN not in mock_hass.data


@pytest.mark.asyncio
async def test_async_setup_entry_log_caps_fallback(mock_hass, mock_entry, mock_device, caplog):
    """Test fallback to default log events when device.api_request fails or returns empty."""
    mock_device.api_request = AsyncMock(return_value={})  # no result or empty
    with (
        patch("custom_components.helios2n.async_get_clientsession", return_value=MagicMock()),
        patch("custom_components.helios2n.Py2NDevice.create", new=AsyncMock(return_value=mock_device)),
        patch("custom_components.helios2n.Helios2nPortDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSwitchDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSensorDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
    ):
        result = await async_setup_entry(mock_hass, mock_entry)

    assert result is True
    # Fallback set expected
    expected = {"SwitchStateChanged", "UserAuthenticated", "InputChanged", "OutputChanged"}
    assert mock_hass.data[DOMAIN][mock_entry.entry_id]["supported_log_events"] == expected
    # Warning should be logged
    assert any(
        "did not report supported log events" in record.message
        for record in caplog.records
        if record.levelname == "WARNING"
    )


@pytest.mark.asyncio
async def test_async_setup_entry_log_subscribe_fails(mock_hass, mock_entry, mock_device, caplog):
    """Test that log subscription failure is logged but does not prevent setup."""
    mock_device.log_subscribe = AsyncMock(side_effect=Exception("log down"))
    with (
        patch("custom_components.helios2n.async_get_clientsession", return_value=MagicMock()),
        patch("custom_components.helios2n.Py2NDevice.create", new=AsyncMock(return_value=mock_device)),
        patch("custom_components.helios2n.async_get_supported_log_events", return_value={"SwitchStateChanged"}),
        patch("custom_components.helios2n.Helios2nPortDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSwitchDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSensorDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
    ):
        result = await async_setup_entry(mock_hass, mock_entry)

    assert result is True
    # Warning about log subscription failure
    assert any(
        "Failed to subscribe to device logs" in record.message
        for record in caplog.records
        if record.levelname == "WARNING"
    )


@pytest.mark.asyncio
async def test_async_setup_entry_forward_setups_failure_raises(mock_hass, mock_entry, mock_device):
    """Test that async_forward_entry_setups exception propagates and fails setup."""
    with (
        patch("custom_components.helios2n.async_get_clientsession", return_value=MagicMock()),
        patch("custom_components.helios2n.Py2NDevice.create", new=AsyncMock(return_value=mock_device)),
        patch("custom_components.helios2n.Helios2nPortDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSwitchDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.Helios2nSensorDataUpdateCoordinator", return_value=AsyncMock(async_config_entry_first_refresh=AsyncMock())),
        patch("custom_components.helios2n.async_get_supported_log_events", return_value={"SwitchStateChanged"}),
    ):
        # Simulate a platform failing during forward
        mock_hass.config_entries.async_forward_entry_setups = AsyncMock(side_effect=RuntimeError("platform boom"))
        with pytest.raises(RuntimeError):
            await async_setup_entry(mock_hass, mock_entry)
