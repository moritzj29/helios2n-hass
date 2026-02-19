"""Shared test fixtures for Helios2N integration."""
import pytest
from unittest.mock import MagicMock, AsyncMock
from py2n import Py2NConnectionData, Py2NDevice


@pytest.fixture
def connection_data():
	"""Create mock connection data."""
	return Py2NConnectionData(
		host="192.168.1.100",
		username="admin",
		password="password123",
		protocol="https",
	)


@pytest.fixture
def mock_device():
	"""Create mock Py2NDevice."""
	device = AsyncMock(spec=Py2NDevice)
	device.api_request = AsyncMock(return_value={"status": "ok"})
	device.log_subscribe = AsyncMock(return_value="logid123")
	device.log_pull = AsyncMock(return_value=[])
	return device


@pytest.fixture
def mock_hass():
	"""Create mock Home Assistant instance."""
	hass = MagicMock()
	hass.data = {}
	hass.async_create_task = MagicMock()
	hass.loop = MagicMock()
	hass.loop.create_task = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()
	hass.services = MagicMock()
	hass.services.async_register = MagicMock()
	hass.services.async_remove = MagicMock()
	hass.config_entries = MagicMock()
	hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
	return hass
