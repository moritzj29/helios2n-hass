"""Tests for sensor metadata and state behavior."""
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from homeassistant.components.sensor import SensorDeviceClass

from custom_components.helios2n.sensor import Helios2nSensorEntity, SENSOR_TYPES


def test_uptime_sensor_uses_seconds_without_timestamp_device_class():
    """Uptime sensor should be exposed as timestamp."""
    sensor_config = SENSOR_TYPES["uptime"]
    assert sensor_config.device_class == SensorDeviceClass.TIMESTAMP
    assert sensor_config.units is None


def test_uptime_sensor_native_value_reads_device_uptime():
    """Uptime sensor should expose reboot timestamp from device data."""
    boot_time = datetime(2026, 2, 20, 8, 0, 0, tzinfo=UTC)
    entity = object.__new__(Helios2nSensorEntity)
    entity._device = SimpleNamespace(data=SimpleNamespace(uptime=boot_time))
    entity._type = "uptime"

    assert entity.native_value == boot_time
    assert entity.extra_state_attributes == {}


def test_uptime_sensor_name_and_unique_id():
    """Uptime sensor should have correct name and unique_id."""
    device = SimpleNamespace(
        data=SimpleNamespace(
            serial="SN123",
            mac="aa:bb:cc:dd:ee:ff",
            host="192.168.1.100",
            name="Device",
            model="X",
            hardware="1.0",
            firmware="2.0",
        ),
        options=SimpleNamespace(protocol="https"),
    )
    # Create a minimally functional coordinator mock
    coordinator = MagicMock()
    coordinator.data = {}
    coordinator.last_update_success = True
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    entity = Helios2nSensorEntity(coordinator, device, "uptime")

    assert entity.name == "Uptime"
    assert entity.unique_id == "SN123_sensor_uptime"
    assert entity.device_info["name"] == "Device"
