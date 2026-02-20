"""Tests for sensor metadata and state behavior."""
from datetime import UTC, datetime
from types import SimpleNamespace

from homeassistant.components.sensor import SensorDeviceClass

from ..sensor import Helios2nSensorEntity, SENSOR_TYPES


def test_uptime_sensor_uses_seconds_without_timestamp_device_class():
	"""Uptime sensor should be exposed as timestamp."""
	assert SENSOR_TYPES["uptime"][1] == SensorDeviceClass.TIMESTAMP
	assert SENSOR_TYPES["uptime"][2] is None


def test_uptime_sensor_native_value_reads_device_uptime():
	"""Uptime sensor should expose reboot timestamp from device data."""
	boot_time = datetime(2026, 2, 20, 8, 0, 0, tzinfo=UTC)
	entity = object.__new__(Helios2nSensorEntity)
	entity._device = SimpleNamespace(data=SimpleNamespace(uptime=boot_time))
	entity._type = "uptime"

	assert entity.native_value == boot_time
	assert entity.extra_state_attributes == {}
