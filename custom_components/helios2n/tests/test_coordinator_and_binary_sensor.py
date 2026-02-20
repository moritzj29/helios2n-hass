"""Tests for coordinator return-data contracts and binary sensor safety."""
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..binary_sensor import Helios2nPortBinarySensorEntity
from ..coordinator import (
    Helios2nPortDataUpdateCoordinator,
    Helios2nSensorDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)


@pytest.mark.asyncio
async def test_port_coordinator_returns_port_state_mapping():
    """Port coordinator should return a state mapping for entities."""
    coordinator = object.__new__(Helios2nPortDataUpdateCoordinator)
    coordinator.device = AsyncMock()
    coordinator.device.data = SimpleNamespace(
        ports=[
            SimpleNamespace(id="input1", state=True),
            SimpleNamespace(id="input2", state=False),
        ]
    )

    result = await coordinator._async_update_data()

    assert result == {"input1": True, "input2": False}


@pytest.mark.asyncio
async def test_switch_coordinator_returns_switch_state_mapping():
    """Switch coordinator should return a switch-id to state mapping."""
    coordinator = object.__new__(Helios2nSwitchDataUpdateCoordinator)
    coordinator.device = SimpleNamespace(
        update_switch_status=AsyncMock(),
        get_switch=MagicMock(side_effect=[True, False]),
        data=SimpleNamespace(
        switches=[SimpleNamespace(id=1), SimpleNamespace(id=2)]
        ),
    )

    result = await coordinator._async_update_data()

    assert result == {1: True, 2: False}


@pytest.mark.asyncio
async def test_sensor_coordinator_returns_uptime_value():
    """Sensor coordinator should return structured data."""
    coordinator = object.__new__(Helios2nSensorDataUpdateCoordinator)
    coordinator.device = AsyncMock()
    boot_time = datetime(2026, 2, 20, 8, 0, 0, tzinfo=UTC)
    coordinator.device.data = SimpleNamespace(uptime=boot_time)

    result = await coordinator._async_update_data()

    assert result == {"uptime": boot_time}


def test_binary_sensor_is_off_when_coordinator_data_is_none():
    """Binary sensor should not crash when coordinator has no data yet."""
    entity = object.__new__(Helios2nPortBinarySensorEntity)
    entity.coordinator = SimpleNamespace(data=None)
    entity._port_id = "input1"

    assert entity.is_on is False


def test_binary_sensor_reads_state_from_coordinator_mapping():
    """Binary sensor should read bool state from coordinator mapping."""
    entity = object.__new__(Helios2nPortBinarySensorEntity)
    entity.coordinator = SimpleNamespace(data={"input1": True})
    entity._port_id = "input1"

    assert entity.is_on is True
