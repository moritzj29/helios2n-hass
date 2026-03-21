"""Tests for coordinator return-data contracts and binary sensor safety."""
import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.helpers.update_coordinator import UpdateFailed
from py2n.exceptions import DeviceUnsupportedError

from custom_components.helios2n.binary_sensor import (
    Helios2nLogSubscriptionHealthBinarySensorEntity,
    Helios2nOutputStatusBinarySensorEntity,
    Helios2nPortBinarySensorEntity,
    Helios2nSwitchStatusBinarySensorEntity,
    async_setup_entry as setup_binary_sensor,
)
from custom_components.helios2n.const import ATTR_LOG_SUBSCRIPTION, DOMAIN
from custom_components.helios2n.coordinator import (
    API_ENDPOINT_IO_STATUS,
    API_ENDPOINT_SWITCH_STATUS,
    API_ENDPOINT_SYSTEM_STATUS,
    Helios2nPortDataUpdateCoordinator,
    Helios2nSensorDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)


class DummyCoordinator:
    """Minimal coordinator implementation for entity unit tests."""

    def __init__(self, data=None):
        self.data = data if data is not None else {}
        self.last_update_success = True
        self.async_request_refresh = AsyncMock()

    def async_add_listener(self, _update_callback, _context=None):
        return lambda: None


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


@pytest.mark.asyncio
async def test_mapping_coordinator_conflict_is_confirmed_by_second_poll():
    """A conflicting poll result should be confirmed before replacing state."""
    coordinator = object.__new__(Helios2nSwitchDataUpdateCoordinator)
    coordinator.data = {1: True}
    coordinator._async_fetch_polled_state = AsyncMock(
        side_effect=[{1: False}, {1: False}]
    )

    result = await coordinator._async_update_data()

    assert result == {1: False}
    assert coordinator._async_fetch_polled_state.await_count == 2


@pytest.mark.asyncio
async def test_mapping_coordinator_keeps_current_state_when_confirmation_disagrees():
    """If follow-up poll disagrees, keep the current event-driven state."""
    coordinator = object.__new__(Helios2nSwitchDataUpdateCoordinator)
    coordinator.data = {1: True}
    coordinator._async_fetch_polled_state = AsyncMock(
        side_effect=[{1: False}, {1: True}]
    )

    result = await coordinator._async_update_data()

    assert result == {1: True}
    assert coordinator._async_fetch_polled_state.await_count == 2


@pytest.mark.asyncio
async def test_mapping_coordinator_applies_event_updates_to_current_data():
    """Event updates should merge into coordinator data."""
    coordinator = object.__new__(Helios2nSwitchDataUpdateCoordinator)
    coordinator.data = {1: False, 2: False}
    coordinator.async_set_updated_data = MagicMock()

    await coordinator.async_apply_event_update({1: True})

    coordinator.async_set_updated_data.assert_called_once_with({1: True, 2: False})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coordinator_cls", "setup_device"),
    [
        (
            Helios2nPortDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_port_status=AsyncMock(side_effect=DeviceUnsupportedError("response malformed")),
                data=SimpleNamespace(ports=[]),
            ),
        ),
        (
            Helios2nSwitchDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_switch_status=AsyncMock(side_effect=DeviceUnsupportedError("response malformed")),
                get_switch=MagicMock(return_value=False),
                data=SimpleNamespace(switches=[]),
            ),
        ),
        (
            Helios2nSensorDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_system_status=AsyncMock(side_effect=DeviceUnsupportedError("response malformed")),
                data=SimpleNamespace(uptime=datetime.now(UTC)),
            ),
        ),
    ],
)
async def test_coordinator_maps_unsupported_responses_to_update_failed(coordinator_cls, setup_device):
    """Malformed/unsupported py2n responses should be wrapped in UpdateFailed."""
    coordinator = object.__new__(coordinator_cls)
    coordinator.device = setup_device()

    with pytest.raises(UpdateFailed, match="response malformed"):
        await coordinator._async_update_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coordinator_cls", "setup_device", "endpoint"),
    [
        (
            Helios2nPortDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_port_status=AsyncMock(side_effect=asyncio.TimeoutError()),
                data=SimpleNamespace(host="192.168.1.25", ports=[]),
            ),
            API_ENDPOINT_IO_STATUS,
        ),
        (
            Helios2nSwitchDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_switch_status=AsyncMock(side_effect=asyncio.TimeoutError()),
                get_switch=MagicMock(return_value=False),
                data=SimpleNamespace(host="192.168.1.25", switches=[]),
            ),
            API_ENDPOINT_SWITCH_STATUS,
        ),
        (
            Helios2nSensorDataUpdateCoordinator,
            lambda: SimpleNamespace(
                update_system_status=AsyncMock(side_effect=asyncio.TimeoutError()),
                data=SimpleNamespace(host="192.168.1.25", uptime=datetime.now(UTC)),
            ),
            API_ENDPOINT_SYSTEM_STATUS,
        ),
    ],
)
async def test_coordinator_timeout_includes_host_and_endpoint(coordinator_cls, setup_device, endpoint):
    """Timeout errors should include host and API endpoint details."""
    coordinator = object.__new__(coordinator_cls)
    coordinator.device = setup_device()

    with pytest.raises(UpdateFailed, match=f"192.168.1.25.*{endpoint}"):
        await coordinator._async_update_data()


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


@pytest.mark.asyncio
async def test_binary_sensor_setup_adds_read_only_status_entities_when_enabled():
    """Read-only switch/output status entities should be created when enabled."""
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="SER",
        name="N",
        mac="M",
        model="X",
        hardware="H",
        firmware="F",
        ports=[
            SimpleNamespace(id="input1", type="input", state=True),
            SimpleNamespace(id="relay1", type="output", state=False),
        ],
        switches=[SimpleNamespace(id=1, enabled=True), SimpleNamespace(id=2, enabled=False)],
    )
    hass = MagicMock()
    hass.data = {
        DOMAIN: {
            "entry-1": {
                "_device": device,
                "binary_sensor": {"coordinator": SimpleNamespace(data={"input1": True, "relay1": False})},
                "lock": {"coordinator": SimpleNamespace(data={1: True, 2: False})},
            }
        }
    }
    config = SimpleNamespace(
        entry_id="entry-1",
        data={
            "protocol": "https",
            "verify_ssl": False,
            "create_read_only_status_entities": True,
        },
    )
    async_add_entities = MagicMock()

    await setup_binary_sensor(hass, config, async_add_entities)

    added_entities = async_add_entities.call_args.args[0]
    assert any(isinstance(entity, Helios2nOutputStatusBinarySensorEntity) for entity in added_entities)
    assert any(isinstance(entity, Helios2nSwitchStatusBinarySensorEntity) for entity in added_entities)


def test_log_subscription_health_binary_sensor_reads_diagnostic_state():
    """Log subscription health entity should expose loop diagnostics."""
    hass = MagicMock()
    hass.data = {
        DOMAIN: {
            "entry-1": {
                ATTR_LOG_SUBSCRIPTION: {
                    "healthy": True,
                    "consecutive_failures": 0,
                    "total_failures": 2,
                    "resubscribe_count": 1,
                    "last_error": "DeviceConnectionError: offline",
                    "last_error_at": "2026-03-07T09:00:00+00:00",
                    "last_success_at": "2026-03-07T09:01:00+00:00",
                    "last_event_at": "2026-03-07T09:01:05+00:00",
                    "last_resubscribe_at": "2026-03-07T09:00:30+00:00",
                }
            }
        }
    }
    device = SimpleNamespace(
        data=SimpleNamespace(
            serial="SER",
            mac="M",
            name="N",
            model="X",
            hardware="H",
            firmware="F",
        )
    )
    entity = Helios2nLogSubscriptionHealthBinarySensorEntity(hass, device, "entry-1")

    assert entity.is_on is True
    attrs = entity.extra_state_attributes
    assert attrs["consecutive_failures"] == 0
    assert attrs["total_failures"] == 2
    assert attrs["resubscribe_count"] == 1
    assert attrs["last_error"] == "DeviceConnectionError: offline"


# Additional attribute tests for binary sensors
def test_port_binary_sensor_name_and_unique_id():
    """Helios2nPortBinarySensorEntity should have formatted name and correct unique_id."""
    device = SimpleNamespace(
        data=SimpleNamespace(
            serial="SER123",
            name="Device",
            mac="M",
            model="X",
            hardware="H",
            firmware="F",
        )
    )
    coordinator = DummyCoordinator()
    entity = Helios2nPortBinarySensorEntity(coordinator, device, "input1")

    assert entity.name == "Input 1"
    assert entity.unique_id == "SER123_port_input1"
    assert entity._attr_entity_registry_enabled_default is False


def test_output_status_binary_sensor_name_unique_id_and_enabled():
    """Helios2nOutputStatusBinarySensorEntity should have formatted name with 'Status' suffix and correct unique_id."""
    device = SimpleNamespace(
        data=SimpleNamespace(
            serial="ABC",
            name="Device",
            mac="M",
            model="X",
            hardware="H",
            firmware="F",
        )
    )
    coordinator = DummyCoordinator()
    entity = Helios2nOutputStatusBinarySensorEntity(coordinator, device, "relay2")

    assert entity.name == "Relay 2 Status"
    assert entity.unique_id == "ABC_port_relay2_status"
    assert entity._attr_entity_registry_enabled_default is True


def test_output_status_binary_sensor_is_on_reads_from_coordinator():
    """Helios2nOutputStatusBinarySensorEntity should read state from coordinator mapping."""
    coordinator = DummyCoordinator(data={"relay1": True, "relay2": False})
    entity = Helios2nOutputStatusBinarySensorEntity(coordinator, MagicMock(), "relay1")
    assert entity.is_on is True

    entity = Helios2nOutputStatusBinarySensorEntity(coordinator, MagicMock(), "relay2")
    assert entity.is_on is False

    # Missing port should return False
    entity = Helios2nOutputStatusBinarySensorEntity(coordinator, MagicMock(), "relay3")
    assert entity.is_on is False



