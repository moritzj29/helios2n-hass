"""Tests for coordinator return-data contracts and binary sensor safety."""
import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.helpers.update_coordinator import UpdateFailed

from ..binary_sensor import (
    Helios2nCertificateMismatchBinarySensorEntity,
    Helios2nPortBinarySensorEntity,
    async_setup_entry as setup_binary_sensor,
)
from ..const import DOMAIN
from ..coordinator import (
    API_ENDPOINT_IO_STATUS,
    API_ENDPOINT_SWITCH_STATUS,
    API_ENDPOINT_SYSTEM_STATUS,
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
async def test_binary_sensor_setup_adds_certificate_entity_only_for_https_without_ssl_verify():
    """Certificate fingerprint entity should be added only for HTTPS with verify_ssl disabled."""
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="SER",
        name="N",
        mac="M",
        model="X",
        hardware="H",
        firmware="F",
        ports=[SimpleNamespace(id="input1", type="input", state=True)],
    )
    hass = MagicMock()
    hass.data = {DOMAIN: {"entry-1": {"_device": device, "binary_sensor": {"coordinator": SimpleNamespace(data={})}}}}
    config = SimpleNamespace(entry_id="entry-1", data={"protocol": "https", "verify_ssl": False})
    async_add_entities = MagicMock()

    await setup_binary_sensor(hass, config, async_add_entities)

    added_entities = async_add_entities.call_args.args[0]
    assert any(isinstance(entity, Helios2nCertificateMismatchBinarySensorEntity) for entity in added_entities)
    cert_entity = next(entity for entity in added_entities if isinstance(entity, Helios2nCertificateMismatchBinarySensorEntity))
    assert cert_entity.name == "Certificate Fingerprint"


@pytest.mark.asyncio
async def test_binary_sensor_setup_skips_certificate_entity_for_non_https_or_verified_ssl():
    """Certificate fingerprint entity should be omitted when HTTPS is not used or SSL verify is enabled."""
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="SER",
        name="N",
        mac="M",
        model="X",
        hardware="H",
        firmware="F",
        ports=[SimpleNamespace(id="input1", type="input", state=True)],
    )
    async_add_entities = MagicMock()

    for protocol, verify_ssl in (("http", False), ("https", True)):
        hass = MagicMock()
        hass.data = {DOMAIN: {"entry-1": {"_device": device, "binary_sensor": {"coordinator": SimpleNamespace(data={})}}}}
        config = SimpleNamespace(entry_id="entry-1", data={"protocol": protocol, "verify_ssl": verify_ssl})

        await setup_binary_sensor(hass, config, async_add_entities)
        added_entities = async_add_entities.call_args.args[0]
        assert not any(
            isinstance(entity, Helios2nCertificateMismatchBinarySensorEntity)
            for entity in added_entities
        )
