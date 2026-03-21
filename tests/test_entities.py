"""Behavioral tests for button, lock, and switch entities."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.helios2n.button import Helios2nRestartButtonEntity, Helios2nSwitchButtonEntity, async_setup_entry as setup_button
from custom_components.helios2n.const import DOMAIN
from custom_components.helios2n.lock import Helios2nLockEntity, async_setup_entry as setup_lock
from custom_components.helios2n.switch import Helios2nPortSwitchEntity, async_setup_entry as setup_switch


class DummyCoordinator:
	"""Minimal coordinator implementation for entity unit tests."""

	def __init__(self, data=None):
		self.data = data if data is not None else {}
		self.last_update_success = True
		self.async_request_refresh = AsyncMock()

	def async_add_listener(self, _update_callback, _context=None):
		return lambda: None


@pytest.mark.asyncio
async def test_button_setup_adds_restart_and_monostable_entities():
	"""Button setup should create restart and monostable switch button entities."""
	device = MagicMock()
	device.data = SimpleNamespace(
		serial="SER",
		name="N",
		mac="M",
		model="X",
		hardware="H",
		firmware="F",
		switches=[
			SimpleNamespace(id=1, enabled=True, mode="monostable"),
			SimpleNamespace(id=2, enabled=True, mode="bistable"),
			SimpleNamespace(id=3, enabled=False, mode="monostable"),
		]
	)
	hass = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {"_device": device}}}
	config = SimpleNamespace(entry_id="entry-1")
	async_add_entities = MagicMock()

	await setup_button(hass, config, async_add_entities)

	added_entities = async_add_entities.call_args.args[0]
	assert len(added_entities) == 2
	assert isinstance(added_entities[0], Helios2nRestartButtonEntity)
	assert isinstance(added_entities[1], Helios2nSwitchButtonEntity)


@pytest.mark.asyncio
async def test_button_entities_call_device_methods():
	"""Button entities should call their mapped device actions."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="SER", name="N", mac="M", model="X", hardware="H", firmware="F")
	device.set_switch = AsyncMock()
	device.restart = AsyncMock()

	switch_button = Helios2nSwitchButtonEntity(device, 5)
	restart_button = Helios2nRestartButtonEntity(device)

	await switch_button.async_press()
	await restart_button.async_press()

	assert device.set_switch.await_args.args == (5, True)
	assert device.restart.await_count == 1


@pytest.mark.asyncio
async def test_lock_setup_adds_only_bistable_switches():
	"""Lock setup should create lock entities only for enabled bistable switches."""
	device = MagicMock()
	device.data = SimpleNamespace(
		serial="SER",
		name="N",
		mac="M",
		model="X",
		hardware="H",
		firmware="F",
		switches=[
			SimpleNamespace(id=1, enabled=True, mode="bistable"),
			SimpleNamespace(id=2, enabled=True, mode="monostable"),
			SimpleNamespace(id=3, enabled=False, mode="bistable"),
		]
	)
	coordinator = DummyCoordinator()
	hass = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {"_device": device, "lock": {"coordinator": coordinator}}}}
	config = SimpleNamespace(entry_id="entry-1", data={})
	async_add_entities = MagicMock()

	await setup_lock(hass, config, async_add_entities)

	added_entities = async_add_entities.call_args.args[0]
	assert len(added_entities) == 1
	assert isinstance(added_entities[0], Helios2nLockEntity)


@pytest.mark.asyncio
async def test_lock_entity_controls_switch_and_refreshes():
	"""Lock entity should map lock/unlock to switch control and refresh."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="SER", name="N", mac="M", model="X", hardware="H", firmware="F")
	device.set_switch = AsyncMock()
	device.get_switch = MagicMock(return_value=True)
	coordinator = DummyCoordinator()
	entity = Helios2nLockEntity(coordinator, device, 7)

	assert entity.is_locked is False

	await entity.async_lock()
	await entity.async_unlock()

	assert device.set_switch.await_args_list[0].args == (7, False)
	assert device.set_switch.await_args_list[1].args == (7, True)
	assert coordinator.async_request_refresh.await_count == 2


@pytest.mark.asyncio
async def test_switch_setup_adds_only_output_ports():
	"""Switch setup should create entities only for output ports."""
	device = MagicMock()
	device.data = SimpleNamespace(
		serial="SER",
		name="N",
		mac="M",
		model="X",
		hardware="H",
		firmware="F",
		ports=[
			SimpleNamespace(id="relay1", type="output", state=False),
			SimpleNamespace(id="input1", type="input", state=True),
		]
	)
	coordinator = DummyCoordinator()
	hass = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {"_device": device, "switch": {"coordinator": coordinator}}}}
	config = SimpleNamespace(entry_id="entry-1", data={})
	async_add_entities = MagicMock()

	await setup_switch(hass, config, async_add_entities)

	added_entities = async_add_entities.call_args.args[0]
	assert len(added_entities) == 1
	assert isinstance(added_entities[0], Helios2nPortSwitchEntity)


@pytest.mark.asyncio
async def test_lock_and_switch_setup_skip_control_entities_when_disabled():
	"""Lock/switch control entities should not be created when control is disabled."""
	device = MagicMock()
	device.data = SimpleNamespace(
		serial="SER",
		name="N",
		mac="M",
		model="X",
		hardware="H",
		firmware="F",
		switches=[SimpleNamespace(id=1, enabled=True, mode="bistable")],
		ports=[SimpleNamespace(id="relay1", type="output", state=False)],
	)
	coordinator = DummyCoordinator()
	hass = MagicMock()
	hass.data = {
		DOMAIN: {
			"entry-1": {
				"_device": device,
				"lock": {"coordinator": coordinator},
				"switch": {"coordinator": coordinator},
			}
		}
	}
	config = SimpleNamespace(entry_id="entry-1", data={"disable_control_entities": True})
	async_add_entities_lock = MagicMock()
	async_add_entities_switch = MagicMock()

	await setup_lock(hass, config, async_add_entities_lock)
	await setup_switch(hass, config, async_add_entities_switch)

	assert async_add_entities_lock.call_args.args[0] == []
	assert async_add_entities_switch.call_args.args[0] == []


@pytest.mark.asyncio
async def test_switch_entity_controls_port_and_refreshes():
	"""Switch entity should read output state and toggle device port."""
	device = MagicMock()
	device.data = SimpleNamespace(
		serial="SER",
		name="N",
		mac="M",
		model="X",
		hardware="H",
		firmware="F",
		ports=[SimpleNamespace(id="relay1", type="output", state=False)],
	)
	device.set_port = AsyncMock()
	coordinator = DummyCoordinator()
	entity = Helios2nPortSwitchEntity(coordinator, device, "relay1")

	assert entity.is_on is False

	await entity.async_turn_on()
	await entity.async_turn_off()

	assert device.set_port.await_args_list[0].args == ("relay1", True)
	assert device.set_port.await_args_list[1].args == ("relay1", False)
	assert coordinator.async_request_refresh.await_count == 2


# Additional attribute tests
def test_switch_entity_name_and_unique_id():
	"""Helios2nPortSwitchEntity should have formatted name and correct unique_id."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="SER123", name="Device", mac="M", model="X", hardware="H", firmware="F")
	coordinator = DummyCoordinator()
	entity = Helios2nPortSwitchEntity(coordinator, device, "relay1")

	assert entity.name == "Relay 1"
	assert entity.unique_id == "SER123_port_relay1"


def test_lock_entity_name_and_unique_id():
	"""Helios2nLockEntity should have formatted name and correct unique_id."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="ABC", name="Device", mac="M", model="X", hardware="H", firmware="F")
	coordinator = DummyCoordinator()
	entity = Helios2nLockEntity(coordinator, device, 5)

	assert entity.name == "Switch 5"
	assert entity.unique_id == "ABC_switch_5"


def test_button_switch_button_name_and_unique_id():
	"""Helios2nSwitchButtonEntity should have formatted name and correct unique_id."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="XYZ", name="Device", mac="M", model="X", hardware="H", firmware="F")
	entity = Helios2nSwitchButtonEntity(device, 2)

	assert entity.name == "Switch 2"
	assert entity.unique_id == "XYZ_switch_2"


def test_button_restart_button_name_and_unique_id():
	"""Helios2nRestartButtonEntity should have fixed name and correct unique_id."""
	device = MagicMock()
	device.data = SimpleNamespace(serial="RESTART", name="Device", mac="M", model="X", hardware="H", firmware="F")
	entity = Helios2nRestartButtonEntity(device)

	assert entity.name == "Restart"
	assert entity.unique_id == "RESTART_restart"



def test_switch_entity_device_info():
    """Helios2nPortSwitchEntity should have accessible device_info property."""
    from custom_components.helios2n.utils import get_device_info
    
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="SER123",
        name="Device Name",
        mac="aa:bb:cc:dd:ee:ff",
        model="IP Verso",
        hardware="1.0.0",
        firmware="2.0.0",
        host="192.168.1.100",
    )
    device.options = SimpleNamespace(protocol="https")
    coordinator = DummyCoordinator()
    entity = Helios2nPortSwitchEntity(coordinator, device, "relay1")

    # Access device_info property - should not raise NameError
    device_info = entity.device_info

    assert device_info is not None
    assert "helios2n" in str(device_info["identifiers"])
    assert "SER123" in str(device_info["identifiers"])


def test_lock_entity_device_info():
    """Helios2nLockEntity should have accessible device_info property."""
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="LOCK001",
        name="Lock Device",
        mac="11:22:33:44:55:66",
        model="IP Force",
        hardware="1.0.0",
        firmware="2.0.0",
        host="192.168.1.200",
    )
    device.options = SimpleNamespace(protocol="http")
    coordinator = DummyCoordinator()
    entity = Helios2nLockEntity(coordinator, device, 5)

    # Access device_info property - should not raise NameError
    device_info = entity.device_info

    assert device_info is not None
    assert "helios2n" in str(device_info["identifiers"])
    assert "LOCK001" in str(device_info["identifiers"])


def test_button_entities_device_info():
    """Button entities should have accessible device_info property."""
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="BTN001",
        name="Button Device",
        mac="aa:bb:cc:dd:ee:ff",
        model="IP Solo",
        hardware="1.0.0",
        firmware="2.0.0",
        host="192.168.1.150",
    )
    device.options = SimpleNamespace(protocol="https")

    restart_button = Helios2nRestartButtonEntity(device)
    switch_button = Helios2nSwitchButtonEntity(device, 3)

    # Access device_info properties - should not raise NameError
    restart_info = restart_button.device_info
    switch_info = switch_button.device_info

    assert restart_info is not None
    assert switch_info is not None
    assert "helios2n" in str(restart_info["identifiers"])
    assert "BTN001" in str(restart_info["identifiers"])
    assert "helios2n" in str(switch_info["identifiers"])
    assert "BTN001" in str(switch_info["identifiers"])


@pytest.mark.asyncio
async def test_switch_entities_setup_as_homeassistant_would():
    """Integration test that verifies switch entities work when setup as HA would do it."""
    # This test simulates the exact flow HomeAssistant uses to setup entities
    import asyncio
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    
    # Create a realistic device mock
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="HA-SETUP-TEST",
        name="Test Switch Device",
        mac="aa:bb:cc:dd:ee:ff",
        model="IP Verso",
        hardware="1.1.0",
        firmware="2.5.0",
        host="192.168.1.50",
        ports=[
            SimpleNamespace(id="relay1", type="output", state=False),
            SimpleNamespace(id="relay2", type="output", state=True),
            SimpleNamespace(id="input1", type="input", state=True),
        ]
    )
    device.options = SimpleNamespace(protocol="https")
    device.set_port = AsyncMock()
    
    # Create coordinator
    coordinator = DummyCoordinator()
    
    # Setup HomeAssistant mock environment
    hass = MagicMock()
    hass.data = {
        DOMAIN: {
            "entry-1": {
                "_device": device,
                "switch": {"coordinator": coordinator}
            }
        }
    }
    
    # Create config entry mock
    config = SimpleNamespace(entry_id="entry-1", data={})
    
    # This will hold the created entities
    created_entities = []
    
    def async_add_entities(entities):
        created_entities.extend(entities)
    
    # Call the setup function exactly as HomeAssistant would
    result = await setup_switch(hass, config, async_add_entities)
    
    # Verify setup succeeded
    assert result is True
    assert len(created_entities) == 2  # Only output ports
    assert all(isinstance(e, Helios2nPortSwitchEntity) for e in created_entities)
    
    # Now verify that HomeAssistant can access all the properties it needs
    for entity in created_entities:
        # These are the properties HomeAssistant accesses when adding entities
        assert entity.unique_id is not None
        assert entity.name is not None
        assert entity.device_info is not None  # This would have failed with NameError
        assert entity.available is True
        assert entity.should_poll is False
        
        # Verify device_info structure
        device_info = entity.device_info
        assert device_info["identifiers"] == {("helios2n", "HA-SETUP-TEST"), ("helios2n", "aa:bb:cc:dd:ee:ff")}
        assert device_info["name"] == "Test Switch Device"
        assert device_info["manufacturer"] == "2N/Helios"
        assert device_info["model"] == "IP Verso"
        assert device_info["configuration_url"] == "https://192.168.1.50"
        
        # Test that the entity can control the device
        await entity.async_turn_on()
        device.set_port.assert_called_with(entity._port_id, True)
        await entity.async_turn_off()
        device.set_port.assert_called_with(entity._port_id, False)


@pytest.mark.asyncio
async def test_lock_entities_setup_as_homeassistant_would():
    """Integration test that verifies lock entities work when setup as HA would do it."""
    from custom_components.helios2n.lock import async_setup_entry as setup_lock
    
    # Create realistic device
    device = MagicMock()
    device.data = SimpleNamespace(
        serial="HA-LOCK-TEST",
        name="Test Lock Device",
        mac="11:22:33:44:55:66",
        model="IP Force",
        hardware="1.0.0",
        firmware="2.0.0",
        host="192.168.1.60",
        switches=[
            SimpleNamespace(id=1, enabled=True, mode="bistable"),
            SimpleNamespace(id=2, enabled=False, mode="bistable"),
            SimpleNamespace(id=3, enabled=True, mode="monostable"),
        ]
    )
    device.options = SimpleNamespace(protocol="http")
    device.set_switch = AsyncMock()
    device.get_switch = AsyncMock(return_value=False)
    
    coordinator = DummyCoordinator()
    hass = MagicMock()
    hass.data = {
        DOMAIN: {
            "entry-1": {
                "_device": device,
                "lock": {"coordinator": coordinator}
            }
        }
    }
    
    config = SimpleNamespace(entry_id="entry-1", data={})
    created_entities = []
    
    def async_add_entities(entities):
        created_entities.extend(entities)
    
    # Setup as HA would
    result = await setup_lock(hass, config, async_add_entities)
    
    assert result is True
    assert len(created_entities) == 1  # Only enabled bistable switch
    assert isinstance(created_entities[0], Helios2nLockEntity)
    
    entity = created_entities[0]
    
    # Verify all properties HA accesses
    assert entity.unique_id == "HA-LOCK-TEST_switch_1"
    assert entity.name == "Switch 1"
    assert entity.device_info is not None
    assert entity.available is True
    
    # Verify device_info
    device_info = entity.device_info
    assert ("helios2n", "HA-LOCK-TEST") in device_info["identifiers"]
    assert device_info["name"] == "Test Lock Device"
    
    # Test lock/unlock
    await entity.async_lock()
    device.set_switch.assert_called_with(1, False)
    await entity.async_unlock()
    device.set_switch.assert_called_with(1, True)
