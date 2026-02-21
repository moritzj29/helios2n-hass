"""Behavioral tests for button, lock, and switch entities."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..button import Helios2nRestartButtonEntity, Helios2nSwitchButtonEntity, async_setup_entry as setup_button
from ..const import DOMAIN
from ..lock import Helios2nLockEntity, async_setup_entry as setup_lock
from ..switch import Helios2nPortSwitchEntity, async_setup_entry as setup_switch


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
