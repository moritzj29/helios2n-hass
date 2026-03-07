"""Tests for retry mechanism and task lifecycle in log polling."""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.const import Platform
from py2n.exceptions import ApiError, DeviceApiError, DeviceConnectionError

import custom_components.helios2n as integration_init_module
from custom_components.helios2n import LOG_POLL_TASK, async_unload_entry, poll_log
from custom_components.helios2n.const import ATTR_LOG_SUBSCRIPTION, DOMAIN

INTEGRATION_MODULE = sys.modules[poll_log.__module__]


@pytest.mark.asyncio
async def test_poll_log_resubscribes_after_max_retries(monkeypatch):
	"""poll_log should resubscribe after max retries instead of exiting."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[
			DeviceConnectionError("no route"),
			DeviceConnectionError("no route"),
			asyncio.CancelledError(),
		]
	)
	device.log_subscribe = AsyncMock(return_value="new-logid")
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {}}}

	sleep_mock = AsyncMock()
	monkeypatch.setattr(INTEGRATION_MODULE.asyncio, "sleep", sleep_mock)

	with pytest.raises(asyncio.CancelledError):
		await poll_log(device, "logid", hass, entry_id="entry-1", retry_count=0, max_retries=1)

	assert device.log_subscribe.await_count == 1
	assert device.log_pull.await_count == 3
	assert device.log_pull.await_args_list[2].args[0] == "new-logid"
	assert sleep_mock.await_count >= 1

	state = hass.data[DOMAIN]["entry-1"][ATTR_LOG_SUBSCRIPTION]
	assert state["resubscribe_count"] == 1
	assert state["total_failures"] >= 2
	assert state["healthy"] is True


@pytest.mark.asyncio
async def test_poll_log_invalid_parameter_resubscribes(monkeypatch):
	"""INVALID_PARAMETER_VALUE should trigger log resubscription."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[
			DeviceApiError(error=ApiError.INVALID_PARAMETER_VALUE),
			asyncio.CancelledError(),
		]
	)
	device.log_subscribe = AsyncMock(return_value="new-logid")
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()

	monkeypatch.setattr(INTEGRATION_MODULE.asyncio, "sleep", AsyncMock())

	with pytest.raises(asyncio.CancelledError):
		await poll_log(device, "old-logid", hass, retry_count=0, max_retries=1)

	assert device.log_subscribe.await_count == 1
	assert device.log_pull.await_args_list[1].args[0] == "new-logid"


@pytest.mark.asyncio
async def test_poll_log_updates_switch_coordinator_cache(monkeypatch):
	"""SwitchStateChanged log events should push state into the switch coordinator."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[
			[{"event": "SwitchStateChanged", "params": {"switch": 1, "state": True}}],
			asyncio.CancelledError(),
		]
	)
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()
	coordinator = MagicMock()
	coordinator.data = {1: False}
	coordinator.async_set_updated_data = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {Platform.LOCK: {"coordinator": coordinator}}}}

	dispatcher_send = MagicMock()
	monkeypatch.setattr(INTEGRATION_MODULE, "async_dispatcher_send", dispatcher_send)

	with pytest.raises(asyncio.CancelledError):
		await poll_log(device, "logid", hass, entry_id="entry-1", retry_count=0, max_retries=1)

	coordinator.async_set_updated_data.assert_called_once_with({1: True})
	dispatcher_send.assert_called_once()
	assert hass.bus.async_fire.call_count == 1


@pytest.mark.asyncio
async def test_poll_log_updates_port_coordinator_cache_from_input_and_output_events(monkeypatch):
	"""InputChanged/OutputChanged log events should push state into the port coordinator."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[
			[
				{"event": "InputChanged", "params": {"input": 1, "state": True}},
				{"event": "OutputChanged", "params": {"output": 1, "state": True}},
			],
			asyncio.CancelledError(),
		]
	)
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()
	coordinator = MagicMock()
	coordinator.data = {"input1": False, "relay1": False}
	def _store_data(data):
		coordinator.data = data
	coordinator.async_set_updated_data = MagicMock(side_effect=_store_data)
	hass.data = {DOMAIN: {"entry-1": {Platform.SWITCH: {"coordinator": coordinator}}}}

	dispatcher_send = MagicMock()
	monkeypatch.setattr(INTEGRATION_MODULE, "async_dispatcher_send", dispatcher_send)

	with pytest.raises(asyncio.CancelledError):
		await poll_log(device, "logid", hass, entry_id="entry-1", retry_count=0, max_retries=1)

	assert coordinator.async_set_updated_data.call_count == 2
	assert coordinator.async_set_updated_data.call_args_list[0].args[0] == {
		"input1": True,
		"relay1": False,
	}
	assert coordinator.async_set_updated_data.call_args_list[1].args[0] == {
		"input1": True,
		"relay1": True,
	}
	assert dispatcher_send.call_count == 2
	assert hass.bus.async_fire.call_count == 2


@pytest.mark.asyncio
async def test_async_unload_entry_cancels_log_poll_task():
	"""Unloading entry should cancel and await running log poll task."""
	pending_task = asyncio.create_task(asyncio.sleep(3600))
	hass = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {LOG_POLL_TASK: pending_task}}}
	hass.config_entries = MagicMock()
	hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
	hass.services = MagicMock()
	hass.services.async_remove = MagicMock()
	entry = MagicMock()
	entry.entry_id = "entry-1"

	result = await async_unload_entry(hass, entry)

	assert result is True
	assert pending_task.cancelled() is True
	assert hass.services.async_remove.call_count == 1
	assert hass.services.async_remove.call_args_list[0].args == (DOMAIN, "api_call")


@pytest.mark.asyncio
async def test_log_polling_watchdog_restarts_task_after_unexpected_exit(monkeypatch):
	"""Unexpected task exit should trigger watchdog resubscribe+restart."""
	calls: list[str] = []
	hold_event = asyncio.Event()

	async def fake_poll_log(device, logid, hass, entry_id=None):
		calls.append(logid)
		if len(calls) == 1:
			return
		await hold_event.wait()

	device = MagicMock()
	device.log_subscribe = AsyncMock(return_value="new-logid")
	hass = MagicMock()
	hass.data = {DOMAIN: {"entry-1": {}}}
	hass.async_create_task = asyncio.create_task

	monkeypatch.setattr(integration_init_module, "poll_log", fake_poll_log)
	monkeypatch.setattr(integration_init_module, "LOG_WATCHDOG_DELAY_SECONDS", 0)

	entry_data = hass.data[DOMAIN]["entry-1"]
	done_task = asyncio.create_task(fake_poll_log(device, "old-logid", hass, "entry-1"))
	entry_data[LOG_POLL_TASK] = done_task
	await done_task
	await integration_init_module._async_handle_log_poll_task_done(
		hass, "entry-1", device, done_task
	)
	watchdog_task = entry_data.get(integration_init_module.LOG_WATCHDOG_TASK)
	assert watchdog_task is not None
	await watchdog_task

	assert calls[:2] == ["old-logid", "new-logid"]
	assert device.log_subscribe.await_count == 1

	entry_data[integration_init_module.LOG_UNLOADING] = True
	running_task = entry_data.get(LOG_POLL_TASK)
	if running_task:
		running_task.cancel()
		with pytest.raises(asyncio.CancelledError):
			await running_task
