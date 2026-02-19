"""Tests for retry mechanism and task lifecycle in log polling."""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
from py2n.exceptions import ApiError, DeviceApiError, DeviceConnectionError

from .. import LOG_POLL_TASK, async_unload_entry, poll_log
from ..const import DOMAIN, SERVICE_RECAPTURE_CERTIFICATE

INTEGRATION_MODULE = sys.modules[poll_log.__module__]


@pytest.mark.asyncio
async def test_poll_log_stops_after_max_retries(monkeypatch):
	"""poll_log exits after repeated connection failures."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[DeviceConnectionError("no route"), DeviceConnectionError("no route")]
	)
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()

	sleep_mock = AsyncMock()
	monkeypatch.setattr(INTEGRATION_MODULE.asyncio, "sleep", sleep_mock)

	await poll_log(device, "logid", hass, retry_count=0, max_retries=1)

	assert device.log_pull.await_count == 2
	assert sleep_mock.await_count == 1


@pytest.mark.asyncio
async def test_poll_log_invalid_parameter_resubscribes(monkeypatch):
	"""INVALID_PARAMETER_VALUE should trigger log resubscription."""
	device = MagicMock()
	device.log_pull = AsyncMock(
		side_effect=[
			DeviceApiError(error=ApiError.INVALID_PARAMETER_VALUE),
			DeviceConnectionError("offline"),
			DeviceConnectionError("offline"),
		]
	)
	device.log_subscribe = AsyncMock(return_value="new-logid")
	hass = MagicMock()
	hass.bus = MagicMock()
	hass.bus.async_fire = MagicMock()

	monkeypatch.setattr(INTEGRATION_MODULE.asyncio, "sleep", AsyncMock())

	await poll_log(device, "old-logid", hass, retry_count=0, max_retries=1)

	assert device.log_subscribe.await_count == 1
	assert device.log_pull.await_args_list[1].args[0] == "new-logid"


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
	assert hass.services.async_remove.call_count == 2
	assert hass.services.async_remove.call_args_list[0].args == (DOMAIN, "api_call")
	assert hass.services.async_remove.call_args_list[1].args == (DOMAIN, SERVICE_RECAPTURE_CERTIFICATE)
