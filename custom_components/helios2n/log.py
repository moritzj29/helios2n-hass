import asyncio
import logging
from typing import Any

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send

from py2n.exceptions import (
    ApiError,
    DeviceApiError,
    DeviceConnectionError,
    DeviceUnsupportedError,
)

from .const import DOMAIN
from .coordinator import (
    Helios2nMappingDataUpdateCoordinator,
    Helios2nPortDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)

_LOGGER = logging.getLogger(__name__)
LOG_POLL_TASK = "_log_poll_task"


def _log_event_signal(entry_id: str) -> str:
    """Return dispatcher signal name for a config entry."""
    return f"{DOMAIN}_{entry_id}_log_event"

# Match Specific Events and Extract Parameters
# --------------------------------------------

def _extract_switch_state_change(event: dict) -> tuple[int, bool] | None:
    """Extract switch id and state from a SwitchStateChanged log event."""
    if event.get("event") != "SwitchStateChanged":
        return None
    params = event.get("params")
    payload = params if isinstance(params, dict) else event
    switch_id = payload.get("switch")
    state = payload.get("state")
    if isinstance(switch_id, bool) or not isinstance(switch_id, int):
        return None
    if not isinstance(state, bool):
        return None
    return switch_id, state


def _extract_port_state_change(event: dict) -> tuple[str, str | int, bool] | None:
    """Extract port identifier and state from InputChanged/OutputChanged events."""
    event_name = event.get("event")
    if event_name not in {"InputChanged", "OutputChanged"}:
        return None

    params = event.get("params")
    payload = params if isinstance(params, dict) else event
    port_key = "input" if event_name == "InputChanged" else "output"
    port_identifier = payload.get(port_key)
    state = payload.get("state")
    if isinstance(port_identifier, bool) or not isinstance(port_identifier, (int, str)):
        return None
    if isinstance(port_identifier, str) and not port_identifier.strip():
        return None
    if not isinstance(state, bool):
        return None
    return event_name, port_identifier, state

# Upate State from Events
# -----------------------

def _resolve_port_id_from_event(
    event_name: str, port_identifier: str | int, known_port_ids: set[str]
) -> str:
    """Resolve event payload port identifier to the integration's port-id format."""
    if isinstance(port_identifier, str):
        port_id = port_identifier.strip()
        if port_id in known_port_ids:
            return port_id
        normalized_map = {port.lower(): port for port in known_port_ids}
        if port_id.lower() in normalized_map:
            return normalized_map[port_id.lower()]
        if port_id.isdigit():
            port_identifier = int(port_id)
        else:
            return port_id

    preferred_prefixes = ("input",) if event_name == "InputChanged" else ("relay", "output")
    numeric_id = int(port_identifier)

    for prefix in preferred_prefixes:
        candidate = f"{prefix}{numeric_id}"
        if candidate in known_port_ids:
            return candidate

    matching_ports = [
        port_id
        for port_id in known_port_ids
        if port_id.endswith(str(numeric_id))
        and any(port_id.startswith(prefix) for prefix in preferred_prefixes)
    ]
    if len(matching_ports) == 1:
        return matching_ports[0]

    return f"{preferred_prefixes[0]}{numeric_id}"


async def _update_switch_state_from_log_event(
    hass: HomeAssistant, entry_id: str, event: dict
) -> None:
    """Push SwitchStateChanged events into the switch coordinator cache.

    Primary path uses coordinator.async_apply_event_update() so state writes are
    serialized with polling reconciliation logic in the coordinator.
    """
    extracted = _extract_switch_state_change(event)
    if extracted is None:
        return

    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict):
        return
    lock_data = entry_data.get(Platform.LOCK)
    if not isinstance(lock_data, dict):
        return
    coordinator: Helios2nSwitchDataUpdateCoordinator | Any | None = lock_data.get(
        "coordinator"
    )
    if coordinator is None or not hasattr(coordinator, "async_set_updated_data"):
        return

    switch_id, state = extracted
    if isinstance(coordinator, Helios2nMappingDataUpdateCoordinator):
        result = coordinator.async_apply_event_update({switch_id: state})
    else:
        result = None
    if asyncio.iscoroutine(result):
        await result
        return

    # Fallback for legacy/dummy coordinator objects that do not implement the
    # async serialized update API.
    current_raw_data = getattr(coordinator, "data", None)
    current_data = current_raw_data if isinstance(current_raw_data, dict) else {}
    updated_data = dict(current_data)
    updated_data[switch_id] = state
    coordinator.async_set_updated_data(updated_data)


async def _update_port_state_from_log_event(
    hass: HomeAssistant, entry_id: str, event: dict
) -> None:
    """Push InputChanged/OutputChanged events into the port coordinator cache."""
    extracted = _extract_port_state_change(event)
    if extracted is None:
        return

    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict):
        return
    switch_data = entry_data.get(Platform.SWITCH)
    if not isinstance(switch_data, dict):
        return
    coordinator: Helios2nPortDataUpdateCoordinator | Any | None = switch_data.get(
        "coordinator"
    )
    if coordinator is None or not hasattr(coordinator, "async_set_updated_data"):
        return

    event_name, port_identifier, state = extracted
    current_raw_data = getattr(coordinator, "data", None)
    current_data = current_raw_data if isinstance(current_raw_data, dict) else {}
    port_id = _resolve_port_id_from_event(event_name, port_identifier, set(current_data))

    if isinstance(coordinator, Helios2nMappingDataUpdateCoordinator):
        result = coordinator.async_apply_event_update({port_id: state})
    else:
        result = None
    if asyncio.iscoroutine(result):
        await result
        return

    updated_data = dict(current_data)
    updated_data[port_id] = state
    coordinator.async_set_updated_data(updated_data)

# Main Log Polling Loop
# ---------------------

async def poll_log(
    device, logid, hass, entry_id: str | None = None, retry_count=0, max_retries=5
):
    """Poll device logs with retry mechanism."""
    while True:
        try:
            for event in await device.log_pull(logid, timeout=30):
                hass.bus.async_fire(DOMAIN + "_event", event)
                if entry_id is not None:
                    async_dispatcher_send(hass, _log_event_signal(entry_id), event)
                    await _update_switch_state_from_log_event(hass, entry_id, event)
                    await _update_port_state_from_log_event(hass, entry_id, event)
            retry_count = 0  # Reset on successful poll
        except asyncio.CancelledError:
            raise
        except (DeviceConnectionError, DeviceUnsupportedError) as err:
            retry_count += 1
            if retry_count > max_retries:
                _LOGGER.error("Max retries exceeded for log polling: %s", err)
                return
            await asyncio.sleep(5)
        except DeviceApiError as err:
            if err.error == ApiError.INVALID_PARAMETER_VALUE:
                try:
                    logid = await device.log_subscribe()
                    retry_count = 0
                except Exception as resubscribe_err:
                    _LOGGER.error("Failed to resubscribe to logs: %s", resubscribe_err)
                    return
            else:
                retry_count += 1
                if retry_count > max_retries:
                    _LOGGER.error("Max retries exceeded for log polling: %s", err)
                    return
                await asyncio.sleep(5)
        except Exception as err:
            _LOGGER.error("Unexpected error in log polling: %s", err)
            retry_count += 1
            if retry_count > max_retries:
                return
            await asyncio.sleep(5)
