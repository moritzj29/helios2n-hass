import asyncio
import logging
from datetime import UTC, datetime
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

from .const import ATTR_LOG_SUBSCRIPTION, DOMAIN
from .coordinator import (
    Helios2nMappingDataUpdateCoordinator,
    Helios2nPortDataUpdateCoordinator,
    Helios2nSwitchDataUpdateCoordinator,
)

_LOGGER = logging.getLogger(__name__)
LOG_POLL_TASK = "_log_poll_task"
RETRY_DELAY_SECONDS = 5
RESUBSCRIBE_RETRY_ATTEMPTS = 3
RESUBSCRIBE_RETRY_DELAY_SECONDS = 5


def _log_event_signal(entry_id: str) -> str:
    """Return dispatcher signal name for a config entry."""
    return f"{DOMAIN}_{entry_id}_log_event"


def _utc_now_iso() -> str:
    """Return current UTC timestamp for diagnostics attributes."""
    return datetime.now(UTC).isoformat()


def _get_or_create_log_subscription_state(
    hass: HomeAssistant, entry_id: str | None
) -> dict[str, Any] | None:
    if entry_id is None:
        return None
    entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
    if not isinstance(entry_data, dict):
        return None
    state = entry_data.get(ATTR_LOG_SUBSCRIPTION)
    if isinstance(state, dict):
        return state
    state = {
        "healthy": True,
        "consecutive_failures": 0,
        "total_failures": 0,
        "resubscribe_count": 0,
        "last_error": None,
        "last_error_at": None,
        "last_success_at": None,
        "last_event_at": None,
        "last_resubscribe_at": None,
    }
    entry_data[ATTR_LOG_SUBSCRIPTION] = state
    return state


def _mark_log_success(hass: HomeAssistant, entry_id: str | None) -> None:
    state = _get_or_create_log_subscription_state(hass, entry_id)
    if state is None:
        return
    state["healthy"] = True
    state["consecutive_failures"] = 0
    state["last_success_at"] = _utc_now_iso()


def _mark_log_event_seen(hass: HomeAssistant, entry_id: str | None) -> None:
    state = _get_or_create_log_subscription_state(hass, entry_id)
    if state is None:
        return
    state["last_event_at"] = _utc_now_iso()


def _mark_log_failure(hass: HomeAssistant, entry_id: str | None, err: Exception) -> None:
    state = _get_or_create_log_subscription_state(hass, entry_id)
    if state is None:
        return
    state["healthy"] = False
    state["consecutive_failures"] = int(state.get("consecutive_failures", 0)) + 1
    state["total_failures"] = int(state.get("total_failures", 0)) + 1
    state["last_error"] = f"{type(err).__name__}: {err}"
    state["last_error_at"] = _utc_now_iso()


def _mark_log_resubscribe(hass: HomeAssistant, entry_id: str | None) -> None:
    state = _get_or_create_log_subscription_state(hass, entry_id)
    if state is None:
        return
    state["resubscribe_count"] = int(state.get("resubscribe_count", 0)) + 1
    state["last_resubscribe_at"] = _utc_now_iso()

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


async def _async_resubscribe_with_retries(device) -> str | None:
    """Retry resubscribe a few times before giving control back to poll loop."""
    for attempt in range(1, RESUBSCRIBE_RETRY_ATTEMPTS + 1):
        try:
            return await device.log_subscribe()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            # Short retries here avoid dropping the task for transient subscribe failures.
            _LOGGER.warning(
                "Log resubscribe attempt %s/%s failed: %s",
                attempt,
                RESUBSCRIBE_RETRY_ATTEMPTS,
                err,
                exc_info=err if attempt == RESUBSCRIBE_RETRY_ATTEMPTS else None,
            )
            if attempt < RESUBSCRIBE_RETRY_ATTEMPTS:
                await asyncio.sleep(RESUBSCRIBE_RETRY_DELAY_SECONDS)
    return None

# Main Log Polling Loop
# ---------------------

async def poll_log(
    device, logid, hass, entry_id: str | None = None, retry_count=0, max_retries=5
):
    """Poll device logs with retry mechanism."""
    _get_or_create_log_subscription_state(hass, entry_id)
    while True:
        try:
            for event in await device.log_pull(logid, timeout=30):
                hass.bus.async_fire(DOMAIN + "_event", event)
                _mark_log_event_seen(hass, entry_id)
                if entry_id is not None:
                    async_dispatcher_send(hass, _log_event_signal(entry_id), event)
                    await _update_switch_state_from_log_event(hass, entry_id, event)
                    await _update_port_state_from_log_event(hass, entry_id, event)
            retry_count = 0  # Reset on successful poll
            _mark_log_success(hass, entry_id)
        except asyncio.CancelledError:
            raise
        except (DeviceConnectionError, DeviceUnsupportedError) as err:
            _mark_log_failure(hass, entry_id, err)
            retry_count += 1
            if retry_count > max_retries:
                # Force a new subscription instead of terminating the background task.
                _LOGGER.error("Max retries exceeded for log polling: %s", err)
                new_logid = await _async_resubscribe_with_retries(device)
                if new_logid is not None:
                    logid = new_logid
                    _mark_log_resubscribe(hass, entry_id)
                    _mark_log_success(hass, entry_id)
                retry_count = 0
                continue
            await asyncio.sleep(RETRY_DELAY_SECONDS)
        except DeviceApiError as err:
            _mark_log_failure(hass, entry_id, err)
            if err.error == ApiError.INVALID_PARAMETER_VALUE:
                new_logid = await _async_resubscribe_with_retries(device)
                if new_logid is not None:
                    logid = new_logid
                    _mark_log_resubscribe(hass, entry_id)
                    _mark_log_success(hass, entry_id)
                retry_count = 0
            else:
                retry_count += 1
                if retry_count > max_retries:
                    _LOGGER.error("Max retries exceeded for log polling: %s", err)
                    new_logid = await _async_resubscribe_with_retries(device)
                    if new_logid is not None:
                        logid = new_logid
                        _mark_log_resubscribe(hass, entry_id)
                        _mark_log_success(hass, entry_id)
                    retry_count = 0
                    continue
                await asyncio.sleep(RETRY_DELAY_SECONDS)
        except Exception as err:
            _mark_log_failure(hass, entry_id, err)
            _LOGGER.exception("Unexpected error in log polling: %s", err)
            retry_count += 1
            if retry_count > max_retries:
                _LOGGER.error("Max retries exceeded for unexpected log polling errors")
                new_logid = await _async_resubscribe_with_retries(device)
                if new_logid is not None:
                    logid = new_logid
                    _mark_log_resubscribe(hass, entry_id)
                    _mark_log_success(hass, entry_id)
                retry_count = 0
                continue
            await asyncio.sleep(RETRY_DELAY_SECONDS)
