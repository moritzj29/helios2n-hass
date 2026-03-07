import asyncio
import logging
from datetime import timedelta
from typing import Generic, Mapping, TypeVar
import async_timeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from py2n import Py2NDevice
from py2n.exceptions import DeviceApiError, DeviceUnsupportedError

_LOGGER = logging.getLogger(__name__)
UPDATE_INTERVAL_SECONDS = 10
COORDINATOR_TIMEOUT_SECONDS = 10
API_ENDPOINT_IO_STATUS = "/api/io/status"
API_ENDPOINT_SWITCH_STATUS = "/api/switch/status"
API_ENDPOINT_SYSTEM_STATUS = "/api/system/status"
TStateKey = TypeVar("TStateKey")


def _get_device_host(device: Py2NDevice) -> str:
    """Best-effort host extraction for timeout diagnostics."""
    data = getattr(device, "data", None)
    host = getattr(data, "host", None)
    if isinstance(host, str) and host:
        return host
    options = getattr(device, "options", None)
    options_host = getattr(options, "host", None)
    if isinstance(options_host, str) and options_host:
        return options_host
    return "unknown"


class Helios2nMappingDataUpdateCoordinator(
    DataUpdateCoordinator[dict[TStateKey, object]], Generic[TStateKey]
):
    """Coordinator with serialized event updates and conflict-aware polling.

    Update strategy:
    - First startup refresh initializes state from API polling.
    - Runtime event updates are applied immediately and serialized via a lock.
    - Periodic polling acts as reconciliation and must not blindly overwrite
      potentially fresher event-driven state.
    """

    def __init__(self, hass: HomeAssistant, *, name: str):
        super().__init__(
            hass,
            _LOGGER,
            name=name,
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
        )
        self._state_lock = asyncio.Lock()

    def _ensure_state_lock(self) -> None:
        """Backfill lock for tests constructing with object.__new__."""
        if not hasattr(self, "_state_lock"):
            self._state_lock = asyncio.Lock()

    async def _async_fetch_polled_state(self) -> dict[TStateKey, object]:
        """Fetch state from device APIs."""
        raise NotImplementedError

    async def _async_update_data(self) -> dict[TStateKey, object]:
        """Fetch periodic state and reconcile with event-driven cache.

        If poll result differs from current state, perform one immediate
        confirmation poll before accepting the new value. This prevents a
        transient or stale poll result from overriding a recent event update.
        """
        self._ensure_state_lock()
        polled_state = await self._async_fetch_polled_state()
        current_raw_data = getattr(self, "data", None)
        current_data = current_raw_data if isinstance(current_raw_data, dict) else None
        if current_data is None or polled_state == current_data:
            return polled_state

        confirmed_state = await self._async_fetch_polled_state()
        async with self._state_lock:
            latest_raw_data = getattr(self, "data", None)
            latest_data = latest_raw_data if isinstance(latest_raw_data, dict) else None
            if latest_data is None:
                return confirmed_state
            if confirmed_state == latest_data:
                return latest_data
            if confirmed_state == polled_state:
                return confirmed_state
            # Keep event-driven state if follow-up poll disagrees.
            return latest_data

    async def async_apply_event_update(self, updates: Mapping[TStateKey, object]) -> None:
        """Apply event-driven partial updates while serializing state mutations.

        This is called by runtime log/event handlers, not only tests.
        """
        if not updates:
            return
        _LOGGER.debug("Applying event updates: %s", updates)
        self._ensure_state_lock()
        async with self._state_lock:
            current_raw_data = getattr(self, "data", None)
            current_data = dict(current_raw_data) if isinstance(current_raw_data, dict) else {}
            updated_data = dict(current_data)
            updated_data.update(updates)
            if updated_data != current_data:
                _LOGGER.debug("Event-driven state change from %s to %s", current_data, updated_data)
                self.async_set_updated_data(updated_data)

    async def _raise_unsupported_response_update_failed(
        self, err: DeviceUnsupportedError, endpoint: str
    ) -> None:
        """Log malformed-response diagnostics from the original failing request."""
        options = getattr(self.device, "options", None)
        protocol = getattr(options, "protocol", "http")
        auth_method = getattr(options, "auth_method", "unknown")
        ssl_verify = getattr(options, "ssl_verify", None)
        url = f"{protocol}://{_get_device_host(self.device)}/{endpoint.lstrip('/')}"
        # Include response payload if available, truncating to avoid huge logs
        response_repr = repr(err.response)[:500] if getattr(err, "response", None) is not None else "None"
        _LOGGER.error(
            "Malformed response from original request. host=%s endpoint=%s url=%s auth_method=%s ssl_verify=%s error=%s response=%s",
            _get_device_host(self.device),
            endpoint,
            url,
            auth_method,
            ssl_verify,
            err,
            response_repr,
            exc_info=err,
        )
        raise UpdateFailed(f"Device unsupported or malformed response: {err}") from err


class Helios2nPortDataUpdateCoordinator(Helios2nMappingDataUpdateCoordinator[str]):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(hass, name=f"Helios2n Port Update [{_get_device_host(device)}]")
        self.device = device

    async def _async_fetch_polled_state(self) -> dict[str, object]:
        try:
            async with async_timeout.timeout(COORDINATOR_TIMEOUT_SECONDS):
                await self.device.update_port_status()
            return {port.id: port.state for port in self.device.data.ports}
        except (TimeoutError, asyncio.TimeoutError) as err:
            host = _get_device_host(self.device)
            _LOGGER.error(
                "Timeout fetching port data from host %s endpoint %s after %ss",
                host,
                API_ENDPOINT_IO_STATUS,
                COORDINATOR_TIMEOUT_SECONDS,
            )
            raise UpdateFailed(
                f"Timeout from host {host} endpoint {API_ENDPOINT_IO_STATUS}"
            ) from err
        except DeviceApiError as err:
            raise UpdateFailed(f"Device API error: {err.error}") from err
        except DeviceUnsupportedError as err:
            await self._raise_unsupported_response_update_failed(err, API_ENDPOINT_IO_STATUS)

class Helios2nSwitchDataUpdateCoordinator(Helios2nMappingDataUpdateCoordinator[int]):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(hass, name=f"Helios2n Switch Update [{_get_device_host(device)}]")
        self.device = device

    async def _async_fetch_polled_state(self) -> dict[int, object]:
        try:
            async with async_timeout.timeout(COORDINATOR_TIMEOUT_SECONDS):
                await self.device.update_switch_status()
            return {switch.id: self.device.get_switch(switch.id) for switch in self.device.data.switches}
        except (TimeoutError, asyncio.TimeoutError) as err:
            host = _get_device_host(self.device)
            _LOGGER.error(
                "Timeout fetching switch data from host %s endpoint %s after %ss",
                host,
                API_ENDPOINT_SWITCH_STATUS,
                COORDINATOR_TIMEOUT_SECONDS,
            )
            raise UpdateFailed(
                f"Timeout from host {host} endpoint {API_ENDPOINT_SWITCH_STATUS}"
            ) from err
        except DeviceApiError as err:
            raise UpdateFailed(f"Device API error: {err.error}") from err
        except DeviceUnsupportedError as err:
            await self._raise_unsupported_response_update_failed(err, API_ENDPOINT_SWITCH_STATUS)

class Helios2nSensorDataUpdateCoordinator(Helios2nMappingDataUpdateCoordinator[str]):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(hass, name=f"Helios2n Sensor Update [{_get_device_host(device)}]")
        self.device = device

    async def _async_fetch_polled_state(self) -> dict[str, object]:
        try:
            async with async_timeout.timeout(COORDINATOR_TIMEOUT_SECONDS):
                await self.device.update_system_status()
            return {"uptime": self.device.data.uptime}
        except (TimeoutError, asyncio.TimeoutError) as err:
            host = _get_device_host(self.device)
            _LOGGER.error(
                "Timeout fetching sensor data from host %s endpoint %s after %ss",
                host,
                API_ENDPOINT_SYSTEM_STATUS,
                COORDINATOR_TIMEOUT_SECONDS,
            )
            raise UpdateFailed(
                f"Timeout from host {host} endpoint {API_ENDPOINT_SYSTEM_STATUS}"
            ) from err
        except DeviceApiError as err:
            raise UpdateFailed(f"Device API error: {err.error}") from err
        except DeviceUnsupportedError as err:
            await self._raise_unsupported_response_update_failed(err, API_ENDPOINT_SYSTEM_STATUS)
