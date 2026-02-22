import asyncio
import logging
from datetime import timedelta
import async_timeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from py2n import Py2NDevice
from py2n.exceptions import DeviceApiError

_LOGGER = logging.getLogger(__name__)
UPDATE_INTERVAL_SECONDS = 10
COORDINATOR_TIMEOUT_SECONDS = 10
API_ENDPOINT_IO_STATUS = "/api/io/status"
API_ENDPOINT_SWITCH_STATUS = "/api/switch/status"
API_ENDPOINT_SYSTEM_STATUS = "/api/system/status"


def _get_device_host(device: Py2NDevice) -> str:
    """Best-effort host extraction for timeout diagnostics."""
    data = getattr(device, "data", None)
    host = getattr(data, "host", None)
    if isinstance(host, str) and host:
        return host
    return "unknown"

class Helios2nPortDataUpdateCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(
            hass,
            _LOGGER,
            name="Helios2n Port Update",
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS)
        )
        self.device = device

    async def _async_update_data(self):
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

class Helios2nSwitchDataUpdateCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(
            hass,
            _LOGGER,
            name="Helios2n Switch Update",
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS)
        )
        self.device = device

    async def _async_update_data(self):
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

class Helios2nSensorDataUpdateCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, device: Py2NDevice):
        super().__init__(
            hass,
            _LOGGER,
            name="Helios2n Sensor Update",
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS)
        )
        self.device = device

    async def _async_update_data(self):
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
