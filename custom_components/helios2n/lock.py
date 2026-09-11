import logging
from typing import Any, cast

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity, DataUpdateCoordinator
from homeassistant.components.lock import LockEntity
from homeassistant.const import Platform

from py2n import Py2NDevice

from .const import DOMAIN, CONF_DISABLE_CONTROL_ENTITIES, DEFAULT_DISABLE_CONTROL_ENTITIES
from .coordinator import Helios2nSwitchDataUpdateCoordinator
from .utils import get_device_info

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.LOCK


async def async_setup_entry(
    hass: HomeAssistant, config: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> bool:
    device: Py2NDevice = hass.data[DOMAIN][config.entry_id]["_device"]
    coordinator: Helios2nSwitchDataUpdateCoordinator = hass.data[DOMAIN][config.entry_id][PLATFORM]["coordinator"]
    config_data = config.data
    disable_control_entities = config_data.get(
        CONF_DISABLE_CONTROL_ENTITIES, DEFAULT_DISABLE_CONTROL_ENTITIES
    )
    entities: list[LockEntity] = []
    if not disable_control_entities:
        for switch in device.data.switches:
            if switch.enabled and switch.mode == "bistable":
                entities.append(Helios2nLockEntity(coordinator, device, switch.id))
    async_add_entities(entities)
    return True


class Helios2nLockEntity(CoordinatorEntity, LockEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: Helios2nSwitchDataUpdateCoordinator, device: Py2NDevice, switch_id: int) -> None:
        # CoordinatorEntity expects DataUpdateCoordinator[dict[str, Any]], but our
        # switch coordinator uses dict[int, object]. Use cast() to satisfy mypy.
        super().__init__(cast(DataUpdateCoordinator, coordinator))
        self._device = device
        self._attr_unique_id = f"{self._device.data.serial}_switch_{switch_id}"
        self._attr_name = f"Switch {switch_id}"
        self._switch_id = switch_id

    @property
    def device_info(self) -> DeviceInfo:
        return get_device_info(self._device)

    @property
    def is_locked(self) -> bool:
        data = self.coordinator.data
        if isinstance(data, dict):
            # Cast to dict[Any, Any] so .get(int_key, ...) is accepted by mypy.
            # The coordinator's data is dict[int, object], but CoordinatorEntity
            # types data as dict[str, Any].
            typed_data = cast(dict[Any, Any], data)
            return not bool(typed_data.get(self._switch_id, False))
        return True

    async def async_unlock(self, **kwargs) -> None:
        await self._device.set_switch(self._switch_id, True)
        await self.coordinator.async_request_refresh()

    async def async_lock(self, **kwargs) -> None:
        await self._device.set_switch(self._switch_id, False)
        await self.coordinator.async_request_refresh()
