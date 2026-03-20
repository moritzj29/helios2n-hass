import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from homeassistant.const import Platform

from py2n import Py2NDevice

from .const import (
    ATTR_LOG_SUBSCRIPTION,
    DOMAIN,
    CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
    DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
)
from .coordinator import Helios2nPortDataUpdateCoordinator, Helios2nSwitchDataUpdateCoordinator
from .utils import format_port_name

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.BINARY_SENSOR

async def async_setup_entry(hass: HomeAssistant, config: ConfigType, async_add_entities: AddEntitiesCallback):
    device: Py2NDevice = hass.data[DOMAIN][config.entry_id]["_device"]
    coordinator: Helios2nPortDataUpdateCoordinator = hass.data[DOMAIN][config.entry_id][PLATFORM]["coordinator"]
    config_data = getattr(config, "data", {})
    switch_coordinator: Helios2nSwitchDataUpdateCoordinator | None = None
    lock_platform_data = hass.data[DOMAIN][config.entry_id].get(Platform.LOCK)
    if isinstance(lock_platform_data, dict):
        switch_coordinator = lock_platform_data.get("coordinator")
    create_read_only_status_entities = config_data.get(
        CONF_CREATE_READ_ONLY_STATUS_ENTITIES, DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES
    )
    entities = []
    for port in device.data.ports:
        if port.type == "input":
            entities.append(Helios2nPortBinarySensorEntity(coordinator, device, port.id))
        elif create_read_only_status_entities and port.type == "output":
            entities.append(Helios2nOutputStatusBinarySensorEntity(coordinator, device, port.id))

    if create_read_only_status_entities and switch_coordinator is not None:
        for switch in device.data.switches:
            if switch.enabled:
                entities.append(
                    Helios2nSwitchStatusBinarySensorEntity(
                        switch_coordinator, device, switch.id
                    )
                )

    # Health indicator for the background log subscription loop.
    entities.append(Helios2nLogSubscriptionHealthBinarySensorEntity(hass, device, config.entry_id))
    
    async_add_entities(entities)
    return True

class Helios2nPortBinarySensorEntity(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: Helios2nPortDataUpdateCoordinator, device: Py2NDevice, port_id: str) -> None:
        super().__init__(coordinator)
        self._device = device
        self._attr_unique_id = f"{self._device.data.serial}_port_{port_id}"
        self._attr_name = format_port_name(port_id)
        self._port_id = port_id

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers = {(DOMAIN, self._device.data.serial), (DOMAIN, self._device.data.mac)},
            name= self._device.data.name,
            manufacturer = "2n/Helios",
            model = self._device.data.model,
            hw_version = self._device.data.hardware,
            sw_version = self._device.data.firmware,
        )

    @property
    def is_on(self) -> bool:
        data = self.coordinator.data
        if isinstance(data, dict):
            return bool(data.get(self._port_id, False))
        return False

class Helios2nLogSubscriptionHealthBinarySensorEntity(BinarySensorEntity):
    """Diagnostic health entity for log subscription state."""

    _attr_has_entity_name = True
    _attr_entity_registry_enabled_default = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, hass: HomeAssistant, device: Py2NDevice, entry_id: str) -> None:
        self.hass = hass
        self._device = device
        self._entry_id = entry_id
        self._attr_unique_id = f"{self._device.data.serial}_log_subscription_healthy"
        self._attr_name = "Log Subscription Healthy"

    def _subscription_state(self) -> dict:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id, {})
        state = entry_data.get(ATTR_LOG_SUBSCRIPTION)
        return state if isinstance(state, dict) else {}

    @property
    def is_on(self) -> bool:
        return bool(self._subscription_state().get("healthy", False))

    @property
    def extra_state_attributes(self) -> dict:
        state = self._subscription_state()
        return {
            "consecutive_failures": state.get("consecutive_failures", 0),
            "total_failures": state.get("total_failures", 0),
            "resubscribe_count": state.get("resubscribe_count", 0),
            "last_error": state.get("last_error"),
            "last_error_at": state.get("last_error_at"),
            "last_success_at": state.get("last_success_at"),
            "last_event_at": state.get("last_event_at"),
            "last_resubscribe_at": state.get("last_resubscribe_at"),
        }

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers = {(DOMAIN, self._device.data.serial), (DOMAIN, self._device.data.mac)},
            name= self._device.data.name,
            manufacturer = "2N/Helios",
            model = self._device.data.model,
            hw_version = self._device.data.hardware,
            sw_version = self._device.data.firmware,
        )


class Helios2nSwitchStatusBinarySensorEntity(CoordinatorEntity, BinarySensorEntity):
    """Read-only status entity for 2N switch API switches."""

    _attr_has_entity_name = True
    _attr_entity_registry_enabled_default = True

    def __init__(
        self,
        coordinator: Helios2nSwitchDataUpdateCoordinator,
        device: Py2NDevice,
        switch_id: int,
    ) -> None:
        super().__init__(coordinator)
        self._device = device
        self._switch_id = switch_id
        self._attr_unique_id = f"{self._device.data.serial}_switch_{switch_id}_status"
        self._attr_name = f"Switch {switch_id} Status"

    @property
    def is_on(self) -> bool:
        data = self.coordinator.data
        if isinstance(data, dict):
            return bool(data.get(self._switch_id, False))
        return False

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers = {(DOMAIN, self._device.data.serial), (DOMAIN, self._device.data.mac)},
            name= self._device.data.name,
            manufacturer = "2n/Helios",
            model = self._device.data.model,
            hw_version = self._device.data.hardware,
            sw_version = self._device.data.firmware,
        )


class Helios2nOutputStatusBinarySensorEntity(CoordinatorEntity, BinarySensorEntity):
    """Read-only status entity for output/relay port status."""

    _attr_has_entity_name = True
    _attr_entity_registry_enabled_default = True

    def __init__(
        self,
        coordinator: Helios2nPortDataUpdateCoordinator,
        device: Py2NDevice,
        port_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._device = device
        self._port_id = port_id
        self._attr_unique_id = f"{self._device.data.serial}_port_{port_id}_status"
        self._attr_name = f"{format_port_name(port_id)} Status"

    @property
    def is_on(self) -> bool:
        data = self.coordinator.data
        if isinstance(data, dict):
            return bool(data.get(self._port_id, False))
        return False

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers = {(DOMAIN, self._device.data.serial), (DOMAIN, self._device.data.mac)},
            name= self._device.data.name,
            manufacturer = "2n/Helios",
            model = self._device.data.model,
            hw_version = self._device.data.hardware,
            sw_version = self._device.data.firmware,
        )
