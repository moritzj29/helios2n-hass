import logging
from typing import Any, Callable, NamedTuple, Optional

from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.const import Platform

from py2n import Py2NDevice

from .const import DOMAIN
from .coordinator import Helios2nSensorDataUpdateCoordinator
from .utils import get_device_info

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.SENSOR


class SensorTypeDef(NamedTuple):
    """Definition of a sensor type configuration."""

    title: str
    device_class: Optional[SensorDeviceClass]
    units: Optional[str]
    icon: str
    enabled_by_default: bool
    state_class: Optional[SensorStateClass]
    update_function: Callable[[Py2NDevice], Any]
    extra_state_function: Optional[Callable[[Py2NDevice], dict[str, Any] | None]]


SENSOR_TYPES: dict[str, SensorTypeDef] = {
    "uptime": SensorTypeDef(
        title="Uptime",
        device_class=SensorDeviceClass.TIMESTAMP,
        units=None,
        icon="mdi:clock-outline",
        enabled_by_default=True,
        state_class=None,
        update_function=lambda device: device.data.uptime,
        extra_state_function=None,
    ),
}

async def async_setup_entry(hass: HomeAssistant, config: ConfigType, async_add_entities: AddEntitiesCallback):
    device: Py2NDevice = hass.data[DOMAIN][config.entry_id]["_device"]
    coordinator: Helios2nSensorDataUpdateCoordinator = hass.data[DOMAIN][config.entry_id][PLATFORM]["coordinator"]
    entities = []
    entities.append(Helios2nSensorEntity(coordinator, device, "uptime"))
    async_add_entities(entities)
    return True

class Helios2nSensorEntity(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: Helios2nSensorDataUpdateCoordinator, device: Py2NDevice, data: str) -> None:
        super().__init__(coordinator)
        self._device = device
        self._type = data
        self._attr_unique_id = f"{self._device.data.serial}_sensor_{data}"

        sensor_config = SENSOR_TYPES[self._type]
        self._attr_name = sensor_config.title
        self._attr_device_class = sensor_config.device_class
        self._attr_native_unit_of_measurement = sensor_config.units
        self._attr_icon = sensor_config.icon
        self._attr_entity_registry_enabled_default = sensor_config.enabled_by_default
        self._attr_state_class = sensor_config.state_class

    @property
    def device_info(self) -> DeviceInfo:
        return get_device_info(self._device)

    @property
    def native_value(self):
        """Return the state of the sensor."""
        sensor_config = SENSOR_TYPES[self._type]
        return sensor_config.update_function(self._device)

    @property
    def extra_state_attributes(self):
        """Return the state attributes of the device."""
        sensor_config = SENSOR_TYPES[self._type]
        if sensor_config.extra_state_function:
            return sensor_config.extra_state_function(self._device) or {}
        return {}
