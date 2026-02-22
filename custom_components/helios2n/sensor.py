import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.components.sensor.const import SensorStateClass
from homeassistant.const import Platform

from homeassistant.const import (
    ATTR_ATTRIBUTION,
    DEGREE,
    PERCENTAGE,
    UnitOfIrradiance,
    UnitOfLength,
    UnitOfPressure,
    UnitOfSpeed,
    UnitOfTemperature,
    UnitOfTime,
    UnitOfVolumetricFlux,
)
from homeassistant.components.sensor import (
    SensorEntity,
)

from homeassistant.components.sensor.const import (
    SensorDeviceClass,
)


from py2n import Py2NDevice

from .const import DOMAIN
from .coordinator import Helios2nSensorDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.SENSOR

# Sensor types are defined as:
#   variable -> [0]title, [1]device_class, [2]units, [3]icon, [4]enabled_by_default, [5]state_class, [6]update_function, [7]extra_state_function
SENSOR_TYPES = {
    "uptime": [
        "Uptime",
        SensorDeviceClass.TIMESTAMP,
        None,
        "mdi:clock-outline",
        True,
        None,
        lambda device: device.data.uptime,
        None,
    ],
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
        self._attr_name = SENSOR_TYPES[self._type][0]
        self._attr_device_class = SENSOR_TYPES[self._type][1]
        self._attr_native_unit_of_measurement = SENSOR_TYPES[self._type][2]
        self._attr_icon = SENSOR_TYPES[self._type][3]
        self._attr_entity_registry_enabled_default = SENSOR_TYPES[self._type][4]
        self._attr_state_class = SENSOR_TYPES[self._type][5]

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
    def native_value(self):
        """Return the state of the sensor."""
        return SENSOR_TYPES[self._type][6](self._device)

    @property
    def extra_state_attributes(self):
        """Return the state attributes of the device."""
        attributes = {}
        if SENSOR_TYPES[self._type][7]:
            attributes = SENSOR_TYPES[self._type][7](self._device)

        return attributes

