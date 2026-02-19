import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from homeassistant.const import Platform

from py2n import Py2NDevice

from .const import DOMAIN, ATTR_CERT_MISMATCH
from .coordinator import Helios2nPortDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.BINARY_SENSOR

async def async_setup_entry(hass: HomeAssistant, config: ConfigType, async_add_entities: AddEntitiesCallback):
    device: Py2NDevice = hass.data[DOMAIN][config.entry_id]["_device"]
    coordinator: Helios2nPortDataUpdateCoordinator = hass.data[DOMAIN][config.entry_id][PLATFORM]["coordinator"]
    entities = []
    for port in device.data.ports:
        if port.type == "input":
            entities.append(Helios2nPortBinarySensorEntity(coordinator, device, port.id))
    
    # Add certificate mismatch binary sensor
    entities.append(Helios2nCertificateMismatchBinarySensorEntity(hass, device, config))
    
    async_add_entities(entities)
    return True

class Helios2nPortBinarySensorEntity(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: Helios2nPortDataUpdateCoordinator, device: Py2NDevice, port_id: str) -> None:
        super().__init__(coordinator)
        self._device = device
        self._attr_unique_id = f"{self._device.data.serial}_port_{port_id}"
        self._attr_name = port_id
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


class Helios2nCertificateMismatchBinarySensorEntity(BinarySensorEntity):
    """Binary sensor for certificate fingerprint mismatch."""
    
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    
    def __init__(self, hass: HomeAssistant, device: Py2NDevice, config: ConfigType) -> None:
        self.hass = hass
        self._device = device
        self._config = config
        self._attr_unique_id = f"{self._device.data.serial}_certificate_mismatch"
        self._attr_name = "Certificate Mismatch"
    
    @property
    def is_on(self) -> bool:
        """Return True if certificate fingerprint doesn't match stored hash."""
        entry_data = self.hass.data[DOMAIN][self._config.entry_id]
        return entry_data.get(ATTR_CERT_MISMATCH, False)
    
    @property
    def available(self) -> bool:
        """Entity available if SSL verification is disabled."""
        return not self._config.data.get("verify_ssl", True) and self._config.data.get("protocol") == "https"
    
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
