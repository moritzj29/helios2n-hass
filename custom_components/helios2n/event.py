import logging
from collections.abc import Mapping
from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType

from py2n import Py2NDevice

from .const import DOMAIN
from .log import _extract_switch_state_change, _log_event_signal

_LOGGER = logging.getLogger(__name__)
PLATFORM = Platform.EVENT


async def async_setup_entry(
    hass: HomeAssistant, config: ConfigType, async_add_entities: AddEntitiesCallback
):
    """Set up Helios/2N event entities."""
    device: Py2NDevice = hass.data[DOMAIN][config.entry_id]["_device"]
    entities = [
        Helios2nSwitchStateChangedEventEntity(config.entry_id, device, switch.id)
        for switch in device.data.switches
        if switch.enabled
    ]
    async_add_entities(entities)
    return True


class Helios2nSwitchStateChangedEventEntity(EventEntity):
    """Event entity for SwitchStateChanged log events."""

    _attr_has_entity_name = True
    _attr_event_types = ["on", "off"]
    _attr_entity_registry_enabled_default = True

    def __init__(self, entry_id: str, device: Py2NDevice, switch_id: int) -> None:
        self._entry_id = entry_id
        self._device = device
        self._switch_id = switch_id
        self._attr_unique_id = f"{self._device.data.serial}_switch_{switch_id}_state_changed"
        self._attr_name = f"Switch {switch_id} State Changed"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._device.data.serial), (DOMAIN, self._device.data.mac)},
            name=self._device.data.name,
            manufacturer="2n/Helios",
            model=self._device.data.model,
            hw_version=self._device.data.hardware,
            sw_version=self._device.data.firmware,
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, _log_event_signal(self._entry_id), self._handle_log_event
            )
        )

    @callback
    def _handle_log_event(self, event: Mapping[str, Any]) -> None:
        if not isinstance(event, dict):
            return

        extracted = _extract_switch_state_change(event)
        if extracted is None:
            return
        switch_id, state = extracted
        if switch_id != self._switch_id:
            return

        params = event.get("params")
        payload = params if isinstance(params, dict) else event
        attributes: dict[str, Any] = {"switch": switch_id, "state": state}
        if "originator" in payload:
            attributes["originator"] = payload["originator"]
        if "utcTime" in event:
            attributes["utc_time"] = event["utcTime"]

        self._trigger_event("on" if state else "off", attributes)
        if self.hass is not None:
            self.async_write_ha_state()
