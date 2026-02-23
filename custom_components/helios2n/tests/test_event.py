"""Tests for Helios/2N event entities."""

from types import SimpleNamespace

import pytest

from ..event import Helios2nSwitchStateChangedEventEntity, async_setup_entry
from ..const import DOMAIN


def _build_device() -> SimpleNamespace:
    return SimpleNamespace(
        data=SimpleNamespace(
            serial="serial-1",
            mac="aa:bb:cc:dd:ee:ff",
            name="Front Door",
            model="IP Verso",
            hardware="1.0",
            firmware="2.0",
            switches=[
                SimpleNamespace(id=1, enabled=True),
                SimpleNamespace(id=2, enabled=False),
            ],
        )
    )


def test_switch_state_changed_event_entity_triggers_on_matching_switch():
    """SwitchStateChanged should trigger on/off events for the matching switch id."""
    device = _build_device()
    entity = Helios2nSwitchStateChangedEventEntity("entry-1", device, 1)

    assert entity.state is None

    entity._handle_log_event(
        {
            "event": "SwitchStateChanged",
            "params": {"switch": 1, "state": True, "originator": "api"},
            "utcTime": "2026-02-22T12:00:00",
        }
    )

    attrs = entity.state_attributes
    assert attrs["event_type"] == "on"
    assert attrs["switch"] == 1
    assert attrs["state"] is True
    assert attrs["originator"] == "api"
    assert attrs["utc_time"] == "2026-02-22T12:00:00"

    # Event for another switch must be ignored.
    entity._handle_log_event(
        {"event": "SwitchStateChanged", "params": {"switch": 2, "state": False}}
    )
    assert entity.state_attributes["event_type"] == "on"


@pytest.mark.asyncio
async def test_event_setup_adds_entities_for_enabled_switches():
    """Only enabled switches should get an event entity."""
    device = _build_device()
    hass = SimpleNamespace(data={DOMAIN: {"entry-1": {"_device": device}}})
    config = SimpleNamespace(entry_id="entry-1")
    entities: list[Helios2nSwitchStateChangedEventEntity] = []

    await async_setup_entry(hass, config, lambda items: entities.extend(items))

    assert len(entities) == 1
    assert entities[0]._switch_id == 1
