"""Tests for Helios/2N event entities."""

from types import SimpleNamespace

import pytest

from custom_components.helios2n.event import (
    Helios2nSwitchStateChangedEventEntity,
    Helios2nUserAuthenticatedEventEntity,
    async_setup_entry,
)
from custom_components.helios2n.const import DOMAIN


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
    """Test that all switches (enabled and disabled) get event entities, plus user auth."""
    device = _build_device()
    hass = SimpleNamespace(data={DOMAIN: {"entry-1": {"_device": device}}})
    config = SimpleNamespace(entry_id="entry-1")
    entities = []

    await async_setup_entry(hass, config, lambda items: entities.extend(items))

    # Should have 2 switch state changed entities (for both switches) + 1 user authenticated entity = 3
    assert len(entities) == 3
    # Find the switch state changed entities
    switch_entities = [e for e in entities if hasattr(e, '_switch_id')]
    assert len(switch_entities) == 2
    switch_ids = {e._switch_id for e in switch_entities}
    assert switch_ids == {1, 2}
    # Check entity_registry_enabled_default: switch 1 enabled=True, switch 2 enabled=False
    for entity in switch_entities:
        if entity._switch_id == 1:
            assert entity._attr_entity_registry_enabled_default is True
        elif entity._switch_id == 2:
            assert entity._attr_entity_registry_enabled_default is False
    # Verify user authenticated entity is present
    user_auth_entities = [e for e in entities if isinstance(e, Helios2nUserAuthenticatedEventEntity)]
    assert len(user_auth_entities) == 1


@pytest.mark.parametrize(
    "supported_events, expected_total, expected_switch_count",
    [
        ({"SwitchStateChanged"}, 2, 2),
        ({"UserAuthenticated"}, 1, 0),
        ({"SwitchStateChanged", "UserAuthenticated"}, 3, 2),
        (set(), 3, 2),  # empty => fallback to default (includes both)
    ],
)
@pytest.mark.asyncio
async def test_event_setup_creates_entities_based_on_capabilities(
    supported_events, expected_total, expected_switch_count
):
    """Event entity creation should respect supported_log_events and create entities for all switches."""
    device = _build_device()
    entry_data = {"_device": device, "supported_log_events": supported_events}
    hass = SimpleNamespace(data={DOMAIN: {"entry-1": entry_data}})
    config = SimpleNamespace(entry_id="entry-1")
    entities = []
    await async_setup_entry(hass, config, lambda items: entities.extend(items))
    assert len(entities) == expected_total
    # Separate switch entities
    switch_entities = [e for e in entities if hasattr(e, '_switch_id')]
    assert len(switch_entities) == expected_switch_count
    if expected_switch_count > 0:
        # Check that we have both switch IDs
        switch_ids = {e._switch_id for e in switch_entities}
        assert switch_ids == {1, 2}
        # Check entity_registry_enabled_default based on switch.enabled
        for entity in switch_entities:
            expected_enabled = entity._switch_id == 1  # switch 1 enabled, switch 2 disabled
            assert entity._attr_entity_registry_enabled_default == expected_enabled
    # Check user auth entity presence
    has_user_auth = any(isinstance(e, Helios2nUserAuthenticatedEventEntity) for e in entities)
    if "UserAuthenticated" in supported_events or not supported_events:
        assert has_user_auth
    else:
        assert not has_user_auth

