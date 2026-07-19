"""Tests for port identifier resolution from log events.

Per the 2N HIPA spec, InputChanged/OutputChanged log events carry
`params.port` as a *string* "I/O port name" (e.g. "led_secured"), which is the
same identifier returned by /api/io/status and stored as the coordinator cache
key. The event port therefore already matches the cache key 1:1; the only
realistic mismatches are whitespace and case differences.
"""
import pytest

from custom_components.helios2n.log import _resolve_port_id_from_event


@pytest.mark.parametrize(
    ("event_name", "port_identifier", "known", "expected"),
    [
        # Exact string match — the common case (e.g. "led_secured")
        ("InputChanged", "input1", {"input1", "relay1"}, "input1"),
        ("OutputChanged", "relay1", {"input1", "relay1"}, "relay1"),
        ("OutputChanged", "led_secured", {"led_secured", "input1"}, "led_secured"),
        # Case/whitespace differences are tolerated defensively
        ("InputChanged", "INPUT1", {"input1", "relay1"}, "input1"),
        ("InputChanged", " input1 ", {"input1", "relay1"}, "input1"),
    ],
)
def test_resolve_port_id_from_event(event_name, port_identifier, known, expected):
    """Event port string should resolve to the matching coordinator cache key."""
    assert _resolve_port_id_from_event(event_name, port_identifier, known) == expected
