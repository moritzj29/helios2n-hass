"""Tests for service validation helpers."""
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.const import CONF_HOST, CONF_PROTOCOL, CONF_VERIFY_SSL
from homeassistant.exceptions import ServiceValidationError

from .. import (
	_validate_api_endpoint,
	_validate_http_method,
	_validate_payload_consistency,
	_validate_timeout,
	async_setup,
)
from ..const import (
    ATTR_CERT_MISMATCH,
    CONF_CERTIFICATE_FINGERPRINT,
    DEFAULT_METHOD,
    DEFAULT_TIMEOUT,
    DOMAIN,
    SERVICE_RECAPTURE_CERTIFICATE,
)

INTEGRATION_MODULE = sys.modules[async_setup.__module__]


def test_validate_http_method_accepts_valid_values_case_insensitively():
    """Method validation should normalize valid methods to uppercase."""
    assert _validate_http_method("GET") == "GET"
    assert _validate_http_method("post") == "POST"
    assert _validate_http_method(DEFAULT_METHOD) == "GET"


def test_validate_http_method_rejects_invalid_method():
    """Method validation should reject unsupported methods."""
    with pytest.raises(ServiceValidationError):
        _validate_http_method("PATCH")


def test_validate_timeout_accepts_bounds_and_strings():
    """Timeout validation should parse integers and enforce bounds."""
    assert _validate_timeout(DEFAULT_TIMEOUT) == 10
    assert _validate_timeout("0") == 0
    assert _validate_timeout("3600") == 3600


@pytest.mark.parametrize("invalid_timeout", ["abc", "30.5", -1, 3601])
def test_validate_timeout_rejects_invalid_values(invalid_timeout):
    """Timeout validation should reject non-integers and out-of-range values."""
    with pytest.raises(ServiceValidationError):
        _validate_timeout(invalid_timeout)


def test_validate_api_endpoint_accepts_relative_allowed_paths():
    """Endpoint validation should allow only explicit safe API path prefixes."""
    assert _validate_api_endpoint("switch/status") == "switch/status"
    assert _validate_api_endpoint("camera/snapshot") == "camera/snapshot"
    assert _validate_api_endpoint("api/system/info") == "system/info"
    assert _validate_api_endpoint("/api/accesspoint/blocking/status") == "accesspoint/blocking/status"
    assert _validate_api_endpoint("/api/system/info?format=json") == "system/info?format=json"


@pytest.mark.parametrize(
    "invalid_endpoint",
    [
        "",
        "http://example.com/evil",
        "../system/restart",
        "/api/system",
        "api/system/../status",
        "api/system/info$",
    ],
)
def test_validate_api_endpoint_rejects_unsafe_or_unknown_paths(invalid_endpoint):
    """Endpoint validation should block malformed and unsafe endpoint paths."""
    with pytest.raises(ServiceValidationError):
        _validate_api_endpoint(invalid_endpoint)


def test_validate_payload_consistency_rejects_data_and_json_together():
	"""Payload validation should reject ambiguous body input."""
	with pytest.raises(ServiceValidationError):
		_validate_payload_consistency({"x": 1}, {"y": 2})


def test_validate_payload_consistency_accepts_single_payload_source():
	"""Payload validation should allow either data or json individually."""
	_validate_payload_consistency({"x": 1}, None)
	_validate_payload_consistency(None, {"y": 2})


def test_certificate_service_constants_are_defined():
    """Certificate-related service constants should remain stable."""
    assert SERVICE_RECAPTURE_CERTIFICATE == "recapture_certificate"
    assert ATTR_CERT_MISMATCH == "certificate_mismatch"
    assert CONF_CERTIFICATE_FINGERPRINT == "certificate_fingerprint"


@pytest.mark.asyncio
async def test_recapture_certificate_service_updates_first_matching_entry(monkeypatch):
    """Recapture service should skip non-matching entries and update HTTPS verify_ssl=False entry."""
    hass = MagicMock()
    hass.data = {
        DOMAIN: {
            "entry1": {ATTR_CERT_MISMATCH: True},
            "entry2": {ATTR_CERT_MISMATCH: True},
        }
    }
    hass.services = MagicMock()
    hass.services.async_register = MagicMock()
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock()
    entry1 = SimpleNamespace(data={CONF_VERIFY_SSL: True, CONF_PROTOCOL: "https", CONF_HOST: "host1"})
    entry2 = SimpleNamespace(data={CONF_VERIFY_SSL: False, CONF_PROTOCOL: "https", CONF_HOST: "host2"})
    hass.config_entries.async_get_entry = MagicMock(
        side_effect=lambda entry_id: {"entry1": entry1, "entry2": entry2}[entry_id]
    )

    await async_setup(hass, {})

    recapture_callback = None
    for register_call in hass.services.async_register.call_args_list:
        if register_call.args[1] == SERVICE_RECAPTURE_CERTIFICATE:
            recapture_callback = register_call.args[2]
            break
    assert recapture_callback is not None

    monkeypatch.setattr(
        INTEGRATION_MODULE,
        "async_get_ssl_certificate_fingerprint",
        AsyncMock(return_value="deadbeef"),
    )

    await recapture_callback(SimpleNamespace(data={}))

    assert hass.config_entries.async_update_entry.call_count == 1
    assert (
        hass.config_entries.async_update_entry.call_args.kwargs["data"][
            CONF_CERTIFICATE_FINGERPRINT
        ]
        == "deadbeef"
    )
    assert hass.data[DOMAIN]["entry2"][ATTR_CERT_MISMATCH] is False
