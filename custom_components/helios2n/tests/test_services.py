"""Tests for service validation helpers."""
import pytest
from homeassistant.exceptions import ServiceValidationError

from .. import (
	_validate_api_endpoint,
	_validate_http_method,
	_validate_payload_consistency,
	_validate_timeout,
)
from ..const import (
	ATTR_CERT_MISMATCH,
	CONF_CERTIFICATE_FINGERPRINT,
	DEFAULT_METHOD,
	DEFAULT_TIMEOUT,
	SERVICE_RECAPTURE_CERTIFICATE,
)


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
	"""Endpoint validation should accept spec-aligned API endpoint formats."""
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
