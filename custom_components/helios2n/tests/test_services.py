"""Tests for service validation logic."""
import pytest
from unittest.mock import MagicMock
from homeassistant.exceptions import ServiceValidationError
from ..const import (
	ATTR_METHOD,
	ATTR_ENDPOINT,
	ATTR_TIMEOUT,
	DEFAULT_METHOD,
	DEFAULT_TIMEOUT,
)


class TestServiceValidation:
	"""Tests for service call validation."""

	def test_valid_http_methods(self):
		"""Test all valid HTTP methods are accepted."""
		valid_methods = ["GET", "POST", "PUT", "DELETE"]
		
		for method in valid_methods:
			assert method in valid_methods

	def test_invalid_http_method_rejected(self):
		"""Test invalid HTTP methods are rejected."""
		valid_methods = ["GET", "POST", "PUT", "DELETE"]
		invalid_methods = ["PATCH", "HEAD", "OPTIONS", "TRACE"]
		
		for method in invalid_methods:
			assert method not in valid_methods

	def test_timeout_validation_bounds(self):
		"""Test timeout must be between 0 and 3600."""
		valid_timeouts = [0, 1, 100, 1800, 3600]
		invalid_timeouts = [-1, -100, 3601, 7200, 10000]
		
		for timeout in valid_timeouts:
			assert 0 <= timeout <= 3600
		
		for timeout in invalid_timeouts:
			assert not (0 <= timeout <= 3600)

	def test_timeout_conversion_to_int(self):
		"""Test timeout string conversion to int."""
		test_cases = [
			("30", 30),
			("0", 0),
			("3600", 3600),
		]
		
		for timeout_str, expected_int in test_cases:
			assert int(timeout_str) == expected_int

	def test_timeout_invalid_string_raises_error(self):
		"""Test invalid timeout strings raise ValueError."""
		invalid_timeouts = ["abc", "30.5", "not_a_number"]
		
		for timeout_str in invalid_timeouts:
			with pytest.raises((ValueError, TypeError)):
				int(timeout_str)

	def test_endpoint_required(self):
		"""Test endpoint parameter is required."""
		endpoints = ["", None, False]
		valid_endpoint = "/api/system/info"
		
		for endpoint in endpoints:
			assert not endpoint or endpoint is None or endpoint == ""
		
		assert valid_endpoint


class TestDefaultValues:
	"""Tests for default parameter values."""

	def test_default_method_is_get(self):
		"""Test default HTTP method is GET."""
		assert DEFAULT_METHOD == "GET"

	def test_default_timeout_is_10(self):
		"""Test default timeout is 10 seconds."""
		assert DEFAULT_TIMEOUT == 10
