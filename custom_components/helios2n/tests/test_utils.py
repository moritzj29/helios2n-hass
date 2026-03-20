"""Tests for utility functions."""
import pytest
from py2n import Py2NConnectionData

from ..const import DEFAULT_AUTH_METHOD
from ..utils import (
	create_connection_data,
	normalize_auth_method,
	sanitize_connection_data,
)


def test_sanitize_connection_data_masks_credentials(connection_data):
	"""Test that credentials are masked in sanitized output."""
	sanitized = sanitize_connection_data(connection_data)
	
	assert sanitized["host"] == "192.168.1.100"
	assert sanitized["protocol"] == "https"
	assert sanitized["username"] == "***"
	assert sanitized["password"] == "***"


def test_sanitize_connection_data_handles_none_credentials():
	"""Test sanitization with None credentials."""

	data = Py2NConnectionData(
		host="192.168.1.100",
		username=None,
		password=None,
		protocol="https"
	)
	sanitized = sanitize_connection_data(data)
	
	assert sanitized["username"] is None
	assert sanitized["password"] is None


def test_sanitize_connection_data_structure(connection_data):
	"""Test sanitized output has all required fields."""
	sanitized = sanitize_connection_data(connection_data)
	
	assert "host" in sanitized
	assert "username" in sanitized
	assert "password" in sanitized
	assert "protocol" in sanitized
	assert len(sanitized) == 4  # Only these 4 fields


def test_normalize_auth_method_defaults_to_basic():
	"""Auth method should default to basic when not provided."""
	assert normalize_auth_method(None) == DEFAULT_AUTH_METHOD


def test_normalize_auth_method_normalizes_case():
	"""Auth method should be normalized to lowercase."""
	assert normalize_auth_method("DiGeSt") == "digest"


def test_normalize_auth_method_rejects_invalid_value():
	"""Invalid auth methods should be rejected."""
	with pytest.raises(ValueError):
		normalize_auth_method("token")


def test_create_connection_data_supports_basic_auth():
	"""Connection data should be created for basic auth."""
	data = create_connection_data(
		host="192.168.1.100",
		username="admin",
		password="secret",
		protocol="https",
		auth_method="basic",
		ssl_verify=True,
	)
	assert data.host == "192.168.1.100"
	assert data.protocol == "https"
	assert data.auth_method == "basic"
	assert data.ssl_verify is True


def test_create_connection_data_supports_digest_auth():
	"""Connection data should be created for digest auth."""
	data = create_connection_data(
		host="192.168.1.100",
		username="admin",
		password="secret",
		protocol="https",
		auth_method="digest",
		ssl_verify=False,
	)
	assert data.host == "192.168.1.100"
	assert data.auth_method == "digest"
	assert data.ssl_verify is False

