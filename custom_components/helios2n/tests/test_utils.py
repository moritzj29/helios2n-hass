"""Tests for utility functions."""
import pytest
from ..utils import sanitize_connection_data


def test_sanitize_connection_data_masks_credentials(connection_data):
	"""Test that credentials are masked in sanitized output."""
	sanitized = sanitize_connection_data(connection_data)
	
	assert sanitized["host"] == "192.168.1.100"
	assert sanitized["protocol"] == "https"
	assert sanitized["username"] == "***"
	assert sanitized["password"] == "***"


def test_sanitize_connection_data_handles_none_credentials():
	"""Test sanitization with None credentials."""
	from py2n import Py2NConnectionData
	
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
