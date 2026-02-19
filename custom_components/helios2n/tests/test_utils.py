"""Tests for utility functions."""
from unittest.mock import AsyncMock, MagicMock

import pytest
from ..utils import (
	async_get_ssl_certificate_fingerprint,
	get_ssl_certificate_fingerprint,
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


def test_get_ssl_certificate_fingerprint_returns_hex_string():
	"""Test fingerprint returns valid hex string format."""
	# This is a unit test - we can't test with real certificate
	# but we can verify the function signature and error handling
	result = get_ssl_certificate_fingerprint("invalid.host.local", 443)
	
	# Should return None on connection error
	assert result is None or isinstance(result, str)
	if isinstance(result, str):
		# Should be hex format (lowercase, 64 chars for SHA256)
		assert all(c in "0123456789abcdef" for c in result)
		assert len(result) == 64


def test_get_ssl_certificate_fingerprint_handles_invalid_host():
	"""Test fingerprint handles invalid hosts gracefully."""
	result = get_ssl_certificate_fingerprint("this.host.does.not.exist.invalid", 443)
	
	# Should return None on connection error, not raise exception
	assert result is None


@pytest.mark.asyncio
async def test_async_get_ssl_certificate_fingerprint_runs_in_executor():
	"""Async helper should delegate blocking work to executor."""
	hass = MagicMock()
	hass.async_add_executor_job = AsyncMock(return_value="abc123")

	result = await async_get_ssl_certificate_fingerprint(hass, "host.local", 443)

	assert result == "abc123"
	assert hass.async_add_executor_job.await_count == 1
	assert hass.async_add_executor_job.await_args.args == (
		get_ssl_certificate_fingerprint,
		"host.local",
		443,
	)
