"""Tests for integration constants."""
import pytest
from ..const import (
	DOMAIN,
	ATTR_METHOD,
	ATTR_ENDPOINT,
	ATTR_TIMEOUT,
	ATTR_DATA,
	ATTR_JSON,
	ATTR_ENTRY,
	DEFAULT_METHOD,
	DEFAULT_TIMEOUT,
)


class TestConstants:
	"""Tests for constant definitions."""

	def test_domain_is_helios2n(self):
		"""Test integration domain is 'helios2n'."""
		assert DOMAIN == "helios2n"

	def test_attribute_names_defined(self):
		"""Test all required attribute names are defined."""
		assert ATTR_METHOD is not None
		assert ATTR_ENDPOINT is not None
		assert ATTR_TIMEOUT is not None
		assert ATTR_DATA is not None
		assert ATTR_JSON is not None
		assert ATTR_ENTRY is not None

	def test_default_values_set(self):
		"""Test default values are properly set."""
		assert DEFAULT_METHOD == "GET"
		assert DEFAULT_TIMEOUT == 10

	def test_attribute_values_are_strings(self):
		"""Test all attributes are string type."""
		assert isinstance(DOMAIN, str)
		assert isinstance(ATTR_METHOD, str)
		assert isinstance(ATTR_ENDPOINT, str)
		assert isinstance(ATTR_TIMEOUT, str)
		assert isinstance(DEFAULT_METHOD, str)
