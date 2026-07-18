"""Tests for integration constants."""
import pytest
from custom_components.helios2n import ALLOWED_HTTP_METHODS, LOG_WATCHDOG_DELAY_SECONDS
from custom_components.helios2n.const import (
    DOMAIN,
    ATTR_METHOD,
    ATTR_ENDPOINT,
    ATTR_TIMEOUT,
    ATTR_DATA,
    ATTR_JSON,
    ATTR_ENTRY,
    DEFAULT_METHOD,
    DEFAULT_TIMEOUT,
    CONF_AUTH_METHOD,
    DEFAULT_AUTH_METHOD,
    SUPPORTED_AUTH_METHODS,
    CONF_CREATE_READ_ONLY_STATUS_ENTITIES,
    DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES,
    CONF_DISABLE_CONTROL_ENTITIES,
    DEFAULT_DISABLE_CONTROL_ENTITIES,
    ATTR_LOG_SUBSCRIPTION,
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

    def test_auth_method_constants(self):
        """Test auth method configuration constants."""
        assert CONF_AUTH_METHOD == "auth_method"
        assert DEFAULT_AUTH_METHOD == "basic"
        assert isinstance(SUPPORTED_AUTH_METHODS, tuple)
        assert "basic" in SUPPORTED_AUTH_METHODS
        assert "digest" in SUPPORTED_AUTH_METHODS

    def test_entity_control_constants(self):
        """Test entity visibility and control constants."""
        assert CONF_CREATE_READ_ONLY_STATUS_ENTITIES == "create_read_only_status_entities"
        assert DEFAULT_CREATE_READ_ONLY_STATUS_ENTITIES is False
        assert CONF_DISABLE_CONTROL_ENTITIES == "disable_control_entities"
        assert DEFAULT_DISABLE_CONTROL_ENTITIES is False

    def test_log_subscription_constant(self):
        """Test log subscription attribute name."""
        assert ATTR_LOG_SUBSCRIPTION == "log_subscription"

    def test_log_watchdog_delay_constant(self):
        """Test log watchdog delay is a positive integer."""
        assert isinstance(LOG_WATCHDOG_DELAY_SECONDS, int)
        assert LOG_WATCHDOG_DELAY_SECONDS > 0

    def test_allowed_http_methods_constant(self):
        """Test allowed HTTP methods set contains expected methods."""
        assert isinstance(ALLOWED_HTTP_METHODS, set)
        assert ALLOWED_HTTP_METHODS == {"GET", "POST", "PUT", "DELETE"}
