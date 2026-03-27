"""Tests for utility functions."""
import pytest
from types import SimpleNamespace
from py2n import Py2NConnectionData

from custom_components.helios2n import utils as utils_module
from custom_components.helios2n.const import DEFAULT_AUTH_METHOD
from custom_components.helios2n.utils import (
    create_connection_data,
    format_port_name,
    get_device_info,
    normalize_auth_method,
    sanitize_connection_data,
)
from py2n import Py2NDevice


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


# Tests for format_port_name
@pytest.mark.parametrize(
    ("port_id", "expected"),
    [
        ("relay1", "Relay 1"),
        ("output1", "Output 1"),
        ("input1", "Input 1"),
        ("relay10", "Relay 10"),
        ("output5", "Output 5"),
        ("input99", "Input 99"),
        ("RELAY1", "Relay 1"),  # uppercase prefix
        ("OUTPUT2", "Output 2"),
        ("Relay3", "Relay 3"),  # already mixed case
    ],
)
def test_format_port_name_formats_correctly(port_id, expected):
    """Port IDs should be formatted to title case with space before number."""
    assert format_port_name(port_id) == expected


def test_format_port_name_returns_original_if_no_digits():
    """If no digit suffix found, return original string."""
    assert format_port_name("aux") == "aux"
    assert format_port_name("main") == "main"
    assert format_port_name("") == ""


def test_format_port_name_handles_none():
    """None input should be returned as-is (or could return empty string, but current behavior returns None)."""
    assert format_port_name(None) is None


# Tests for get_device_info
def test_get_device_info_returns_complete_structure():
    """get_device_info should return a DeviceInfo with all fields."""
    mock_device = SimpleNamespace(
        data=SimpleNamespace(
            serial="ABC123",
            mac="aa:bb:cc:dd:ee:ff",
            host="192.168.1.100",
            name="Door Entry",
            model="IP Verso",
            hardware="1.0.0",
            firmware="2.0.0",
        ),
        options=SimpleNamespace(protocol="https"),
    )
    device_info = get_device_info(mock_device)
    assert device_info["identifiers"] == {("helios2n", "ABC123"), ("helios2n", "aa:bb:cc:dd:ee:ff")}
    assert device_info["connections"] == {("mac", "aa:bb:cc:dd:ee:ff")}
    assert device_info["name"] == "Door Entry"
    assert device_info["manufacturer"] == "2N/Helios"
    assert device_info["model"] == "IP Verso"
    assert device_info["serial_number"] == "ABC123"
    assert device_info["hw_version"] == "1.0.0"
    assert device_info["sw_version"] == "2.0.0"
    assert device_info["configuration_url"] == "https://192.168.1.100"


def test_get_device_info_with_none_optional_fields():
    """get_device_info should set None for optional fields while required fields are still populated."""
    mock_device = SimpleNamespace(
        data=SimpleNamespace(
            serial="SN123",
            mac="11:22:33:44:55:66",
            host="192.168.1.200",
            name=None,
            model=None,
            hardware=None,
            firmware=None,
        ),
        options=SimpleNamespace(protocol="http"),
    )
    device_info = get_device_info(mock_device)
    assert device_info["identifiers"] == {("helios2n", "SN123"), ("helios2n", "11:22:33:44:55:66")}
    assert device_info["connections"] == {("mac", "11:22:33:44:55:66")}
    assert device_info["name"] is None
    assert device_info["manufacturer"] == "2N/Helios"
    assert device_info["model"] is None
    assert device_info["serial_number"] == "SN123"
    assert device_info["hw_version"] is None
    assert device_info["sw_version"] is None
    assert device_info["configuration_url"] == "http://192.168.1.200"


