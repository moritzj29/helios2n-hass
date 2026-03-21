"""Utility functions for Helios2N integration."""
import re

from homeassistant.helpers.entity import DeviceInfo
from py2n import Py2NDevice, Py2NConnectionData

from .const import DEFAULT_AUTH_METHOD, SUPPORTED_AUTH_METHODS, DOMAIN


def normalize_auth_method(auth_method_raw: object | None) -> str:
    """Normalize and validate API auth method."""
    if auth_method_raw is None:
        return DEFAULT_AUTH_METHOD
    auth_method = str(auth_method_raw).strip().lower()
    if auth_method in SUPPORTED_AUTH_METHODS:
        return auth_method
    raise ValueError(f"Unsupported auth method: {auth_method_raw}")


def create_connection_data(
    *,
    host: str,
    username: str | None,
    password: str | None,
    protocol: str,
    auth_method: str,
    ssl_verify: bool,
) -> Py2NConnectionData:
    """Create connection data using py2n's explicit auth_method API."""
    auth_method = normalize_auth_method(auth_method)
    return Py2NConnectionData(
        host=host,
        username=username,
        password=password,
        auth_method=auth_method,
        protocol=protocol,
        ssl_verify=ssl_verify,
    )


def format_port_name(port_id: str) -> str:
    """Format port ID to a user-friendly label (e.g., 'relay1' -> 'Relay 1')."""
    if not port_id:
        return port_id
    # Match non-digits followed by digits at the end (e.g., "relay1" -> "relay", "1")
    match = re.search(r'(\D+)(\d+)$', port_id)
    if match:
        prefix, number = match.groups()
        return f"{prefix.title()} {number}"
    # If pattern doesn't match, return as-is
    return port_id


def get_device_info(device: Py2NDevice) -> DeviceInfo:
    """Create standardized DeviceInfo for Helios/2N devices."""
    return DeviceInfo(
        identifiers={(DOMAIN, device.data.serial), (DOMAIN, device.data.mac)},
        connections={("mac", device.data.mac)},
        name=device.data.name,
        manufacturer="2N/Helios",
        model=device.data.model,
        serial_number=device.data.serial,
        hw_version=device.data.hardware,
        sw_version=device.data.firmware,
        configuration_url=f"{device.options.protocol}://{device.data.host}",
    )


def sanitize_connection_data(connection_data: Py2NConnectionData) -> dict:
	"""Sanitize connection data for logging (mask sensitive fields)."""
	return {
		"host": connection_data.host,
		"username": "***" if connection_data.username else None,
		"password": "***" if connection_data.password else None,
		"protocol": connection_data.protocol,
	}
