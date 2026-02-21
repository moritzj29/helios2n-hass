"""Utility functions for Helios2N integration."""
import hashlib
import socket
import ssl

from homeassistant.core import HomeAssistant
from py2n import Py2NConnectionData

from .const import DEFAULT_AUTH_METHOD, SUPPORTED_AUTH_METHODS


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


def sanitize_connection_data(connection_data: Py2NConnectionData) -> dict:
    """Sanitize connection data for logging (mask sensitive fields)."""
    return {
        "host": connection_data.host,
        "username": "***" if connection_data.username else None,
        "password": "***" if connection_data.password else None,
        "protocol": connection_data.protocol,
    }


def get_ssl_certificate_fingerprint(host: str, port: int = 443) -> str | None:
    """Get SHA256 fingerprint of remote SSL certificate.
    
    Args:
        host: Hostname or IP address
        port: Port number (default 443 for HTTPS)
        
    Returns:
        SHA256 fingerprint as hex string or None if unable to get certificate
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as conn:
            with context.wrap_socket(conn, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    fingerprint = hashlib.sha256(cert_der).hexdigest()
                    return fingerprint
    except Exception:
        pass
    return None


async def async_get_ssl_certificate_fingerprint(
    hass: HomeAssistant, host: str, port: int = 443
) -> str | None:
    """Get fingerprint in executor to avoid blocking Home Assistant's event loop."""
    return await hass.async_add_executor_job(get_ssl_certificate_fingerprint, host, port)
