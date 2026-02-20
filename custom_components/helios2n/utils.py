"""Utility functions for Helios2N integration."""
import hashlib
import socket
import ssl
from py2n import Py2NConnectionData


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
