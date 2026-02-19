"""Utility functions for Helios2N integration."""
from py2n import Py2NConnectionData


def sanitize_connection_data(connection_data: Py2NConnectionData) -> dict:
	"""Sanitize connection data for logging (mask sensitive fields)."""
	return {
		"host": connection_data.host,
		"username": "***" if connection_data.username else None,
		"password": "***" if connection_data.password else None,
		"protocol": connection_data.protocol,
	}
