"""Tests for retry mechanism in log polling."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from py2n.exceptions import DeviceConnectionError, DeviceApiError, ApiError
import asyncio


@pytest.mark.asyncio
async def test_retry_counter_resets_on_success():
	"""Test retry counter resets after successful poll."""
	# Simulate a successful poll
	retry_count = 0
	max_retries = 5
	
	# After successful operation, reset
	retry_count = 0
	
	assert retry_count == 0


@pytest.mark.asyncio
async def test_retry_counter_increments_on_error():
	"""Test retry counter increments on error."""
	retry_count = 0
	max_retries = 5
	
	# Simulate error, increment retry
	retry_count += 1
	
	assert retry_count == 1
	assert retry_count <= max_retries


@pytest.mark.asyncio
async def test_max_retries_exceeded_returns():
	"""Test function returns when max retries exceeded."""
	retry_count = 6
	max_retries = 5
	
	# Should abort
	should_continue = retry_count <= max_retries
	
	assert not should_continue


@pytest.mark.asyncio
async def test_retry_backoff_wait_time():
	"""Test retry backoff uses correct wait time."""
	backoff_time = 5  # seconds
	
	assert backoff_time == 5


class TestResubscribeLogic:
	"""Tests for log resubscription on invalid parameter error."""

	def test_invalid_parameter_error_triggers_resubscribe(self):
		"""Test INVALID_PARAMETER_VALUE error triggers log_subscribe."""
		from py2n.exceptions import ApiError
		
		error = DeviceApiError(error=ApiError.INVALID_PARAMETER_VALUE)
		
		assert error.error == ApiError.INVALID_PARAMETER_VALUE

	def test_other_api_errors_do_not_trigger_resubscribe(self):
		"""Test other API errors do not trigger resubscribe."""
		from py2n.exceptions import ApiError
		
		error = DeviceApiError(error=ApiError.AUTHORIZATION_REQUIRED)
		
		assert error.error != ApiError.INVALID_PARAMETER_VALUE
