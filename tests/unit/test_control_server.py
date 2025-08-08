from unittest.mock import AsyncMock, patch

import pytest

from mcp_scan.models import ScanPathResult
from mcp_scan.upload import (
    get_user_info,
    upload,  # Make sure this import is correct
)


def test_opt_out_does_not_create_identity():
    """
    Test that opt_out does not create an identity.
    """
    # Get user info with opt_out=True
    user_info = get_user_info(email="test@example.com", opt_out=True)

    # Check that personal information is not included in the identity
    assert user_info.hostname is None
    assert user_info.username is None
    assert user_info.email is None
    assert user_info.ip_address is None

    # But anonymous_identifier should be present
    assert user_info.anonymous_identifier is not None


def test_get_identity_maintains_identity_when_opt_out_is_false():
    """
    Test that get_identity maintains the same identity when opt_out is False.
    """
    # Get user info with opt_out=False
    user_info_1 = get_user_info(email="test@example.com", opt_out=False)
    user_info_2 = get_user_info(email="test@example.com", opt_out=False)

    # The anonymous_identifier should be the same
    assert user_info_1.anonymous_identifier == user_info_2.anonymous_identifier


def test_get_identity_regenerates_identity_when_opt_out_is_true():
    """
    Test that get_identity regenerates identity when opt_out is True.
    """
    # Get user info with opt_out=True
    user_info_1 = get_user_info(email="test@example.com", opt_out=True)
    user_info_2 = get_user_info(email="test@example.com", opt_out=True)

    # The anonymous_identifier should be different (new identity generated each time)
    assert user_info_1.anonymous_identifier != user_info_2.anonymous_identifier


def test_opt_out_does_not_return_personal_information():
    """
    Test that opt_out does not return personal information.
    """
    # Get user info with opt_out=True
    user_info = get_user_info(email="test@example.com", opt_out=True)

    # Check that personal information is not included in the identity
    assert user_info.hostname is None
    assert user_info.username is None
    assert user_info.email is None
    assert user_info.ip_address is None

    # But anonymous_identifier should be present
    assert user_info.anonymous_identifier is not None


@pytest.mark.asyncio
async def test_upload_function_calls_get_user_info_with_correct_parameters():
    """
    Test that the upload function calls get_user_info with the correct parameters.
    """
    # Create a mock scan result
    mock_result = ScanPathResult(path="/test/path")

    # Mock the get_user_info function
    with patch("mcp_scan.upload.get_user_info") as mock_get_user_info:
        # 1. Create a mock for the HTTP response object.
        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        # 2. Create the mock async context manager for the `session.post()` call
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        # 3. Patch the `aiohttp.ClientSession.post` method directly on the class
        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            #    Configure the mocked `post` method to return our mock context manager
            mock_post_method.return_value = mock_post_context_manager

            # Call upload with opt_out=True
            await upload([mock_result], "https://control.mcp.scan", "push_key", "email", True)

            # Verify that get_user_info was called with the correct parameters
            mock_get_user_info.assert_called_once_with(email="email", opt_out=True)


@pytest.mark.asyncio
async def test_upload_function_calls_get_user_info_with_opt_out_false():
    """
    Test that the upload function calls get_user_info with opt_out=False when specified.
    """
    # Create a mock scan result
    mock_result = ScanPathResult(path="/test/path")

    # Mock the get_user_info function
    with patch("mcp_scan.upload.get_user_info") as mock_get_user_info:
        # 1. Create a mock for the HTTP response object.
        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        # 2. Create the mock async context manager for the `session.post()` call
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        # 3. Patch the `aiohttp.ClientSession.post` method directly on the class
        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            #    Configure the mocked `post` method to return our mock context manager
            mock_post_method.return_value = mock_post_context_manager

            # Call upload with opt_out=False
            await upload([mock_result], "https://control.mcp.scan", "push_key", "email", False)

            # Verify that get_user_info was called with the correct parameters
            mock_get_user_info.assert_called_once_with(email="email", opt_out=False)
