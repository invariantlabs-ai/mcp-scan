import json
import sys
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlsplit

import aiohttp
import httpx
import pytest

from mcp_scan.MCPScanner import MCPScanner
from mcp_scan.redact import redact_args, redact_traceback
from mcp_scan.models import (
    RemoteServer,
    ScanError,
    ScanPathResult,
    ScanUserInfo,
    ServerScanResult,
    StdioServer,
    UnknownMCPConfig,
)
from mcp_scan.upload import (
    get_user_info,
    upload,  # Make sure this import is correct
)


def test_opt_out_does_not_create_identity():
    """
    Test that opt_out does not create an identity.
    """
    # Get user info with opt_out=True
    user_info = get_user_info(identifier="test@example.com", opt_out=True)

    # Check that personal information is not included in the identity
    assert user_info.hostname is None
    assert user_info.username is None
    assert user_info.identifier is None
    assert user_info.ip_address is None

    # But anonymous_identifier should be present
    assert user_info.anonymous_identifier is not None


def test_get_identity_maintains_identity_when_opt_out_is_false():
    """
    Test that get_identity maintains the same identity when opt_out is False.
    """
    # Get user info with opt_out=False
    user_info_1 = get_user_info(identifier="test@example.com", opt_out=False)
    user_info_2 = get_user_info(identifier="test@example.com", opt_out=False)

    # The anonymous_identifier should be the same
    assert user_info_1.anonymous_identifier == user_info_2.anonymous_identifier


def test_get_identity_regenerates_identity_when_opt_out_is_true():
    """
    Test that get_identity regenerates identity when opt_out is True.
    """
    # Get user info with opt_out=True
    user_info_1 = get_user_info(identifier="test@example.com", opt_out=True)
    user_info_2 = get_user_info(identifier="test@example.com", opt_out=True)

    # The anonymous_identifier should be different (new identity generated each time)
    assert user_info_1.anonymous_identifier != user_info_2.anonymous_identifier


def test_opt_out_does_not_return_personal_information():
    """
    Test that opt_out does not return personal information.
    """
    # Get user info with opt_out=True
    user_info = get_user_info(identifier="test@example.com", opt_out=True)

    # Check that personal information is not included in the identity
    assert user_info.hostname is None
    assert user_info.username is None
    assert user_info.identifier is None
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
        mock_get_user_info.return_value = ScanUserInfo()

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
            await upload([mock_result], "https://control.mcp.scan", "email", True)

            # Verify that get_user_info was called with the correct parameters
            mock_get_user_info.assert_called_once_with(identifier="email", opt_out=True)


@pytest.mark.asyncio
async def test_upload_function_calls_get_user_info_with_opt_out_false():
    """
    Test that the upload function calls get_user_info with opt_out=False when specified.
    """
    # Create a mock scan result
    mock_result = ScanPathResult(path="/test/path")

    # Mock the get_user_info function
    with patch("mcp_scan.upload.get_user_info") as mock_get_user_info:
        mock_get_user_info.return_value = ScanUserInfo()

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
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that get_user_info was called with the correct parameters
            mock_get_user_info.assert_called_once_with(identifier="email", opt_out=False)


@pytest.mark.asyncio
async def test_upload_includes_scan_error_in_payload():
    """
    Ensure that when a ScanPathResult has an error, it is serialized
    and included in the payload sent by upload().
    """

    # Prepare a ScanPathResult with at least one server (so it isn't skipped) and an error
    server = ServerScanResult(name="server1", server=StdioServer(command="echo"))
    scan_error_message = "something went wrong"
    exception_message = "could not start server"
    traceback = "traceback"
    path_result_with_error = ScanPathResult(
        path="/test/path",
        servers=[server],
        error=ScanError(
            message=scan_error_message,
            exception=Exception(exception_message),
            traceback=traceback,
            is_failure=True,
            category="server_startup",
        ),
    )

    with patch("mcp_scan.upload.get_user_info") as mock_get_user_info:
        mock_get_user_info.return_value = ScanUserInfo()

        # Mock HTTP response
        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        # Async context manager for session.post
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        # Patch aiohttp ClientSession.post
        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([path_result_with_error], "https://control.mcp.scan", "email", False)

            # Capture payload
            assert mock_post_method.call_args is not None, "upload did not call ClientSession.post"
            sent_kwargs = mock_post_method.call_args.kwargs
            assert "data" in sent_kwargs, "upload did not send JSON payload in 'data'"

            payload = json.loads(sent_kwargs["data"])
            # Validate structure and error propagation
            assert "scan_path_results" in payload and isinstance(payload["scan_path_results"], list)
            assert len(payload["scan_path_results"]) == 1
            sent_result = payload["scan_path_results"][0]

            # Error must be present and correctly serialized
            assert "error" in sent_result and sent_result["error"] is not None
            assert scan_error_message in sent_result["error"].get("message")
            assert exception_message in sent_result["error"].get("exception")
            assert sent_result["error"]["is_failure"] is True
            assert sent_result["error"]["traceback"] == traceback


@pytest.mark.asyncio
async def test_get_servers_from_path_sets_file_not_found_error_and_uploads_payload():
    """
    Patch MCPScanner.get_servers_from_path dependencies so that scan_mcp_config_file raises FileNotFoundError
    and ensure the resulting ScanPathResult has error message "file does not exist" and is uploaded.
    """
    with (
        patch.object(
            sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", side_effect=FileNotFoundError("missing")
        ),
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
    ):
        mock_get_user_info.return_value = ScanUserInfo()

        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            async with MCPScanner(files=["/nonexistent/path"]) as scanner:
                result = await scanner.get_servers_from_path("/nonexistent/path")

            await upload([result], "https://control.mcp.scan", None, False)

            payload = json.loads(mock_post_method.call_args.kwargs["data"])
            sent_result = payload["scan_path_results"][0]
            assert sent_result["servers"] is None
            assert sent_result["path"] == "/nonexistent/path"
            assert sent_result["error"]["message"] == "file /nonexistent/path does not exist"
            assert sent_result["error"]["is_failure"] is False
            assert "missing" in (sent_result["error"].get("exception") or "")


@pytest.mark.asyncio
async def test_get_servers_from_path_sets_parse_error_and_uploads_payload():
    """
    Patch MCPScanner.get_servers_from_path dependencies so that scan_mcp_config_file raises a generic Exception
    and ensure the resulting ScanPathResult has error message "could not parse file" and is uploaded.
    """
    with (
        patch.object(
            sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", side_effect=Exception("parse failure")
        ),
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
    ):
        mock_get_user_info.return_value = ScanUserInfo()

        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            async with MCPScanner(files=["/bad/config"]) as scanner:
                result = await scanner.get_servers_from_path("/bad/config")

            await upload([result], "https://control.mcp.scan", None, False)

            payload = json.loads(mock_post_method.call_args.kwargs["data"])
            sent_result = payload["scan_path_results"][0]
            assert sent_result["servers"] is None
            assert sent_result["path"] == "/bad/config"
            assert sent_result["error"]["message"] == "could not parse file /bad/config"
            assert sent_result["error"]["is_failure"] is True
            assert "parse failure" in (sent_result["error"].get("exception") or "")


@pytest.mark.asyncio
async def test_scan_server_sets_http_status_error_and_uploads_payload():
    """
    Patch MCPScanner to return a server, then make check_server raise HTTPStatusError and
    ensure the server-level error message "server returned HTTP status code" is included on upload.
    """

    class DummyCfg:
        def get_servers(self):
            return {"srv": StdioServer(command="echo")}

    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=DummyCfg()),
        patch.object(
            sys.modules["mcp_scan.MCPScanner"],
            "check_server",
            side_effect=httpx.HTTPStatusError("bad", request=None, response=None),
        ),
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
    ):
        mock_get_user_info.return_value = ScanUserInfo()

        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            async with MCPScanner(files=["/ok/path"]) as scanner:
                # inspect_only to avoid verification path
                result = await scanner.scan_path("/ok/path", inspect_only=True)

            await upload([result], "https://control.mcp.scan", None, False)

            payload = json.loads(mock_post_method.call_args.kwargs["data"])
            assert payload["scan_path_results"][0]["servers"] is not None
            sent_result = payload["scan_path_results"][0]
            assert sent_result["servers"][0]["error"]["message"] == "server returned HTTP status code"
            assert sent_result["servers"][0]["error"]["is_failure"] is True


@pytest.mark.asyncio
async def test_scan_server_sets_could_not_start_error_and_uploads_payload():
    """
    Patch MCPScanner to return a server, then make check_server raise a generic Exception and
    ensure the server-level error message "could not start server" is included on upload.
    """

    class DummyCfg:
        def get_servers(self):
            return {"srv": StdioServer(command="echo")}

    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=DummyCfg()),
        patch.object(sys.modules["mcp_scan.MCPScanner"], "check_server", side_effect=Exception("spawn failed")),
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
    ):
        mock_get_user_info.return_value = ScanUserInfo()

        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            async with MCPScanner(files=["/ok/path"]) as scanner:
                result = await scanner.scan_path("/ok/path", inspect_only=True)

            await upload([result], "https://control.mcp.scan", None, False)

            payload = json.loads(mock_post_method.call_args.kwargs["data"])
            assert payload["scan_path_results"][0]["servers"] is not None
            sent_result = payload["scan_path_results"][0]
            assert sent_result["servers"][0]["error"]["message"] == "could not start server"
            assert sent_result["servers"][0]["error"]["is_failure"] is True


@pytest.mark.asyncio
async def test_upload_retries_on_network_error():
    """
    Test that upload retries up to 3 times on network errors.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None  # Speed up tests by not actually sleeping

        # Mock HTTP response to always fail with network error
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted 3 times
            assert mock_post_method.call_count == 3

            # Verify that sleep was called between retries (2 times for 3 attempts)
            assert mock_sleep.call_count == 2
            # Verify exponential backoff: 1s, 2s
            mock_sleep.assert_any_call(1)
            mock_sleep.assert_any_call(2)


@pytest.mark.asyncio
async def test_upload_retries_on_server_error():
    """
    Test that upload retries on 5xx server errors but not on 4xx client errors.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # Mock HTTP response with 503 Service Unavailable
        mock_http_response = AsyncMock(status=503)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = "Service Unavailable"

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted 3 times
            assert mock_post_method.call_count == 3

            # Verify that sleep was called between retries
            assert mock_sleep.call_count == 2


@pytest.mark.asyncio
async def test_upload_does_not_retry_on_client_error():
    """
    Test that upload does NOT retry on 4xx client errors (like 400, 404).
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # Mock HTTP response with 400 Bad Request
        mock_http_response = AsyncMock(status=400)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = "Bad Request"

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted only once (no retries on 4xx)
            assert mock_post_method.call_count == 1

            # Verify that sleep was NOT called
            mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_scan_path_redacts_remote_url_query_and_headers():
    """
    Ensure RemoteServer headers are redacted and URL query parameter values are replaced with REDACTED.
    Uses scanner.scan_path to exercise _redact_server in the normal flow.
    """

    class DummyCfg:
        def get_servers(self):
            return {
                "remote": RemoteServer(
                    url="https://api.example.com/endpoint?token=abc123&api_key=xyz",
                    type="http",
                    headers={"Authorization": "Bearer secret", "X-Custom": "value"},
                )
            }

    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=DummyCfg()),
        patch.object(sys.modules["mcp_scan.MCPScanner"], "check_server", return_value=None),
    ):
        async with MCPScanner(files=["/dummy/path"]) as scanner:
            result = await scanner.scan_path("/dummy/path", inspect_only=True)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, RemoteServer)
    # Headers should be redacted
    assert srv.server.headers["Authorization"] == "**REDACTED**"
    assert srv.server.headers["X-Custom"] == "**REDACTED**"
    # URL query param values should be redacted (keys preserved)
    parts = urlsplit(srv.server.url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    assert qs.get("token") == "**REDACTED**"
    assert qs.get("api_key") == "**REDACTED**"


@pytest.mark.asyncio
async def test_scan_path_redacts_stdio_env_vars():
    """
    Ensure StdioServer environment variable values are redacted via scanner.scan_path.
    """

    class DummyCfg:
        def get_servers(self):
            return {
                "stdio": StdioServer(
                    command="echo",
                    args=["hello"],
                    env={"SECRET": "shh", "API_TOKEN": "tok"},
                )
            }

    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=DummyCfg()),
        patch.object(sys.modules["mcp_scan.MCPScanner"], "check_server", return_value=None),
    ):
        async with MCPScanner(files=["/dummy/path"]) as scanner:
            result = await scanner.scan_path("/dummy/path", inspect_only=True)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, StdioServer)
    # Env values should be redacted; keys preserved
    assert srv.server.env["SECRET"] == "**REDACTED**"
    assert srv.server.env["API_TOKEN"] == "**REDACTED**"


class TestRedactTraceback:
    """Unit tests for redact_traceback function."""

    def test_redact_traceback_none(self):
        """Test that None input returns None."""
        assert redact_traceback(None) is None

    def test_redact_traceback_empty(self):
        """Test that empty string returns empty string."""
        assert redact_traceback("") == ""

    def test_redact_traceback_unix_paths(self):
        """Test that Unix absolute paths are redacted to just filenames."""
        traceback = '''Traceback (most recent call last):
  File "/Users/kudrinsky/Documents/mcp-scan/src/mcp_scan/MCPScanner.py", line 144, in get_servers_from_path
    mcp_config = await scan_mcp_config_file(path)
  File "/Users/kudrinsky/Documents/mcp-scan/src/mcp_scan/mcp_client.py", line 256, in scan_mcp_config_file
    with open(path) as f:
FileNotFoundError: [Errno 2] No such file or directory'''

        result = redact_traceback(traceback)

        assert "/Users/kudrinsky/Documents/mcp-scan/src/mcp_scan/" not in result
        assert "MCPScanner.py" in result
        assert "mcp_client.py" in result
        assert "line 144" in result
        assert "line 256" in result

    def test_redact_traceback_preserves_non_paths(self):
        """Test that non-path content is preserved."""
        traceback = "Error: Something went wrong with value 123"
        assert redact_traceback(traceback) == traceback


class TestRedactArgs:
    """Unit tests for redact_args function."""

    def testredact_args_none(self):
        """Test that None input returns None."""
        assert redact_args(None) is None

    def testredact_args_empty(self):
        """Test that empty list returns empty list."""
        assert redact_args([]) == []

    def testredact_args_positional_only(self):
        """Test that positional arguments are preserved."""
        args = ["script.js", "input.txt", "output.txt"]
        result = redact_args(args)
        assert result == ["script.js", "input.txt", "output.txt"]

    def testredact_args_flag_with_value(self):
        """Test that flag values are redacted."""
        args = ["--api-key", "secret123"]
        result = redact_args(args)
        assert result == ["--api-key", "**REDACTED**"]

    def testredact_args_short_flag_with_value(self):
        """Test that short flag values are redacted."""
        args = ["-k", "secret123"]
        result = redact_args(args)
        assert result == ["-k", "**REDACTED**"]

    def testredact_args_equals_syntax(self):
        """Test that --flag=value syntax is handled."""
        args = ["--api-key=secret123", "--token=xyz"]
        result = redact_args(args)
        assert result == ["--api-key=**REDACTED**", "--token=**REDACTED**"]

    def testredact_args_flag_without_value(self):
        """Test that flags without values are preserved."""
        args = ["--verbose", "--debug"]
        result = redact_args(args)
        assert result == ["--verbose", "--debug"]

    def testredact_args_mixed(self):
        """Test mixed positional, flags, and flag-value pairs."""
        args = ["script.js", "--verbose", "--api-key", "secret", "-o", "output.txt"]
        result = redact_args(args)
        assert result == ["script.js", "--verbose", "--api-key", "**REDACTED**", "-o", "**REDACTED**"]

    def testredact_args_complex_command(self):
        """Test a realistic MCP server command.
        Note: -y is treated as a boolean flag (like in npx -y), so the following arg is not its value.
        """
        args = ["-y", "some-mcp-server", "--token", "abc123", "--port", "3000"]
        result = redact_args(args)
        # -y is a boolean flag, so "some-mcp-server" is preserved as a positional arg
        assert result == ["-y", "some-mcp-server", "--token", "**REDACTED**", "--port", "**REDACTED**"]

    def testredact_args_mixed_equals_and_space(self):
        """Test mix of equals and space-separated values."""
        args = ["--key=value1", "--secret", "value2", "--flag"]
        result = redact_args(args)
        assert result == ["--key=**REDACTED**", "--secret", "**REDACTED**", "--flag"]

    def test_redact_args_unix_paths(self):
        """Test that Unix absolute paths are redacted."""
        args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/code"]
        result = redact_args(args)
        assert result == ["-y", "@modelcontextprotocol/server-filesystem", "**REDACTED**"]

    def test_redact_args_home_paths(self):
        """Test that home directory paths are redacted."""
        args = ["-y", "some-server", "~/Documents/projects"]
        result = redact_args(args)
        assert result == ["-y", "some-server", "**REDACTED**"]

    def test_redact_args_preserves_package_names(self):
        """Test that npm package names are not redacted."""
        args = ["-y", "@modelcontextprotocol/server-github", "--token", "secret"]
        result = redact_args(args)
        assert result == ["-y", "@modelcontextprotocol/server-github", "--token", "**REDACTED**"]


@pytest.mark.asyncio
async def test_scan_path_redacts_stdio_args():
    """
    Ensure StdioServer argument values are redacted via scanner.scan_path.
    Note: -y is treated as a boolean flag (like in npx -y), so the package name is preserved.
    """

    class DummyCfg:
        def get_servers(self):
            return {
                "stdio": StdioServer(
                    command="npx",
                    args=["-y", "some-server", "--api-key", "secret123", "--token=xyz"],
                    env={},
                )
            }

    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=DummyCfg()),
        patch.object(sys.modules["mcp_scan.MCPScanner"], "check_server", return_value=None),
    ):
        async with MCPScanner(files=["/dummy/path"]) as scanner:
            result = await scanner.scan_path("/dummy/path", inspect_only=True)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, StdioServer)
    # Argument values should be redacted, but -y is a boolean flag so "some-server" is preserved
    assert srv.server.args == ["-y", "some-server", "--api-key", "**REDACTED**", "--token=**REDACTED**"]


@pytest.mark.asyncio
async def test_upload_succeeds_on_second_attempt():
    """
    Test that upload succeeds if it fails first but succeeds on retry.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # First attempt fails, second succeeds
        mock_error_context = AsyncMock()
        mock_error_context.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        mock_success_response = AsyncMock(status=200)
        mock_success_response.json.return_value = []
        mock_success_context = AsyncMock()
        mock_success_context.__aenter__.return_value = mock_success_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            # First call fails, second succeeds
            mock_post_method.side_effect = [mock_error_context, mock_success_context]

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted twice (failed once, succeeded on retry)
            assert mock_post_method.call_count == 2

            # Verify that sleep was called once
            assert mock_sleep.call_count == 1
            mock_sleep.assert_called_once_with(1)  # First backoff is 1 second


@pytest.mark.asyncio
async def test_upload_custom_max_retries():
    """
    Test that upload respects custom max_retries parameter.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # Mock to always fail
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload with custom max_retries=5
            await upload([mock_result], "https://control.mcp.scan", "email", False, max_retries=5)

            # Verify that post was attempted 5 times
            assert mock_post_method.call_count == 5

            # Verify that sleep was called 4 times (between 5 attempts)
            assert mock_sleep.call_count == 4


@pytest.mark.asyncio
async def test_upload_exponential_backoff():
    """
    Test that upload uses exponential backoff between retries.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # Mock to always fail
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False, max_retries=3)

            # Verify exponential backoff: 2^0=1, 2^1=2
            assert mock_sleep.call_count == 2
            sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
            assert sleep_calls == [1, 2]  # Exponential: 1s, 2s


@pytest.mark.asyncio
async def test_upload_does_not_retry_on_unexpected_error():
    """
    Test that upload does NOT retry on unexpected (non-network) errors and re-raises them.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
        patch("mcp_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_get_user_info.return_value = ScanUserInfo()
        mock_sleep.return_value = None

        # Mock to raise unexpected error
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = ValueError("Unexpected error")

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload and expect ValueError to be raised
            with pytest.raises(ValueError, match="Unexpected error"):
                await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted only once (no retry on unexpected errors)
            assert mock_post_method.call_count == 1

            # Verify that sleep was NOT called
            mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_get_servers_from_path_sets_unknown_mcp_config_error_and_uploads_payload():
    """
    Patch MCPScanner.get_servers_from_path dependencies so that scan_mcp_config_file returns UnknownMCPConfig
    and ensure the resulting ScanPathResult has a non-failing error and is uploaded with empty servers list.
    """
    with (
        patch.object(sys.modules["mcp_scan.MCPScanner"], "scan_mcp_config_file", return_value=UnknownMCPConfig()),
        patch("mcp_scan.upload.get_user_info") as mock_get_user_info,
    ):
        mock_get_user_info.return_value = ScanUserInfo()

        # Mock successful HTTP response
        mock_http_response = AsyncMock(status=200)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = ""

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("mcp_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            async with MCPScanner(files=["/unknown.cfg"]) as scanner:
                result = await scanner.get_servers_from_path("/unknown.cfg")

            await upload([result], "https://control.mcp.scan", None, False)

            payload = json.loads(mock_post_method.call_args.kwargs["data"])
            sent_result = payload["scan_path_results"][0]
            assert sent_result["servers"] == []
            assert sent_result["path"] == "/unknown.cfg"
            assert sent_result["error"]["message"] == "Unknown MCP config: /unknown.cfg"
            assert sent_result["error"]["is_failure"] is False
