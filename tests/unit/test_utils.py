import os

import pytest

from mcp_scan.MCPScanner import MCPScanner
from mcp_scan.models import RemoteServer, ScanError, ScanPathResult, ServerScanResult, StdioServer
from mcp_scan.utils import (
    CommandParsingError,
    calculate_distance,
    get_relative_path,
    rebalance_command_args,
)


class TestGetRelativePath:
    def test_path_in_home_directory(self):
        home = os.path.expanduser("~")
        path = os.path.join(home, ".cursor", "mcp.json")
        result = get_relative_path(path)
        assert result == "~/.cursor/mcp.json"

    def test_path_with_tilde(self):
        result = get_relative_path("~/.cursor/mcp.json")
        assert result == "~/.cursor/mcp.json"

    def test_path_outside_home(self):
        result = get_relative_path("/etc/config.json")
        assert result == "/etc/config.json"

    def test_empty_path(self):
        result = get_relative_path("")
        assert result == ""


class TestPopulateScanMetadata:
    """Tests for MCPScanner._populate_scan_metadata method."""

    def _create_scanner_and_populate(self, scan_results):
        """Helper to create a scanner and call _populate_scan_metadata."""
        scanner = MCPScanner(files=[], control_servers=[{"url": "http://test"}])
        scanner._populate_scan_metadata(scan_results)
        return scanner.scan_context

    def test_empty_results(self):
        metadata = self._create_scanner_and_populate([])
        assert metadata["scanned_files"] == []
        assert metadata["failed_to_parse_files"] == []
        assert metadata["not_found_files"] == []
        assert metadata["failed_servers"] == []

    def test_successful_scan(self):
        server = StdioServer(command="npx", args=["-y", "test-server"])
        server_result = ServerScanResult(name="test-server", server=server)
        path_result = ScanPathResult(path="~/.cursor/mcp.json", client="cursor", servers=[server_result])

        metadata = self._create_scanner_and_populate([path_result])

        assert len(metadata["scanned_files"]) == 1
        assert metadata["scanned_files"][0]["path"] == "~/.cursor/mcp.json"
        assert metadata["scanned_files"][0]["client"] == "cursor"
        assert metadata["scanned_files"][0]["server_count"] == 1
        assert metadata["scanned_files"][0]["successful_server_count"] == 1

    def test_file_not_found(self):
        path_result = ScanPathResult(
            path="~/.cursor/mcp.json",
            client="cursor",
            servers=None,
            error=ScanError(message="file ~/.cursor/mcp.json does not exist", is_failure=False),
        )

        metadata = self._create_scanner_and_populate([path_result])

        assert len(metadata["not_found_files"]) == 1
        assert metadata["not_found_files"][0]["path"] == "~/.cursor/mcp.json"
        assert len(metadata["scanned_files"]) == 0

    def test_file_parse_error(self):
        path_result = ScanPathResult(
            path="~/.cursor/mcp.json",
            client="cursor",
            servers=None,
            error=ScanError(message="could not parse file ~/.cursor/mcp.json", is_failure=True),
        )

        metadata = self._create_scanner_and_populate([path_result])

        assert len(metadata["failed_to_parse_files"]) == 1
        assert metadata["failed_to_parse_files"][0]["path"] == "~/.cursor/mcp.json"
        assert "could not parse" in metadata["failed_to_parse_files"][0]["error_message"]

    def test_server_start_failure(self):
        server = StdioServer(command="npx", args=["-y", "broken-server"])
        server_result = ServerScanResult(
            name="broken-server",
            server=server,
            error=ScanError(message="could not start server", is_failure=True),
        )
        path_result = ScanPathResult(path="~/.cursor/mcp.json", client="cursor", servers=[server_result])

        metadata = self._create_scanner_and_populate([path_result])

        assert len(metadata["failed_servers"]) == 1
        failed_server = metadata["failed_servers"][0]
        assert failed_server["entry_name"] == "broken-server"
        assert failed_server["command"] == "npx"
        assert failed_server["args"] == ["-y", "broken-server"]
        assert failed_server["file_path"] == "~/.cursor/mcp.json"
        assert failed_server["client"] == "cursor"
        assert "could not start server" in failed_server["error_message"]

    def test_remote_server_failure_no_command_args(self):
        """Remote servers don't have command/args, so those fields should be absent."""
        server = RemoteServer(url="https://example.com/mcp", type="http")
        server_result = ServerScanResult(
            name="remote-server",
            server=server,
            error=ScanError(message="could not connect to server", is_failure=True),
        )
        path_result = ScanPathResult(path="~/.cursor/mcp.json", client="cursor", servers=[server_result])

        metadata = self._create_scanner_and_populate([path_result])

        assert len(metadata["failed_servers"]) == 1
        failed_server = metadata["failed_servers"][0]
        assert failed_server["entry_name"] == "remote-server"
        assert "command" not in failed_server
        assert "args" not in failed_server

    def test_mixed_results(self):
        """Test a mix of successful, failed files, and failed servers."""
        # Successful server
        successful_server = ServerScanResult(
            name="good-server", server=StdioServer(command="npx", args=["-y", "good-server"])
        )
        # Failed server
        failed_server = ServerScanResult(
            name="bad-server",
            server=StdioServer(command="npx", args=["-y", "bad-server"]),
            error=ScanError(message="could not start server", is_failure=True),
        )
        # Successful file with mixed servers
        path_result1 = ScanPathResult(
            path="~/.cursor/mcp.json", client="cursor", servers=[successful_server, failed_server]
        )
        # Not found file
        path_result2 = ScanPathResult(
            path="~/.claude/config.json",
            client="claude",
            servers=None,
            error=ScanError(message="file does not exist", is_failure=False),
        )
        # Parse error file
        path_result3 = ScanPathResult(
            path="~/.vscode/mcp.json",
            client="vscode",
            servers=None,
            error=ScanError(message="could not parse file", is_failure=True),
        )

        metadata = self._create_scanner_and_populate([path_result1, path_result2, path_result3])

        assert len(metadata["scanned_files"]) == 1
        assert metadata["scanned_files"][0]["server_count"] == 2
        assert metadata["scanned_files"][0]["successful_server_count"] == 1
        assert len(metadata["not_found_files"]) == 1
        assert len(metadata["failed_to_parse_files"]) == 1
        assert len(metadata["failed_servers"]) == 1


@pytest.mark.parametrize(
    "input_command, input_args, expected_command, expected_args, raises_error",
    [
        ("ls -l", ["-a"], "ls", ["-l", "-a"], False),
        ("ls -l", [], "ls", ["-l"], False),
        ("ls -lt", ["-r", "-a"], "ls", ["-lt", "-r", "-a"], False),
        ("ls   -l    ", [], "ls", ["-l"], False),
        ("ls   -l    .local", [], "ls", ["-l", ".local"], False),
        ("ls   -l    example.local", [], "ls", ["-l", "example.local"], False),
        ('ls "hello"', [], "ls", ['"hello"'], False),
        ("ls -l \"my file.txt\" 'data.csv'", [], "ls", ["-l", '"my file.txt"', "'data.csv'"], False),
        ('ls "unterminated', [], "", [], True),
    ],
)
def test_rebalance_command_args(
    input_command: str, input_args: list[str], expected_command: str, expected_args: list[str], raises_error: bool
):
    try:
        command, args = rebalance_command_args(input_command, input_args)
        assert command == expected_command
        assert args == expected_args
        assert not raises_error
    except CommandParsingError:
        assert raises_error


def test_calculate_distance():
    assert calculate_distance(["a", "b", "c"], "b")[0] == ("b", 0)
