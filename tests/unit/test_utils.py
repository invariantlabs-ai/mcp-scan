import io
import os
import sys

import pytest

from mcp_scan.models import CommandParsingError, rebalance_command_args
from mcp_scan.utils import (
    calculate_distance,
    get_relative_path,
    suppress_stdout,
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


class TestSuppressStdout:
    """Test suite for suppress_stdout context manager."""

    def test_suppress_stdout_suppresses_print(self):
        """Test that suppress_stdout suppresses print statements."""
        # Capture what would be printed to stdout
        captured_output = io.StringIO()
        original_stdout = sys.stdout

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                print("This should be suppressed")
                print("This too")
            # After context, stdout should be restored
            print("This should appear")
        finally:
            sys.stdout = original_stdout

        # Only the print after the context should appear
        assert captured_output.getvalue() == "This should appear\n"

    def test_suppress_stdout_restores_stdout_after_context(self):
        """Test that stdout is properly restored after suppress_stdout context."""
        original_stdout = sys.stdout
        captured_output = io.StringIO()

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                pass
            # After context, stdout should be the same as before
            assert sys.stdout is captured_output
            print("Restored stdout works")
        finally:
            sys.stdout = original_stdout

        assert captured_output.getvalue() == "Restored stdout works\n"

    def test_suppress_stdout_works_with_multiple_prints(self):
        """Test that suppress_stdout works with multiple print statements."""
        captured_output = io.StringIO()
        original_stdout = sys.stdout

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                for i in range(10):
                    print(f"Line {i}")
            print("Final line")
        finally:
            sys.stdout = original_stdout

        # Only the final print should appear
        assert captured_output.getvalue() == "Final line\n"
