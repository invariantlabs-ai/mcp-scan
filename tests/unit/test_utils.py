import pytest

from mcp_scan.utils import CommandParsingError, calculate_distance, rebalance_command_args


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
