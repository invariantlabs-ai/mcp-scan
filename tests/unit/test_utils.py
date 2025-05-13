from mcp_scan.utils import calculate_distance, rebalance_command_args
import pytest


@pytest.mark.parametrize(
    "input_command, input_args, expected_command, expected_args",
    [
        ("ls -l", ["-a"], "ls", ["-l", "-a"]),
        ("ls -l", [], "ls", ["-l"]),
        ("ls   -l    ", [], "ls", ["-l"]),
        ("ls   -l    .local", [], "ls", ["-l", ".local"]),
        ("ls   -l    example.local", [], "ls", ["-l", "example.local"]),
    ]
)
def test_rebalance_command_args(input_command, input_args, expected_command, expected_args):
    command, args = rebalance_command_args(input_command, input_args)
    assert command == expected_command
    assert args == expected_args


def test_calculate_distance():
    assert calculate_distance(["a", "b", "c"], "b")[0] == ("b", 0)
