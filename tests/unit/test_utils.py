from mcp_scan.utils import calculate_distance, rebalance_command_args


def test_rebalance_command_args():
    command, args = rebalance_command_args("ls -l", ["-a"])
    assert command == "ls"
    assert args == ["-l", "-a"]

    command, args = rebalance_command_args("ls -l", [])
    assert command == "ls"
    assert args == ["-l"]

    command, args = rebalance_command_args("ls   -l    ", [])
    assert command == "ls"
    assert args == ["-l"]


def test_calculate_distance():
    assert calculate_distance(["a", "b", "c"], "b")[0] == ("b", 0)
