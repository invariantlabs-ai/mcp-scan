from mcp_scan.utils import rebalance_command_args


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
