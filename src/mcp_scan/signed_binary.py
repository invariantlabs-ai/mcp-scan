import logging
import re
import subprocess
import sys

from mcp_scan.models import ScanPathResult, StdioServer
from mcp_scan.utils import check_executable_exists, rebalance_command_args

logger = logging.getLogger(__name__)


def check_server_signature(server: StdioServer) -> StdioServer:
    """Get detailed code signing information."""
    if sys.platform != "darwin":
        logger.info(f"Binary signature check not supported on {sys.platform}. Only supported on macOS.")
        return server
    try:
        # check that the binary exists
        if not check_executable_exists(server.command):
            logger.info(f"Binary {server.command} does not exist. Rebalancing command and args.")

            command, _ = rebalance_command_args(server.command, server.args)
            if not check_executable_exists(command):
                logger.info(f"Binary {command} does not exist. Cannot check signature for aliases.")
                return server
        else:
            command = server.command

        result = subprocess.run(["codesign", "-dvvv", command], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return server

        output = result.stderr

        if match := re.search(r"Identifier=(.+)", output):
            binary_identifier = match.group(1)
            logger.info(f"Binary {server.command} is signed as {binary_identifier}")
            assert isinstance(binary_identifier, str), f"Binary identifier is not a string: {binary_identifier}"
            server.binary_identifier = binary_identifier
        else:
            logger.info(f"Binary {server.command} is signed but could not get identifier. Output: {output}")
        return server

    except Exception as e:
        logger.info(f"Error checking binary signature of server {server.command}: {e}")
        return server


async def check_signed_binary(result_verified: list[ScanPathResult]) -> list[ScanPathResult]:
    """
    Check if the binary is signed by a trusted authority.
    """

    for path_result in result_verified:
        for server in path_result.servers or []:
            if server.server.type == "stdio":
                # inplace modification of the server
                server.server = check_server_signature(server.server)

    return result_verified
