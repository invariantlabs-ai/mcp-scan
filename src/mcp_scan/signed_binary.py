import logging
import re
import subprocess

from mcp_scan.models import ScanPathResult, StdioServer

logger = logging.getLogger(__name__)


def check_server_signature(server: StdioServer) -> StdioServer:
    """Get detailed code signing information."""
    try:
        result = subprocess.run(["codesign", "-dvvv", server.command], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return server

        output = result.stderr

        if match := re.search(r"Identifier=(.+)", output):
            binary_identifier = match.group(1)
            logger.info(f"Server {server.command} is signed by {binary_identifier}")
            server.signed_by = binary_identifier
        else:
            logger.info(f"Server {server.command} is signed but could not get identifier. Output: {output}")
        return server

    except Exception as e:
        logger.error(f"Error checking signature of server {server.command}: {e}")
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
