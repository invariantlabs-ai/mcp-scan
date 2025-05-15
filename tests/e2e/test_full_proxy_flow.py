"""End-to-end tests for complete MCP scanning workflow."""

import asyncio
import subprocess

import dotenv
import pytest
from mcp import ClientSession

from mcp_scan.mcp_client import get_client, scan_mcp_config_file


async def run_toy_server_client(config):
    await asyncio.sleep(1)
    async with get_client(config) as (read, write):
        async with ClientSession(read, write) as session:
            print("[Client] Initializing connection")
            await session.initialize()
            print("[Client] Listing tools")
            tools = await session.list_tools()
            print("[Client] Tools: ", tools.tools)

            print("[Client] Calling tool add")
            result = await session.call_tool("add", arguments={"a": 1, "b": 2})
            result = result.content[0].text
            print("[Client] Result: ", result)
            await asyncio.sleep(0.2)
    return result


class TestFullProxyFlow:
    """Test cases for end-to-end scanning workflows."""

    PORT = 91234

    @pytest.mark.asyncio
    async def test_basic(self, toy_server_add_config_file):
        args = dotenv.dotenv_values(".env")
        gateway_dir = args.get("INVARIANT_GATEWAY_DIR", None)
        command = ["uv", "run", "-m", "src.mcp_scan.run", "proxy", "--mcp-scan-server-port", str(self.PORT)]
        if gateway_dir is not None:
            command.extend(["--gateway-dir", gateway_dir])
        command.append(toy_server_add_config_file)

        # start process in background
        process = subprocess.Popen(command)

        # start client
        config = await scan_mcp_config_file(toy_server_add_config_file)
        servers = list(config.mcpServers.values())
        assert len(servers) == 1
        server = servers[0]
        client_program = run_toy_server_client(server)

        # wait for client to finish
        result = await asyncio.wait_for(client_program, timeout=5)
        assert int(result) == 3

        # shut down server
        process.terminate()
        process.wait()
