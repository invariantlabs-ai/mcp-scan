"""End-to-end tests for complete MCP scanning workflow."""

import asyncio
import subprocess
import time

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

            return {
                "result": result,
                "tools": tools.tools,
            }
    return result


async def ensure_config_file_contains_gateway(config_file, timeout=3):
    s = time.time()
    content = ""

    while True:
        with open(config_file) as f:
            content = f.read()
            if "invariant-gateway" in content:
                return True
        await asyncio.sleep(0.1)
        if time.time() - s > timeout:
            return False


class TestFullProxyFlow:
    """Test cases for end-to-end scanning workflows."""

    PORT = 9123

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pretty", ["oneline", "full", "compact"])
    async def test_basic(self, toy_server_add_config_file, pretty):
        # if available, check for 'lsof' and make sure the port is not in use
        try:
            subprocess.check_output(["lsof", "-i", f":{self.PORT}"])
            print(f"Port {self.PORT} is in use")
            return
        except subprocess.CalledProcessError:
            pass
        except FileNotFoundError:
            print("lsof not found, skipping port check")

        args = dotenv.dotenv_values(".env")
        gateway_dir = args.get("INVARIANT_GATEWAY_DIR", None)
        command = [
            "uv",
            "run",
            "-m",
            "src.mcp_scan.run",
            "proxy",
            "--mcp-scan-server-port",
            str(self.PORT),
            "--port",
            str(self.PORT),
            "--pretty",
            pretty,
        ]
        if gateway_dir is not None:
            command.extend(["--gateway-dir", gateway_dir])
        command.append(toy_server_add_config_file)

        # start process in background
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # wait for gateway to be installed
        if not (await ensure_config_file_contains_gateway(toy_server_add_config_file)):
            # print out toy_server_add_config_file
            with open(toy_server_add_config_file) as f:
                # assert that 'invariant-gateway' is in the file
                content = f.read()

                if "invariant-gateway" not in content:
                    # terminate the process and get output
                    process.terminate()
                    process.wait()

                    # get output
                    stdout, stderr = process.communicate()
                    print(stdout.decode())
                    print(stderr.decode())

                    assert "invariant-gateway" in content, (
                        "invariant-gateway wrapper was not found in the config file: "
                        + content
                        + "\nProcess output: "
                        + stdout.decode()
                        + "\nError output: "
                        + stderr.decode()
                    )

        with open(toy_server_add_config_file) as f:
            # assert that 'invariant-gateway' is in the file
            content = f.read()
            print(content)

        # start client
        config = await scan_mcp_config_file(toy_server_add_config_file)
        servers = list(config.mcpServers.values())
        assert len(servers) == 1
        server = servers[0]
        client_program = run_toy_server_client(server)

        # wait for client to finish
        client_output = await client_program
        assert int(client_output["result"]) == 3

        # shut down server
        process.terminate()
        process.wait()

        # collect proxy server output
        stdout, stderr = process.communicate()

        # basic checks for the log
        assert "used Toy to tools/list" in stdout.decode(), "basic activity log statement not found"
        assert "call_1" in stdout.decode(), "call_1 not found in log"

        assert "call_2" in stdout.decode(), "call_2 not found in log"
        assert "to add" in stdout.decode(), "call to 'add' not found in log"

        # assert there is no 'address is already in use' error
        assert "address already in use" not in stderr.decode(), (
            "mcp-scan proxy failed to start because the testing port "
            + str(self.PORT)
            + " is already in use. Please make sure to stop any other mcp-scan proxy server running on this port."
        )
