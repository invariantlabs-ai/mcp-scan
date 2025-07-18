"""End-to-end tests for complete MCP scanning workflow."""

import asyncio
import os
import subprocess
import time

import dotenv
import pytest
from mcp import ClientSession

from mcp_scan.mcp_client import get_client, scan_mcp_config_file


# Helper function to safely decode subprocess output
def safe_decode(bytes_output, encoding="utf-8", errors="replace"):
    """Safely decode subprocess output, handling potential Unicode errors"""
    if bytes_output is None:
        return ""
    try:
        return bytes_output.decode(encoding)
    except UnicodeDecodeError:
        # Fall back to a more lenient error handler
        return bytes_output.decode(encoding, errors=errors)


async def run_toy_server_client(config):
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

    PORT = 9129

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pretty", ["oneline", "full", "compact"])
    # skip on windows
    @pytest.mark.skipif(
        os.name == "nt",
        reason="Skipping test on Windows due to subprocess handling issues",
    )
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
            # ensure we are using the right ports
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
        env = {**os.environ, "COLUMNS": "256"}
        # Ensure proper handling of Unicode on Windows
        if os.name == "nt":  # Windows
            # Explicitly set encoding for console on Windows
            env["PYTHONIOENCODING"] = "utf-8"

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            universal_newlines=False,  # Binary mode for better Unicode handling
        )

        # wait for gateway to be installed
        if not (await ensure_config_file_contains_gateway(toy_server_add_config_file)):
            # if process is not running, raise an error
            if process.poll() is not None:
                # process has terminated
                stdout, stderr = process.communicate()
                print(safe_decode(stdout))
                print(safe_decode(stderr))
                raise AssertionError("process terminated before gateway was installed")

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
                    print(safe_decode(stdout))
                    print(safe_decode(stderr))

                    assert "invariant-gateway" in content, (
                        "invariant-gateway wrapper was not found in the config file: "
                        + content
                        + "\nProcess output: "
                        + safe_decode(stdout)
                        + "\nError output: "
                        + safe_decode(stderr)
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
        try:
            client_output = await asyncio.wait_for(client_program, timeout=20)
        except asyncio.TimeoutError as e:
            print("Client timed out")
            process.terminate()
            process.wait()
            stdout, stderr = process.communicate()
            print(safe_decode(stdout))
            print(safe_decode(stderr))
            raise AssertionError("timed out waiting for MCP server to respond") from e

        assert int(client_output["result"]) == 3

        # shut down server and collect output
        process.terminate()
        stdout, stderr = process.communicate()
        process.wait()

        # print full outputs
        stdout_text = safe_decode(stdout)
        stderr_text = safe_decode(stderr)
        print("stdout: ", stdout_text)
        print("stderr: ", stderr_text)

        # basic checks for the log
        assert "used toy to tools/list" in stdout_text, "basic activity log statement not found"
        assert "call_1" in stdout_text, "call_1 not found in log"

        assert "call_2" in stdout_text, "call_2 not found in log"
        assert "to add" in stdout_text, "call to 'add' not found in log"

        # assert there is no 'address is already in use' error
        assert "address already in use" not in stderr_text, (
            "mcp-scan proxy failed to start because the testing port "
            + str(self.PORT)
            + " is already in use. Please make sure to stop any other mcp-scan proxy server running on this port."
        )
