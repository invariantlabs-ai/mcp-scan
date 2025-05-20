"""End-to-end tests for complete MCP scanning workflow."""

import asyncio
import os
import random
import socket
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


def find_free_port():
    """Find a free port to use for testing to avoid port conflicts."""
    # Try to find a port in a higher range to avoid conflicts
    base_port = random.randint(30000, 60000)

    # Try up to 10 ports starting from the base port
    for port_offset in range(10):
        port = base_port + port_offset
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Set SO_REUSEADDR to avoid 'address already in use' errors
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Try to bind to the port
                s.bind(("127.0.0.1", port))

                # If we reach here, the port is available
                return port
        except OSError:
            continue

    # If we reach here, we couldn't find a free port
    # Use a default, but with a warning
    print(f"Warning: Couldn't find a free port, using default port {base_port}")
    return base_port


def windows_check_ports():
    """Windows-specific function to check for ports in use."""
    if os.name != "nt":  # Only run on Windows
        return "Not running on Windows"

    try:
        # Use netstat to check active connections - Windows specific
        netstat_output = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
        return netstat_output
    except Exception as e:
        return f"Error running netstat: {e}"


def windows_kill_process_by_port(port):
    """Windows-specific function to kill process using a specific port."""
    if os.name != "nt":  # Only run on Windows
        return "Not running on Windows"

    try:
        # Find the process ID (PID) using the port
        find_pid = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True, universal_newlines=True)

        # Extract the PID from the output (last column)
        if find_pid:
            lines = find_pid.strip().split("\n")
            if lines:
                pid = lines[0].strip().split()[-1]
                # Kill the process
                subprocess.check_output(f"taskkill /F /PID {pid}", shell=True)
                return f"Killed process {pid} using port {port}"

        return f"No process found using port {port}"
    except Exception as e:
        return f"Error killing process on port {port}: {e}"


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

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pretty", ["oneline", "full", "compact"])
    async def test_basic(self, toy_server_add_config_file, pretty):
        # Find a free port dynamically to avoid conflicts, especially on Windows CI
        PORT = find_free_port()
        print(f"Using dynamic port {PORT} for test")

        # Additional Windows-specific socket cleanup
        if os.name == "nt":  # Windows
            try:
                # First, check if any process is using our port and kill it
                print(windows_kill_process_by_port(PORT))

                # Then, try to ensure the socket is properly released
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        s.bind(("0.0.0.0", PORT))
                    except OSError as e:
                        if "10048" in str(e):  # Address already in use
                            print(f"Port {PORT} is already in use on Windows, trying another port")
                            # Extra diagnostic info
                            print(windows_check_ports())
                            # Try a new port
                            PORT = find_free_port()
                            print(f"New port: {PORT}")
            except Exception as e:
                print(f"Socket test error: {e}")

        # Unix (Linux/Mac) port check
        if os.name != "nt":  # Not Windows
            try:
                subprocess.check_output(["lsof", "-i", f":{PORT}"])
                print(f"Port {PORT} is in use")
                PORT = find_free_port()
                print(f"New port: {PORT}")
            except subprocess.CalledProcessError:
                # This is good - port is not in use
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
            # Use the dynamically allocated port
            "--mcp-scan-server-port",
            str(PORT),
            "--port",
            str(PORT),
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
        except asyncio.TimeoutError as timeout_err:
            print("Client timed out")
            process.terminate()
            process.wait()
            stdout, stderr = process.communicate()
            print(safe_decode(stdout))
            print(safe_decode(stderr))
            raise AssertionError("timed out waiting for MCP server to respond") from timeout_err

        assert int(client_output["result"]) == 3

        # shut down server - ensure proper cleanup, especially on Windows
        try:
            # First try graceful termination
            process.terminate()
            # Wait up to 3 seconds for process to terminate
            for _ in range(30):
                if process.poll() is not None:  # Process has terminated
                    break
                time.sleep(0.1)
            else:
                # If process hasn't terminated after timeout, force kill it
                if os.name == "nt":  # Windows
                    process.kill()  # More aggressive than terminate()
                else:
                    import signal

                    os.kill(process.pid, signal.SIGKILL)
        except Exception as e:
            print(f"Error shutting down process: {e}")
        finally:
            # Ensure we wait for the process to fully terminate
            process.wait(timeout=2)

        # collect proxy server output
        stdout, stderr = process.communicate(timeout=1)

        # print full outputs
        stdout_text = safe_decode(stdout)
        stderr_text = safe_decode(stderr)

        # Add extra diagnostic info for Windows
        if os.name == "nt":
            print(f"Windows environment port diagnostics for port {PORT}:")
            print(windows_check_ports())

        print("stdout: ", stdout_text)
        print("stderr: ", stderr_text)

        # basic checks for the log
        missing_logs = []

        # Check for required log messages
        if "used Toy to tools/list" not in stdout_text:
            missing_logs.append("basic activity log statement")
        if "call_1" not in stdout_text:
            missing_logs.append("call_1")
        if "call_2" not in stdout_text:
            missing_logs.append("call_2")
        if "to add" not in stdout_text:
            missing_logs.append("call to 'add'")

        # Raise assertion error if any logs are missing
        assert not missing_logs, f"Missing expected log entries: {', '.join(missing_logs)}"

        # assert there is no 'address is already in use' error
        assert "address already in use" not in stderr_text, (
            "mcp-scan proxy failed to start because the testing port "
            + str(PORT)
            + " is already in use. Please make sure to stop any other mcp-scan proxy server running on this port."
        )
