"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess

import pytest
from pytest_lazy_fixtures import lf

from mcp_scan.utils import TempFile


class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("claudestyle_config_file"),
            lf("vscode_mcp_config_file"),
            lf("vscode_config_file"),
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_basic(self, sample_config_file):
        """Test a basic complete scan workflow from CLI to results. This does not mean that the results are correct or the servers can be run."""
        # Run mcp-scan with JSON output mode
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", sample_config_file],
            capture_output=True,
            text=True,
        )

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        print(result.stdout)
        print(result.stderr)

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert sample_config_file in output
        except json.JSONDecodeError:
            print(result.stdout)
            pytest.fail("Failed to parse JSON output")

    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_scan_sse_http(self, sample_config_file):
        """Test scanning with SSE and HTTP transport configurations."""
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", sample_config_file],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert {tool["name"] for tool in output[sample_config_file]["servers"][0]["signature"]["tools"]} == {
            "is_prime",
            "gcd",
            "lcm",
        }, "Tools in signature do not match expected values"
        print(output)

    @pytest.mark.parametrize(
        "path, server_names",
        [
            ("tests/mcp_servers/configs_files/weather_config.json", ["Weather"]),
            ("tests/mcp_servers/configs_files/math_config.json", ["Math"]),
            ("tests/mcp_servers/configs_files/all_config.json", ["Weather", "Math"]),
        ],
    )
    def test_scan(self, path, server_names):
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)

        for server in output[path]["servers"]:
            server["signature"]["metadata"]["serverInfo"]["version"] = (
                "mcp_version"  # swap actual version with placeholder
            )

            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"

        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        path = next(iter(output.keys()))
        issues = output[path]["issues"]
        if "Math" not in server_names:
            assert len(issues) == 0, "There should be no issues for the Weather server"
        else:
            assert len(issues) in [1, 2], "There should be 2 or 1 issues for the Math server"
            assert {issue["code"] for issue in issues}.issubset({"W001", "TF002"}), "Issues codes do not match expected values"

    def test_inspect(self):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "inspect", "--json", path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)

        assert path in output
        for server in output[path]["servers"]:
            server["signature"]["metadata"]["serverInfo"]["version"] = (
                "mcp_version"  # swap actual version with placeholder
            )

            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"

    @pytest.fixture
    def vscode_settings_no_mcp_file(self):
        settings = {
            "[javascript]": {},
            "github.copilot.advanced": {},
            "github.copilot.chat.agent.thinkingTool": {},
            "github.copilot.chat.codesearch.enabled": {},
            "github.copilot.chat.languageContext.typescript.enabled": {},
            "github.copilot.chat.welcomeMessage": {},
            "github.copilot.enable": {},
            "github.copilot.preferredAccount": {},
            "settingsSync.ignoredExtensions": {},
            "tabnine.experimentalAutoImports": {},
            "workbench.colorTheme": {},
            "workbench.startupEditor": {},
        }
        with TempFile(mode="w") as temp_file:
            json.dump(settings, temp_file)
            temp_file.flush()
            yield temp_file.name

    def test_vscode_settings_no_mcp(self, vscode_settings_no_mcp_file):
        """Test scanning VSCode settings with no MCP configurations."""
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", vscode_settings_no_mcp_file],
            capture_output=True,
            text=True,
        )

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert vscode_settings_no_mcp_file in output
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON output")
