"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess

import pytest

from mcp_scan.utils import TempFile

class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    def test_basic(self, sample_configs):
        """Test a basic complete scan workflow from CLI to results."""
        # Run mcp-scan with JSON output mode
        with TempFile(mode="w") as temp_file:
            fn = temp_file.name
            temp_file.write(sample_configs[0])  # Use the first config from the fixture
            temp_file.flush()
            result = subprocess.run(
                ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", fn],
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
            assert fn in output
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON output")

    def test_scan(self):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        results: dict[str, dict] = {}
        for server in output[path]["servers"]:
            results[server["name"]] = server["result"]
            server["signature"]["metadata"]["serverInfo"]["version"] = "mcp_version" # swap actual version with placeholder

            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"
        
        assert results["Weather"] == [{
            'changed': None,
            'messages': [],
            'status': None,
            'verified': True,
            'whitelisted': None,
        }]
        assert results["Math"] == [{
            'changed': None,
            'messages': [],
            'status': None,
            'verified': True,
            'whitelisted': None,
        }] * 4

    def test_inspect(self):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            ["uv", "run", "-m", "src.mcp_scan.run", "inspect", "--json", path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        print(output)
        assert path in output
        for server in output[path]["servers"]:
            server["signature"]["metadata"]["serverInfo"]["version"] = "mcp_version" # swap actual version with placeholder

            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"

    def vscode_settings_no_mcp(self):
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
            result = subprocess.run(
                ["uv", "run", "-m", "src.mcp_scan.run", "scan", "--json", temp_file.name],
                capture_output=True,
                text=True,
            )
            fn = temp_file.name

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert fn in output
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON output")
