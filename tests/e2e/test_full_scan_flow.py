"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess
import tempfile

import pytest
from pytest_lazy_fixtures import lf


class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    @pytest.mark.parametrize("sample_config", [lf("claudestyle_config"), lf("vscode_mcp_config"), lf("vscode_config")])
    def test_basic(self, sample_config):
        """Test a basic complete scan workflow from CLI to results."""
        # Run mcp-scan with JSON output mode
        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            temp_file.write(sample_config)
            temp_file.flush()
            result = subprocess.run(
                ["uv", "run", "-m", "src.mcp_scan.cli", "scan", "--json", temp_file.name],
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
            print(result.stdout)
            pytest.fail("Failed to parse JSON output")

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
        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            json.dump(settings, temp_file)
            temp_file.flush()
            result = subprocess.run(
                ["uv", "run", "-m", "src.mcp_scan.cli", "scan", "--json", temp_file.name],
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
