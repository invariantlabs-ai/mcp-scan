"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess

import pytest

from mcp_scan.utils import TempFile
{'tests/mcp_servers/configs_files/all_config.json': {'path': 'tests/mcp_servers/configs_files/all_config.json', 'servers': [{'name': 'Weather', 'server': {'command': 'uv run python', 'args': ['tests/mcp_servers/weather_server.py'], 'type': 'stdio', 'env': {}}, 'signature': {'metadata': {'meta': None, 'protocolVersion': '2024-11-05', 'capabilities': {'experimental': {}, 'logging': None, 'prompts': {'listChanged': False}, 'resources': {'subscribe': False, 'listChanged': False}, 'tools': {'listChanged': False}}, 'serverInfo': {'name': 'Single Tool Server', 'version': '1.7.1'}, 'instructions': None}, 'prompts': [], 'resources': [], 'tools': [{'name': 'weather', 'description': 'Get current weather for a location.', 'inputSchema': {'properties': {'location': {'title': 'Location', 'type': 'string'}}, 'required': ['location'], 'title': 'weatherArguments', 'type': 'object'}, 'annotations': None}]}, 'result': [{'verified': True, 'changed': None, 'whitelisted': None, 'status': None, 'messages': []}], 'error': None}, {'name': 'Math', 'server': {'command': 'uv run python', 'args': ['tests/mcp_servers/math_server.py'], 'type': 'stdio', 'env': {}}, 'signature': {'metadata': {'meta': None, 'protocolVersion': '2024-11-05', 'capabilities': {'experimental': {}, 'logging': None, 'prompts': {'listChanged': False}, 'resources': {'subscribe': False, 'listChanged': False}, 'tools': {'listChanged': False}}, 'serverInfo': {'name': 'Math', 'version': '1.7.1'}, 'instructions': None}, 'prompts': [], 'resources': [], 'tools': [{'name': 'add', 'description': 'Add two numbers.', 'inputSchema': {'properties': {'a': {'title': 'A', 'type': 'integer'}, 'b': {'title': 'B', 'type': 'integer'}}, 'required': ['a', 'b'], 'title': 'addArguments', 'type': 'object'}, 'annotations': None}, {'name': 'subtract', 'description': 'Subtract two numbers.', 'inputSchema': {'properties': {'a': {'title': 'A', 'type': 'integer'}, 'b': {'title': 'B', 'type': 'integer'}}, 'required': ['a', 'b'], 'title': 'subtractArguments', 'type': 'object'}, 'annotations': None}, {'name': 'multiply', 'description': 'Multiply two numbers.', 'inputSchema': {'properties': {'a': {'title': 'A', 'type': 'integer'}, 'b': {'title': 'B', 'type': 'integer'}}, 'required': ['a', 'b'], 'title': 'multiplyArguments', 'type': 'object'}, 'annotations': None}, {'name': 'divide', 'description': 'Divide two numbers.', 'inputSchema': {'properties': {'a': {'title': 'A', 'type': 'integer'}, 'b': {'title': 'B', 'type': 'integer'}}, 'required': ['a', 'b'], 'title': 'divideArguments', 'type': 'object'}, 'annotations': None}]}, 'result': [{'verified': True, 'changed': None, 'whitelisted': None, 'status': None, 'messages': []}, {'verified': True, 'changed': None, 'whitelisted': None, 'status': None, 'messages': []}, {'verified': True, 'changed': None, 'whitelisted': None, 'status': None, 'messages': []}, {'verified': True, 'changed': None, 'whitelisted': None, 'status': None, 'messages': []}], 'error': None}], 'error': None, 'cross_ref_result': {'found': False, 'sources': []}}}

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
        signatures: dict[str, dict] = {}
        results: dict[str, dict] = {}
        for server in output[path]["servers"]:
            signatures[server["name"]] = server["signature"]
            results[server["name"]] = server["result"]
        for name in signatures:
            assert signatures[name] == json.load(open(f"tests/mcp_servers/signatures/{name.lower()}_server_signature.json")), f"Signature mismatch for {name} server"
        
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
        }, {
            'changed': None,
            'messages': [],
            'status': None,
            'verified': True,
            'whitelisted': None,
        }, {
            'changed': None,
            'messages': [],
            'status': None,
            'verified': True,
            'whitelisted': None,
        }, {
            'changed': None,
            'messages': [],
            'status': None,
            'verified': True,
            'whitelisted': None,
        }]

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
            if server["name"] == "Weather":
                assert server["signature"] == json.load(open("tests/mcp_servers/signatures/weather_server_signature.json")), "Signature mismatch for Weather server"
            if server["name"] == "Math":
                assert server["signature"] == json.load(open("tests/mcp_servers/signatures/math_server_signature.json")), "Signature mismatch for Math server"


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
