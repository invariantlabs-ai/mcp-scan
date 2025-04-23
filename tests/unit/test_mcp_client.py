"""Unit tests for the mcp_client module."""

import pytest
from unittest.mock import patch, Mock, AsyncMock
from mcp_scan.mcp_client import check_server_with_timeout, scan_mcp_config_file
import tempfile
import json
from mcp_scan.models import ClaudeConfigFile, VSCodeMCPConfig, VSCodeConfigFile

claudestyle_config = """
{
    "mcpServers": {
        "claude": {
            "command": "mcp",
            "args": ["--server", "http://localhost:8000"],
        }
    }
}
"""

vscode_mcp_config = """
{
  // 💡 Inputs are prompted on first server start, then stored securely by VS Code.
  "inputs": [
    {
      "type": "promptString",
      "id": "perplexity-key",
      "description": "Perplexity API Key",
      "password": true
    }
  ],
  "servers": {
    // https://github.com/ppl-ai/modelcontextprotocol/
    "Perplexity": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-perplexity-ask"],
      "env": {
        "PERPLEXITY_API_KEY": "ASDF"
      }
    }
  }
}

"""

vscode_config = """
// settings.json
{
  "mcp": {
    "servers": {
      "my-mcp-server": {
        "type": "stdio",
        "command": "my-command",
        "args": []
      }
    }
  }
}
"""


def test_scan_mcp_config_file():
    for config in [claudestyle_config, vscode_mcp_config, vscode_config]:
        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            temp_file.write(config)
            temp_file.flush()
            servers = scan_mcp_config_file(temp_file.name)
            print(servers)
