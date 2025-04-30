"""Global pytest fixtures for mcp-scan tests."""

import pytest


@pytest.fixture
def claudestyle_config():
    """Sample Claude-style MCP config."""
    return """{
    "mcpServers": {
        "claude": {
            "command": "mcp",
            "args": ["--server", "http://localhost:8000"],
        }
    }
}"""


@pytest.fixture
def vscode_mcp_config():
    """Sample VSCode MCP config with inputs."""
    return """{
  // Inputs are prompted on first server start, then stored securely by VS Code.
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


@pytest.fixture
def vscode_config():
    """Sample VSCode settings.json with MCP config."""
    return """// settings.json
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
}"""
