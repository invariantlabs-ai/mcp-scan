"""Global pytest fixtures for mcp-scan tests."""

import pytest

from mcp_scan.utils import TempFile


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
def claudestyle_config_file(claudestyle_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(claudestyle_config)
        temp_file.flush()
        yield temp_file.name


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
def vscode_mcp_config_file(vscode_mcp_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_mcp_config)
        temp_file.flush()
        yield temp_file.name


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


@pytest.fixture
def vscode_config_file(vscode_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_config)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def toy_server_add():
    """Example toy server from the mcp docs."""
    return """
from mcp.server.fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Demo")

# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
"""


@pytest.fixture
def toy_server_add_file(toy_server_add):
    with TempFile(mode="w", suffix=".py") as temp_file:
        temp_file.write(toy_server_add)
        temp_file.flush()
        yield temp_file.name.replace("\\", "/")

    # filename = "tmp_toy_server_" + str(uuid.uuid4()) + ".py"
    # # create the file
    # with open(filename, "w") as temp_file:
    #     temp_file.write(toy_server_add)
    #     temp_file.flush()
    #     temp_file.seek(0)

    # # run tests
    # yield filename.replace("\\", "/")
    # # cleanup
    # import os

    # os.remove(filename)


@pytest.fixture
def toy_server_add_config(toy_server_add_file):
    return f"""
    {{
    "mcpServers": {{
        "toy": {{
            "command": "mcp",
            "args": ["run", "{toy_server_add_file}"]
        }}
    }}
    }}
    """


@pytest.fixture
def toy_server_add_config_file(toy_server_add_config):
    with TempFile(mode="w", suffix=".json") as temp_file:
        temp_file.write(toy_server_add_config)
        temp_file.flush()
        yield temp_file.name.replace("\\", "/")

    # filename = "tmp_config_" + str(uuid.uuid4()) + ".json"

    # # create the file
    # with open(filename, "w") as temp_file:
    #     temp_file.write(toy_server_add_config)
    #     temp_file.flush()
    #     temp_file.seek(0)

    # # run tests
    # yield filename.replace("\\", "/")

    # # cleanup
    # import os

    # os.remove(filename)


@pytest.fixture
def math_server_config_path():
    return "tests/mcp_servers/mcp_config.json"
