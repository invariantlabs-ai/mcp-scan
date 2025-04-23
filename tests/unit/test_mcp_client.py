"""Unit tests for the mcp_client module."""
import pytest
from unittest.mock import patch, Mock, AsyncMock
from mcp_scan.mcp_client import check_server_with_timeout, check_server, scan_mcp_config_file
import tempfile
import json
from mcp_scan.models import StdioServer
import asyncio

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


@pytest.mark.asyncio
@patch('mcp_scan.mcp_client.stdio_client')
async def test_check_server_mocked(mock_stdio_client):
    # Create mock objects
    mock_session = Mock()
    mock_read = AsyncMock()
    mock_write = AsyncMock()
    
    # Mock initialize response
    mock_meta = Mock()
    mock_meta.capabilities = Mock()
    mock_meta.capabilities.prompts = Mock()
    mock_meta.capabilities.resources = Mock()
    mock_meta.capabilities.tools = Mock()
    mock_meta.capabilities.prompts.supported = True
    mock_meta.capabilities.resources.supported = True
    mock_meta.capabilities.tools.supported = True
    mock_session.initialize = AsyncMock(return_value=mock_meta)
    
    # Mock list responses
    mock_prompts = Mock()
    mock_prompts.prompts = ["prompt1", "prompt2"]
    mock_session.list_prompts = AsyncMock(return_value=mock_prompts)
    
    mock_resources = Mock()
    mock_resources.resources = ["resource1"]
    mock_session.list_resources = AsyncMock(return_value=mock_resources)
    
    mock_tools = Mock()
    mock_tools.tools = ["tool1", "tool2", "tool3"]
    mock_session.list_tools = AsyncMock(return_value=mock_tools)
    
    # Set up the mock stdio client to return our mocked read/write pair
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_stdio_client.return_value = mock_client
    
    # Mock ClientSession with proper async context manager protocol
    class MockClientSession:
        def __init__(self, read, write):
            self.read = read
            self.write = write
            
        async def __aenter__(self):
            return mock_session
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
    
    # Test function with mocks
    with patch('mcp_scan.mcp_client.ClientSession', MockClientSession):
        server = StdioServer(command="mcp", args=["run", "some_file.py"])
        prompts, resources, tools = await check_server(server, 20, True)
        
        # Verify results
        assert len(prompts) == 2
        assert len(resources) == 1
        assert len(tools) == 3
