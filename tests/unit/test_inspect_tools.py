import json

import pytest

from mcp_scan import inspect as inspect_api
from mcp_scan.models import StaticToolsServer


@pytest.mark.asyncio
async def test_inspect_with_direct_tools_json():
    tools = [
        {
            "name": "search",
            "description": "Search something",
            "inputSchema": {
                "type": "object",
                "required": ["query"],
                "properties": {"query": {"type": "string"}},
            },
            "outputSchema": {
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
            },
        },
        {
            "name": "fetch_content",
            "description": "Fetch URL content",
            "inputSchema": {
                "type": "object",
                "required": ["url"],
                "properties": {"url": {"type": "string"}},
            },
            "outputSchema": {
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
            },
        },
    ]

    path = "tools:" + json.dumps(tools)

    results = await inspect_api(path)

    # One path result
    assert isinstance(results, list)
    assert len(results) == 1
    path_result = results[0]

    # No verification in inspect-only mode
    assert path_result.issues == []
    assert path_result.labels == []

    # One server created from static tools
    assert len(path_result.servers) == 1
    server_result = path_result.servers[0]

    # Underlying server is StaticToolsServer with type "tools"
    assert isinstance(server_result.server, StaticToolsServer)
    assert server_result.server.type == "tools"

    # Signature exists and contains our tools
    assert server_result.signature is not None
    tool_names = {t.name for t in server_result.signature.tools}
    assert tool_names == {"search", "fetch_content"}

    # Metadata is the built-in placeholder from tools protocols
    assert server_result.signature.metadata.protocolVersion == "built-in"
    assert server_result.signature.metadata.serverInfo.name == "<tools>"
