import asyncio
import json
import logging

from mcp_scan import inspect, scan
from mcp_scan.printer import print_scan_result

# no logging by default
logging.getLogger().setLevel(logging.CRITICAL + 1)  # Higher than any standard level
logging.getLogger().addHandler(logging.NullHandler())

# scan PyPI package
result = asyncio.run(scan("pypi:arxiv-mcp-server"))
print_scan_result(result)

# scan oci package
result = asyncio.run(inspect("oci:zenmldocker/mcp-zenml"))
print_scan_result(result, inspect_mode=True)

# scan npm package
result = asyncio.run(inspect("npm:mcp-sequentialthinking-tools"))
print_scan_result(result, inspect_mode=True)

# scan tools directly
tools = [
    {
        "name": "search",
        "description": "\n    Search DuckDuckGo and return formatted results.\n\n    Args:\n        query: The search query string\n        max_results: Maximum number of results to return (default: 10)\n        ctx: MCP context for logging\n    ",
        "inputSchema": {
            "type": "object",
            "title": "searchArguments",
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "title": "Query"},
                "max_results": {"type": "integer", "title": "Max Results", "default": 10},
            },
        },
        "outputSchema": {
            "type": "object",
            "title": "searchOutput",
            "required": ["result"],
            "properties": {"result": {"type": "string", "title": "Result"}},
        },
    },
    {
        "name": "fetch_content",
        "description": "\n    Fetch and parse content from a webpage URL.\n\n    Args:\n        url: The webpage URL to fetch content from\n        ctx: MCP context for logging\n    ",
        "inputSchema": {
            "type": "object",
            "title": "fetch_contentArguments",
            "required": ["url"],
            "properties": {"url": {"type": "string", "title": "Url"}},
        },
        "outputSchema": {
            "type": "object",
            "title": "fetch_contentOutput",
            "required": ["result"],
            "properties": {"result": {"type": "string", "title": "Result"}},
        },
    },
]
result = asyncio.run(inspect("tools:" + json.dumps(tools)))
print_scan_result(result, inspect_mode=True)
