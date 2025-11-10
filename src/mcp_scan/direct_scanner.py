"""
Scans MCP servers directly from package, URL or provided tool signatures.
"""

import json
import tempfile
from collections.abc import Callable, Coroutine
from typing import Any

from mcp.types import Tool

from mcp_scan.mcp_client import scan_mcp_config_file
from mcp_scan.models import MCPConfig, StaticToolsConfig, StaticToolsServer

SUPPORTED_TYPES = ["streamable-https", "streamable-http", "sse", "pypi", "npm", "oci", "nuget", "mcpb", "tools"]


def is_direct_scan(path: str) -> bool:
    return any(path.startswith(f"{t}:") for t in SUPPORTED_TYPES)


async def scan_streamable_https(url: str, secure=True):
    config_file = f"""
{{
    "mcpServers": {{
        "http-mcp-server": {{
            "url": "http{"s" if secure else ""}://{url}"
        }}
    }}
}}
    """

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        print(config_file)
        return await scan_mcp_config_file(tmp.name)


async def scan_streamable_http(url: str):
    return await scan_streamable_https(url, secure=False)


async def scan_npm(package_name: str):
    name, version = package_name.split("@") if "@" in package_name else (package_name, "latest")

    config_file = f"""{{
    "mcpServers": {{
        "{name}": {{
            "command": "npx",
            "args": [
                "-y",
                "{name}@{version}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_pypi(package_name: str):
    name, version = package_name.split("@") if "@" in package_name else (package_name, "latest")
    config_file = f"""{{
    "mcpServers": {{
        "{name}": {{
            "command": "uvx",
            "args": [
                "{name}@{version}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_oci(oci_url: str):
    config_file = f"""{{
    "mcpServers": {{
        "{oci_url}": {{
            "command": "docker",
            "args": [
                "run", "-i", "--rm",
                "{oci_url}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_tools(path: str):
    # check if path starts with '{', if so parse as JSON
    if path.startswith("["):
        raw_tools = json.loads(path)
    else:
        with open(path) as f:
            raw_tools = json.load(f)

    # Expect a list of tool dicts. Construct proper Tool models, preserving schemas.
    tools: list[Tool] = []
    for item in raw_tools:
        # Be defensive about missing keys and default to empty schemas
        tools.append(
            Tool(
                name=item.get("name", "<unnamed-tool>"),
                description=item.get("description"),
                inputSchema=item.get("inputSchema", {}),
                outputSchema=item.get("outputSchema", {}),
                annotations=item.get("annotations"),
                meta=item.get("meta", {}),
            )
        )

    server_name = path if not path.startswith("[") else "<tools>"
    return StaticToolsConfig(signature={server_name: StaticToolsServer(name=server_name, signature=tools)})


SCANNERS: dict[str, Callable[..., Coroutine[Any, Any, MCPConfig]]] = {
    "streamable-https": scan_streamable_https,
    "streamable-http": scan_streamable_http,
    "npm": scan_npm,
    "pypi": scan_pypi,
    "oci": scan_oci,
    "tools": scan_tools,
}


async def direct_scan(path: str):
    """
    Scans an MCP server directly from a package or URL.
    """
    scan_type = path.split(":")[0]
    if scan_type not in SCANNERS:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    return await SCANNERS[scan_type](path[len(scan_type) + 1 :])
