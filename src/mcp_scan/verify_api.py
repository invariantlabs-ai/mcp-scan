import asyncio
import logging

import aiohttp
from mcp.types import Tool

from .models import (
    AnalysisServerResponse,
    ErrorLabels,
    Issue,
    ScalarToolLabels,
    ScanPathResult,
    ServerSignature,
    ToolAnnotationsWithLabels,
    VerifyServerRequest,
)

logger = logging.getLogger(__name__)


POLICY_PATH = "src/mcp_scan/policy.gr"


async def tool_get_labels(tool: Tool, base_url: str) -> Tool:
    """
    Get labels from the tool and add them to the tool's metadata.
    """
    logger.debug("Getting labels for tool: %s", tool.name)
    output_tool = tool.model_copy(deep=True)
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/labels"
    headers = {"Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=tool.model_dump_json()) as response:
                if response.status == 200:
                    scalar_tool_labels = ScalarToolLabels.model_validate_json(await response.read())
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")
    except Exception as e:
        output_tool.annotations = ToolAnnotationsWithLabels(
            **output_tool.annotations.model_dump() if output_tool.annotations else {},
            labels=ErrorLabels(error=str(e) if isinstance(e, Exception) else "Unknown error"),
        )
        return output_tool
    output_tool.annotations = ToolAnnotationsWithLabels(
        **output_tool.annotations.model_dump() if output_tool.annotations else {},
        labels=scalar_tool_labels,
    )
    return output_tool


async def server_get_labels(server: ServerSignature, base_url: str) -> ServerSignature:
    """
    Get labels from the server and add them to the server's metadata.
    """
    logger.debug("Getting labels for server: %s", server.metadata.serverInfo.name)
    output_server = server.model_copy(deep=True)
    annotated_tools = [tool_get_labels(tool, base_url) for tool in output_server.tools]
    output_server.tools = await asyncio.gather(*annotated_tools)
    return output_server


async def scan_path_get_labels(servers: list[ServerSignature | None], base_url: str) -> list[ServerSignature | None]:
    """
    Get labels for all servers in the scan path.
    """
    logger.debug(f"Getting labels for {len(servers)} servers")

    async def server_get_labels_or_skip(server: ServerSignature | None) -> ServerSignature | None:
        if server is None:
            return None
        return await server_get_labels(server, base_url)

    return await asyncio.gather(*[server_get_labels_or_skip(server) for server in servers])


async def analyze_scan_path(scan_path: ScanPathResult, base_url: str) -> ScanPathResult:
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/mcp-analysis"
    headers = {"Content-Type": "application/json"}
    payload = VerifyServerRequest(root=[])
    for server in scan_path.servers:
        # None server signature are servers which are not reachable.
        if server.signature is not None:
            payload.root.append(server.signature)
    # Server signatures do not contain any information about the user setup. Only about the server itself.
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=payload.model_dump_json()) as response:
                if response.status == 200:
                    results = AnalysisServerResponse.model_validate_json(await response.read())
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")

        # Assign labels
        for server_idx, (server, labels) in enumerate(zip(scan_path.servers, results.labels, strict=False)):
            if server.signature is None:
                for issue in results.issues:
                    if issue.reference and issue.reference[0] == server_idx:
                        issue.reference = (issue.reference[0] + 1, issue.reference[1])
                continue
            server.labels = labels

        # Assign issues
        for server_idx, server in enumerate(scan_path.servers):
            if server.signature is None:
                # reassign references
                for issue in results.issues:
                    if issue.reference and issue.reference[0] == server_idx:
                        issue.reference = (issue.reference[0] + 1, issue.reference[1])
        scan_path.issues += results.issues

    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        for server_idx, server in enumerate(scan_path.servers):
            if server.signature is not None:
                for i, _ in enumerate(server.entities):
                    scan_path.issues.append(
                        Issue(
                            code="X001",
                            message=f"could not reach analysis server {errstr}",
                            reference=(server_idx, i),
                        )
                    )
    return scan_path


async def verify_scan_path_and_labels(scan_path: ScanPathResult, base_url: str, run_locally: bool) -> ScanPathResult:
    """
    Verify the scan path and get labels for all servers in the scan path.
    Runs concurrently to speed up the process.
    """
    verified_scan_path = await analyze_scan_path(
        scan_path=scan_path,
        base_url=base_url,
    )
    return verified_scan_path
