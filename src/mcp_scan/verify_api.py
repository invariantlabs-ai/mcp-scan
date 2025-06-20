import ast
import asyncio
import logging

import aiohttp
from invariant.analyzer.policy import LocalPolicy
from mcp.types import Tool

from .models import (
    EntityScanResult,
    ErrorLabels,
    ScalarToolLabels,
    ScanPathResult,
    ServerSignature,
    ToolAnnotationsWithLabels,
    VerifyServerRequest,
    VerifyServerResponse,
    entity_to_tool,
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


async def verify_scan_path_public_api(scan_path: ScanPathResult, base_url: str) -> ScanPathResult:
    output_path = scan_path.clone()
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/mcp-scan"
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
                    results = VerifyServerResponse.model_validate_json(await response.read())
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")
        for server in output_path.servers:
            if server.signature is None:
                continue
            server.result = results.root.pop(0)
        assert len(results.root) == 0  # all results should be consumed
        return output_path
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        for server in output_path.servers:
            if server.signature is not None:
                server.result = [
                    EntityScanResult(status="could not reach verification server " + errstr) for _ in server.entities
                ]

        return output_path


def get_policy() -> str:
    with open(POLICY_PATH) as f:
        policy = f.read()
    return policy


async def verify_scan_path_locally(scan_path: ScanPathResult) -> ScanPathResult:
    output_path = scan_path.clone()
    tools_to_scan: list[Tool] = []
    for server in scan_path.servers:
        # None server signature are servers which are not reachable.
        if server.signature is not None:
            for entity in server.entities:
                tools_to_scan.append(entity_to_tool(entity))
    messages = [{"tools": [tool.model_dump() for tool in tools_to_scan]}]

    policy = LocalPolicy.from_string(get_policy())
    check_result = await policy.a_analyze(messages)
    results = [EntityScanResult(verified=True) for _ in tools_to_scan]
    for error in check_result.errors:
        idx: int = ast.literal_eval(error.key)[1][0]
        if results[idx].verified:
            results[idx].verified = False
        if results[idx].status is None:
            results[idx].status = "failed - "
        results[idx].status += " ".join(error.args or [])  # type: ignore

    for server in output_path.servers:
        if server.signature is None:
            continue
        server.result = results[: len(server.entities)]
        results = results[len(server.entities) :]
    if results:
        raise Exception("Not all results were consumed. This should not happen.")
    return output_path


async def verify_scan_path(scan_path: ScanPathResult, base_url: str, run_locally: bool) -> ScanPathResult:
    if run_locally:
        return await verify_scan_path_locally(scan_path)
    else:
        return await verify_scan_path_public_api(scan_path, base_url)


async def verify_scan_path_and_labels(scan_path: ScanPathResult, base_url: str, run_locally: bool) -> ScanPathResult:
    """
    Verify the scan path and get labels for all servers in the scan path.
    Runs concurrently to speed up the process.
    """
    verified_scan_path_task = verify_scan_path(scan_path, base_url, run_locally)
    signatures_with_labels_task = scan_path_get_labels([server.signature for server in scan_path.servers], base_url)
    verified_scan_path, signatures_with_labels = await asyncio.gather(
        verified_scan_path_task,
        signatures_with_labels_task,
    )
    logger.debug("Verified scan path and labels retrieved successfully")
    for server, signature in zip(verified_scan_path.servers, signatures_with_labels, strict=False):
        server.signature = signature
    return verified_scan_path
