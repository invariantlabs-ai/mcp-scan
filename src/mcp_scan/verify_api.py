import ast
from typing import TYPE_CHECKING

import aiohttp
from invariant.analyzer.policy import LocalPolicy

from .models import (
    EntityScanResult,
    ScanPathResult,
    VerifyServerRequest,
    VerifyServerResponse,
    entity_to_tool,
)

if TYPE_CHECKING:
    from mcp.types import Tool

POLICY_PATH = "src/mcp_scan/policy.gr"


async def verify_scan_path_public_api(scan_path: ScanPathResult, base_url: str) -> ScanPathResult:
    output_path = scan_path.model_copy(deep=True)
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
                pass
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
    output_path = scan_path.model_copy(deep=True)
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
