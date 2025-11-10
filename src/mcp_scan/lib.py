"""
MCP-scan high-level API for programmatic use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcp_scan.MCPScanner import MCPScanner
from mcp_scan.upload import upload as _upload
from mcp_scan.utils import parse_headers

if TYPE_CHECKING:
    from collections.abc import Sequence


async def _run_scan_or_inspect(
    mode: str,
    files: str | Sequence[str] | None = None,
    **options: Any,
) -> list:
    """
    Internal helper to run a scan or inspect using MCPScanner.

    Parameters:
    - mode: "scan" or "inspect".
    - files: a path, or a list/sequence of paths. If None, an empty list is used
      and MCPScanner will rely on provided options.
    - options: forwarded to MCPScanner, with special handling for:
        - verification_H: list[str] -> mapped to additional_headers via parse_headers
        - control_server, push_key, email, opt_out, control_server_H: if provided,
          results will be uploaded after the run.

    Returns: list[ScanPathResult]
    """
    # Normalize files to a list[str]
    if files is None:
        file_list: list[str] = []
    elif isinstance(files, str):
        file_list = [files]
    else:
        file_list = list(files)

    # Handle verification headers -> additional_headers for verification API
    verification_H = options.pop("verification_H", None)
    additional_headers = parse_headers(verification_H) if verification_H is not None else {}

    # Extract optional upload settings
    control_server = options.pop("control_server", None)
    push_key = options.pop("push_key", None)
    email = options.pop("email", None)
    opt_out = bool(options.get("opt_out", False))
    control_server_H = options.pop("control_server_H", None)
    control_additional_headers = parse_headers(control_server_H) if control_server_H is not None else {}

    async with MCPScanner(files=file_list, additional_headers=additional_headers, **options) as scanner:
        if mode == "scan":
            results = await scanner.scan()
        elif mode == "inspect":
            results = await scanner.inspect()
        else:
            raise ValueError("mode must be 'scan' or 'inspect'")

    # Optionally upload results
    if control_server and push_key:
        await _upload(
            results,
            control_server,
            push_key,
            email,
            opt_out,
            additional_headers=control_additional_headers,
        )

    return results


async def scan(files: str | Sequence[str] | None = None, **options: Any):
    """
    Run a security scan for MCP servers referenced by the given file(s).

    Example:
        await scan("SCAN_FILE", checks_per_server=1, server_timeout=10)

    The options map to `MCPScanner` kwargs and CLI flags where applicable, e.g.:
    - checks_per_server: int (default 1)
    - storage_file: str (default "~/.mcp-scan")
    - analysis_url: str (default "https://mcp.invariantlabs.ai/api/v1/public/mcp-analysis")
    - server_timeout: int (default 10)
    - suppress_mcpserver_io: bool (default True)
    - opt_out: bool (default False)
    - include_built_in: bool (default False)
    - verbose: bool (default False)
    - verification_H: list[str] parsed to additional headers for verification API
    - control_server, push_key, email, control_server_H: optional upload settings
    """
    return await _run_scan_or_inspect("scan", files, **options)


async def inspect(files: str | Sequence[str] | None = None, **options: Any):
    """
    Inspect MCP servers (tools/prompts/resources) without verification.

    Example:
        await inspect(["SCAN_FILE1", "SCAN_FILE2"], include_built_in=True)

    Accepts the same options as `scan()`, but does not run verification unless
    upload settings are provided (upload only happens when control_server and push_key are set).
    """
    return await _run_scan_or_inspect("inspect", files, **options)
