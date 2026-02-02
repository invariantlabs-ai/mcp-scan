from pydantic import BaseModel

from mcp_scan.inspect import inspect_machine, inspected_client_to_scan_path_result
from mcp_scan.models import ControlServer, ScanPathResult, TokenAndClientInfo
from mcp_scan.upload import upload
from mcp_scan.utils import get_push_key
from mcp_scan.verify_api import analyze_machine


class ScanArgs(BaseModel):
    timeout: int
    tokens: list[TokenAndClientInfo]


class AnalyzeArgs(BaseModel):
    analysis_url: str
    identifier: str | None = None
    additional_headers: dict | None = None
    opt_out_of_identity: bool = False
    max_retries: int = 3
    skip_ssl_verify: bool = False


class PushArgs(BaseModel):
    control_servers: list[ControlServer]
    skip_ssl_verify: bool = False
    version: str | None = None


async def pipeline_scan_and_analyze(
    scan_args: ScanArgs,
    analyze_args: AnalyzeArgs,
    push_args: PushArgs,
    verbose: bool = False,
) -> list[ScanPathResult]:
    """
    Pipeline the scan and analyze the machine.
    """
    # scan
    scanned_machine = await inspect_machine(scan_args.timeout, scan_args.tokens)
    scan_path_results = [
        inspected_client_to_scan_path_result(scanned_client) for scanned_client in scanned_machine.clients
    ]

    # analyze
    verified_scan_path_results = await analyze_machine(
        scan_path_results,
        analysis_url=analyze_args.analysis_url,
        identifier=analyze_args.identifier,
        additional_headers=analyze_args.additional_headers,
        opt_out_of_identity=analyze_args.opt_out_of_identity,
        verbose=verbose,
        skip_pushing=bool(push_args.control_servers),
        push_key=get_push_key(push_args.control_servers),
        max_retries=analyze_args.max_retries,
        skip_ssl_verify=analyze_args.skip_ssl_verify,
    )
    # push
    for control_server in push_args.control_servers:
        await upload(
            verified_scan_path_results,
            control_server.url,
            control_server.identifier,
            control_server.opt_out,
            verbose=verbose,
            additional_headers=control_server.headers,
            skip_ssl_verify=push_args.skip_ssl_verify,
            scan_context={"cli_version": push_args.version},
        )

    return verified_scan_path_results
