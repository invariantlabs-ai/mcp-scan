import os

from pydantic import BaseModel

from mcp_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
    inspect_machine,
    inspected_client_to_scan_path_result,
)
from mcp_scan.models import (
    CandidateClient,
    ClientToInspect,
    ControlServer,
    ScanError,
    ScanPathResult,
    SkillServer,
    TokenAndClientInfo,
)
from mcp_scan.upload import upload
from mcp_scan.utils import get_push_key
from mcp_scan.verify_api import analyze_machine


class InspectArgs(BaseModel):
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


async def inspect_analyze_upload_machine(
    inspect_args: InspectArgs,
    analyze_args: AnalyzeArgs,
    push_args: PushArgs,
    verbose: bool = False,
) -> list[ScanPathResult]:
    """
    Pipeline the scan and analyze the machine.
    """
    # scan
    inspected_machine = await inspect_machine(inspect_args.timeout, inspect_args.tokens)
    scan_path_results = [
        inspected_client_to_scan_path_result(inspected_client) for inspected_client in inspected_machine.clients
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


async def client_to_inspect_from_path(path: str, use_path_as_client_name: bool = False) -> ClientToInspect | None:
    if os.path.isdir(os.path.expanduser(path)):
        if os.path.exists(os.path.join(path, "SKILL.md")):
            # split last dir from all other dirs in the path
            last_dir = path.split("/")[-1]
            path_without_last_dir = "/".join(path.split("/")[:-1])
            return ClientToInspect(
                name="not-available" if use_path_as_client_name else path,
                client_path=path_without_last_dir,
                mcp_configs={},
                skills_dirs={
                    path_without_last_dir: [(last_dir, SkillServer(path=path))],
                },
            )
        else:
            candidate_client = CandidateClient(
                name="not-available" if use_path_as_client_name else path,
                client_exists_paths=[path],
                mcp_config_paths=[],
                skills_dir_paths=[path],
            )
            return await get_mcp_config_per_client(candidate_client)
    else:
        candidate_client = CandidateClient(
            name="not-available" if use_path_as_client_name else path,
            client_exists_paths=[path],
            mcp_config_paths=[path],
            skills_dir_paths=[],
        )
        return await get_mcp_config_per_client(candidate_client)


async def inspect_analyze_paths(
    paths: list[str],
    inspect_args: InspectArgs,
    analyze_args: AnalyzeArgs,
    verbose: bool = False,
) -> list[ScanPathResult]:
    """
    Pipeline the inspect, analyze, and upload the MCP config.
    """

    client_to_inspect_list = [await client_to_inspect_from_path(path, True) for path in paths]

    scan_path_results: list[ScanPathResult] = []
    for path, client_to_inspect in zip(paths, client_to_inspect_list, strict=True):
        if client_to_inspect is None:
            scan_path_results.append(
                ScanPathResult(
                    path=path,
                    client=path,
                    servers=[],
                    issues=[],
                    labels=[],
                    error=ScanError(message="File or folder not found", is_failure=False, category="file_not_found"),
                )
            )
            continue

        inspected_client = await inspect_client(client_to_inspect, inspect_args.timeout, inspect_args.tokens)
        scan_path_results.append(inspected_client_to_scan_path_result(inspected_client))
    verified_scan_path_results = await analyze_machine(
        scan_path_results,
        analysis_url=analyze_args.analysis_url,
        identifier=analyze_args.identifier,
        additional_headers=analyze_args.additional_headers,
        opt_out_of_identity=analyze_args.opt_out_of_identity,
        verbose=verbose,
        skip_pushing=False,
        push_key=None,
        max_retries=analyze_args.max_retries,
        skip_ssl_verify=analyze_args.skip_ssl_verify,
    )
    return verified_scan_path_results
