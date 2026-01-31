import logging
import os
import traceback

from httpx import HTTPStatusError

from mcp_scan.mcp_client import check_server, scan_mcp_config_file, scan_skill, scan_skills_dir
from mcp_scan.models import (
    CandidateClient,
    ClientToScan,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    RemoteServer,
    ScanError,
    ScannedClient,
    ScannedExtension,
    ScannedMachine,
    ScanPathResult,
    ServerHTTPError,
    ServerScanResult,
    ServerSignature,
    ServerStartupError,
    SkillScannError,
    SkillServer,
    StdioServer,
    TokenAndClientInfo,
    UnknownConfigFormat,
    UnknownMCPConfig,
)
from mcp_scan.traffic_capture import TrafficCapture
from mcp_scan.well_known_clients import get_well_known_clients

logger = logging.getLogger(__name__)


async def get_mcp_config_per_client(client: CandidateClient) -> ClientToScan | None:
    """
    Looks for Client (Cursor, VSCode, etc.) config files.
    If found, returns a ClientToScan object with the MCP config paths and skills dir paths.
    If not found, returns None.
    """

    # check if client exists
    client_path: str | None = None
    for path in client.client_exists_paths:
        if os.path.exists(os.path.expanduser(path)):
            client_path = path
            break

    if client_path is None:
        return None

    # parse mcp configs
    mcp_configs: dict[
        str,
        list[tuple[str, StdioServer | RemoteServer]]
        | FileNotFoundConfig
        | UnknownConfigFormat
        | CouldNotParseMCPConfig,
    ] = {}
    for mcp_config_path in client.mcp_config_paths:
        if not os.path.exists(os.path.expanduser(mcp_config_path)):
            mcp_configs[mcp_config_path] = FileNotFoundConfig(
                message=f"file {mcp_config_path} does not exist",
                is_failure=False,
            )
            continue
        try:
            mcp_config = await scan_mcp_config_file(mcp_config_path)
            if isinstance(mcp_config, UnknownMCPConfig):
                mcp_configs[mcp_config_path] = UnknownConfigFormat(
                    message=f"Unknown MCP config: {mcp_config_path}",
                    is_failure=False,
                )
                continue
            servers = mcp_config.get_servers()
            mcp_configs[mcp_config_path] = [(server_name, server) for server_name, server in servers.items()]
        except Exception as e:
            logger.exception(f"Error parsing MCP config file {mcp_config_path}: {e}")
            mcp_configs[mcp_config_path] = CouldNotParseMCPConfig(
                message=f"could not parse file {mcp_config_path}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )

    # parse skills dirs
    skills_dirs: dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig] = {}
    for skills_dir_path in client.skills_dir_paths:
        if os.path.exists(os.path.expanduser(skills_dir_path)):
            skills_dirs[skills_dir_path] = scan_skills_dir(skills_dir_path)
        else:
            skills_dirs[skills_dir_path] = FileNotFoundConfig(message=f"Skills dir {skills_dir_path} does not exist")

    return ClientToScan(
        name=client.name,
        client_path=client_path,
        mcp_configs=mcp_configs,
        skills_dirs=skills_dirs,
    )


async def scan_extension(
    name: str,
    config: StdioServer | RemoteServer | SkillServer,
    timeout: int,
    token: TokenAndClientInfo | None = None,
) -> ScannedExtension:
    """
    Scan an extension (MCP server or skill) and return a ScannedExtension object.
    """
    traffic_capture = TrafficCapture()
    if isinstance(config, StdioServer):
        try:
            signature, _ = await check_server(config, timeout, traffic_capture, token)
            return ScannedExtension(name=name, config=config, signature_or_error=signature)
        except Exception as e:
            return ScannedExtension(
                name=name,
                config=config,
                signature_or_error=ServerStartupError(
                    message="could not start server",
                    traceback=traceback.format_exc(),
                    sub_exception_message=str(e),
                    is_failure=True,
                    server_output=traffic_capture.get_traffic_log(),
                ),
            )

    if isinstance(config, RemoteServer):
        try:
            signature, fixed_config = await check_server(config, timeout, traffic_capture, token)
            assert isinstance(fixed_config, RemoteServer), f"Fixed config is not a RemoteServer: {fixed_config}"
            return ScannedExtension(name=name, config=config, signature_or_error=signature)
        except HTTPStatusError as e:
            return ScannedExtension(
                name=name,
                config=config,
                signature_or_error=ServerHTTPError(
                    message="server returned HTTP status code",
                    traceback=traceback.format_exc(),
                    is_failure=True,
                    sub_exception_message=str(e),
                    server_output=traffic_capture.get_traffic_log(),
                ),
            )
        except Exception as e:
            return ScannedExtension(
                name=name,
                config=config,
                signature_or_error=ServerStartupError(
                    message="could not start server",
                    traceback=traceback.format_exc(),
                    sub_exception_message=str(e),
                    is_failure=True,
                    category="server_startup",
                    server_output=traffic_capture.get_traffic_log() if traffic_capture else None,
                ),
            )

    elif isinstance(config, SkillServer):
        try:
            signature = await scan_skill(config)
            return ScannedExtension(name=name, config=config, signature_or_error=signature)
        except Exception as e:
            return ScannedExtension(
                name=name,
                config=config,
                signature_or_error=SkillScannError(
                    message="could not scan skill",
                    traceback=traceback.format_exc(),
                    is_failure=True,
                    category="skill_scan_error",
                    sub_exception_message=str(e),
                ),
            )


async def scan_client(
    client: ClientToScan,
) -> ScannedClient:
    """
    Scan a client (Cursor, VSCode, etc.) and return a ScannedClient object.
    """
    extensions: dict[
        str,
        list[ScannedExtension] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScannError,
    ] = {}
    for mcp_config_path, mcp_configs in client.mcp_configs.items():
        if isinstance(mcp_configs, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
            extensions[mcp_config_path] = mcp_configs
            continue
        extensions_for_mcp_config: list[ScannedExtension] = []
        for name, server in mcp_configs:
            extension = await scan_extension(name, server, 10)
            extensions_for_mcp_config.append(extension)
        extensions[mcp_config_path] = extensions_for_mcp_config

    for skills_dir_path, skills_dirs in client.skills_dirs.items():
        if isinstance(skills_dirs, FileNotFoundConfig):
            extensions[skills_dir_path] = skills_dirs
            continue
        extensions_for_skills_dir: list[ScannedExtension] = []
        for name, skill in skills_dirs:
            extension = await scan_extension(name, skill, 10)
            extensions_for_skills_dir.append(extension)
        extensions[skills_dir_path] = extensions_for_skills_dir

    return ScannedClient(name=client.name, client_path=client.client_path, extensions=extensions)


async def scan_machine() -> ScannedMachine:
    """
    Scan all the well known clients (Cursor, VSCode, etc.) and return a ScannedMachine object.
    """
    well_known_clients = get_well_known_clients()

    logger.info(f"Scanning {len(well_known_clients)} well known clients")
    clients_to_scan: list[ClientToScan] = []
    for client in well_known_clients:
        client_to_scan = await get_mcp_config_per_client(client)
        if client_to_scan is None:
            logger.info(f"Client {client.name} does not exist os this machine. {client.client_exists_paths}")
            continue
        logger.info(f"Client {client.name} found on this machine")
        clients_to_scan.append(client_to_scan)
    logger.info(f"Scanning {len(clients_to_scan)} clients")
    scanned_clients: list[ScannedClient] = []
    for client_to_scan in clients_to_scan:
        scanned_client = await scan_client(client_to_scan)
        scanned_clients.append(scanned_client)

    return ScannedMachine(clients=scanned_clients)


async def scanned_machine_to_analyzed_machine(scanned_client: ScannedClient) -> ScanPathResult:
    """
    Convert a ScannedClient object to a ScanPathResult object.
    """
    servers: list[ServerScanResult] = []
    error = None
    for _, extensions_or_error in scanned_client.extensions.items():
        if isinstance(
            extensions_or_error, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScannError
        ):
            error = ScanError(
                message=extensions_or_error.message,
                exception=extensions_or_error.sub_exception_message,
                traceback=extensions_or_error.traceback,
                is_failure=extensions_or_error.is_failure,
                category=extensions_or_error.category,
            )
            continue
        for extension in extensions_or_error:
            if isinstance(extension.signature_or_error, ServerSignature):
                servers.append(
                    ServerScanResult(
                        name=extension.name, server=extension.config, signature=extension.signature_or_error, error=None
                    )
                )
            else:
                servers.append(
                    ServerScanResult(
                        name=extension.name,
                        server=extension.config,
                        signature=None,
                        error=ScanError(
                            message=extension.signature_or_error.message,
                            exception=extension.signature_or_error.sub_exception_message,
                            traceback=extension.signature_or_error.traceback,
                            is_failure=extension.signature_or_error.is_failure,
                            category=extension.signature_or_error.category,
                            server_output=extension.signature_or_error.server_output
                            if isinstance(extension.signature_or_error, ServerStartupError | ServerHTTPError)
                            else None,
                        ),
                    )
                )
    return ScanPathResult(
        client=scanned_client.name, path=scanned_client.client_path, servers=servers, issues=[], labels=[], error=error
    )
