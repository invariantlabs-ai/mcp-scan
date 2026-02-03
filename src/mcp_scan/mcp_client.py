import asyncio
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal
from urllib.parse import urlparse

import httpx
import pyjson5
import yaml  # type: ignore
from mcp import ClientSession, StdioServerParameters
from mcp.client.auth import OAuthClientProvider
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata
from mcp.types import (
    Implementation,
    InitializeResult,
    Prompt,
    PromptsCapability,
    Resource,
    ResourcesCapability,
    ServerCapabilities,
    Tool,
    ToolsCapability,
)

from mcp_scan.models import (
    ClaudeConfigFile,
    FileTokenStorage,
    MCPConfig,
    RemoteServer,
    ServerSignature,
    SkillServer,
    StaticToolsServer,
    StdioServer,
    TokenAndClientInfo,
    UnknownMCPConfig,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)
from mcp_scan.traffic_capture import PipeStderrCapture, TrafficCapture, capturing_client
from mcp_scan.utils import resolve_command_and_args

# Set up logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def streamablehttp_client_without_session(
    url: str,
    headers: dict[str, str],
    timeout: int,
    token: TokenAndClientInfo | None = None,
):
    async def handle_redirect(auth_url: str) -> None:
        raise NotImplementedError(f"handle_redirect is not implemented {auth_url}")

    async def handle_callback(auth_code: str, state: str | None) -> tuple[str, str | None]:
        raise NotImplementedError(f"handle_callback is not implemented {auth_code} {state}")

    if token:
        oauth_client_provider = OAuthClientProvider(
            server_url=token.mcp_server_url,
            client_metadata=OAuthClientMetadata(
                client_name="mcp-scan",
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                redirect_uris=["http://localhost:3030/callback"],
            ),
            storage=FileTokenStorage(data=token),
            redirect_handler=handle_redirect,
            callback_handler=handle_callback,
        )
    else:
        oauth_client_provider = None
    async with httpx.AsyncClient(
        auth=oauth_client_provider, follow_redirects=True, headers=headers, timeout=timeout
    ) as custom_client:
        async with streamable_http_client(url=url, http_client=custom_client) as (read, write, _):
            yield read, write


@asynccontextmanager
async def get_client(
    server_config: StdioServer | RemoteServer,
    timeout: int | None = None,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
) -> AsyncIterator[tuple]:
    """
    Create an MCP client for the given server config.

    If traffic_capture is provided, all MCP protocol traffic will be captured
    for debugging purposes.
    """
    if isinstance(server_config, RemoteServer) and server_config.type == "sse":
        logger.debug("Creating SSE client with URL: %s", server_config.url)
        client_cm = sse_client(
            url=server_config.url,
            headers=server_config.headers,
            # env=server_config.env, #Not supported by MCP yet, but present in vscode
            timeout=timeout,
        )
    elif isinstance(server_config, RemoteServer) and server_config.type == "http":
        logger.debug(
            "Creating Streamable HTTP client with URL: %s with headers %s", server_config.url, server_config.headers
        )
        client_cm = streamablehttp_client_without_session(
            url=server_config.url,
            headers=server_config.headers,
            timeout=timeout or 60,
            token=token,
        )
    elif isinstance(server_config, StdioServer):
        logger.debug("Creating stdio client")

        command, args = resolve_command_and_args(server_config)
        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=server_config.env,
        )
        # Create stderr capture with real pipe if traffic capture is enabled
        stderr_capture = PipeStderrCapture(traffic_capture) if traffic_capture else None
        client_cm = stdio_client(server_params, errlog=stderr_capture)
    else:
        raise ValueError(f"Invalid server config: {server_config}")

    # Wrap client to capture traffic if requested
    if traffic_capture:
        # Start stderr reader for stdio servers
        if isinstance(server_config, StdioServer) and stderr_capture:
            await stderr_capture.start_reading()
        try:
            async with capturing_client(client_cm, traffic_capture) as streams:
                yield streams
        finally:
            # Clean up stderr capture
            if isinstance(server_config, StdioServer) and stderr_capture:
                await stderr_capture.close()
    else:
        async with client_cm as streams:
            yield streams


async def _check_server_pass(
    server_config: StdioServer | RemoteServer | StaticToolsServer,
    timeout: int,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
) -> ServerSignature:
    async def _check_server() -> ServerSignature:
        if isinstance(server_config, StaticToolsServer):
            logger.debug("Creating static tools client")
            return ServerSignature(
                metadata=InitializeResult(
                    protocolVersion="built-in",
                    capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
                    serverInfo=Implementation(name="<tools>", version="built-in"),
                    instructions="",
                ),
                prompts=[],
                resources=[],
                resource_templates=[],
                tools=server_config.signature,
            )

        async with get_client(server_config, timeout=timeout, traffic_capture=traffic_capture, token=token) as (
            read,
            write,
        ):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                logger.debug("Server initialized with metadata: %s", meta)
                # for see servers we need to check the announced capabilities
                prompts: list = []
                resources: list = []
                resource_templates: list = []
                tools: list = []
                # completions are currently not implemented
                completions: list = []  # noqa: F841
                logger.debug(f"Server capabilities: {meta.capabilities}")
                if isinstance(server_config, StdioServer) or meta.capabilities.prompts:
                    logger.debug("Fetching prompts")
                    try:
                        prompts += (await session.list_prompts()).prompts
                        logger.debug("Found %d prompts", len(prompts))
                    except Exception:
                        logger.exception("Failed to list prompts")

                logger.debug("Server capabilities: %s", meta.capabilities)
                if isinstance(server_config, StdioServer) or meta.capabilities.resources:
                    logger.debug("Fetching resources")
                    try:
                        resources += (await session.list_resources()).resources
                        logger.debug("Found %d resources", len(resources))
                    except Exception:
                        logger.exception("Failed to list resources")

                    logger.debug("Fetching resource templates")
                    try:
                        resource_templates += (await session.list_resource_templates()).resourceTemplates
                        logger.debug("Found %d resource templates", len(resource_templates))
                    except Exception:
                        logger.exception("Failed to list resource templates")

                if isinstance(server_config, StdioServer) or meta.capabilities.tools:
                    logger.debug("Fetching tools")
                    try:
                        tools += (await session.list_tools()).tools
                        logger.debug("Found %d tools", len(tools))
                    except Exception:
                        logger.exception("Failed to list tools")
                logger.info("Server check completed successfully")
                return ServerSignature(
                    metadata=meta,
                    prompts=prompts,
                    resources=resources,
                    resource_templates=resource_templates,
                    tools=tools,
                )

    return await _check_server()


async def check_server(
    server_config: StdioServer | RemoteServer | StaticToolsServer,
    timeout: int,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
) -> tuple[ServerSignature, StdioServer | RemoteServer | StaticToolsServer]:
    logger.debug("Checking server with timeout: %s seconds", timeout)

    if not isinstance(server_config, RemoteServer):
        result = await asyncio.wait_for(_check_server_pass(server_config, timeout, traffic_capture), timeout)
        logger.debug("Server check completed within timeout")
        return result, server_config
    else:
        logger.debug(f"Remote server with url: {server_config.url}, type: {server_config.type or 'none'}")
        strategy: list[tuple[Literal["sse", "http"], str]] = []
        url_path = urlparse(server_config.url).path
        if url_path.endswith("/sse"):
            url_with_sse = server_config.url
            url_without_end = server_config.url.replace("/sse", "")
            url_with_mcp = server_config.url.replace("/sse", "/mcp")
        elif url_path.endswith("/mcp"):
            url_with_mcp = server_config.url
            url_without_end = server_config.url.replace("/mcp", "")
            url_with_sse = server_config.url.replace("/mcp", "/sse")
        else:
            url_without_end = server_config.url
            url_with_mcp = server_config.url + "/mcp"
            url_with_sse = server_config.url + "/sse"

        if server_config.type == "http" or server_config.type is None:
            strategy.append(("http", url_with_mcp))
            strategy.append(("http", url_without_end))
            strategy.append(("sse", url_with_mcp))
            strategy.append(("sse", url_without_end))
            strategy.append(("http", url_with_sse))
            strategy.append(("sse", url_with_sse))
        else:
            strategy.append(("sse", url_with_mcp))
            strategy.append(("sse", url_without_end))
            strategy.append(("http", url_with_mcp))
            strategy.append(("http", url_without_end))
            strategy.append(("sse", url_with_sse))
            strategy.append(("http", url_with_sse))

        exceptions: list[Exception] = []
        for protocol, url in strategy:
            try:
                server_config.type = protocol
                server_config.url = url
                logger.debug(f"Trying {protocol} with url: {url}")
                result = await asyncio.wait_for(
                    _check_server_pass(server_config, timeout, traffic_capture, token), timeout
                )
                logger.debug("Server check completed within timeout")
                return result, server_config
            except asyncio.TimeoutError as e:
                logger.debug("Server check timed out")
                exceptions.append(e)
                continue
            except Exception as e:
                logger.debug("Server check failed")
                exceptions.append(e)
                continue

        # if python 3.11 or higher, use ExceptionGroup
        if sys.version_info >= (3, 11):
            raise ExceptionGroup("Could not connect to remote server", exceptions)  # noqa: F821
        else:
            raise Exception("Could not connect to remote server.") from exceptions[0]


async def scan_mcp_config_file(path: str) -> MCPConfig:
    logger.info("Scanning MCP config file: %s", path)
    path = os.path.expanduser(path)
    logger.debug("Expanded path: %s", path)

    def parse_and_validate(config: dict) -> MCPConfig:
        logger.debug("Parsing and validating config")
        models: list[type[MCPConfig]] = [
            ClaudeConfigFile,  # used by most clients
            VSCodeConfigFile,  # used by vscode settings.json
            VSCodeMCPConfig,  # used by vscode mcp.json
            UnknownMCPConfig,  # used by unknown config files
        ]
        for model in models:
            try:
                logger.debug("Trying to validate with model: %s", model.__name__)
                return model.model_validate(config)
            except Exception:
                logger.debug("Validation with %s failed", model.__name__)
        error_msg = "Could not parse config file as any of " + str([model.__name__ for model in models])
        raise Exception(error_msg)

    try:
        logger.debug("Opening config file")
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            content = f.read()
        logger.debug("Config file read successfully")

        # if content is empty, return an empty MCPConfig
        if content is None or content.strip() == "" or not content:
            logger.warning("Config file is empty")
            return parse_and_validate({})

        # use json5 to support comments as in vscode
        config = pyjson5.loads(content)
        logger.debug("Config JSON parsed successfully")

        # try to parse model
        result = parse_and_validate(config)
        logger.info("Config file parsed and validated successfully")
        return result
    except Exception:
        logger.exception("Error processing config file")
        raise


def inspect_skill(config: SkillServer) -> ServerSignature:
    logger.info(f"Scanning skill at path: {config.path}")
    with open(os.path.expanduser(os.path.join(config.path, "SKILL.md")), encoding="utf-8") as f:
        content = f.read()
    logger.debug("Skill file read successfully")

    # parse SKILL.md file
    content_chunks = content.split("---")
    if len(content_chunks) <= 2:
        raise Exception(
            f"Invalid SKILL.md file: {config.path}. Could not find the YAML and the MD parts in the SKILL.md file."
        )
    yaml_content = content_chunks[1].strip()
    text_content = "---".join(content_chunks[2:])

    yaml_data = yaml.safe_load(yaml_content)
    if "name" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing name in the YAML frontmatter.")
    name = yaml_data["name"]
    if "description" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing description in the YAML frontmatter.")
    description = yaml_data["description"]
    base_prompt = Prompt(
        name="SKILL.md",
        description=text_content,
        arguments=[],
    )
    prompts, resources, tools = traverse_skill_tree(config.path, None)
    return ServerSignature(
        metadata=InitializeResult(
            protocolVersion="built-in",
            instructions=description,
            capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
            prompts=PromptsCapability(listChanged=False),
            resources=ResourcesCapability(listChanged=False),
            serverInfo=Implementation(name=name, version="skills"),
        ),
        prompts=[base_prompt, *prompts],
        resources=resources,
        tools=tools,
    )
    # skill tree traversal


def traverse_skill_tree(skill_path: str, relative_path: str | None) -> tuple[list[Prompt], list[Resource], list[Tool]]:
    path = os.path.join(skill_path, relative_path) if relative_path else skill_path

    prompts: list[Prompt] = []
    resources: list[Resource] = []
    tools: list[Tool] = []

    for file in os.listdir(os.path.expanduser(path)):
        full_path = os.path.join(path, file)
        relative_full_path = os.path.join(relative_path, file) if relative_path else file
        if os.path.isdir(os.path.expanduser(full_path)):
            prompts_sub, resources_sub, tools_sub = traverse_skill_tree(skill_path, relative_full_path)
            prompts.extend(prompts_sub)
            resources.extend(resources_sub)
            tools.extend(tools_sub)
            continue
        elif file == "SKILL.md" and not relative_path:
            continue

        elif file.endswith(".md"):
            with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                content = f.read()
                prompts.append(
                    Prompt(
                        name=os.path.join(relative_path or "", file),
                        description=content,
                    )
                )

        elif file.split(".")[-1] in ["py", "js", "ts", "sh"]:
            with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                code = f.read()
            tools.append(
                Tool(
                    name=file,
                    description=f"Script: {file}. Code:\n{code or 'No code available'}",
                    inputSchema={},
                    outputSchema=None,
                    annotations=None,
                )
            )

        else:
            try:
                with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                logger.exception(f"Error reading file: {file}. The file is not a bianry")
                content = "Binary file. No content available."
            resources.append(
                Resource(
                    name=file,
                    uri=f"skill://{relative_full_path.replace(os.path.sep, '/')}",
                    description=content,
                )
            )

    return prompts, resources, tools


def inspect_skills_dir(path: str) -> list[tuple[str, SkillServer]]:
    logger.info("Scanning skills dir: %s", path)

    candidate_skills_dirs = os.listdir(os.path.expanduser(path))
    skills_servers: list[tuple[str, SkillServer]] = []
    for candidate_skills_dir in candidate_skills_dirs:
        if os.path.isdir(os.path.expanduser(os.path.join(path, candidate_skills_dir))) and os.path.exists(
            os.path.expanduser(os.path.join(path, candidate_skills_dir, "SKILL.md"))
        ):
            skills_servers.append((candidate_skills_dir, SkillServer(path=os.path.join(path, candidate_skills_dir))))
    logger.info("Found %d skills servers", len(skills_servers))
    return skills_servers
