import asyncio
import logging
import os
import shutil
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import pyjson5
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Implementation, InitializeResult, ServerCapabilities, ToolsCapability

from mcp_scan.models import (
    ClaudeConfigFile,
    MCPConfig,
    RemoteServer,
    ServerSignature,
    StaticToolsServer,
    StdioServer,
    UnknownMCPConfig,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)
from mcp_scan.traffic_capture import PipeStderrCapture, TrafficCapture, capturing_client
from mcp_scan.utils import rebalance_command_args

# Set up logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def streamablehttp_client_without_session(*args, **kwargs):
    async with streamablehttp_client(*args, **kwargs) as (read, write, _):
        yield read, write


def check_executable_exists(command: str) -> bool:
    path = Path(command)
    return path.exists() or shutil.which(command) is not None


@asynccontextmanager
async def get_client(
    server_config: StdioServer | RemoteServer,
    timeout: int | None = None,
    traffic_capture: TrafficCapture | None = None,
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
            timeout=timeout,
        )
    elif isinstance(server_config, StdioServer):
        logger.debug("Creating stdio client")

        # check if command points to an executable and wether it exists absolute or on the path
        if not check_executable_exists(server_config.command):
            # attempt to rebalance the command/arg structure
            logger.debug(f"Command does not exist: {server_config.command}, attempting to rebalance")
            command, args = rebalance_command_args(server_config.command, server_config.args)
            if not check_executable_exists(command):
                logger.warning(f"Path does not exist: {command}")
                raise ValueError(f"Path does not exist: {command}")
        else:
            command = server_config.command
            args = server_config.args

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

        async with get_client(server_config, timeout=timeout, traffic_capture=traffic_capture) as (read, write):
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
) -> ServerSignature:
    logger.debug("Checking server with timeout: %s seconds", timeout)

    if not isinstance(server_config, RemoteServer):
        result = await asyncio.wait_for(_check_server_pass(server_config, timeout, traffic_capture), timeout)
        logger.debug("Server check completed within timeout")
        return result
    else:
        logger.debug(f"Remote server with url: {server_config.url}, type: {server_config.type or 'none'}")
        strategy: list[tuple[Literal["sse", "http"], str]] = []
        url_path = urlparse(server_config.url).path
        has_sse_in_url = url_path.endswith("/sse")
        if has_sse_in_url:
            url_with_sse = server_config.url
            url_without_sse = server_config.url.replace("/sse", "")
        else:
            url_with_sse = server_config.url + "/sse"
            url_without_sse = server_config.url

        if server_config.type == "http" or server_config.type is None:
            strategy.append(("http", url_without_sse))
            strategy.append(("http", url_with_sse))
            strategy.append(("sse", url_with_sse))
            strategy.append(("sse", url_without_sse))
        else:
            strategy.append(("sse", url_with_sse))
            strategy.append(("sse", url_without_sse))
            strategy.append(("http", url_without_sse))
            strategy.append(("http", url_with_sse))

        exceptions: list[Exception] = []
        for protocol, url in strategy:
            try:
                server_config.type = protocol
                server_config.url = url
                logger.debug(f"Trying {protocol} with url: {url}")
                result = await asyncio.wait_for(_check_server_pass(server_config, timeout, traffic_capture), timeout)
                logger.debug("Server check completed within timeout")
                return result
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
        with open(path) as f:
            content = f.read()
        logger.debug("Config file read successfully")
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
