import asyncio
from ctypes import LibraryLoader
import logging
import os
import subprocess
from contextlib import asynccontextmanager
from typing import AsyncContextManager, Literal  # noqa: UP035

import pyjson5
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from mcp_scan.models import (
    ClaudeConfigFile,
    MCPConfig,
    ServerSignature,
    StdioServer,
    RemoteServer,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)

from .utils import rebalance_command_args

# Set up logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def streamablehttp_client_without_session(*args, **kwargs):
    async with streamablehttp_client(*args, **kwargs) as (read, write, _):
        yield read, write


def get_client(
    server_config: StdioServer | RemoteServer, protocol: Literal["sse", "http", "stdio"], timeout: int | None = None, verbose: bool = False
) -> AsyncContextManager:
    if protocol == "sse":
        logger.debug("Creating SSE client with URL: %s", server_config.url)
        return sse_client(
            url=server_config.url,
            headers=server_config.headers,
            # env=server_config.env, #Not supported by MCP yet, but present in vscode
            timeout=timeout,
        )
    elif protocol == "http":
        logger.debug(
            "Creating Streamable HTTP client with URL: %s with headers %s", server_config.url, server_config.headers
        )

        return streamablehttp_client_without_session(
            url=server_config.url,
            headers=server_config.headers,
            timeout=timeout,
        )
    elif protocol == "stdio":
        logger.debug("Creating stdio client")
        # handle complex configs
        command, args = rebalance_command_args(server_config.command, server_config.args)
        logger.debug("Using command: %s, args: %s", command, args)
        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=server_config.env,
        )
        return stdio_client(server_params, errlog=subprocess.DEVNULL if not verbose else None)
    else:
        raise ValueError(f"Invalid protocol: {protocol}")


async def check_server(
    server_config: StdioServer | RemoteServer, protocol: Literal["sse", "http", "stdio"], timeout: int, suppress_mcpserver_io: bool
) -> ServerSignature:
    logger.info("Checking server with config: %s, timeout: %s", server_config, timeout)

    async def _check_server(verbose: bool) -> ServerSignature:
        logger.info("Initializing server connection")
        async with get_client(server_config, protocol, timeout=timeout, verbose=verbose) as (read, write):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                logger.debug("Server initialized with metadata: %s", meta)
                # for see servers we need to check the announced capabilities
                prompts: list = []
                resources: list = []
                resource_templates: list = []
                tools: list = []
                completions: list = []
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

    return await _check_server(verbose=not suppress_mcpserver_io)


async def check_server_with_timeout(
    server_config: StdioServer | RemoteServer,
    timeout: int,
    suppress_mcpserver_io: bool,
) -> ServerSignature:
    logger.debug("Checking server with timeout: %s seconds", timeout)
    retry = True
    protocols_tried = []
    while retry:
        retry = False
        try:
            if isinstance(server_config, StdioServer) or (isinstance(server_config, RemoteServer) and server_config.type is not None):
                protocol = server_config.type
            elif isinstance(server_config, RemoteServer) and server_config.type is None:
                if "http" not in protocols_tried:
                    protocol = "http"
                    logger.debug("Remote server with no type, trying http")
                else:
                    protocol = "sse"
                    logger.debug("Remote server with no type, trying sse")
            protocols_tried.append(protocol)

            result = await asyncio.wait_for(check_server(server_config, protocol, timeout, suppress_mcpserver_io), timeout)
            logger.debug("Server check completed within timeout")
            return result
        except asyncio.TimeoutError:
            logger.exception("Server check timed out after %s seconds", timeout)
            if isinstance(server_config, RemoteServer) and server_config.type is None and "http" in protocols_tried and "sse" not in protocols_tried:
                logger.debug("Scan with HTTP failed, retrying with SSE")
                retry = True
            else:
                raise


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
