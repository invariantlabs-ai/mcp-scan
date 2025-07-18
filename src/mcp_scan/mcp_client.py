import asyncio
import logging
import os
import subprocess
from contextlib import asynccontextmanager
from typing import AsyncContextManager  # noqa: UP035

import pyjson5
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from mcp_scan.models import (
    ClaudeConfigFile,
    MCPConfig,
    ServerSignature,
    SSEServer,
    StdioServer,
    StreamableHTTPServer,
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
    server_config: SSEServer | StdioServer | StreamableHTTPServer, timeout: int | None = None, verbose: bool = False
) -> AsyncContextManager:
    if isinstance(server_config, SSEServer):
        logger.debug("Creating SSE client with URL: %s", server_config.url)
        return sse_client(
            url=server_config.url,
            headers=server_config.headers,
            # env=server_config.env, #Not supported by MCP yet, but present in vscode
            timeout=timeout,
        )
    elif isinstance(server_config, StreamableHTTPServer):
        logger.debug(
            "Creating Streamable HTTP client with URL: %s with headers %s", server_config.url, server_config.headers
        )

        return streamablehttp_client_without_session(
            url=server_config.url,
            headers=server_config.headers,
        )
    else:
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


async def check_server(
    server_config: SSEServer | StdioServer | StreamableHTTPServer, timeout: int, suppress_mcpserver_io: bool
) -> ServerSignature:
    logger.info("Checking server with config: %s, timeout: %s", server_config, timeout)

    async def _check_server(verbose: bool) -> ServerSignature:
        logger.info("Initializing server connection")
        async with get_client(server_config, timeout=timeout, verbose=verbose) as (read, write):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                logger.debug("Server initialized with metadata: %s", meta)
                # for see servers we need to check the announced capabilities
                prompts: list = []
                resources: list = []
                tools: list = []
                logger.debug(f"Server capabilities: {meta.capabilities}")
                if isinstance(server_config, StdioServer) or meta.capabilities.prompts:
                    logger.debug("Fetching prompts")
                    try:
                        prompts += (await session.list_prompts()).prompts
                        logger.debug("Found %d prompts", len(prompts))
                    except Exception:
                        logger.exception("Failed to list prompts")

                if isinstance(server_config, StdioServer) or meta.capabilities.resources:
                    logger.debug("Fetching resources")
                    try:
                        resources += (await session.list_resources()).resources
                        logger.debug("Found %d resources", len(resources))
                    except Exception:
                        logger.exception("Failed to list resources")
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
                    tools=tools,
                )

    return await _check_server(verbose=not suppress_mcpserver_io)


async def check_server_with_timeout(
    server_config: SSEServer | StdioServer | StreamableHTTPServer,
    timeout: int,
    suppress_mcpserver_io: bool,
) -> ServerSignature:
    logger.debug("Checking server with timeout: %s seconds", timeout)
    try:
        result = await asyncio.wait_for(check_server(server_config, timeout, suppress_mcpserver_io), timeout)
        logger.debug("Server check completed within timeout")
        return result
    except asyncio.TimeoutError:
        logger.exception("Server check timed out after %s seconds", timeout)
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
