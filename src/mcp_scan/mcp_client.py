import asyncio
import logging
import os
from typing import AsyncContextManager  # noqa: UP035

import aiofiles  # type: ignore
import pyjson5
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.types import Prompt, Resource, Tool

from mcp_scan.models import (
    ClaudeConfigFile,
    MCPConfig,
    SSEServer,
    StdioServer,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)

from .suppressIO import SuppressStd
from .utils import rebalance_command_args

# Set up logger for this module
logger = logging.getLogger(__name__)


async def check_server(
    server_config: SSEServer | StdioServer, timeout: int, suppress_mcpserver_io: bool
) -> tuple[list[Prompt], list[Resource], list[Tool]]:
    logger.info("Checking server with config: %s, timeout: %s", server_config, timeout)

    def get_client(server_config: SSEServer | StdioServer) -> AsyncContextManager:
        if isinstance(server_config, SSEServer):
            logger.debug("Creating SSE client with URL: %s", server_config.url)
            return sse_client(
                url=server_config.url,
                headers=server_config.headers,
                # env=server_config.env, #Not supported by MCP yet, but present in vscode
                timeout=timeout,
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
            return stdio_client(server_params)

    async def _check_server() -> tuple[list[Prompt], list[Resource], list[Tool]]:
        logger.info("Initializing server connection")
        async with get_client(server_config) as (read, write):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                logger.debug("Server initialized with metadata: %s", meta)
                # for see servers we need to check the announced capabilities
                prompts: list[Prompt] = []
                resources: list[Resource] = []
                tools: list[Tool] = []
                if not isinstance(server_config, SSEServer) or meta.capabilities.prompts:
                    logger.debug("Fetching prompts")
                    try:
                        prompts = (await session.list_prompts()).prompts
                        logger.debug("Found %d prompts", len(prompts))
                    except Exception:
                        logger.exception("Failed to list prompts")

                if not isinstance(server_config, SSEServer) or meta.capabilities.resources:
                    logger.debug("Fetching resources")
                    try:
                        resources = (await session.list_resources()).resources
                        logger.debug("Found %d resources", len(resources))
                    except Exception:
                        logger.exception("Failed to list resources")
                if not isinstance(server_config, SSEServer) or meta.capabilities.tools:
                    logger.debug("Fetching tools")
                    try:
                        tools = (await session.list_tools()).tools
                        logger.debug("Found %d tools", len(tools))
                    except Exception:
                        logger.exception("Failed to list tools")
                logger.info("Server check completed successfully")
                return prompts, resources, tools

    if suppress_mcpserver_io:
        logger.debug("Suppressing MCP server IO")
        with SuppressStd():
            return await _check_server()
    else:
        return await _check_server()


async def check_server_with_timeout(
    server_config: SSEServer | StdioServer,
    timeout: int,
    suppress_mcpserver_io: bool,
) -> tuple[list[Prompt], list[Resource], list[Tool]]:
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
        async with aiofiles.open(path) as f:
            content = await f.read()
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
