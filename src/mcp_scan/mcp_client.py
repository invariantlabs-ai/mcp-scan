import asyncio
import os
from typing import AsyncContextManager, Type

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


async def check_server(
    server_config: SSEServer | StdioServer, timeout: int, suppress_mcpserver_io: bool
) -> tuple[list[Prompt], list[Resource], list[Tool]]:

    def get_client(server_config: SSEServer | StdioServer) -> AsyncContextManager:
        if isinstance(server_config, SSEServer):
            return sse_client(
                url=server_config.url,
                headers=server_config.headers,
                # env=server_config.env, #Not supported by MCP yet, but present in vscode
                timeout=timeout,
            )
        else:
            # handle complex configs
            command, args = rebalance_command_args(server_config.command, server_config.args)
            server_params = StdioServerParameters(
                command=command,
                args=args,
                env=server_config.env,
            )
            return stdio_client(server_params)

    async def _check_server() -> tuple[list[Prompt], list[Resource], list[Tool]]:
        async with get_client(server_config) as (read, write):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                # for see servers we need to check the announced capabilities
                prompts: list[Prompt] = []
                resources: list[Resource] = []
                tools: list[Tool] = []
                if not isinstance(server_config, SSEServer) or meta.capabilities.prompts:
                    try:
                        prompts = (await session.list_prompts()).prompts
                    except Exception:
                        pass

                if not isinstance(server_config, SSEServer) or meta.capabilities.resources:
                    try:
                        resources = (await session.list_resources()).resources
                    except Exception:
                        pass
                if not isinstance(server_config, SSEServer) or meta.capabilities.tools:
                    try:
                        tools = (await session.list_tools()).tools
                    except Exception:
                        pass
                return prompts, resources, tools

    if suppress_mcpserver_io:
        with SuppressStd():
            return await _check_server()
    else:
        return await _check_server()


async def check_server_with_timeout(
    server_config: SSEServer | StdioServer,
    timeout: int,
    suppress_mcpserver_io: bool,
) -> tuple[list[Prompt], list[Resource], list[Tool]]:
    return await asyncio.wait_for(check_server(server_config, timeout, suppress_mcpserver_io), timeout)


def scan_mcp_config_file(path: str) -> MCPConfig:
    path = os.path.expanduser(path)

    def parse_and_validate(config: dict) -> MCPConfig:
        models: list[Type[MCPConfig]] = [
            ClaudeConfigFile,  # used by most clients
            VSCodeConfigFile,  # used by vscode settings.json
            VSCodeMCPConfig,  # used by vscode mcp.json
        ]
        errors = []
        for model in models:
            try:
                return model.model_validate(config)
            except Exception as e:
                errors.append(e)
        if len(errors) > 0:
            raise Exception(
                "Could not parse config file as any of "
                + str([model.__name__ for model in models])
                + "\nErrors:\n"
                + "\n".join([str(e) for e in errors])
            )
        raise Exception("Could not parse config file")

    with open(path, "r") as f:
        # use json5 to support comments as in vscode
        config = pyjson5.load(f)
        # try to parse model
        return parse_and_validate(config)
