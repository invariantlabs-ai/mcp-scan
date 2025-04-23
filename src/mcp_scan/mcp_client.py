from .utils import rebalance_command_args
from .suppressIO import SuppressStd
from .models import (
    SSEServer,
    StdioServer,
    VSCodeConfigFile,
    VSCodeMCPConfig,
    ClaudeConfigFile
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
import asyncio
import pyjson5
import os

async def check_server(
    server_config: SSEServer | StdioServer, timeout, suppress_mcpserver_io
):
    is_sse = isinstance(server_config, SSEServer)

    def get_client(server_config):
        if is_sse:
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

    async def _check_server():
        async with get_client(server_config) as (read, write):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                # for see servers we need to check the announced capabilities
                if not is_sse or meta.capabilities.prompts.supported:
                    try:
                        prompts = await session.list_prompts()
                        prompts = list(prompts.prompts)
                    except:
                        prompts = []
                else:
                    prompts = []
                if not is_sse or meta.capabilities.resources.supported:
                    try:
                        resources = await session.list_resources()
                        resources = list(resources.resources)
                    except:
                        resources = []
                else:
                    resources = []
                if not is_sse or meta.capabilities.tools.supported:
                    try:
                        tools = await session.list_tools()
                        tools = list(tools.tools)
                    except:
                        tools = []
                else:
                    tools = []
                return prompts, resources, tools

    if suppress_mcpserver_io:
        with SuppressStd():
            return await _check_server()
    else:
        return await _check_server()


async def check_server_with_timeout(server_config, timeout, suppress_mcpserver_io):
    return await asyncio.wait_for(
        check_server(server_config, timeout, suppress_mcpserver_io), timeout
    )

def scan_mcp_config_file(path):
    path = os.path.expanduser(path)

    def parse_and_validate(config):
        models = [
            ClaudeConfigFile,  # used by most clients
            VSCodeConfigFile,  # used by vscode settings.json
            VSCodeMCPConfig,  # used by vscode mcp.json
        ]
        errors = []
        for model in models:
            try:
                return model.parse_obj(config)
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
        model = parse_and_validate(config)
        if isinstance(model, VSCodeConfigFile):
            servers = model.mcp.servers
        elif isinstance(model, VSCodeMCPConfig):
            servers = model.servers
        elif isinstance(model, ClaudeConfigFile):
            servers = model.mcpServers
        else:
            assert False
        return servers

