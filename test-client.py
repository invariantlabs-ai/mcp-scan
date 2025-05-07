import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CONFIG_PATH = Path("/Users/luca/.cursor/mcp.json")
SERVER_KEY = "whatsapp-mcp"


def load_server_params(key: str) -> StdioServerParameters:
    config = json.loads(CONFIG_PATH.read_text())
    server_cfg = config["mcpServers"][key]
    return StdioServerParameters(
        command=server_cfg["command"], args=server_cfg.get("args", []), env=server_cfg.get("env", {})
    )


async def run():
    await asyncio.sleep(1)
    server_params = load_server_params(SERVER_KEY)
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()

            (
                await session.call_tool(
                    "list_chats", arguments={"limit": 20, "include_last_message": True, "sort_by": "last_active"}
                ),
            )
            await asyncio.sleep(0.2)

            await session.call_tool("send_message", arguments={"chat_id": "123", "message": "Hello, world!"})
            await asyncio.sleep(0.2)


if __name__ == "__main__":
    asyncio.run(run())
