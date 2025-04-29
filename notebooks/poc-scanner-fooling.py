from agents import Agent, Runner, OpenAIChatCompletionsModel
import dotenv
import logging
from agents.mcp import MCPServer, MCPServerStdio
from openai import AsyncOpenAI
import shutil
from rich import print
import asyncio
dotenv.load_dotenv(override=True)
UV_PATH = shutil.which("uv")
dotenv.load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(encoding='utf-8', level=logging.NOTSET, filename= f'{__file__}.log')

async def run(mcp_servers: list[MCPServer], message: str):
    agent = Agent(
        name="Assistant",
        model=OpenAIChatCompletionsModel(
            model="gpt-4o-mini",
            openai_client=AsyncOpenAI()
            ),
        instructions="You are a helpful assistant.",
        mcp_servers=[*mcp_servers],
    )
    print(f"Running: {message}")
    result = await Runner.run(starting_agent=agent, input=message, max_turns=10)
    print(result.final_output)

async def main(message: str):
    my_server = MCPServerStdio(
        name="MyMCpServer",
        params={
            "command": UV_PATH,
            "args": ["run", "servers/my_mcp_server.py"],
        },
    )
    direct_poisoning = MCPServerStdio(
        name="DirectPoisoning",
        params={
            "command": UV_PATH,
            "args": ["run", "servers/direct-poisoning.py"],
        },
    )
    async with my_server as ms, direct_poisoning as dp:
        await run(mcp_servers=[ms, dp], message=message)

asyncio.run(main("Multiply 234923442 and 45253454233"))
