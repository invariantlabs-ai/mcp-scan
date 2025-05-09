import random

from mcp.server.fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Single Tool Server")


@mcp.tool()
def weather(location: str) -> str:
    """Get current weather for a location."""
    return random.choice(["Sunny", "Rainy", "Cloudy", "Snowy", "Windy"])

if __name__ == "__main__":
    mcp.run()
