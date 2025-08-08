"""MCP Server that can be used either as sse or streamable_http."""

import argparse

import uvicorn
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server for Weather tools.
# If json_response is set to True, the server will use JSON responses instead of SSE streams
# If stateless_http is set to True, the server uses true stateless mode (new transport per request)
mcp = FastMCP(name="prime_numbers", json_response=False, stateless_http=False)


@mcp.tool()
def is_prime(n: int) -> bool:
    """Return True if n is a prime number, False otherwise.

    Args:
        n: integer to check for primality
    """
    if n < 2:
        return False
    return all(n % i != 0 for i in range(2, int(n**0.5) + 1))


@mcp.tool()
def gcd(val1: int, val2: int) -> int:
    """Calculate the greatest common divisor (GCD) of two integers."""
    while val2:
        val1, val2 = val2, val1 % val2
    return abs(val1)


@mcp.tool()
def lcm(val1: int, val2: int) -> int:
    """Calculate the least common multiple (LCM) of two integers."""
    if val1 == 0 or val2 == 0:
        return 0
    return abs(val1 * val2) // gcd(val1, val2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Streamable HTTP based server")
    parser.add_argument("--port", type=int, default=8123, help="Localhost port to listen on")
    parser.add_argument(
        "--transport",
        type=str,
        default="streamable_http",
    )
    args = parser.parse_args()
    if args.transport not in ["sse", "stdio", "streamable_http"]:
        raise ValueError("Invalid transport type. Choose from 'sse', 'stdio', or 'streamable_http'.")
    if args.transport == "sse":
        uvicorn.run(mcp.sse_app, host="localhost", port=args.port)
    elif args.transport == "streamable_http":
        uvicorn.run(mcp.streamable_http_app, host="localhost", port=args.port)
    elif args.transport == "stdio":
        mcp.run()
