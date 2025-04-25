from mcp.server.fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Demo")


# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


# Add a subtraction tool
@mcp.tool()
def subtract(a: int, b: int) -> int:
    """Subtract two numbers."""
    return a - b


# Add a multiplication tool
@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b


# Add a division tool
@mcp.tool()
def divide(a: int, b: int) -> int:
    """Divide two numbers."""
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a // b


if __name__ == "__main__":
    mcp.run()
