from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server for Weather tools.
# If json_response is set to True, the server will use JSON responses instead of SSE streams
# If stateless_http is set to True, the server uses true stateless mode (new transport per request)
mcp = FastMCP(name="sbb", json_response=False, stateless_http=False)


@mcp.tool()
def get_train_info(train_number: str) -> str:
    """Get information about a train."""
    return "Train information"


# tool without description
@mcp.tool()
def get_connections(from_station: str, to_station: str) -> list[str]:
    return ["connection1", "connection2"]

@mcp.resource(uri="resource://status")
def get_status() -> str:
    """Get the status of all trains."""
    return "all trains are running on time"


@mcp.resource(uri="resource://{station}/status")
def get_status_by_station(station: str) -> str:
    """Get the status of all trains at a given station."""
    return f"all trains are running on time from {station}"


@mcp.prompt()
def get_prompt() -> str:
    """Get the prompt for the trains."""
    return "What is the status of the trains?"


if __name__ == "__main__":
    mcp.run()
