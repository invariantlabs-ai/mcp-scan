import re
import sys

if sys.platform == "linux" or sys.platform == "linux2":
    # Linux
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "vscode": ["~/.vscode/mcp.json", "~/.config/Code/User/settings.json"],
    }
    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
elif sys.platform == "darwin":
    # OS X
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "claude": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "vscode": ["~/.vscode/mcp.json", "~/Library/Application Support/Code/User/settings.json"],
    }
    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
elif sys.platform == "win32":
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "claude": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        "vscode": ["~/.vscode/mcp.json", "~/AppData/Roaming/Code/User/settings.json"],
    }

    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
else:
    WELL_KNOWN_MCP_PATHS = []


def get_client_from_path(path: str) -> str | None:
    """
    Returns the client name from a path.

    Args:
        path (str): The path to get the client from.

    Returns:
        str: The client name or None if it cannot be guessed from the path.
    """
    for client, paths in CLIENT_PATHS.items():
        if path in paths:
            return client
    return None


def client_shorthands_to_paths(shorthands: list[str]):
    """
    Converts a list of client shorthands to a list of paths.

    Does nothing if the shorthands are already paths.
    """
    paths = []
    if any(not re.match(r"^[A-z0-9_-]+$", shorthand) for shorthand in shorthands):
        return shorthands

    for shorthand in shorthands:
        if shorthand in CLIENT_PATHS:
            paths.extend(CLIENT_PATHS[shorthand])
        else:
            raise ValueError(f"{shorthand} is not a valid client shorthand")
    return paths
