import sys
import argparse
from .MCPScanner import MCPScanner
import rich
from .version import version_info


def str2bool(v):
    return v.lower() in ("true", "1", "t", "y", "yes")


if sys.platform == "linux" or sys.platform == "linux2":
    WELL_KNOWN_MCP_PATHS = [
        "~/.codeium/windsurf/mcp_config.json",  # windsurf
        "~/.cursor/mcp.json",  # cursor
        "~/.vscode/mcp.json",  # vscode
        "~/.config/Code/User/settings.json",  # vscode linux
    ]
elif sys.platform == "darwin":
    # OS X
    WELL_KNOWN_MCP_PATHS = [
        "~/.codeium/windsurf/mcp_config.json",  # windsurf
        "~/.cursor/mcp.json",  # cursor
        "~/Library/Application Support/Claude/claude_desktop_config.json",  # Claude Desktop mac
        "~/.vscode/mcp.json",  # vscode
        "~/Library/Application Support/Code/User/settings.json",  # vscode mac
    ]
elif sys.platform == "win32":
    WELL_KNOWN_MCP_PATHS = [
        "~/.codeium/windsurf/mcp_config.json",  # windsurf
        "~/.cursor/mcp.json",  # cursor
        "~/AppData/Roaming/Claude/claude_desktop_config.json",  # Claude Desktop windows
        "~/.vscode/mcp.json",  # vscode
        "~/AppData/Roaming/Code/User/settings.json",  # vscode windows
    ]
else:
    WELL_KNOWN_MCP_PATHS = []


def main():
    parser = argparse.ArgumentParser(description="MCP-scan CLI")
    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan MCP servers [default]")
    scan_parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to previous scan results",
    )
    scan_parser.add_argument(
        "--base-url",
        type=str,
        default="https://mcp.invariantlabs.ai/",
        help="Base URL for the checking server",
    )
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="Number of checks to perform on each server, values greater than 1 help catch non-deterministic behavior",
    )
    scan_parser.add_argument(
        "--server-timeout",
        type=float,
        default=10,
        help="Number of seconds to wait while trying a mcp server",
    )
    scan_parser.add_argument(
        "--suppress-mcpserver-io",
        default=True,
        type=str2bool,
        help="Suppress the output of the mcp server",
    )
    scan_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help="Different file locations to scan. This can include custom file locations as long as they are in an expected format, including Claude, Cursor or VSCode format.",
    )

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Print tool descriptions of installed tools")
    inspect_parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to previous scan results",
    )
    inspect_parser.add_argument(
        "--base-url",
        type=str,
        default="https://mcp.invariantlabs.ai/",
        help="Base URL for the checking server",
    )
    inspect_parser.add_argument(
        "--server-timeout",
        type=float,
        default=10,
        help="Number of seconds to wait while trying a mcp server",
    )
    inspect_parser.add_argument(
        "--suppress-mcpserver-io",
        default=True,
        type=str2bool,
        help="Suppress the output of the mcp server",
    )
    inspect_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help="Different file locations to scan. This can include custom file locations as long as they are in an expected format, including Claude, Cursor or VSCode format.",
    )
    
    # whitelist
    whitelist_parser = subparsers.add_parser("whitelist", help="Whitelist MCP tools")
    whitelist_parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to previous scan results",
    )
    whitelist_parser.add_argument(
        "--base-url",
        type=str,
        default="https://mcp.invariantlabs.ai/",
        help="Base URL for the checking server",
    )
    whitelist_parser.add_argument(
        "--reset",
        default=False,
        action="store_true",
        help="Reset the whitelist.",
    )
    whitelist_parser.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Do not contribute to the global whitelist.",
    )
    whitelist_parser.add_argument(
        "name",
        type=str,
        default=None,
        nargs="?",
        help="Tool name.",
    )
    whitelist_parser.add_argument(
        "hash",
        type=str,
        default=None,
        nargs="?",
        help="Tool hash.",
    )

    # help
    help_parser = subparsers.add_parser("help", help="Print this help message")

    rich.print("[bold blue]Invariant MCP-scan v{}[/bold blue]\n".format(version_info))

    # by default run in scan mode
    args = parser.parse_args(['scan'] if len(sys.argv) == 1 else None)
    
    if args.command == 'help':
        parser.print_help()
        sys.exit(0)
    elif args.command == 'inspect':
        MCPScanner(**vars(args)).inspect()
        sys.exit(0)
    elif args.command == 'whitelist':
        if args.reset:
            MCPScanner(**vars(args)).reset_whitelist()
            sys.exit(0)
        elif all(map(lambda x: x is None, [args.name, args.hash])): # no args
            MCPScanner(**vars(args)).print_whitelist()
            sys.exit(0)
        elif all(map(lambda x: x is not None, [args.name, args.hash])):
            MCPScanner(**vars(args)).whitelist(args.name, args.hash, args.local_only)
            MCPScanner(**vars(args)).print_whitelist()
            sys.exit(0)
        else:
            rich.print("[bold red]Please provide a name and hash.[/bold red]")
            sys.exit(1)
    elif args.command == 'scan' or args.command is None: # default to scan
        MCPScanner(**vars(args)).start()
        sys.exit(0)
    else:
        rich.print("[bold red]Unknown command: {}[/bold red]".format(args.command))
        sys.exit(1)

if __name__ == "__main__":
    main()
