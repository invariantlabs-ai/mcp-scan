import argparse
import asyncio
import json
import sys

import psutil
import rich

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller
from mcp_scan_server.server import MCPScanServer

from .MCPScanner import MCPScanner
from .printer import print_scan_result
from .StorageFile import StorageFile
from .version import version_info


def get_invoking_name():
    try:
        parent = psutil.Process().parent()
        cmd = parent.cmdline()
        argv = sys.argv[1:]
        # remove args that are in argv from cmd
        for i in range(len(argv)):
            if cmd[-1] == argv[-i]:
                cmd = cmd[:-1]
            else:
                break
        cmd = " ".join(cmd)
    except Exception:
        cmd = "mcp-scan"
    return cmd


def str2bool(v: str) -> bool:
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


def add_common_arguments(parser):
    """Add arguments that are common to multiple commands."""
    parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to store scan results and whitelist information",
        metavar="FILE",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="https://mcp.invariantlabs.ai/",
        help="Base URL for the verification server",
        metavar="URL",
    )


def add_server_arguments(parser):
    """Add arguments related to MCP server connections."""
    server_group = parser.add_argument_group("MCP Server Options")
    server_group.add_argument(
        "--server-timeout",
        type=float,
        default=10,
        help="Seconds to wait before timing out server connections (default: 10)",
        metavar="SECONDS",
    )
    server_group.add_argument(
        "--suppress-mcpserver-io",
        default=True,
        type=str2bool,
        help="Suppress stdout/stderr from MCP servers (default: True)",
        metavar="BOOL",
    )


def check_install_args(args):
    if args.command == "install" and not args.local_only and not args.api_key:
        raise argparse.ArgumentError(None, "argument --api-key is required when --local-only is not set")


async def main():
    # Create main parser with description
    program_name = get_invoking_name()
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="MCP-scan: Security scanner for Model Context Protocol servers and tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {program_name}                     # Scan all known MCP configs\n"
            f"  {program_name} ~/custom/config.json # Scan a specific config file\n"
            f"  {program_name} inspect             # Just inspect tools without verification\n"
            f"  {program_name} whitelist           # View whitelisted tools\n"
            f'  {program_name} whitelist tool "add" "a1b2c3..." # Whitelist the \'add\' tool\n'
        ),
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands (default: scan)",
        metavar="COMMAND",
    )

    # SCAN command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan MCP servers for security issues [default]",
        description="Scan MCP configurations for security vulnerabilities in tools, prompts, and resources.",
    )
    add_common_arguments(scan_parser)
    add_server_arguments(scan_parser)
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="Number of checks to perform on each server (default: 1)",
        metavar="NUM",
    )
    scan_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help="Configuration files to scan (default: known MCP config locations)",
        metavar="CONFIG_FILE",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format in non-interactive mode",
    )

    # INSPECT command
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Print descriptions of tools, prompts, and resources without verification",
        description="Inspect and display MCP tools, prompts, and resources without security verification.",
    )
    add_common_arguments(inspect_parser)
    add_server_arguments(inspect_parser)
    inspect_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help="Configuration files to inspect (default: known MCP config locations)",
        metavar="CONFIG_FILE",
    )
    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format in non-interactive mode",
    )

    # WHITELIST command
    whitelist_parser = subparsers.add_parser(
        "whitelist",
        help="Manage the whitelist of approved entities",
        description=(
            "View, add, or reset whitelisted entities. " "Whitelisted entities bypass security checks during scans."
        ),
    )
    add_common_arguments(whitelist_parser)

    whitelist_group = whitelist_parser.add_argument_group("Whitelist Options")
    whitelist_group.add_argument(
        "--reset",
        default=False,
        action="store_true",
        help="Reset the entire whitelist",
    )
    whitelist_group.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Only update local whitelist, don't contribute to global whitelist",
    )

    whitelist_parser.add_argument(
        "type",
        type=str,
        choices=["tool", "prompt", "resource"],
        default="tool",
        nargs="?",
        help="Type of entity to whitelist (default: tool)",
        metavar="TYPE",
    )
    whitelist_parser.add_argument(
        "name",
        type=str,
        default=None,
        nargs="?",
        help="Name of the entity to whitelist",
        metavar="NAME",
    )
    whitelist_parser.add_argument(
        "hash",
        type=str,
        default=None,
        nargs="?",
        help="Hash of the entity to whitelist",
        metavar="HASH",
    )
    # install
    install_parser = subparsers.add_parser("install", help="Install Invariant Gateway")
    install_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help=(
            "Different file locations to scan. "
            "This can include custom file locations as long as "
            "they are in an expected format, including Claude, "
            "Cursor or VSCode format."
        ),
    )
    install_parser.add_argument(
        "--project_name",
        type=str,
        default="mcp-gateway",
        help="Project name for the Invariant Gateway",
    )
    install_parser.add_argument(
        "--api-key",
        type=str,
        help="API key for the Invariant Gateway",
    )
    install_parser.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Prevent pushing traces to the explorer.",
    )
    install_parser.add_argument(
        "--mcp-scan-server-port",
        type=int,
        default=8000,
        help="MCP scan server port (default: 8000).",
        metavar="PORT",
    )

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall Invariant Gateway")
    uninstall_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help=(
            "Different file locations to scan. "
            "This can include custom file locations as long as "
            "they are in an expected format, including Claude, Cursor or VSCode format."
        ),
    )

    # HELP command
    help_parser = subparsers.add_parser(  # noqa: F841
        "help",
        help="Show detailed help information",
        description="Display detailed help information and examples.",
    )

    # SERVER command
    server_parser = subparsers.add_parser("server", help="Start the MCP scan server")
    server_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the server on (default: 8000)",
        metavar="PORT",
    )
    add_common_arguments(server_parser)

    # Parse arguments (default to 'scan' if no command provided)
    args = parser.parse_args(["scan"] if len(sys.argv) == 1 else None)

    # Display version banner
    if not args.json:
        rich.print(f"[bold blue]Invariant MCP-scan v{version_info}[/bold blue]\n")

    # Handle commands
    if args.command == "help":
        parser.print_help()
        sys.exit(0)
    elif args.command == "whitelist":
        sf = StorageFile(args.storage_file)
        if args.reset:
            sf.reset_whitelist()
            rich.print("[bold]Whitelist reset[/bold]")
            sys.exit(0)
        elif all(map(lambda x: x is None, [args.type, args.name, args.hash])):  # no args
            sf.print_whitelist()
            sys.exit(0)
        elif all(map(lambda x: x is not None, [args.type, args.name, args.hash])):
            sf.add_to_whitelist(
                args.type,
                args.name,
                args.hash,
                base_url=args.base_url if not args.local_only else None,
            )
            sf.print_whitelist()
            sys.exit(0)
        else:
            rich.print("[bold red]Please provide all three parameters: type, name, and hash.[/bold red]")
            whitelist_parser.print_help()
            sys.exit(1)
    elif args.command == "inspect":
        result = await MCPScanner(**vars(args)).inspect()
        if args.json:
            result = dict((r.path, r.model_dump()) for r in result)
            print(json.dumps(result, indent=2))
        else:
            print_scan_result(result)
        sys.exit(0)
    elif args.command == "install":
        try:
            check_install_args(args)
        except argparse.ArgumentError as e:
            parser.error(e)

        invariant_api_url = (
            f"http://localhost:{args.mcp_scan_server_port}" if args.local_only else "https://explorer.invariantlabs.ai"
        )
        installer = MCPGatewayInstaller(paths=args.files, invariant_api_url=invariant_api_url)
        installer.install(
            gateway_config=MCPGatewayConfig(
                project_name=args.project_name,
                push_explorer=not args.local_only,
                api_key=args.api_key or "",
            ),
            verbose=True,
        )
        # install logic here
    elif args.command == "uninstall":
        installer = MCPGatewayInstaller(paths=args.files)
        installer.uninstall(verbose=True)
        # uninstall logic here
    elif args.command == "whitelist":
        if args.reset:
            MCPScanner(**vars(args)).reset_whitelist()
            sys.exit(0)
        elif all(map(lambda x: x is None, [args.name, args.hash])):  # no args
            MCPScanner(**vars(args)).print_whitelist()
            sys.exit(0)
        elif all(map(lambda x: x is not None, [args.name, args.hash])):
            MCPScanner(**vars(args)).whitelist(args.name, args.hash, args.local_only)
            MCPScanner(**vars(args)).print_whitelist()
            sys.exit(0)
        else:
            rich.print("[bold red]Please provide a name and hash.[/bold red]")
            sys.exit(1)
    elif args.command == "scan" or args.command is None:  # default to scan
        async with MCPScanner(**vars(args)) as scanner:
            # scanner.hook('path_scanned', print_path_scanned)
            result = await scanner.scan()
        if args.json:
            result = dict((r.path, r.model_dump()) for r in result)
            print(json.dumps(result, indent=2))
        else:
            print_scan_result(result)
        sys.exit(0)
    elif args.command == "server":
        sf = StorageFile(args.storage_file)
        guardrails_config_path = sf.create_guardrails_config()
        mcp_scan_server = MCPScanServer(port=args.port, config_file_path=guardrails_config_path)
        mcp_scan_server.run()
        sys.exit(0)
    elif args.command == "server":
        sf = StorageFile(args.storage_file)
        guardrails_config_path = sf.create_guardrails_config()
        mcp_scan_server = MCPScanServer(port=args.port, config_file_path=guardrails_config_path)
        mcp_scan_server.run()
        sys.exit(0)
    else:
        # This shouldn't happen due to argparse's handling
        rich.print(f"[bold red]Unknown command: {args.command}[/bold red]")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
