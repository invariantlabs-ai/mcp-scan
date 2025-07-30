import argparse
import asyncio
import json
import logging
import sys

import psutil
import rich
from invariant.__main__ import add_extra
from rich.logging import RichHandler

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller
from mcp_scan.upload import upload
from mcp_scan_server.server import MCPScanServer

from .MCPScanner import MCPScanner
from .paths import WELL_KNOWN_MCP_PATHS, client_shorthands_to_paths
from .printer import print_scan_result
from .StorageFile import StorageFile
from .version import version_info

# Configure logging to suppress all output by default
logging.getLogger().setLevel(logging.CRITICAL + 1)  # Higher than any standard level
# Add null handler to prevent "No handler found" warnings
logging.getLogger().addHandler(logging.NullHandler())


def setup_logging(verbose=False):
    """Configure logging based on the verbose flag."""
    if verbose:
        # Configure the root logger
        root_logger = logging.getLogger()
        # Remove any existing handlers (including the NullHandler)
        for hdlr in root_logger.handlers:
            root_logger.removeHandler(hdlr)
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            force=True,
            level=logging.DEBUG,
            handlers=[RichHandler(markup=True, rich_tracebacks=True)],
        )

        # Log that verbose mode is enabled
        root_logger.debug("Verbose mode enabled, logging initialized")


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
    parser.add_argument(
        "--verbose",
        default=False,
        action="store_true",
        help="Enable detailed logging output",
    )
    parser.add_argument(
        "--print-errors",
        default=False,
        action="store_true",
        help="Show error details and tracebacks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results in JSON format instead of rich text",
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
    server_group.add_argument(
        "--pretty",
        type=str,
        default="compact",
        choices=["oneline", "compact", "full", "none"],
        help="Pretty print the output (default: compact)",
    )
    server_group.add_argument(
        "--install-extras",
        nargs="+",
        default=None,
        help="Install extras for the Invariant Gateway - use 'all' or a space-separated list of extras",
        metavar="EXTRA",
    )


def add_install_arguments(parser):
    parser.add_argument(
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
    parser.add_argument(
        "--project_name",
        type=str,
        default="mcp-gateway",
        help="Project name for the Invariant Gateway",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="API key for the Invariant Gateway",
    )
    parser.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Prevent pushing traces to the explorer.",
    )
    parser.add_argument(
        "--gateway-dir",
        type=str,
        help="Source directory for the Invariant Gateway. Set this, if you want to install a custom gateway implementation. (default: the published package is used).",
        default=None,
    )
    parser.add_argument(
        "--mcp-scan-server-port",
        type=int,
        default=8129,
        help="MCP scan server port (default: 8129).",
        metavar="PORT",
    )


def add_uninstall_arguments(parser):
    parser.add_argument(
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


def check_install_args(args):
    if args.command == "install" and not args.local_only and not args.api_key:
        # prompt for api key
        print(
            "To install mcp-scan with remote logging, you need an Invariant API key (https://explorer.invariantlabs.ai/settings).\n"
        )
        args.api_key = input("API key (or just press enter to install with --local-only): ")
        if not args.api_key:
            args.local_only = True


def install_extras(args):
    if hasattr(args, "install_extras") and args.install_extras:
        add_extra(*args.install_extras, "-y")


def main():
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
            f"  {program_name} --verbose           # Enable detailed logging output\n"
            f"  {program_name} --print-errors      # Show error details and tracebacks\n"
            f"  {program_name} --json              # Output results in JSON format\n"
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
        help="Scan one or more MCP config files [default]",
        description=(
            "Scan one or more MCP configuration files for security issues. "
            "If no files are specified, well-known config locations will be checked."
        ),
    )
    scan_parser.add_argument(
        "files",
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help="Path(s) to MCP config file(s). If not provided, well-known paths will be checked",
        metavar="CONFIG_FILE",
    )
    add_common_arguments(scan_parser)
    add_server_arguments(scan_parser)
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="Number of times to check each server (default: 1)",
        metavar="NUM",
    )
    scan_parser.add_argument(
        "--full-toxic-flows",
        default=False,
        action="store_true",
        help="Show all tools in the toxic flows, by default only the first 3 are shown.",
    )
    scan_parser.add_argument(
        "--control-server",
        default=False,
        help="Upload the scan results to the provided control server URL (default: Do not upload)",
    )
    scan_parser.add_argument(
        "--push-key",
        default=False,
        help="When uploading the scan results to the provided control server URL, pass the push key (default: Do not upload)",
    )
    scan_parser.add_argument(
        "--email",
        default=None,
        help="When uploading the scan results to the provided control server URL, pass the email.",
    )
    scan_parser.add_argument(
        "--opt-out",
        default=False,
        action="store_true",
        help="Opts out of sending unique a unique user identifier with every scan.",
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

    # WHITELIST command
    whitelist_parser = subparsers.add_parser(
        "whitelist",
        help="Manage the whitelist of approved entities",
        description=(
            "View, add, or reset whitelisted entities. Whitelisted entities bypass security checks during scans."
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
    add_install_arguments(install_parser)

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall Invariant Gateway")
    add_uninstall_arguments(uninstall_parser)

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
        default=8129,
        help="Port to run the server on (default: 8129)",
        metavar="PORT",
    )
    add_common_arguments(server_parser)
    add_server_arguments(server_parser)

    # PROXY command
    proxy_parser = subparsers.add_parser("proxy", help="Installs and proxies MCP requests, uninstalls on exit")
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=8129,
        help="Port to run the server on (default: 8129)",
        metavar="PORT",
    )
    add_common_arguments(proxy_parser)
    add_server_arguments(proxy_parser)
    add_install_arguments(proxy_parser)

    # Parse arguments (default to 'scan' if no command provided)
    if len(sys.argv) == 1 or sys.argv[1] not in subparsers.choices:
        sys.argv.insert(1, "scan")
    args = parser.parse_args()

    # postprocess the files argument (if shorthands are used)
    if hasattr(args, "files") and args.files is None:
        args.files = client_shorthands_to_paths(args.files)

    # Display version banner
    if not (hasattr(args, "json") and args.json):
        rich.print(f"[bold blue]Invariant MCP-scan v{version_info}[/bold blue]\n")

    async def install():
        try:
            check_install_args(args)
        except argparse.ArgumentError as e:
            parser.error(e)

        invariant_api_url = (
            f"http://localhost:{args.mcp_scan_server_port}" if args.local_only else "https://explorer.invariantlabs.ai"
        )
        installer = MCPGatewayInstaller(paths=args.files, invariant_api_url=invariant_api_url)
        await installer.install(
            gateway_config=MCPGatewayConfig(
                project_name=args.project_name,
                push_explorer=True,
                api_key=args.api_key or "",
                source_dir=args.gateway_dir,
            ),
            verbose=True,
        )

    async def uninstall():
        installer = MCPGatewayInstaller(paths=args.files)
        await installer.uninstall(verbose=True)

    def server(on_exit=None):
        sf = StorageFile(args.storage_file)
        guardrails_config_path = sf.create_guardrails_config()
        mcp_scan_server = MCPScanServer(
            port=args.port, config_file_path=guardrails_config_path, on_exit=on_exit, pretty=args.pretty
        )
        mcp_scan_server.run()

    # Set up logging if verbose flag is enabled
    do_log = hasattr(args, "verbose") and args.verbose
    setup_logging(do_log)

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
        elif all(x is None for x in [args.type, args.name, args.hash]):  # no args
            sf.print_whitelist()
            sys.exit(0)
        elif all(x is not None for x in [args.type, args.name, args.hash]):
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
        asyncio.run(run_scan_inspect(mode="inspect", args=args))
        sys.exit(0)
    elif args.command == "install":
        asyncio.run(install())
        sys.exit(0)
    elif args.command == "uninstall":
        asyncio.run(uninstall())
        sys.exit(0)
    elif args.command == "scan" or args.command is None:  # default to scan
        asyncio.run(run_scan_inspect(args=args))
        sys.exit(0)
    elif args.command == "server":
        install_extras(args)
        server()
        sys.exit(0)
    elif args.command == "proxy":
        args.local_only = True
        install_extras(args)
        asyncio.run(install())
        print("[Proxy installed, you may need to restart/reload your MCP clients to use it]")
        server(on_exit=uninstall)
        sys.exit(0)
    else:
        # This shouldn't happen due to argparse's handling
        rich.print(f"[bold red]Unknown command: {args.command}[/bold red]")
        parser.print_help()
        sys.exit(1)


async def run_scan_inspect(mode="scan", args=None):
    async with MCPScanner(**vars(args)) as scanner:
        # scanner.hook('path_scanned', print_path_scanned)
        if mode == "scan":
            result = await scanner.scan()
        elif mode == "inspect":
            result = await scanner.inspect()
        else:
            raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")

    # upload scan result to control server if specified
    if (
        hasattr(args, "control_server")
        and args.control_server
        and hasattr(args, "push_key")
        and args.push_key
        and hasattr(args, "email")
        and hasattr(args, "opt_out")
    ):
        await upload(result, args.control_server, args.push_key, args.email, args.opt_out)

    if args.json:
        result = {r.path: r.model_dump() for r in result}
        print(json.dumps(result, indent=2))
    else:
        print_scan_result(
            result,
            args.print_errors,
            args.full_toxic_flows if hasattr(args, "full_toxic_flows") else False,
            mode == "inspect",
        )


if __name__ == "__main__":
    main()
