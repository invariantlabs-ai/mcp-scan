import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
import os

import psutil
import rich
from invariant.__main__ import add_extra
from rich.logging import RichHandler

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller
from mcp_scan_server.server import MCPScanServer

from .MCPScanner import MCPScanner
from .paths import WELL_KNOWN_MCP_PATHS, client_shorthands_to_paths
from .printer import print_scan_result
from .StorageFile import StorageFile
from .version import version_info
# ← 캐시 관련 import 추가
from .cache import SimpleCache
from rich.console import Console
from rich.table import Table
from .help_formatter import HelpFormatter
from .error_handler import ErrorHandler
from .report_generator import ReportGenerator


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


# ← 새로운 함수: 캐시 관련 인수 추가
def add_cache_arguments(parser):
    """Add cache-related arguments."""
    cache_group = parser.add_argument_group("Cache Options")
    cache_group.add_argument(
        "--no-cache",
        action="store_true",
        help="캐시를 사용하지 않고 새로 스캔",
    )
    cache_group.add_argument(
        "--clear-cache",
        action="store_true",
        help="만료된 캐시 파일들을 정리",
    )
    cache_group.add_argument(
        "--cache-stats",
        action="store_true",
        help="캐시 사용 통계 출력",
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


# ← 새로운 함수: 리포트 관련 인수 추가
def add_report_arguments(parser):
    """Add report generation arguments."""
    report_group = parser.add_argument_group("Report Options")
    report_group.add_argument(
        "--report",
        type=str,
        metavar="FILE",
        help="HTML 리포트 파일 생성 경로 (예: report.html)",
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


# ← 새로운 함수: 캐시 관련 명령어 처리
def handle_cache_commands(args):
    """Handle cache-related commands."""
    console = Console()
    
    if args.cache_stats:
        cache = SimpleCache()
        stats = cache.get_cache_stats()
        
        table = Table(title="📊 캐시 통계")
        table.add_column("항목", style="cyan")
        table.add_column("값", style="white")
        
        for key, value in stats.items():
            table.add_row(key, str(value))
        console.print(table)
        return True
    
    if args.clear_cache:
        cache = SimpleCache()
        cleared = cache.clear()
        console.print(f"🗑️ {cleared}개의 만료된 캐시 파일을 정리했습니다.", style="green")
        return True
    
    return False


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
    # Debugging prints
    print(f"DEBUG: Current working directory: {os.getcwd()}")
    print(f"DEBUG: sys.argv: {sys.argv}")

    # Create the main parser for global arguments and common settings
    parser = create_enhanced_parser()

    # Create subparsers for commands (using the same parser object)
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
    add_cache_arguments(scan_parser)  # ← 캐시 인수 추가
    add_report_arguments(scan_parser)  # ← 리포트 인수 추가
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="Number of times to check each server (default: 1)",
        metavar="NUM",
    )
    scan_parser.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Only run verification locally. Does not run all checks, results will be less accurate.",
    )

    # INSPECT command
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Print descriptions of tools, prompts, and resources without verification",
        description="Inspect and display MCP tools, prompts, and resources without security verification.",
    )
    add_common_arguments(inspect_parser)
    add_server_arguments(inspect_parser)
    add_cache_arguments(inspect_parser)  # ← 캐시 인수 추가 (inspect에도)
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

    # Add global cache arguments to the main parser
    parser.add_argument(
        "--cache-stats",
        action="store_true",
        help="캐시 사용 통계 출력",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="만료된 캐시 파일들을 정리",
    )

    # Parse arguments (default to 'scan' if no command provided or if only global flags are given)
    # This must be the *only* parse_args call.
    # Check if a subcommand was provided by looking at sys.argv[1]
    if len(sys.argv) == 1 or (len(sys.argv) > 1 and sys.argv[1] not in subparsers.choices):
        # If no command is provided (sys.argv is just script name) or
        # if the first arg is not a recognized subcommand (e.g., it's a global flag like --verbose)
        # then default to 'scan' and re-parse with 'scan' prepended.
        args = parser.parse_args(["scan"] + sys.argv[1:])
    else:
        # If a subcommand is provided (e.g., 'scan', 'inspect'), parse as normal.
        args = parser.parse_args()

    # Determine the project root dynamically
    # Assuming cli.py is at mcp-scan/src/mcp_scan/cli.py
    current_script_dir = Path(__file__).resolve().parent
    project_root_path = current_script_dir.parent.parent.parent # Corrected to go up to mcp-scan/

    # Resolve relative paths to absolute paths for 'files' argument relative to project root
    if hasattr(args, "files") and args.files:
        resolved_files = []
        for file_path in args.files:
            p = Path(file_path).expanduser() # Handle '~'
            
            if p.is_absolute():
                resolved_files.append(str(p))
            else:
                # Special handling for paths that start with the project root name itself, and are relative.
                # This covers cases where user types `mcp-scan/test_data/file.json` from outside project root.
                # Or `mcp-scan/mcp-scan/test_data/file.json` if CWD is something else.
                if p.parts and p.parts[0] == project_root_path.name:
                    # If the path already includes the project_root_path name, strip it to avoid duplication.
                    # e.g., if project_root_path.name is 'mcp-scan' and file_path is 'mcp-scan/test_data/file.json'
                    # then relative_to_project_root becomes 'test_data/file.json'
                    relative_to_project_root = Path(*p.parts[1:])
                else:
                    # For standard relative paths (e.g., 'test_data/file.json' when CWD is mcp-scan)
                    relative_to_project_root = p
                
                resolved_files.append(str((project_root_path / relative_to_project_root).resolve()))
        args.files = resolved_files

    # Handle global commands that might exit the program early
    if args.examples:
        HelpFormatter.show_examples()
        sys.exit(0)
    
    if args.troubleshooting:
        HelpFormatter.show_troubleshooting()
        sys.exit(0)

    # Handle global cache commands (these also might exit)
    if handle_cache_commands(args):
        sys.exit(0)

    # Display version banner (only if not JSON output)
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
    # ← MCPScanner에 캐시 옵션 전달
    scanner_kwargs = vars(args).copy()
    scanner_kwargs['use_cache'] = not getattr(args, 'no_cache', False)
    scanner_kwargs['generate_report'] = bool(getattr(args, 'report', None))
    scanner_kwargs['report_path'] = getattr(args, 'report', None)
    
    async with MCPScanner(**scanner_kwargs) as scanner:
        # scanner.hook('path_scanned', print_path_scanned)
        if mode == "scan":
            result = await scanner.scan()
        elif mode == "inspect":
            result = await scanner.inspect()
    if args.json:
        result = {r.path: r.model_dump() for r in result}
        print(json.dumps(result, indent=2))
    else:
        print_scan_result(result)


# add_arguments 함수 수정
def create_enhanced_parser():
    """향상된 인수 파서 생성"""
    program_name = get_invoking_name()
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="🔍 MCP-Scan: Model Context Protocol 보안 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
[bold green]일반적인 사용 예시:[/bold green]
  {program_name} scan                     # 기본 스캔
  {program_name} scan --verbose --report  # 상세 로그 + HTML 리포트
  {program_name} --examples              # 더 많은 예시 보기

[bold yellow]문제 해결:[/bold yellow]
  설정 파일을 찾을 수 없는 경우:
    → 파일 경로를 확인하거나 절대 경로를 사용하세요
  
  스캔이 느린 경우:
    → 캐시가 활성화되어 있는지 확인하세요 (기본값)
    
[bold blue]더 많은 정보:[/bold blue] https://github.com/CoCo-1223/mcp-scan
        """
    )
    
    # 전역 옵션 추가
    parser.add_argument('--examples', action='store_true', help='상세한 사용 예시 출력')
    parser.add_argument('--troubleshooting', action='store_true', help='문제 해결 가이드 출력')
    
    return parser


if __name__ == "__main__":
    main()