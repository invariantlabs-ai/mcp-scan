import argparse
import os

import rich
from pydantic import BaseModel
from rich.text import Text
from rich.tree import Tree

from mcp_scan.mcp_client import scan_mcp_config_file
from mcp_scan.MCPScanner import format_path_line
from mcp_scan.models import MCPConfig, SSEServer, StdioServer

parser = argparse.ArgumentParser(
    description="MCP-scan CLI",
    prog="invariant-gateway@latest mcp",
)

parser.add_argument(
    "--project-name",
    type=str,
    required=True,
)
parser.add_argument(
    "--push-explorer",
    action="store_true",
)
parser.add_argument("--exec", type=str, required=True, nargs=argparse.REMAINDER)


class MCPServerIsNotGateway(Exception):
    pass


class MCPServerAlreadyGateway(Exception):
    pass


class MCPGatewayConfig(BaseModel):
    project_name: str
    push_explorer: bool
    api_key: str


def is_invariant_installed(server: StdioServer) -> bool:
    if server.args is None:
        return False
    if not server.args:
        return False
    return server.args[0] == "invariant-gateway@latest"


def install_gateway(
    server: StdioServer,
    config: MCPGatewayConfig,
) -> StdioServer:
    """Install the gateway for the given server."""
    if is_invariant_installed(server):
        raise MCPServerAlreadyGateway()
    return StdioServer(
        command="uvx",
        args=[
            "invariant-gateway@latest",
            "mcp",
            "--project-name",
            config.project_name,
        ]
        + (["--push-explorer"] if config.push_explorer else [])
        + ["--exec", server.command]
        + (server.args if server.args else []),
        env=server.env | {"INVARIANT_API_KEY": config.api_key},
    )


def uninstall_gateway(
    server: StdioServer,
) -> StdioServer:
    """Uninstall the gateway for the given server."""
    if not is_invariant_installed(server):
        raise MCPServerIsNotGateway()

    assert isinstance(server.args, list), "args is not a list"
    args = parser.parse_args(server.args[2:])
    new_env = {k: v for k, v in server.env.items() if k != "INVARIANT_API_KEY"}
    assert args.exec is not None, "exec is None"
    assert args.exec, "exec is empty"
    return StdioServer(
        command=args.exec[0],
        args=args.exec[1:],
        env=new_env,
    )


def format_install_line(server: str, status: str, success: bool | None) -> Text:
    color = {True: "[green]", False: "[red]", None: "[gray62]"}[success]

    if len(server) > 25:
        server = server[:22] + "..."
    server = server + " " * (25 - len(server))
    icon = {True: ":white_heavy_check_mark:", False: ":cross_mark:", None: ""}[success]

    text = f"{color}[bold]{server}[/bold]{icon} {status}{color.replace('[', '[/')}"
    return Text.from_markup(text)


class MCPGatewayInstaller:
    """A class to install and uninstall the gateway for a given server."""

    def __init__(
        self,
        paths: list[str],
    ) -> None:
        self.paths = paths

    def install(
        self,
        gateway_config: MCPGatewayConfig,
        verbose: bool = False,
    ) -> None:
        for path in self.paths:
            config: MCPConfig | None = None
            try:
                config = scan_mcp_config_file(path)
                status = f"found {len(config.get_servers())} server{'' if len(config.get_servers()) == 1 else 's'}"
            except FileNotFoundError:
                status = "file does not exist"
            except Exception:
                status = "could not parse file"
            if verbose:
                rich.print(format_path_line(path, status, operation="Installing Gateway"))
            if config is None:
                continue

            path_print_tree = Tree("│")
            new_servers: dict[str, SSEServer | StdioServer] = {}
            for name, server in config.get_servers().items():
                if isinstance(server, StdioServer):
                    try:
                        new_servers[name] = install_gateway(server, gateway_config)
                        path_print_tree.add(format_install_line(server=name, status="Installed", success=True))
                    except MCPServerAlreadyGateway:
                        new_servers[name] = server
                        path_print_tree.add(format_install_line(server=name, status="Already installed", success=True))
                    except Exception:
                        new_servers[name] = server
                        path_print_tree.add(format_install_line(server=name, status="Failed to install", success=False))

                else:
                    new_servers[name] = server
                    path_print_tree.add(
                        format_install_line(server=name, status="sse servers not supported yet", success=False)
                    )

            if verbose:
                rich.print(path_print_tree)
            config.set_servers(new_servers)
            with open(os.path.expanduser(path), "w") as f:
                f.write(config.model_dump_json(indent=4) + "\n")

    def uninstall(self, verbose: bool = False) -> None:
        for path in self.paths:
            config: MCPConfig | None = None
            try:
                config = scan_mcp_config_file(path)
                status = f"found {len(config.get_servers())} server{'' if len(config.get_servers()) == 1 else 's'}"
            except FileNotFoundError:
                status = "file does not exist"
            except Exception:
                status = "could not parse file"
            if verbose:
                rich.print(format_path_line(path, status, operation="Installing Gateway"))
            if config is None:
                continue

            path_print_tree = Tree("│")
            config = scan_mcp_config_file(path)
            new_servers: dict[str, SSEServer | StdioServer] = {}
            for name, server in config.get_servers().items():
                if isinstance(server, StdioServer):
                    try:
                        new_servers[name] = uninstall_gateway(server)
                        path_print_tree.add(format_install_line(server=name, status="Uninstalled", success=True))
                    except MCPServerIsNotGateway:
                        new_servers[name] = server
                        path_print_tree.add(
                            format_install_line(server=name, status="Already not installed", success=True)
                        )
                    except Exception:
                        new_servers[name] = server
                        path_print_tree.add(
                            format_install_line(server=name, status="Failed to uninstall", success=False)
                        )
                else:
                    new_servers[name] = server
                    path_print_tree.add(
                        format_install_line(server=name, status="sse servers not supported yet", success=None)
                    )
            config.set_servers(new_servers)
            if verbose:
                rich.print(path_print_tree)
            with open(os.path.expanduser(path), "w") as f:
                f.write(config.model_dump_json(indent=4) + "\n")
