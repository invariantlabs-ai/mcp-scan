import argparse
import os

import rich
from pydantic import BaseModel
from rich.text import Text
from rich.tree import Tree

from mcp_scan.mcp_client import scan_mcp_config_file
from mcp_scan.models import MCPConfig, SSEServer, StdioServer, StreamableHTTPServer
from mcp_scan.paths import get_client_from_path
from mcp_scan.printer import format_path_line

parser = argparse.ArgumentParser(
    description="MCP-scan CLI",
    prog="invariant-gateway@latest mcp",
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

    # the source directory of the gateway implementation to use
    # (if None, uses the published package)
    source_dir: str | None = None


def is_invariant_installed(server: StdioServer) -> bool:
    if server.args is None:
        return False
    if not server.args:
        return False
    return any("invariant-gateway" in a for a in server.args)


def install_gateway(
    server: StdioServer,
    config: MCPGatewayConfig,
    invariant_api_url: str = "https://explorer.invariantlabs.ai",
    extra_metadata: dict[str, str] | None = None,
) -> StdioServer:
    """Install the gateway for the given server."""
    if is_invariant_installed(server):
        raise MCPServerAlreadyGateway()

    env = (server.env or {}) | {
        "INVARIANT_API_KEY": config.api_key or "<no-api-key>",
        "INVARIANT_API_URL": invariant_api_url,
        "GUARDRAILS_API_URL": invariant_api_url,
    }

    cmd = "uvx"
    base_args = [
        "invariant-gateway@latest",
        "mcp",
    ]

    # if running gateway from source-dir, use 'uv run' instead
    if config.source_dir:
        cmd = "uv"
        base_args = ["run", "--directory", config.source_dir, "invariant-gateway", "mcp"]

    flags = [
        "--project-name",
        config.project_name,
        *(["--push-explorer"] if config.push_explorer else []),
    ]
    if extra_metadata:
        # add extra metadata flags
        for k, v in extra_metadata.items():
            flags.append(f"--metadata-{k}={v}")

    # add exec section
    flags += [*["--exec", server.command], *(server.args if server.args else [])]

    # return new server config
    return StdioServer(command=cmd, args=base_args + flags, env=env)


def uninstall_gateway(
    server: StdioServer,
) -> StdioServer:
    """Uninstall the gateway for the given server."""
    if not is_invariant_installed(server):
        raise MCPServerIsNotGateway()

    assert isinstance(server.args, list), "args is not a list"
    args, unknown = parser.parse_known_args(server.args[2:])
    if server.env is None:
        new_env = None
    else:
        new_env = {
            k: v
            for k, v in server.env.items()
            if k != "INVARIANT_API_KEY" and k != "INVARIANT_API_URL" and k != "GUARDRAILS_API_URL"
        } or None
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
        invariant_api_url: str = "https://explorer.invariantlabs.ai",
    ) -> None:
        self.paths = paths
        self.invariant_api_url = invariant_api_url

    async def install(
        self,
        gateway_config: MCPGatewayConfig,
        verbose: bool = False,
    ) -> None:
        for path in self.paths:
            config: MCPConfig | None = None
            try:
                config = await scan_mcp_config_file(path)
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
            new_servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer] = {}
            for name, server in config.get_servers().items():
                if isinstance(server, StdioServer):
                    try:
                        new_servers[name] = install_gateway(
                            server,
                            gateway_config,
                            self.invariant_api_url,
                            {"server": name, "client": get_client_from_path(path) or path},
                        )
                        path_print_tree.add(format_install_line(server=name, status="Installed", success=True))
                    except MCPServerAlreadyGateway:
                        new_servers[name] = server
                        path_print_tree.add(format_install_line(server=name, status="Already installed", success=True))
                    except Exception as e:
                        new_servers[name] = server
                        print(f"Failed to install gateway for {name}", e)
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
                # flush the file to disk
                f.flush()
                os.fsync(f.fileno())

    async def uninstall(self, verbose: bool = False) -> None:
        for path in self.paths:
            config: MCPConfig | None = None
            try:
                config = await scan_mcp_config_file(path)
                status = f"found {len(config.get_servers())} server{'' if len(config.get_servers()) == 1 else 's'}"
            except FileNotFoundError:
                status = "file does not exist"
            except Exception:
                status = "could not parse file"
            if verbose:
                rich.print(format_path_line(path, status, operation="Uninstalling Gateway"))
            if config is None:
                continue

            path_print_tree = Tree("│")
            config = await scan_mcp_config_file(path)
            new_servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer] = {}
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
                f.write(
                    config.model_dump_json(
                        indent=4,
                        exclude_none=True,
                    )
                    + "\n"
                )
