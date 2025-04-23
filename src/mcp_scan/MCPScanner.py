import inspect
import os
import json
import textwrap
import asyncio
import requests
import ast
import rich
from rich.tree import Tree
from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .models import Result
from .StorageFile import StorageFile
from .verify_api import verify_server


def format_err_str(e, max_length=None):
    try:
        if isinstance(e, ExceptionGroup):
            text = ", ".join([format_err_str(e) for e in e.exceptions])
        elif isinstance(e, TimeoutError):
            text = "Could not reach server within timeout"
        else:
            raise Exception()
    except:
        text = None
    if text is None:
        name = type(e).__name__
        try:

            def _mapper(e):
                if isinstance(e, Exception):
                    return format_err_str(e)
                return str(e)

            message = ",".join(map(_mapper, e.args))
        except Exception:
            message = str(e)
        message = message.strip()
        if len(message) > 0:
            text = f"{name}: {message}"
        else:
            text = name
    if max_length is not None and len(text) > max_length:
        text = text[: (max_length - 3)] + "..."
    return text


def format_path_line(path, status, operation="Scanning"):
    text = f"● {operation} [bold]{path}[/bold] [gray62]{status}[/gray62]"
    return rich.text.Text.from_markup(text)


def format_servers_line(server, status=None):
    text = f"[bold]{server}[/bold]"
    if status:
        text += f" [gray62]{status}[/gray62]"
    return rich.text.Text.from_markup(text)


def format_tool_line(
    tool,
    verified: Result,
    changed: Result = Result(),
    type="tool",
    include_description=False,
    additional_text=None,
):
    is_verified = verified.value
    if is_verified is not None and changed.value is not None:
        is_verified = is_verified and not changed.value

    message = [verified.message, changed.message]
    message = [m for m in message if m is not None]
    message = ", ".join(message)

    color = {True: "[green]", False: "[red]", None: "[gray62]"}[is_verified]
    icon = {True: ":white_heavy_check_mark:", False: ":cross_mark:", None: ""}[
        is_verified
    ]
    
    # right-pad & truncate name
    name = tool.name
    if len(name) > 25:
        name = name[:22] + "..."
    name = name + " " * (25 - len(name))
    
    # right-pad type
    type = type + " " * (len('resource') - len(type))
    
    text = f"{type} {color}[bold]{name}[/bold] {icon} {message}"

    if include_description:
        if hasattr(tool, "description"):
            description = tool.description
            description = textwrap.dedent(description)
        else:
            description = "<no description available>"
        text += f"\n[gray62][bold]Current description:[/bold]\n{description}[/gray62]"

    if additional_text is not None:
        text += f"\n[gray62]{additional_text}[/gray62]"

    text = rich.text.Text.from_markup(text)
    return text


class MCPScanner:
    def __init__(
        self,
        files=[],
        base_url="https://mcp.invariantlabs.ai/",
        checks_per_server=1,
        storage_file="~/.mcp-scan",
        server_timeout=10,
        suppress_mcpserver_io=True,
        **kwargs,
    ):
        self.paths = files
        self.base_url = base_url
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        self.storage_file = StorageFile(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io

    def scan(self, path, verbose=True, inspect_only=False):
        try:
            servers = scan_mcp_config_file(path)
            status = f"found {len(servers)} server{'' if len(servers) == 1 else 's'}"
        except FileNotFoundError:
            status = f"file does not exist"
            return
        except Exception:
            status = f"could not parse file"
            return
        finally:
            if verbose:
                rich.print(format_path_line(path, status))

        path_print_tree = Tree("│")
        servers_with_entities = {}
        for server_name, server_config in servers.items():
            try:
                prompts, resources, tools = asyncio.run(
                    check_server_with_timeout(
                        server_config, self.server_timeout, self.suppress_mcpserver_io
                    )
                )
                status = None
            except Exception as e:
                status = format_err_str(e)
                continue
            finally:
                server_print = path_print_tree.add(
                    format_servers_line(server_name, status)
                )
            servers_with_entities[server_name] = tools + prompts + resources

            if inspect_only:
                for type, entities in [
                    ("tool", tools),
                    ("prompt", prompts),
                    ("resource", resources),
                ]:
                    for entity in entities:
                        server_print.add(
                            format_tool_line(
                                entity,
                                Result(None),
                                Result(None),
                                include_description=True,
                                type=type,
                            )
                        )
            else:
                (
                    verification_result_tools,
                    verification_result_prompts,
                    verification_result_resources,
                ) = verify_server(tools, prompts, resources, base_url=self.base_url)
                for type, entities, verification_results in [
                    ("tool", tools, verification_result_tools),
                    ("prompt", prompts, verification_result_prompts),
                    ("resource", resources, verification_result_resources),
                ]:
                    for entity, verified in zip(entities, verification_results):
                        additional_text = None
                        # check if tool has changed
                        changed, prev_data = self.storage_file.check_and_update(
                            server_name, entity, verified.value
                        )
                        if changed.value is True:
                            additional_text = f"[bold]Previous description({prev_data['timestamp']}):[/bold]\n{prev_data['description']}"

                        # check if tool is whitelisted
                        if self.storage_file.is_whitelisted(entity):
                            verified = Result(
                                True,
                                message="[bold]whitelisted[/bold] " + verified.message,
                            )
                        elif verified.value is False or changed.value is True:
                            hash = self.storage_file.compute_hash(entity)
                            message = f'[bold]You can whitelist this {type} by running `mcp-scan whitelist {type} "{entity.name}" {hash}`[/bold]'
                            if additional_text is not None:
                                additional_text += "\n\n" + message
                            else:
                                additional_text = message

                        server_print.add(
                            format_tool_line(
                                entity,
                                verified,
                                changed,
                                include_description=(
                                    verified.value is False or changed.value is True
                                ),
                                additional_text=additional_text,
                                type=type,
                            )
                        )

        if len(servers) > 0 and verbose:
            rich.print(path_print_tree)

        # cross-references check
        # for each tool check if it referenced by tools of other servers
        cross_ref_found = False
        cross_reference_sources = set()
        for server_name, entities in servers_with_entities.items():
            other_server_names = set(servers.keys())
            other_server_names.remove(server_name)
            other_entity_names = [
                entity.name
                for s in other_server_names
                for entity in servers_with_entities.get(s, [])
            ]
            flagged_names = list(other_server_names) + other_entity_names
            flagged_names = set(map(str.lower, flagged_names))
            for entity in entities:
                tokens = entity.description.lower().split()
                for token in tokens:
                    if token in flagged_names:
                        cross_ref_found = True
                        cross_reference_sources.add(token)
        if verbose:
            if cross_ref_found:
                rich.print(
                    rich.text.Text.from_markup(
                        f"\n[bold yellow]:construction: Cross-Origin Violation: Descriptions of server {cross_reference_sources} explicitly mention tools or resources of other servers, or other servers.[/bold yellow]"
                    ),
                )
            rich.print()

    def start(self):
        for i, path in enumerate(self.paths):
            for k in range(self.checks_per_server):
                self.scan(path, verbose=(k == self.checks_per_server - 1))
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()

    def inspect(self):
        for i, path in enumerate(self.paths):
            self.scan(path, verbose=True, inspect_only=True)
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()
