import asyncio
import os
import textwrap
from typing import Any

import rich
from rich.text import Text
from rich.tree import Tree

from mcp_scan.models import Entity, entity_type_to_str

from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .models import Result
from .StorageFile import StorageFile
from .verify_api import verify_server


def format_err_str(e: Exception, max_length: int | None = None) -> str:
    try:
        if isinstance(e, ExceptionGroup):
            text = ", ".join([format_err_str(e) for e in e.exceptions])
        elif isinstance(e, TimeoutError):
            text = "Could not reach server within timeout"
        else:
            raise Exception()
    except Exception:
        text = None
    if text is None:
        name = type(e).__name__
        try:

            def _mapper(e: Exception | str) -> str:
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


def format_path_line(path: str, status: str | None, operation: str = "Scanning") -> Text:
    text = f"● {operation} [bold]{path}[/bold] [gray62]{status or ''}[/gray62]"
    return Text.from_markup(text)


def format_servers_line(server: str, status: str | None = None) -> Text:
    text = f"[bold]{server}[/bold]"
    if status:
        text += f" [gray62]{status}[/gray62]"
    return Text.from_markup(text)


def format_entity_line(
    entity: Entity,
    verified: Result,
    changed: Result = Result(),
    include_description: bool = False,
    additional_text: str | None = None,
) -> Text:
    is_verified = verified.value
    if is_verified is not None and changed.value is not None:
        is_verified = is_verified and not changed.value

    message = ", ".join([m for m in [verified.message, changed.message] if m is not None])

    color = {True: "[green]", False: "[red]", None: "[gray62]"}[is_verified]
    icon = {True: ":white_heavy_check_mark:", False: ":cross_mark:", None: ""}[is_verified]

    # right-pad & truncate name
    name = entity.name
    if len(name) > 25:
        name = name[:22] + "..."
    name = name + " " * (25 - len(name))

    # right-pad type
    type = entity_type_to_str(entity)
    type = type + " " * (len("resource") - len(type))

    text = f"{type} {color}[bold]{name}[/bold] {icon} {message}"

    if include_description:
        if hasattr(entity, "description") and entity.description is not None:
            description = textwrap.dedent(entity.description)
        else:
            description = "<no description available>"
        text += f"\n[gray62][bold]Current description:[/bold]\n{description}[/gray62]"

    if additional_text is not None:
        text += f"\n[gray62]{additional_text}[/gray62]"

    formatted_text = Text.from_markup(text)
    return formatted_text


class MCPScanner:
    def __init__(
        self,
        files: list[str] = [],
        base_url: str = "https://mcp.invariantlabs.ai/",
        checks_per_server: int = 1,
        storage_file: str = "~/.mcp-scan",
        server_timeout: int = 10,
        suppress_mcpserver_io: bool = True,
        **kwargs: Any,
    ):
        self.paths = files
        self.base_url = base_url
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        self.storage_file = StorageFile(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io

    def scan(self, path: str, verbose: bool = True, inspect_only: bool = False) -> None:
        status: str | None = None
        try:
            servers = scan_mcp_config_file(path).get_servers()
            status = f"found {len(servers)} server{'' if len(servers) == 1 else 's'}"
        except FileNotFoundError:
            status = "file does not exist"
            return
        except Exception:
            status = "could not parse file"
            return
        finally:
            if verbose:
                rich.print(format_path_line(path, status))

        path_print_tree = Tree("│")
        servers_with_entities: dict[str, list[Entity]] = {}
        for server_name, server_config in servers.items():
            try:
                prompts, resources, tools = asyncio.run(
                    check_server_with_timeout(server_config, self.server_timeout, self.suppress_mcpserver_io)
                )
                status = None
            except Exception as e:
                status = format_err_str(e)
                continue
            finally:
                server_print = path_print_tree.add(format_servers_line(server_name, status))
            entities: list[Entity] = tools + prompts + resources
            servers_with_entities[server_name] = entities

            if inspect_only:
                for entity in entities:
                    server_print.add(
                        format_entity_line(
                            entity,
                            Result(None),
                            Result(None),
                            include_description=True,
                        )
                    )
            else:
                (
                    verification_result_tools,
                    verification_result_prompts,
                    verification_result_resources,
                ) = verify_server(tools, prompts, resources, base_url=self.base_url)
                verification_results = (
                    verification_result_tools + verification_result_prompts + verification_result_resources
                )
                for entity, verified in zip(
                    entities,
                    verification_results,
                ):
                    additional_text = None
                    # check if tool has changed
                    changed, prev_data = self.storage_file.check_and_update(server_name, entity, verified.value)
                    if changed.value is True and prev_data is not None:
                        additional_text = (
                            f"[bold]Previous description({prev_data.timestamp}):[/bold]\n{prev_data.description}"
                        )

                    # check if tool is whitelisted
                    if self.storage_file.is_whitelisted(entity):
                        verified = Result(
                            True,
                            message="[bold]whitelisted[/bold] " + (verified.message or ""),
                        )
                    elif verified.value is False or changed.value is True:
                        hash = self.storage_file.compute_hash(entity)
                        message = (
                            f"[bold]You can whitelist this {entity_type_to_str(entity)} "
                            f"by running `mcp-scan whitelist {entity_type_to_str(entity)} "
                            f"'{entity.name}' {hash}`[/bold]"
                        )
                        if additional_text is not None:
                            additional_text += "\n\n" + message
                        else:
                            additional_text = message

                    server_print.add(
                        format_entity_line(
                            entity,
                            verified,
                            changed,
                            include_description=(verified.value is False or changed.value is True),
                            additional_text=additional_text,
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
                entity.name for s in other_server_names for entity in servers_with_entities.get(s, [])
            ]
            flagged_names = set(map(str.lower, list(other_server_names) + other_entity_names))
            for entity in entities:
                tokens = (entity.description or "").lower().split()
                for token in tokens:
                    if token in flagged_names:
                        cross_ref_found = True
                        cross_reference_sources.add(token)
        if verbose:
            if cross_ref_found:
                rich.print(
                    rich.text.Text.from_markup(
                        f"\n[bold yellow]:construction: Cross-Origin Violation: "
                        f"Descriptions of server {cross_reference_sources} explicitly mention "
                        f"tools or resources of other servers, or other servers.[/bold yellow]"
                    ),
                )
            rich.print()

    def start(self) -> None:
        for i, path in enumerate(self.paths):
            for k in range(self.checks_per_server):
                self.scan(path, verbose=(k == self.checks_per_server - 1))
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()

    def inspect(self) -> None:
        for i, path in enumerate(self.paths):
            self.scan(path, verbose=True, inspect_only=True)
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()
