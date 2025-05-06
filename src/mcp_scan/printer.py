import builtins
import textwrap

import rich
from rich.text import Text
from rich.traceback import Traceback as rTraceback
from rich.tree import Tree

from .models import Entity, EntityScanResult, ScanError, ScanPathResult, entity_type_to_str, hash_entity


def format_exception(e: Exception | None) -> tuple[str, rTraceback | None]:
    if e is None:
        return "", None
    name = builtins.type(e).__name__
    message = str(e).strip()
    cause = getattr(e, "__cause__", None)
    context = getattr(e, "__context__", None)
    parts = [f"{name}: {message}"]
    if cause is not None:
        parts.append(f"Caused by: {format_exception(cause)[0]}")
    if context is not None:
        parts.append(f"Context: {format_exception(context)[0]}")
    text = "\n".join(parts)
    tb = rTraceback.from_exception(builtins.type(e), e, getattr(e, "__traceback__", None))
    return text, tb


def format_error(e: ScanError) -> tuple[str, rTraceback | None]:
    status, traceback = format_exception(e.exception)
    if e.message:
        status = e.message
    return status, traceback


def format_path_line(path: str, status: str | None, operation: str = "Scanning") -> Text:
    text = f"● {operation} [bold]{path}[/bold] [gray62]{status or ''}[/gray62]"
    return Text.from_markup(text)


def format_servers_line(server: str, status: str | None = None) -> Text:
    text = f"[bold]{server}[/bold]"
    if status:
        text += f" [gray62]{status}[/gray62]"
    return Text.from_markup(text)


def append_status(status: str, new_status: str) -> str:
    if status == "":
        return new_status
    return f"{new_status}, {status}"


def format_entity_line(entity: Entity, result: EntityScanResult | None = None) -> Text:
    # is_verified = verified.value
    # if is_verified is not None and changed.value is not None:
    #     is_verified = is_verified and not changed.value
    is_verified = None
    status = ""
    include_description = True
    if result is not None:
        is_verified = result.verified
        status = result.status or ""
        if result.changed is not None and result.changed:
            is_verified = False
            status = append_status(status, "[bold]changed since previous scan[/bold]")
        if not is_verified and result.whitelisted is not None and result.whitelisted:
            status = append_status(status, "[bold]whitelisted[/bold]")
            is_verified = True
        include_description = not is_verified

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

    text = f"{type} {color}[bold]{name}[/bold] {icon} {status}"

    if include_description:
        if hasattr(entity, "description") and entity.description is not None:
            description = textwrap.dedent(entity.description)
        else:
            description = "<no description available>"
        text += f"\n[gray62][bold]Current description:[/bold]\n{description}[/gray62]"

    messages = result.messages if result is not None else []
    if not is_verified:
        hash = hash_entity(entity)
        messages.append(
            f"[bold]You can whitelist this {entity_type_to_str(entity)} "
            f"by running `mcp-scan whitelist {entity_type_to_str(entity)} "
            f"'{entity.name}' {hash}`[/bold]"
        )

    if len(messages) > 0:
        message = "\n".join(messages)
        text += f"\n\n[gray62]{message}[/gray62]"

    formatted_text = Text.from_markup(text)
    return formatted_text


def print_scan_path_result(result: ScanPathResult, print_errors: bool = False) -> None:
    if result.error is not None:
        err_status, traceback = format_error(result.error)
        rich.print(format_path_line(result.path, err_status))
        if print_errors and traceback is not None:
            console = rich.console.Console()
            console.print(traceback)
        return

    message = f"found {len(result.servers)} server{'' if len(result.servers) == 1 else 's'}"
    rich.print(format_path_line(result.path, message))
    path_print_tree = Tree("│")
    server_tracebacks = []
    for server in result.servers:
        if server.error is not None:
            err_status, traceback = format_error(server.error)
            server_print = path_print_tree.add(format_servers_line(server.name or "", err_status))
            if traceback is not None:
                server_tracebacks.append((server, traceback))
        else:
            server_print = path_print_tree.add(format_servers_line(server.name or ""))
            for entity, entity_result in server.entities_with_result:
                server_print.add(format_entity_line(entity, entity_result))

    if len(result.servers) > 0:
        rich.print(path_print_tree)
    if result.cross_ref_result is not None and result.cross_ref_result.found:
        rich.print(
            rich.text.Text.from_markup(
                f"\n[bold yellow]:construction: Cross-Origin Violation: "
                f"Descriptions of server {result.cross_ref_result.sources} explicitly mention "
                f"tools or resources of other servers, or other servers.[/bold yellow]"
            ),
        )
    if print_errors and len(server_tracebacks) > 0:
        console = rich.console.Console()
        for server, traceback in server_tracebacks:
            console.print()
            console.print("[bold]Exception when scanning " + (server.name or "") + "[/bold]")
            console.print(traceback)


def print_scan_result(result: list[ScanPathResult], print_errors: bool = False) -> None:
    for i, path_result in enumerate(result):
        print_scan_path_result(path_result, print_errors)
        if i < len(result) - 1:
            rich.print()
