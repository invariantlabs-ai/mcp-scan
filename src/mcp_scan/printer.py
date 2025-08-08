import builtins
import textwrap

import rich
from rich.text import Text
from rich.traceback import Traceback as rTraceback
from rich.tree import Tree

from .models import Entity, Issue, ScanError, ScanPathResult, ToxicFlowExtraData, entity_type_to_str, hash_entity

MAX_ENTITY_NAME_LENGTH = 25
MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH = 30


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


def format_entity_line(entity: Entity, issues: list[Issue], inspect_mode: bool = False) -> Text:
    # is_verified = verified.value
    # if is_verified is not None and changed.value is not None:
    #     is_verified = is_verified and not changed.value
    if any(issue.code.startswith("X002") for issue in issues):
        status = "whitelisted"
    elif any(issue.code.startswith("X") for issue in issues):
        status = "analysis_error"
    elif any(issue.code.startswith("E") for issue in issues):
        status = "issue"
    elif any(issue.code.startswith("W") for issue in issues):
        status = "warning"
    else:
        status = "successful"

    color_map = {
        "successful": "[green]",
        "issue": "[red]",
        "analysis_error": "[gray62]",
        "warning": "[yellow]",
        "whitelisted": "[blue]",
        "inspect_mode": "[white]",
    }
    color = color_map[status] if not inspect_mode else color_map["inspect_mode"]
    icon_map = {
        "successful": ":white_heavy_check_mark:",
        "issue": ":cross_mark:",
        "analysis_error": "",
        "warning": "⚠️ ",
        "whitelisted": ":white_heavy_check_mark:",
        "inspect_mode": "  ",
    }
    icon = icon_map[status] if not inspect_mode else icon_map["inspect_mode"]
    include_description = inspect_mode or (status not in ["whitelisted", "analysis_error", "successful"])

    # right-pad & truncate name
    name = entity.name
    if len(name) > MAX_ENTITY_NAME_LENGTH:
        name = name[: (MAX_ENTITY_NAME_LENGTH - 3)] + "..."
    name = name + " " * (MAX_ENTITY_NAME_LENGTH - len(name))

    # right-pad type
    type = entity_type_to_str(entity)
    type = type + " " * (len("resource") - len(type))

    status_text = " ".join(
        [
            color_map["analysis_error"]
            + rf"\[{issue.code}]: {issue.message}"
            + color_map["analysis_error"].replace("[", "[/")
            for issue in issues
            if issue.code.startswith("X")
        ]
        + [
            color_map["issue"] + rf"\[{issue.code}]: {issue.message}" + color_map["issue"].replace("[", "[/")
            for issue in issues
            if issue.code.startswith("E")
        ]
        + [
            color_map["warning"] + rf"\[{issue.code}]: {issue.message}" + color_map["warning"].replace("[", "[/")
            for issue in issues
            if issue.code.startswith("W")
        ]
    )
    text = f"{type} {color}[bold]{name}[/bold] {icon} {status_text}"

    if include_description:
        if hasattr(entity, "description") and entity.description is not None:
            description = textwrap.dedent(entity.description)
        else:
            description = "<no description available>"
        text += f"\n[gray62][bold]Current description:[/bold]\n{description}[/gray62]"

    messages = []
    if status not in ["successful", "analysis_error", "whitelisted"]:
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


def format_tool_flow(tool_name: str, server_name: str, value: float) -> Text:
    text = "{tool_name} {risk}"
    tool_name = f"{server_name}/{tool_name}"
    if len(tool_name) > MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH:
        tool_name = tool_name[: (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - 3)] + "..."
    tool_name = tool_name + " " * (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - len(tool_name))

    risk = "[yellow]Low[/yellow]" if value <= 1.5 else "[red]High[/red]"
    return Text.from_markup(text.format(tool_name=tool_name, risk=risk))


def format_global_issue(result: ScanPathResult, issue: Issue, show_all: bool = False) -> Tree:
    """
    Format issues about the whole scan.
    """
    assert issue.reference is None, "Global issues should not have a reference"
    assert issue.code.startswith("TF"), (
        "Global issues should start with 'TF'. Only Toxic Flows are supported as global issues."
    )
    tree = Tree(f"[yellow]\n⚠️ [{issue.code}]: {issue.message}[/yellow]")

    def _format_tool_kind_name(tool_kind_name: str) -> str:
        return " ".join(tool_kind_name.split("_")).title()

    def _format_tool_name(server_name: str, tool_name: str, value: float) -> str:
        tool_string = f"{server_name}/{tool_name}"
        if len(tool_string) > MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH:
            tool_string = tool_string[: (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - 3)] + "..."
        tool_string = tool_string + " " * (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - len(tool_string))
        if value <= 1.5:
            severity = "[yellow]Low[/yellow]"
        elif value <= 2.5:
            severity = "[red]High[/red]"
        else:
            severity = "[bold][red]Critical[/red][/bold]"
        return f"{tool_string} {severity}"

    try:
        extra_data = ToxicFlowExtraData.model_validate(issue.extra_data)
    except Exception:
        tree.add("[gray62]Invalid extra data format[/gray62]")
        return tree

    for tool_kind_name, tool_references in extra_data.root.items():
        tool_references.sort(key=lambda x: x.label_value, reverse=True)
        tool_tree = tree.add(f"[bold]{_format_tool_kind_name(tool_kind_name)}[/bold]")
        for tool_reference in tool_references[: 3 if not show_all else None]:
            tool_tree.add(
                _format_tool_name(
                    result.servers[tool_reference.reference[0]].name or "",
                    result.servers[tool_reference.reference[0]].signature.entities[tool_reference.reference[1]].name,
                    tool_reference.label_value,
                )
            )
        if len(tool_references) > 3 and not show_all:
            tool_tree.add(
                f"[gray62]... and {len(tool_references) - 3} more tools (to see all, use --full-toxic-flows)[/gray62]"
            )
    return tree


def print_scan_path_result(
    result: ScanPathResult,
    print_errors: bool = False,
    full_toxic_flows: bool = False,
    inspect_mode: bool = False,
) -> None:
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
    for server_idx, server in enumerate(result.servers):
        if server.error is not None:
            err_status, traceback = format_error(server.error)
            path_print_tree.add(format_servers_line(server.name or "", err_status))
            if traceback is not None:
                server_tracebacks.append((server, traceback))
        else:
            server_print = path_print_tree.add(format_servers_line(server.name or ""))
            for entity_idx, entity in enumerate(server.entities):
                issues = [issue for issue in result.issues if issue.reference == (server_idx, entity_idx)]
                server_print.add(format_entity_line(entity, issues, inspect_mode))

    if len(result.servers) > 0:
        rich.print(path_print_tree)

    # print global issues
    for issue in result.issues:
        if issue.reference is None:
            rich.print(format_global_issue(result, issue, full_toxic_flows))

    if print_errors and len(server_tracebacks) > 0:
        console = rich.console.Console()
        for server, traceback in server_tracebacks:
            console.print()
            console.print("[bold]Exception when scanning " + (server.name or "") + "[/bold]")
            console.print(traceback)
    print(end="", flush=True)


def print_scan_result(
    result: list[ScanPathResult],
    print_errors: bool = False,
    full_toxic_flows: bool = False,
    inspect_mode: bool = False,
) -> None:
    for i, path_result in enumerate(result):
        print_scan_path_result(path_result, print_errors, full_toxic_flows, inspect_mode)
        if i < len(result) - 1:
            rich.print()
    print(end="", flush=True)
