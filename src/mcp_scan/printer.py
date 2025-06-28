import builtins
import textwrap

import rich
from rich.text import Text
from rich.traceback import Traceback as rTraceback
from rich.tree import Tree

from .models import (
    Entity,
    Issue,
    ScalarToolLabels,
    ScanError,
    ScanPathResult,
    ServerScanResult,
    ToolAnnotationsWithLabels,
    entity_type_to_str,
    hash_entity,
)

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


def format_scalar_labels(labels: ScalarToolLabels) -> str:
    """
    Format scalar labels into a string.
    """
    label_parts = []
    if labels.is_public_sink > 0:
        label_parts.append("Public sink")
    if labels.destructive > 0:
        label_parts.append("Destructive")
    if labels.untrusted_output > 0:
        label_parts.append("Untrusted output")
    if labels.private_data > 0:
        label_parts.append("Private data")

    return "[gray62]" + " | ".join(label_parts) + "[/gray62]"


def format_entity_line(entity: Entity, labels: ScalarToolLabels | None, issues: list[Issue]) -> Text:
    # is_verified = verified.value
    # if is_verified is not None and changed.value is not None:
    #     is_verified = is_verified and not changed.value
    if any(issue.code.startswith("X") for issue in issues):
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
    }
    color = color_map[status]
    icon = {
        "successful": ":white_heavy_check_mark:",
        "issue": ":cross_mark:",
        "analysis_error": "",
        "warning": "⚠️ ",
        "whitelisted": ":white_heavy_check_mark:",
    }[status]

    include_description = status not in ["whitelisted", "analysis_error", "successful"]

    # right-pad & truncate name
    name = entity.name
    if len(name) > MAX_ENTITY_NAME_LENGTH:
        name = name[: (MAX_ENTITY_NAME_LENGTH - 3)] + "..."
    name = name + " " * (MAX_ENTITY_NAME_LENGTH - len(name))

    # right-pad type
    type = entity_type_to_str(entity)
    type = type + " " * (len("resource") - len(type))

    # labels
    labels_str = ""
    if status not in ["issue", "analysis_error"]:
        if labels is not None:
            labels_str = format_scalar_labels(labels)
        else:
            labels_str = "[gray62]Error in labels computation[/gray62]"

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
    text = f"{type} {color}[bold]{name}[/bold] {icon} {status_text} {labels_str}"

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

    risk = "[gold1]Mild[/gold1]" if value <= 1.5 else "[red]High[/red]"
    return Text.from_markup(text.format(tool_name=tool_name, risk=risk))


def format_toxic_flows(servers: list[ServerScanResult]) -> list[Tree]:
    """
    Format toxic flows from the scan results into a tree structure.
    """
    untrusted_output_tools: list[tuple[str, str, float]] = []
    destructive_tools: list[tuple[str, str, float]] = []
    private_data_tools: list[tuple[str, str, float]] = []
    is_public_sink_tools: list[tuple[str, str, float]] = []

    for server in servers:
        if server.signature is None:
            continue
        for tool in server.signature.tools:
            if (
                tool.annotations is not None
                and isinstance(tool.annotations, ToolAnnotationsWithLabels)
                and isinstance(tool.annotations.labels, ScalarToolLabels)
            ):
                if tool.annotations.labels.untrusted_output > 0:
                    untrusted_output_tools.append(
                        (tool.name, server.name or "", tool.annotations.labels.untrusted_output)
                    )
                if tool.annotations.labels.destructive > 0:
                    destructive_tools.append((tool.name, server.name or "", tool.annotations.labels.destructive))
                if tool.annotations.labels.private_data > 0:
                    private_data_tools.append((tool.name, server.name or "", tool.annotations.labels.private_data))
                if tool.annotations.labels.is_public_sink > 0:
                    is_public_sink_tools.append((tool.name, server.name or "", tool.annotations.labels.is_public_sink))

    untrusted_output_tools.sort(key=lambda x: x[2], reverse=True)
    destructive_tools.sort(key=lambda x: x[2], reverse=True)
    private_data_tools.sort(key=lambda x: x[2], reverse=True)
    is_public_sink_tools.sort(key=lambda x: x[2], reverse=True)

    toxic_flows: list[Tree] = []

    # Flow 1: Untrusted output -> Private data -> Public sink
    leak_data_flow = Tree("[bold]Leak data flow[/bold]")
    untrusted_output_tree = Tree("[bold]Untrusted output[/bold]")
    private_data_tree = Tree("[bold]Private data[/bold]")
    public_sink_tree = Tree("[bold]Public sink[/bold]")
    for tool_name, server_name, value in untrusted_output_tools:
        untrusted_output_tree.add(format_tool_flow(tool_name, server_name, value))
    for tool_name, server_name, value in private_data_tools:
        private_data_tree.add(format_tool_flow(tool_name, server_name, value))
    for tool_name, server_name, value in is_public_sink_tools:
        public_sink_tree.add(format_tool_flow(tool_name, server_name, value))
    if len(untrusted_output_tools) > 0 and len(private_data_tools) > 0 and len(is_public_sink_tools) > 0:
        leak_data_flow.add(untrusted_output_tree)
        leak_data_flow.add(private_data_tree)
        leak_data_flow.add(public_sink_tree)
        toxic_flows.append(leak_data_flow)

    # Flow 2: Untrusted output -> Destructive
    destructive_flow = Tree("[bold]Harm flow[/bold]")
    untrusted_output_tree = Tree("[bold]Untrusted output[/bold]")
    destructive_tree = Tree("[bold]Destructive[/bold]")
    for tool_name, server_name, value in untrusted_output_tools:
        untrusted_output_tree.add(format_tool_flow(tool_name, server_name, value))
    for tool_name, server_name, value in destructive_tools:
        destructive_tree.add(format_tool_flow(tool_name, server_name, value))
    if len(untrusted_output_tools) > 0 and len(destructive_tools) > 0:
        destructive_flow.add(untrusted_output_tree)
        destructive_flow.add(destructive_tree)
        toxic_flows.append(destructive_flow)

    return toxic_flows


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
    for server_idx, server in enumerate(result.servers):
        if server.error is not None:
            err_status, traceback = format_error(server.error)
            server_print = path_print_tree.add(format_servers_line(server.name or "", err_status))
            if traceback is not None:
                server_tracebacks.append((server, traceback))
        else:
            server_labels = [None] * len(server.entities) if server.labels is None else server.labels
            for (entity_idx, entity), labels in zip(
                enumerate(server.entities),
                server_labels,
                strict=False,
            ):
                issues = [issue for issue in result.issues if issue.reference == (server_idx, entity_idx)]
                server_print.add(format_entity_line(entity, labels, issues))

    if len(result.servers) > 0:
        rich.print(path_print_tree)

    toxic_flows = format_toxic_flows(result.servers)
    if toxic_flows:
        toxic_flows_tree = Tree("● [bold][gold1]Toxic flows found:[/bold][/gold1]")
        for flow in toxic_flows:
            toxic_flows_tree.add(flow)
        rich.print(flush=True)
        rich.print(toxic_flows_tree, flush=True)

    if print_errors and len(server_tracebacks) > 0:
        console = rich.console.Console()
        for server, traceback in server_tracebacks:
            console.print()
            console.print("[bold]Exception when scanning " + (server.name or "") + "[/bold]")
            console.print(traceback)
    print(end="", flush=True)


def print_scan_result(result: list[ScanPathResult], print_errors: bool = False) -> None:
    for i, path_result in enumerate(result):
        print_scan_path_result(path_result, print_errors)
        if i < len(result) - 1:
            rich.print()
    print(end="", flush=True)
