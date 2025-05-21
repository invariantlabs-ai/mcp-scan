# type: ignore
import json
from typing import Literal

from fastapi import FastAPI, Request
from invariant.analyzer.policy import ErrorInformation
from rich.console import Console

from mcp_scan_server.models import PolicyCheckResult


class ActivityLogger:
    """
    Logs trace events as they are received (e.g. tool calls, tool outputs, etc.).

    Ensures that each event is only logged once. Also includes metadata in log output,
    like the client, user, server name and tool name.
    """

    def __init__(self, pretty: Literal["oneline", "compact", "full", "none"] = "compact"):
        # level of pretty printing
        self.pretty = pretty

        # (session_id, formatted_output) -> bool
        self.logged_output: dict[tuple[str, str], bool] = {}
        # last logged (session_id, tool_call_id), so we can skip logging tool call headers if it is directly
        # followed by output
        self.last_logged_tool: tuple[str, str] | None = None
        self.console = Console()

    def empty_metadata(self):
        return {"client": "Unknown Client", "mcp_server": "Unknown Server", "user": None}

    def log_tool_call(self, user_portion, client, server, name, tool_args, call_id_portion):
        if self.pretty == "oneline":
            self.console.print(
                f"→ [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]({{...}}) {call_id_portion}"
            )
        elif self.pretty == "compact":
            self.console.rule(
                f"→ [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green] {call_id_portion}"
            )
            self.console.print("Arguments:", tool_args)
        elif self.pretty == "full":
            self.console.rule(
                f"→ [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green] {call_id_portion}"
            )
            self.console.print("Arguments:", json.dumps(tool_args))
        elif self.pretty == "none":
            pass

    def log_tool_output(self, has_header, user_portion, name, client, server, content, tool_call_id):
        def compact_content(input: str) -> str:
            try:
                input = json.loads(input)
                input = repr(input)
                input = input[:400] + "..." if len(input) > 400 else input
            except ValueError:
                pass
            return input.replace("\n", " ").replace("\r", "")

        def full_content(input: str) -> str:
            try:
                input = json.loads(input)
                input = json.dumps(input, indent=2)
            except ValueError:
                pass
            return input

        if self.pretty == "oneline":
            text = "← (" + tool_call_id + ") "
            if not has_header:
                text += f"[bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]: "
            text += f"tool response ({len(content)} characters)"
            self.console.print(text)
        elif self.pretty == "compact":
            if not has_header:
                self.console.rule(
                    "← ("
                    + tool_call_id
                    + f") [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]"
                )
            self.console.print(compact_content(content), markup=False)
        elif self.pretty == "full":
            if not has_header:
                self.console.rule(
                    "← ("
                    + tool_call_id
                    + f") [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]"
                )
            self.console.print(full_content(content), markup=False)
        elif self.pretty == "none":
            pass

    async def log(
        self,
        messages,
        metadata,
        guardrails_results: list[PolicyCheckResult] | None = None,
        guardrails_action: str | None = None,
    ):
        """
        Console-logs the relevant parts of the given messages and metadata.
        """
        session_id = metadata.get("session_id", "<no session id>")
        client = metadata.get("client", "Unknown Client")
        server = metadata.get("mcp_server", "Unknown Server")
        user = metadata.get("user", None)

        tool_names: dict[str, str] = {}

        for msg in messages:
            if msg.get("role") == "tool":
                if (session_id, "output-" + msg.get("tool_call_id")) in self.logged_output:
                    continue
                self.logged_output[(session_id, "output-" + msg.get("tool_call_id"))] = True

                has_header = self.last_logged_tool == (session_id, msg.get("tool_call_id"))
                if not has_header:
                    self.last_logged_tool = (session_id, msg.get("tool_call_id"))

                user_portion = "" if user is None else f" ([bold red]{user}[/bold red])"
                name = tool_names.get(msg.get("tool_call_id"), "<unknown tool>")
                content = message_content(msg)
                self.log_tool_output(
                    has_header, user_portion, name, client, server, content, tool_call_id=msg.get("tool_call_id")
                )
                self.console.print("")

            else:
                for tc in msg.get("tool_calls") or []:
                    name = tc.get("function", {}).get("name", "<unknown tool>")
                    tool_names[tc.get("id")] = name
                    tool_args = tc.get("function", {}).get("arguments", {})

                    if (session_id, tc.get("id")) in self.logged_output:
                        continue
                    self.logged_output[(session_id, tc.get("id"))] = True

                    self.last_logged_tool = (session_id, tc.get("id"))

                    user_portion = "" if user is None else f" ([bold red]{user}[/bold red])"
                    call_id_portion = "(" + tc.get("id") + ")"

                    self.log_tool_call(user_portion, client, server, name, tool_args, call_id_portion)
                    self.console.print("")

        any_error = guardrails_results and any(
            result.result is not None and len(result.result.errors) > 0 for result in guardrails_results
        )

        if any_error:
            self.console.rule()
            if guardrails_results is not None:
                for guardrail_result in guardrails_results:
                    if (
                        guardrail_result.result is not None
                        and len(guardrail_result.result.errors) > 0
                        and guardrails_action is not None
                    ):
                        self.console.print(
                            f"[bold red]GUARDRAIL {guardrails_action.upper()}[/bold red]",
                            format_guardrailing_errors(guardrail_result.result.errors),
                        )
            self.console.rule()
            self.console.print("")


def format_guardrailing_errors(errors: list[ErrorInformation]) -> str:
    """Format a list of errors in a response string."""

    def format_error(error) -> str:
        msg = " ".join(error.args)
        msg += " ".join([f"{k}={v}" for k, v in error.kwargs])
        msg += f" ({len(error.ranges)} range{'' if len(error.ranges) == 1 else 's'})"
        return msg

    return ", ".join([format_error(error) for error in errors])


def message_content(msg: dict) -> str:
    if type(msg.get("content")) is str:
        return msg.get("content", "")
    elif type(msg.get("content")) is list:
        return "\n".join([c["text"] for c in msg.get("content", []) if c["type"] == "text"])
    else:
        return ""


async def get_activity_logger(request: Request) -> ActivityLogger:
    """
    Returns a singleton instance of the ActivityLogger.
    """
    return request.app.state.activity_logger


def setup_activity_logger(app: FastAPI, pretty: Literal["oneline", "compact", "full", "none"] = "compact"):
    """
    Sets up the ActivityLogger as a dependency for the given FastAPI app.
    """
    app.state.activity_logger = ActivityLogger(pretty=pretty)
