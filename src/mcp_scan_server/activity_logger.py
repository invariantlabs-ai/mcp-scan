from typing import Literal
import uuid
import rich
import json

from fastapi import APIRouter, FastAPI, Request
from invariant_sdk.types.push_traces import PushTracesResponse

from rich import print
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.rule import Rule
from textwrap import shorten

class ActivityLogger:
    def __init__(self, pretty: Literal["oneline", "compact", "full"] = "compact"):
        self.cached_metadata = {}
        # level of pretty printing
        self.pretty = pretty

        # (session_id, tool_call_id) -> bool
        self.logged_header = {}
        self.logged_result = {}

        # (session_id, formatted_output) -> bool
        self.logged_output = {}
        # last logged (session_id, tool_call_id), so we can skip logging tool call headers if it is directly followed by output
        self.last_logged_tool = None
    
    async def handle_push(self, messages, metadata):
        """
        Handles a push request with the given messages and metadata.
        """
        for i, batch_items in enumerate(messages):
            trace_id = str(uuid.uuid4())
            self.cached_metadata[trace_id] = metadata[i]
            await self.log(batch_items, metadata[i])

        return trace_id

    async def handle_append(self, trace_id: str, messages: list[dict]):
        """
        Handles an append request with the given trace ID and messages.
        """
        metadata = self.cached_metadata.get(trace_id, {})
        await self.log(messages, metadata)

    def empty_metadata(self):
        return {
            "client": "Unknown Client",
            "mcp_server": "Unknown Server",
            "user": None
        }

    async def log(self, messages, metadata):
        """
        Console-logs the relevant parts of the given messages and metadata.
        """
        session_id = metadata.get("session_id", "<no session id>")
        client = metadata.get("client", "Unknown Client").capitalize()
        server = metadata.get("mcp_server", "Unknown Server").capitalize()
        user = metadata.get("user", None)

        tool_names = {}

        for msg in messages:
            if msg.get('role') == 'tool':
                if (session_id, 'output-' + msg.get('tool_call_id')) in self.logged_output:
                    continue
                self.logged_output[(session_id, 'output-' + msg.get('tool_call_id'))] = True

                has_header = self.last_logged_tool == (session_id, msg.get('tool_call_id'))
                
                if not has_header:
                    print(Rule())
                    # left arrow for output
                    user_portion = "" if user is None else f" ([bold red]{user}[/bold red])"
                    name = tool_names.get(msg.get('tool_call_id'), "<unknown tool>")
                    print(f"← [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]")
                print(Rule())

                # tool output
                content = message_content(msg)
                if type(content) is str and content.startswith("Error"):
                    print(Syntax(content, "pytb", theme="monokai"))
                else:
                    print(Syntax(content, "json", theme="monokai"))
                print(Rule())

            else:
                for tc in (msg.get('tool_calls') or []):
                    name = tc.get('function', {}).get('name', "<unknown tool>")
                    tool_names[tc.get('id')] = name

                    if (session_id, tc.get('id')) in self.logged_output:
                        continue
                    self.logged_output[(session_id, tc.get('id'))] = True

                    self.last_logged_tool = (session_id, tc.get('id'))

                    # header
                    user_portion = "" if user is None else f" ([bold red]{user}[/bold red])"

                    print(Rule())
                    print(f"→ [bold blue]{client}[/bold blue]{user_portion} used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]")
                    print(Rule())

                    # tool arguments
                    print(Syntax(json.dumps(tc.get('arguments', {}), indent=2), "json", theme="monokai"))


def message_content(msg: dict) -> str:
    if type(msg.get('content')) is str:
        return msg.get('content', '')
    elif type(msg.get('content')) is list:
        return "\n".join([c['text'] for c in msg.get('content', []) if c['type'] == 'text'])
    else:
        return ""

async def get_activity_logger(request: Request) -> ActivityLogger:
    """
    Returns a singleton instance of the ActivityLogger.
    """
    return request.app.state.activity_logger

def setup_activity_logger(app: FastAPI, pretty: Literal["oneline", "compact", "full"] = "compact"):
    """
    Sets up the ActivityLogger as a dependency for the given FastAPI app.
    """
    app.state.activity_logger = ActivityLogger(pretty=pretty)

