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
        metadata = self.cached_metadata.get(trace_id, None)
        await self.log(messages, metadata)

    async def log(self, messages, metadata=None):
        """
        Console-logs the relevant parts of the given messages and metadata.
        """

        client = metadata.get("client", "Unknown Client").capitalize()
        server = metadata.get("mcp_server", "Unknown Server").capitalize()
        user = metadata.get("user", "Unknown User")
        
        for tc in tool_calls(messages):
            name = tc['name']

            print(Rule())
            print(f"● [bold blue]{client}[/bold blue] (@[bold red]{user}[/bold red]) used [bold green]{server}[/bold green] to [bold green]{name}[/bold green]")
            print(Rule())
            
            if self.pretty != 'oneline':
                args = tc.get("arguments", {})
                result = tc.get("result", "")

                if self.pretty == 'compact':
                    truncated_result = truncate_preserving_whitespace(result)

                    print(Syntax(json.dumps(args, indent=2), "json", theme="monokai"))
                    print(Rule(style="grey50"))
                    print(Syntax(truncated_result, "json" if not truncated_result.startswith("Error") else "pytb", theme="monokai"))
                    print(Rule(style="grey50"))
                else:
                    print(Syntax(json.dumps(args, indent=2), "json", theme="monokai"))
                    print(Rule(style="grey50"))
                    print(Syntax(result, "json" if not result.startswith("Error") else "pytb", theme="monokai"))
                    print(Rule(style="grey50"))


def tool_calls(messages: list[dict]) -> list[dict]:
    calls = {}

    # First pass: index tool call requests
    for msg in messages:
        if 'tool_calls' in msg:
            for call in (msg['tool_calls'] or []):
                calls[call['id']] = {
                    "name": call['function'].get('name', "<unknown tool>"),
                    "arguments": call['function'].get('arguments', {})
                }

    # Second pass: find responses with matching tool_call_id
    for msg in messages:
        if msg.get('tool_call_id') in calls:
            result_texts = [c['text'] for c in msg.get('content', []) if c['type'] == 'text']
            calls[msg['tool_call_id']]["result"] = "\n".join(result_texts)

    return list(calls.values())

def truncate_preserving_whitespace(text, max_lines=20, max_chars=2000):
    lines = text.splitlines()
    truncated = "\n".join(lines[:max_lines])
    if len(truncated) > max_chars:
        truncated = truncated[:max_chars] + "\n... [truncated]"
    elif len(lines) > max_lines:
        truncated += "# \n... [truncated]"
    return truncated

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

