import sys
import json
import uuid
from datetime import datetime, timezone
from pydantic import BaseModel
from typing import Any
import requests


DEFAULT_BASE_URL = "http://localhost:8129"
DATASET_POLICY_PATH = "/api/v1/dataset/byuser/audit/mcp-gateway/policy?client_name={client_name}&server_name={server_name}"
BATCH_CHECK_PATH = "/api/v1/policy/check/batch"

# {'policies': [{'id': 'cursor-audit-links-default', 'name': 'links', 'content': '# {{ REQUIRES: []}}\n\nraise PolicyViolation("Detected link in tool output.") if:\n    (tooloutput: ToolOutput)\n    \n    any([match("https?://[^\\s]+", t) for t in  text(tooloutput.content)])\n', 'enabled': True, 'action': 'log', 'extra_metadata': {}, 'last_updated_time': '2025-10-20 16:54:10'}, {'id': 'cursor-audit-secrets-default', 'name': 'secrets', 'content': '# {{ REQUIRES: []}}\n\nfrom invariant.detectors import secrets\n\nraise PolicyViolation("Found secret in tool output.") if:\n    (tooloutput: ToolOutput)\n    \n    any(secrets(tooloutput.content))\n', 'enabled': True, 'action': 'log', 'extra_metadata': {}, 'last_updated_time': '2025-10-20 16:54:10'}]}
def fetch_policies(base_url: str = DEFAULT_BASE_URL, client_name: str | None = None, server_name: str | None = None) -> Any:
    """Fetch policies from the local policy endpoint.
    """
    return requests.get(base_url + DATASET_POLICY_PATH.format(client_name=client_name, server_name=server_name)).json()

EVENT_HANDLERS = {}

class ParametersMetadata(BaseModel):
    client: str
    server: str
    session_id: str

class ParametersModel(BaseModel):
    metadata: ParametersMetadata


class PayloadModel(BaseModel):
    messages: list[dict]
    policies: list
    parameters: ParametersModel


def check_policies(
    payload_model: PayloadModel,
    *,
    base_url: str = DEFAULT_BASE_URL,
    client_name: str | None = 'cursor',
    server_name: str | None = 'audit',
    timeout: float = 1.0,
    conversation_id: str | None = None,
    generation_id: str | None = None,
) -> Any | None:
    """POST the batch policy check request."""
    policies = fetch_policies(base_url, client_name, server_name)
    policies_content = [p['content'] for p in policies.get("policies", [])]
    payload_model.policies = policies_content

    resp = requests.post(
        base_url + BATCH_CHECK_PATH,
        headers={"Content-Type": "application/json"},
        data=payload_model.model_dump_json(),
        timeout=timeout,
    )
    
    # policy evaluation returns current session length
    session_length = int(resp.headers.get("X-Session-Length", 0))
    last_message_index = session_length - 1

    return convert_to_hook_response(resp.json(), policies.get("policies", []), last_message_index)

def convert_to_hook_response(policy_result: dict, policies: list[dict], current_message_index: int) -> Any:
    # collect all violations
    ACTION_TO_PERMISSION_MAPPING = {
        "log": "approve",
        "paused": "approve",
        "block": "deny",
        "ask": "ask"
    }

    violation_messages = []
    permissions = []

    #policy_result: {'result': [{'policy': '# {{ REQUIRES: []}}\n\nfrom invariant.detectors import secrets\n\nraise PolicyViolation("Found secret in tool output.") if:\n    (tooloutput: ToolOutput)\n    \n    any(secrets(tooloutput.content))\n', 'errors': [], 'success': True, 'error_message': ''}, {'policy': '# {{ REQUIRES: []}}\n\nraise PolicyViolation("Detected link in tool output.") if:\n    (tooloutput: ToolOutput)\n    \n    any(["http://" in t for t in  text(tooloutput.content)])\n', 'errors': [{'key': '(0, (-1, 31))', 'args': ['Detected link in tool output.'], 'kwargs': {}, 'ranges': ['messages.31', 'messages.31.content:116-123', 'messages.31.content']}], 'success': True, 'error_message': ''}]}
    for policy, result in zip(policies, policy_result.get("result", []), strict=True):
        assert policy['content'] == result['policy'], "Policy content does not match."
        if len(result.get("errors", [])) > 0:
            errors_in_current_message = [e for e in result.get("errors", []) if e.get("ranges", [])[0].startswith("messages." + str(current_message_index))]
            
            # only count violations in the current message
            if len(errors_in_current_message) > 0:
                permissions.append(ACTION_TO_PERMISSION_MAPPING.get(policy.get("action", "block"), "deny"))
                violation_messages.append(result.get("error_message", "Policy " + policy.get("name") + " was violated."))

    if any(p == "deny" for p in permissions):
        return {
            "permission": "deny",
            "userMessage": "\n".join(violation_messages),
            "agentMessage": "\n".join(violation_messages),
        }
    elif any(p == "ask" for p in permissions):
        return {
            "permission": "ask",
            "userMessage": "Potential policy violation detected.\n\n" + "\n".join(violation_messages),
            "agentMessage": "Potential policy violation detected.\n\n" + "\n".join(violation_messages),
        }
    else:
        return {
            "permission": "allow",
            "userMessage": "Action Approved",
            "agentMessage": "Action Approved",
        }

def offset(isotimestamp: str, delta: int = 0.0001):
    """Takes an ISO timestamp and returns an ISO timestamp 'delta' seconds in the future."""
    t = datetime.fromisoformat(isotimestamp).replace(tzinfo=timezone.utc).timestamp() + delta
    return datetime.fromtimestamp(t).isoformat().replace("+00:00", "") + "Z"


def tool_call_message(
    conversation_id: str,
    generation_id: str,
    tool_name: str,
    tool_input: dict,
    timestamp: str,
    workspace_roots: list,
    tool_call_id: str,
    hook_event_name: str,
):
    return {
        "role": "assistant",
        "content": "<built-in tool call>",
        "tool_calls": [
            {
                "type": "function",
                "id": tool_call_id,
                "function": {"name": tool_name, "arguments": tool_input},
            }
        ],
        "timestamp": timestamp,
        "metadata": {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": hook_event_name,
            "workspace_roots": workspace_roots,
        },
    }


def tool_output_message(
    conversation_id: str,
    generation_id: str,
    timestamp: str,
    workspace_roots: list,
    tool_call_id: str,
    hook_event_name: str,
    content: str,
):
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": content,
        "timestamp": timestamp,
        "metadata": {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": hook_event_name,
            "workspace_roots": workspace_roots,
        },
    }


def user_message(
    conversation_id: str,
    generation_id: str,
    content: str,
    timestamp: str,
    workspace_roots: list,
    hook_event_name: str,
):
    return {
        "role": "user",
        "content": content,
        "timestamp": timestamp,
        "metadata": {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": hook_event_name,
            "workspace_roots": workspace_roots,
        },
    }


def assistant_message(
    conversation_id: str,
    generation_id: str,
    content: str,
    timestamp: str,
    workspace_roots: list,
    hook_event_name: str,
):
    return {
        "role": "assistant",
        "content": content,
        "timestamp": timestamp,
        "metadata": {
            "conversation_id": conversation_id,
            "generation_id": generation_id,
            "hook_event_name": hook_event_name,
            "workspace_roots": workspace_roots,
        },
    }


def onhook(event_name):
    def decorator(func):
        EVENT_HANDLERS[event_name] = func
        return func

    return decorator


@onhook("stop")
def stop_handler(data):
    conversation_id: str = data.get("conversation_id")
    generation_id: str = data.get("generation_id")
    status: str = data.get("status")
    hook_event_name: str = data.get("hook_event_name")
    workspace_roots: list = data.get("workspace_roots")

    # create an assistant message with the content '<agent stopped>'
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    session_id = str(uuid.uuid4())

    payload_model = PayloadModel(
        messages=[
            assistant_message(
                conversation_id,
                generation_id,
                "<agent stopped status=" + status + ">",
                timestamp,
                workspace_roots,
                hook_event_name,
            )
        ],
        policies=[],
        parameters=ParametersModel(
            metadata=ParametersMetadata(
                client="cursor-" + conversation_id + "-" + generation_id,
                server="<user>",
                session_id=session_id,
            )
        ),
    )

    response = check_policies(payload_model, conversation_id=conversation_id, generation_id=generation_id)
    print(response)


@onhook("beforeSubmitPrompt")
def prompt(data):
    conversation_id: str = data.get("conversation_id")
    generation_id: str = data.get("generation_id")
    prompt: str = data.get("prompt")
    attachments: list = data.get("attachments")
    hook_event_name: str = data.get("hook_event_name")
    workspace_roots: list = data.get("workspace_roots")

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    session_id = str(uuid.uuid4())

    payload_model = PayloadModel(
        messages=[
            user_message(
                conversation_id,
                generation_id,
                prompt + "\n\nAttachments: " + str(attachments),
                timestamp,
                workspace_roots,
                hook_event_name,
            )
        ],
        policies=[],
        parameters=ParametersModel(
            metadata=ParametersMetadata(
                client="cursor-" + conversation_id + "-" + generation_id,
                server="<user>",
                session_id=session_id,
            )
        ),
    )

    response = check_policies(payload_model, conversation_id=conversation_id, generation_id=generation_id)
    # expects '{"continue": true | false}'
    print(json.dumps({
        "continue": response['permission'] == 'allow'
    }))


@onhook("beforeReadFile")
def read_file(data):
    conversation_id: str = data.get("conversation_id")
    generation_id: str = data.get("generation_id")
    content: str = data.get("content")
    file_path: str = data.get("file_path")
    hook_event_name: str = data.get("hook_event_name")
    workspace_roots = data.get("workspace_roots")

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # output time is 'timestamp' but 1m later
    output_time = offset(timestamp)

    session_id = str(uuid.uuid4())
    tool_call_id = conversation_id + "-" + str(uuid.uuid4())

    payload_model = PayloadModel(
        messages=[
            tool_call_message(
                conversation_id,
                generation_id,
                "read_file",
                {"file_path": file_path},
                timestamp,
                workspace_roots,
                tool_call_id,
                hook_event_name,
            ),
            tool_output_message(
                conversation_id,
                generation_id,
                output_time,
                workspace_roots,
                tool_call_id,
                hook_event_name,
                content,
            ),
        ],
        policies=[],
        parameters=ParametersModel(
            metadata=ParametersMetadata(
                client="cursor-" + conversation_id + "-" + generation_id,
                server="<built-in tools>",
                session_id=session_id,
            )
        ),
    )

    response = check_policies(payload_model, conversation_id=conversation_id, generation_id=generation_id)
    # expects {"permission": "allow" | "deny"}
    print(json.dumps({
        "permission": "allow" if response['permission'] == 'allow' else 'deny'
    }))


@onhook("beforeMCPExecution")
def mcp_execution(data):
    conversation_id: str = data.get("conversation_id")
    generation_id: str = data.get("generation_id")
    tool_name: str = data.get("tool_name")
    tool_input: dict = json.loads(data.get("tool_input"))
    command: str = data.get("command")
    workspace_roots: list = data.get("workspace_roots")
    hook_event_name: str = data.get("hook_event_name")

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # output time is 'timestamp' but 1m later
    output_time = offset(timestamp)

    session_id = str(uuid.uuid4())
    tool_call_id = conversation_id + "-" + str(uuid.uuid4())

    payload_model = PayloadModel(
        messages=[
            tool_call_message(
                conversation_id,
                generation_id,
                tool_name,
                tool_input,
                timestamp,
                workspace_roots,
                tool_call_id,
                hook_event_name,
            ),
            tool_output_message(
                conversation_id,
                generation_id,
                output_time,
                workspace_roots,
                tool_call_id,
                hook_event_name,
                "<mcp tool output not yet available>",
            ),
        ],
        policies=[],
        parameters=ParametersModel(
            metadata=ParametersMetadata(
                client="cursor-" + conversation_id + "-" + generation_id,
                server="mcp:" + command,
                session_id=session_id,
            )
        ),
    )

    print(check_policies(payload_model, conversation_id=conversation_id, generation_id=generation_id))


@onhook("beforeShellExecution")
def shell_execution(data):
    conversation_id: str = data.get("conversation_id")
    generation_id: str = data.get("generation_id")
    command: str = data.get("command")
    cwd: str = data.get("cwd")
    hook_event_name: str = data.get("hook_event_name")
    workspace_roots: list = data.get("workspace_roots")

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # output time is 'timestamp' but 1m later
    output_time = offset(timestamp)

    session_id = str(uuid.uuid4())
    tool_call_id = conversation_id + "-" + str(uuid.uuid4())

    payload_model = PayloadModel(
        messages=[
            tool_call_message(
                conversation_id,
                generation_id,
                "execute_shell",
                {"command": command, "cwd": cwd},
                timestamp,
                workspace_roots,
                tool_call_id,
                hook_event_name,
            ),
            tool_output_message(
                conversation_id,
                generation_id,
                output_time,
                workspace_roots,
                tool_call_id,
                hook_event_name,
                "<execute_shell output not yet available>",
            ),
        ],
        policies=[],
        parameters=ParametersModel(
            metadata=ParametersMetadata(
                client="cursor-" + conversation_id + "-" + generation_id,
                server="<built-in tools>",
                session_id=session_id,
            )
        ),
    )

    print(check_policies(payload_model, conversation_id=conversation_id, generation_id=generation_id))


def main():
    data = json.load(sys.stdin)
    event_name = data.get("hook_event_name")
    if event_name in EVENT_HANDLERS:
        EVENT_HANDLERS[event_name](data)
    else:
        print("Unknown event name:", event_name)


if __name__ == "__main__":
    main()
