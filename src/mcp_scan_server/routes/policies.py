# type: ignore
import asyncio
import os
from typing import Any

import fastapi
import rich
import yaml  # type: ignore
from fastapi import APIRouter, Depends, Request
from invariant.analyzer.policy import LocalPolicy
from invariant.analyzer.runtime.nodes import Event
from invariant.analyzer.runtime.runtime_errors import (
    ExcessivePolicyError,
    InvariantAttributeError,
    MissingPolicyParameter,
)
from pydantic import ValidationError

from mcp_scan_server.activity_logger import ActivityLogger, get_activity_logger
from mcp_scan_server.session_store import SessionStore, to_session

from ..models import (
    DEFAULT_GUARDRAIL_CONFIG,
    BatchCheckRequest,
    BatchCheckResponse,
    DatasetPolicy,
    GuardrailConfigFile,
    PolicyCheckResult,
)
from ..parse_config import parse_config

router = APIRouter()
session_store = SessionStore()


async def load_guardrails_config_file(config_file_path: str) -> GuardrailConfigFile:
    """Load the guardrails config file.

    Args:
        config_file_path: The path to the config file.

    Returns:
        The loaded config file.
    """
    if not os.path.exists(config_file_path):
        rich.print(
            f"""[bold red]Guardrail config file not found: {config_file_path}. Creating an empty one.[/bold red]"""
        )
        config = GuardrailConfigFile()
        with open(config_file_path, "w") as f:
            f.write(DEFAULT_GUARDRAIL_CONFIG)

    with open(config_file_path) as f:
        try:
            config = yaml.load(f, Loader=yaml.FullLoader)
        except yaml.YAMLError as e:
            rich.print(f"[bold red]Error loading guardrail config file: {e}[/bold red]")
            raise ValueError("Invalid guardrails config file at " + config_file_path) from e

        try:
            config = GuardrailConfigFile.model_validate(config)
        except ValidationError as e:
            rich.print(f"[bold red]Error validating guardrail config file: {e}[/bold red]")
            raise ValueError("Invalid guardrails config file at " + config_file_path) from e
        except Exception as e:
            raise ValueError("Invalid guardrails config file at " + config_file_path) from e

    if not config:
        rich.print(f"[bold red]Guardrail config file is empty: {config_file_path}[/bold red]")
        raise ValueError("Empty config file")

    return config


async def get_all_policies(
    config_file_path: str,
    client_name: str | None = None,
    server_name: str | None = None,
) -> list[DatasetPolicy]:
    """Get all policies from local config file.

    Args:
        config_file_path: The path to the config file.
        client_name: The client name to include guardrails for.
        server_name: The server name to include guardrails for.

    Returns:
        A list of DatasetPolicy objects.
    """

    try:
        config = await load_guardrails_config_file(config_file_path)
    except ValueError as e:
        rich.print(f"[bold red]Error loading guardrail config file: {config_file_path}[/bold red]")
        raise fastapi.HTTPException(
            status_code=400,
            detail="Error loading guardrail config file",
        ) from e

    configured_policies = await parse_config(config, client_name, server_name)
    return configured_policies


@router.get("/dataset/byuser/{username}/{dataset_name}/policy")
async def get_policy(
    username: str, dataset_name: str, request: Request, client_name: str | None = None, server_name: str | None = None
):
    """Get a policy from local config file."""
    policies = await get_all_policies(request.app.state.config_file_path, client_name, server_name)
    return {"policies": policies}


async def check_policy(
    policy_str: str, messages: list[dict[str, Any]], parameters: dict | None = None, from_index: int = -1
) -> PolicyCheckResult:
    """
    Check a policy using the invariant analyzer.

    Args:
        policy_str: The policy to check.
        messages: The messages to check the policy against.
        parameters: The parameters to pass to the policy analyze call.

    Returns:
        A PolicyCheckResult object.
    """

    # If from_index is not provided, assume all but the last message have been analyzed
    from_index = from_index if from_index != -1 else len(messages) - 1

    try:
        policy = LocalPolicy.from_string(policy_str)

        if isinstance(policy, Exception):
            return PolicyCheckResult(
                policy=policy_str,
                success=False,
                error_message=str(policy),
            )
        result = await policy.a_analyze_pending(messages[:from_index], messages[from_index:], **(parameters or {}))

        return PolicyCheckResult(
            policy=policy_str,
            result=result,
            success=True,
        )

    except (MissingPolicyParameter, ExcessivePolicyError, InvariantAttributeError) as e:
        return PolicyCheckResult(
            policy=policy_str,
            success=False,
            error_message=str(e),
        )
    except Exception as e:
        return PolicyCheckResult(
            policy=policy_str,
            success=False,
            error_message="Unexpected error: " + str(e),
        )


def to_json_serializable_dict(obj):
    """Convert a dictionary to a JSON serializable dictionary."""
    if isinstance(obj, dict):
        return {k: to_json_serializable_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [to_json_serializable_dict(v) for v in obj]
    elif isinstance(obj, str | int | float | bool):
        return obj
    else:
        return type(obj).__name__ + "(" + str(obj) + ")"


async def get_messages_from_session(
    check_request: BatchCheckRequest, client_name: str, server_name: str, session_id: str
) -> list[Event]:
    """Get the messages from the session store."""
    try:
        session = await to_session(check_request.messages, server_name, session_id)
        session = session_store.fetch_and_merge(client_name, session)
        messages = [node.message for node in session.get_sorted_nodes()]
    except Exception as e:
        rich.print(
            f"[bold red]Error parsing messages for client {client_name} and server {server_name}: {e}[/bold red]"
        )

        # If we fail to parse the session, return the original messages
        messages = check_request.messages

    return messages


@router.post("/policy/check/batch", response_model=BatchCheckResponse)
async def batch_check_policies(
    check_request: BatchCheckRequest,
    request: fastapi.Request,
    activity_logger: ActivityLogger = Depends(get_activity_logger),
):
    """Check a policy using the invariant analyzer."""
    metadata = check_request.parameters.get("metadata", {})

    mcp_client = metadata.get("client", "Unknown Client")
    mcp_server = metadata.get("server", "Unknown Server")
    session_id = metadata.get("session_id", "<no session id>")

    messages = await get_messages_from_session(check_request, mcp_client, mcp_server, session_id)
    last_analysis_index = session_store[mcp_client].last_analysis_index

    results = await asyncio.gather(
        *[
            check_policy(policy, messages, check_request.parameters, last_analysis_index)
            for policy in check_request.policies
        ]
    )

    # Update the last analysis index
    session_store[mcp_client].last_analysis_index = len(messages)
    guardrails_action = check_request.parameters.get("action", "block")

    await activity_logger.log(
        check_request.messages,
        {
            "client": mcp_client,
            "mcp_server": mcp_server,
            "user": metadata.get("system_user", None),
            "session_id": session_id,
        },
        results,
        guardrails_action,
    )

    return fastapi.responses.JSONResponse(
        content={"result": [to_json_serializable_dict(result.to_dict()) for result in results]}
    )
