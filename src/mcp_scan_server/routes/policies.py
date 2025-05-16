# type: ignore
import asyncio
import os

import fastapi
import rich
import yaml  # type: ignore
from fastapi import APIRouter, Depends, Request
from invariant.analyzer.policy import LocalPolicy
from invariant.analyzer.runtime.runtime_errors import (
    ExcessivePolicyError,
    InvariantAttributeError,
    MissingPolicyParameter,
)
from pydantic import ValidationError

from mcp_scan_server.activity_logger import ActivityLogger, get_activity_logger

from ..models import (
    BatchCheckRequest,
    BatchCheckResponse,
    DatasetPolicy,
    GuardrailConfigFile,
    PolicyCheckResult,
)
from ..parse_config import parse_config

router = APIRouter()


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
    if not os.path.exists(config_file_path):
        rich.print(
            f"""[bold red]Guardrail config file not found: {config_file_path}. Creating an empty one.[/bold red]"""
        )
        config = GuardrailConfigFile()
        with open(config_file_path, "w") as f:
            f.write(config.model_dump_yaml())

    with open(config_file_path) as f:
        try:
            config = yaml.load(f, Loader=yaml.FullLoader)
        except yaml.YAMLError as e:
            rich.print(f"[bold red]Error loading guardrail config file: {e}[/bold red]")
            raise fastapi.HTTPException(status_code=400, detail=str(e)) from e

        try:
            config = GuardrailConfigFile.model_validate(config)
        except ValidationError as e:
            rich.print(f"[bold red]Error validating guardrail config file: {e}[/bold red]")
            raise fastapi.HTTPException(status_code=400, detail=str(e)) from e
        except Exception as e:
            raise fastapi.HTTPException(status_code=400, detail=str(e)) from e

    configured_policies = await parse_config(config, client_name, server_name)
    return configured_policies


@router.get("/dataset/byuser/{username}/{dataset_name}/policy")
async def get_policy(
    username: str, dataset_name: str, request: Request, client_name: str | None = None, server_name: str | None = None
):
    """Get a policy from local config file."""
    policies = await get_all_policies(request.app.state.config_file_path, client_name, server_name)
    return {"policies": policies}


async def check_policy(policy_str: str, messages: list[dict], parameters: dict | None = None) -> PolicyCheckResult:
    """
    Check a policy using the invariant analyzer.

    Args:
        policy_str: The policy to check.
        messages: The messages to check the policy against.
        parameters: The parameters to pass to the policy analyze call.

    Returns:
        A PolicyCheckResult object.
    """
    try:
        policy = LocalPolicy.from_string(policy_str)

        if isinstance(policy, Exception):
            return PolicyCheckResult(
                policy=policy_str,
                success=False,
                error_message=str(policy),
            )

        result = await policy.a_analyze_pending(messages[:-1], [messages[-1]], **(parameters or {}))

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


@router.post("/policy/check/batch", response_model=BatchCheckResponse)
async def batch_check_policies(
    check_request: BatchCheckRequest,
    request: fastapi.Request,
    activity_logger: ActivityLogger = Depends(get_activity_logger),
):
    """Check a policy using the invariant analyzer."""
    results = await asyncio.gather(
        *[check_policy(policy, check_request.messages, check_request.parameters) for policy in check_request.policies]
    )

    metadata = check_request.parameters.get("metadata", {})
    guardrails_action = check_request.parameters.get("action", "block")

    await activity_logger.log(
        check_request.messages,
        {
            "client": metadata.get("client", "Unknown Client"),
            "mcp_server": metadata.get("server", "Unknown Server"),
            "user": metadata.get("system_user", None),
            "session_id": metadata.get("session_id", "<no session id>"),
        },
        results,
        guardrails_action,
    )

    return fastapi.responses.JSONResponse(
        content={"result": [to_json_serializable_dict(result.to_dict()) for result in results]}
    )
