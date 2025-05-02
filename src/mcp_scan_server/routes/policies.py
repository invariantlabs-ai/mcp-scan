import asyncio
import os

import fastapi
import rich
import yaml  # type: ignore
from fastapi import APIRouter, Request
from invariant.analyzer.policy import LocalPolicy
from invariant.analyzer.runtime.runtime_errors import (
    ExcessivePolicyError,
    InvariantAttributeError,
    MissingPolicyParameter,
)
from pydantic import ValidationError

from ..models import (
    BatchCheckRequest,
    BatchCheckResponse,
    DatasetPolicy,
    GuardrailConfigFile,
    PolicyCheckResult,
)

router = APIRouter()


async def get_all_policies(
    config_file_path: str, client_names: list[str] | None = None, server_names: list[str] | None = None
) -> list[DatasetPolicy]:
    """Get all policies from local config file.

    Args:
        config_file_path: The path to the config file.
        client_names: List of client names to include guardrails for.
        server_names: List of server names to include guardrails for.

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

    with open(config_file_path, "r") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        try:
            config = GuardrailConfigFile.model_validate(config)
        except ValidationError as e:
            rich.print(f"[bold red]Error validating guardrail config file: {e}[/bold red]")
            raise fastapi.HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise fastapi.HTTPException(status_code=400, detail=str(e))

    policies: list[DatasetPolicy] = []
    for client_name, client_conf in config:
        # If no filter is set or the client name is not in the filter, skip
        if client_names and client_name not in client_names or client_conf is None:
            continue

        for server_name, server_conf in client_conf.items():
            # If no filter is set or the server name is not in the filter, skip
            if server_names and server_name not in server_names or server_conf is None:
                continue

            # Add guardrails
            for policy in server_conf.guardrails.custom_guardrails:
                if policy.enabled:
                    policies.append(policy)

    return policies


@router.get("/dataset/byuser/{username}/{dataset_name}/policy")
async def get_policy(username: str, dataset_name: str, request: Request):
    """Get a policy from local config file."""
    policies = await get_all_policies(request.app.state.config_file_path)
    return {"policies": policies}


async def check_policy(policy_str: str, messages: list[dict], parameters: dict = {}) -> PolicyCheckResult:
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

        result = await policy.a_analyze_pending(messages[:-1], [messages[-1]], **parameters)

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
    elif isinstance(obj, str):
        return obj
    elif isinstance(obj, (int, float, bool)):
        return obj
    else:
        return type(obj).__name__ + "(" + str(obj) + ")"


@router.post("/policy/check/batch", response_model=BatchCheckResponse)
async def batch_check_policies(request: BatchCheckRequest):
    """Check a policy using the invariant analyzer."""
    results = await asyncio.gather(
        *[check_policy(policy, request.messages, request.parameters) for policy in request.policies]
    )

    return fastapi.responses.JSONResponse(
        content={"result": [to_json_serializable_dict(result.to_dict()) for result in results]}
    )
