import asyncio

import fastapi
import yaml
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
    PolicyCheckResult,
    GuardrailConfig,
)

router = APIRouter()


async def get_all_policies(config_file_path: str) -> list[DatasetPolicy]:
    """
    Get all policies from local config file.
    """
    with open(config_file_path, "r") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        try:
            config = GuardrailConfig.model_validate(config)
        except ValidationError as e:
            raise fastapi.HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise fastapi.HTTPException(status_code=400, detail=str(e))

    policies = [
        DatasetPolicy(
            id=guardrail.id,
            name=guardrail.name,
            content=guardrail.content,
            enabled=guardrail.enabled,
            action=guardrail.action,
            extra_metadata={
                "platform": platform_name,
                "tool": tool_name,
            },
        )
        for platform_name, platform_data in config.root.items()
        for tool_name, server_guardrails in platform_data.items()
        for guardrail in server_guardrails.guardrails
    ]

    return policies


@router.get("/dataset/byuser/{username}/{dataset_name}/policy")
async def get_policy(username: str, dataset_name: str, request: Request):
    """
    Get a policy from local config file.
    """
    policies = await get_all_policies(request.app.state.config_file_path)
    return {"policies": policies}


async def check_policy(
    policy_str: str, messages: list[dict], parameters: dict = {}
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
    try:
        policy = LocalPolicy.from_string(policy_str)

        if isinstance(policy, Exception):
            return PolicyCheckResult(
                policy=policy_str,
                success=False,
                error_message=str(policy),
            )

        result = await policy.a_analyze(messages, **parameters)

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
    """
    Converts a dictionary to a JSON serializable dictionary.
    """
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
    """
    Check a policy using the invariant analyzer.
    """
    results = await asyncio.gather(
        *[
            check_policy(policy, request.messages, request.parameters)
            for policy in request.policies
        ]
    )

    return fastapi.responses.JSONResponse(
        content={
            "result": [
                to_json_serializable_dict(result.to_dict()) for result in results
            ]
        }
    )
