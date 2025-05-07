import os
from unittest.mock import patch

import pytest
import yaml  # type: ignore
from fastapi import HTTPException
from fastapi.testclient import TestClient

from mcp_scan_server.models import DatasetPolicy, GuardrailConfig
from mcp_scan_server.routes.policies import check_policy, get_all_policies
from mcp_scan_server.server import MCPScanServer

client = TestClient(MCPScanServer().app)


@pytest.fixture
def valid_guardrail_config_file(tmp_path):
    """Fixture that creates a temporary valid config file and returns its path."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
cursor:
  browsermcp:
    guardrails:
      - name: "Guardrail 1"
        id: "guardrail_1"
        runs-on: "local"
        enabled: true
        action: "block"
        content: |
          raise "error" if:
            (msg: ToolOutput)
            "Test1" in msg.content
      - name: "Guardrail 2"
        id: "guardrail_2"
        runs-on: "local"
        enabled: true
        action: "block"
        content: |
          raise "error" if:
            (msg: ToolOutput)
            "Test2" in msg.content
"""
    )
    return str(config_file)


@pytest.fixture
def invalid_guardrail_config_file(tmp_path):
    """Fixture that creates a temporary invalid config file and returns its path."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
cursor:
  browsermcp:
    guardrails:
      - name: "Guardrail 1"
        id: "guardrail_1"
        runs-on: "local"
        enabled: true
        action: "block"
"""
    )
    return str(config_file)


@pytest.mark.anyio
async def test_get_all_policies_valid_config(valid_guardrail_config_file):
    """Test that the get_all_policies function returns the correct policies for a valid config file."""
    policies = await get_all_policies(valid_guardrail_config_file)
    print(policies)
    assert len(policies) == 2
    assert all(isinstance(policy, DatasetPolicy) for policy in policies)
    assert policies[0].id == "guardrail_1"
    assert policies[1].id == "guardrail_2"
    assert policies[0].name == "Guardrail 1"
    assert policies[1].name == "Guardrail 2"


@pytest.mark.anyio
async def test_get_all_policies_invalid_config(invalid_guardrail_config_file):
    """Test that the get_all_policies function raises an HTTPException for an invalid config file."""
    with pytest.raises(HTTPException):
        await get_all_policies(invalid_guardrail_config_file)


@pytest.mark.anyio
async def test_get_all_policies_creates_file_when_missing(tmp_path):
    """Test that get_all_policies creates a config file if it doesn't exist."""
    # Create a path to a non-existent file
    config_file_path = str(tmp_path / "nonexistent_config.yaml")

    # Verify the file doesn't exist before calling the function
    assert not os.path.exists(config_file_path)

    # Call the function
    await get_all_policies(config_file_path)

    # Verify the file now exists
    assert os.path.exists(config_file_path)

    # Verify the file contains a valid empty config
    with open(config_file_path) as f:
        config_content = f.read()
        loaded_config = yaml.safe_load(config_content)

        # Validate the config
        GuardrailConfig.model_validate(loaded_config)


@pytest.mark.anyio
async def mock_get_all_policies(config_file_path: str) -> list[str]:
    return ["some_guardrail"]


@patch("mcp_scan_server.routes.policies.get_all_policies", mock_get_all_policies)
def test_get_policy_endpoint():
    """Test that the get_policy returns a dict with a list of policies."""
    response = client.get("/api/v1/dataset/byuser/testuser/test_dataset/policy")
    assert response.status_code == 200
    assert response.json() == {"policies": ["some_guardrail"]}


# fixture policy_str
@pytest.fixture
def error_one_policy_str():
    return """
    raise "error_one" if:
      (msg: Message)
      "error_one" in msg.content
    """


@pytest.fixture
def error_two_policy_str():
    return """
    raise "error_two" if:
      (msg: Message)
      "error_two" in msg.content
    """


@pytest.fixture
def detect_random_policy_str():
    return """
    raise "error_random" if:
      (msg: Message)
      "random" in msg.content
    """


@pytest.fixture
def detect_simple_flow_policy_str():
    return """
    raise "error_flow" if:
      (msg1: Message)
      (msg2: ToolOutput)
      msg1.content == "request_tool"
      msg2.content == "tool_output"
    """


@pytest.fixture
def simple_trace():
    return [
        {"content": "error_one", "role": "user"},
        {"content": "error_two", "role": "user"},
    ]


@pytest.fixture
def simple_flow_trace():
    return [
        {"content": "request_tool", "role": "user"},
        {"content": "some_response", "role": "assistant"},
        {"content": "tool_output", "role": "tool"},
    ]


@pytest.mark.anyio
async def test_check_policy_raises_exception_when_trace_violates_policy(error_two_policy_str, simple_trace):
    """Test that the check_policy endpoint raises an exception when the trace violates the policy."""
    result = await check_policy(error_two_policy_str, simple_trace)
    assert len(result.result.errors) == 1
    assert result.result.errors[0].args[0] == "error_two"


@pytest.mark.anyio
async def test_check_policy_only_raises_error_on_last_message(error_one_policy_str, error_two_policy_str, simple_trace):
    """Test that the check_policy endpoint only raises an error on the last message."""
    # Should not raise an error as the last message does not contain "error_one"
    result_one = await check_policy(error_one_policy_str, simple_trace)
    assert len(result_one.result.errors) == 0
    assert result_one.error_message == ""

    # Should raise an error as the last message contains "error_two"
    result_two = await check_policy(error_two_policy_str, simple_trace)
    assert len(result_two.result.errors) == 1
    assert result_two.result.errors[0].args[0] == "error_two"


@pytest.mark.anyio
async def test_check_policy_returns_success_when_trace_does_not_violate_policy(detect_random_policy_str, simple_trace):
    """Test that the check_policy endpoint returns success when the trace does not violate the policy."""
    result = await check_policy(detect_random_policy_str, simple_trace)
    assert len(result.result.errors) == 0
    assert result.error_message == ""


@pytest.mark.anyio
async def test_check_policy_catches_flow_violations(detect_simple_flow_policy_str, simple_flow_trace):
    """Test that the check_policy endpoint catches flow violations."""
    result = await check_policy(detect_simple_flow_policy_str, simple_flow_trace)
    assert len(result.result.errors) == 1
    assert result.result.errors[0].args[0] == "error_flow"
