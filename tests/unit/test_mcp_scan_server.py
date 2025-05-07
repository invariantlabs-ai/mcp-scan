import os
from unittest.mock import patch

import pytest
import yaml  # type: ignore
from fastapi import HTTPException
from fastapi.testclient import TestClient

from mcp_scan_server.format_guardrail import blacklist_tool_from_guardrail, whitelist_tool_from_guardrail
from mcp_scan_server.models import (
    DatasetPolicy,
    GuardrailConfig,
    GuardrailConfigFile,
    GuardrailMode,
    ServerGuardrailConfig,
    ToolGuardrailConfig,
)
from mcp_scan_server.parse_config import _parse_default_guardrails, _parse_tool_guardrails, parse_config
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
  server1:
    guardrails:
      pii: "block"
      moderated: "block"
      links: "block"
      secrets: "block"

      custom_guardrails:
        - name: "Guardrail 1"
          id: "guardrail_1"
          enabled: true
          action: "block"
          content: |
            raise "error" if:
              (msg: ToolOutput)
              "Test1" in msg.content

        - name: "Guardrail 2"
          id: "guardrail_2"
          enabled: true
          action: "block"
          content: |
            raise "error" if:
              (msg: ToolOutput)
              "Test2" in msg.content

    tools:
        tool_name:
            enabled: true
            pii: "block"
            moderated: "block"
            links: "block"
            secrets: "block"
  server2:
    guardrails:
      pii: "block"
      moderated: "block"
      links: "block"
      secrets: "block"

    tools:
        tool_name:
            enabled: true
            pii: "block"
            moderated: "block"
            links: "block"
            secrets: "block"
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
    policies = await get_all_policies(valid_guardrail_config_file, ["cursor"], ["server1"])
    print(policies)
    assert len(policies) == 6
    assert all(isinstance(policy, DatasetPolicy) for policy in policies)

    policies = await get_all_policies(valid_guardrail_config_file, ["cursor"], ["server2"])
    print(policies)
    assert len(policies) == 4
    assert all(isinstance(policy, DatasetPolicy) for policy in policies)


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
async def mock_get_all_policies(*args, **kwargs) -> list[str]:
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


@pytest.fixture
def default_guardrails() -> dict[str, str]:
    basepath = os.path.dirname(__file__)
    guardrails_path = os.path.join(basepath, "..", "..", "src", "mcp_scan_server", "default_guardrails")
    guardrails = {}
    for file in os.listdir(guardrails_path):
        if file.endswith(".gr"):
            with open(os.path.join(guardrails_path, file)) as f:
                guardrails[file.replace(".gr", "")] = f.read()
    return guardrails


def test_all_default_guardrails_have_blacklist_whitelist_statement(default_guardrails):
    """Test that all default guardrails have an blacklist/whitelist statement."""
    print(default_guardrails)
    for guardrail_name, guardrail_content in default_guardrails.items():
        assert (
            "#BLACKLIST_WHITELIST_STATEMENT" in guardrail_content
        ), f"""Default guardrail '{guardrail_name}' does not have an blacklist/whitelist statement.
            It must include exactly '#BLACKLIST_WHITELIST_STATEMENT'."""


@pytest.mark.parametrize(
    "tool_names",
    [
        ["tool_name"],
        ["tool_name", "tool_name2"],
        ["tool_name", "tool_name2", "tool_name3"],
    ],
)
def test_format_guardrail_whitelist_tool(tool_names):
    """Test that the format_guardrail function whitelists a tool correctly."""
    guardrail_content = """
    raise "error" if:
      (tooloutput: ToolOutput)
      #BLACKLIST_WHITELIST_STATEMENT
      "error" in tooloutput.content
    """

    assert "#BLACKLIST_WHITELIST_STATEMENT" in guardrail_content

    formatted_guardrail = whitelist_tool_from_guardrail(guardrail_content, tool_names)
    assert (
        formatted_guardrail
        == f"""
    raise "error" if:
      (tooloutput: ToolOutput)
      tool_call(tooloutput).function.name in {tool_names}
      "error" in tooloutput.content
    """
    )


@pytest.mark.parametrize(
    "tool_names",
    [
        ["tool_name"],
        ["tool_name", "tool_name2"],
        ["tool_name", "tool_name2", "tool_name3"],
    ],
)
def test_format_guardrail_blacklist_tool(tool_names):
    """Test that the format_guardrail function blacklists a tool correctly."""
    guardrail_content = """
    raise "error" if:
      (tooloutput: ToolOutput)
      #BLACKLIST_WHITELIST_STATEMENT
      "error" in tooloutput.content
    """

    assert "#BLACKLIST_WHITELIST_STATEMENT" in guardrail_content

    formatted_guardrail = blacklist_tool_from_guardrail(guardrail_content, tool_names)
    assert (
        formatted_guardrail
        == f"""
    raise "error" if:
      (tooloutput: ToolOutput)
      not (tool_call(tooloutput).function.name in {tool_names})
      "error" in tooloutput.content
    """
    )


@pytest.mark.anyio
async def test_parse_tool_guardrails():
    """Test that the parse_tool_guardrails function parses tool guardrails correctly."""
    server_guardrail_config = ServerGuardrailConfig(
        guardrails=GuardrailConfig(
            pii=GuardrailMode.block,
            moderated=GuardrailMode.log,
        ),
        tools={
            "tool_name": ToolGuardrailConfig(
                pii=GuardrailMode.block,
                moderated=GuardrailMode.paused,
                enabled=True,
            ),
            "tool_name2": ToolGuardrailConfig(
                pii=GuardrailMode.block,
                moderated=GuardrailMode.paused,
                enabled=True,
            ),
        },
    )

    res = await _parse_tool_guardrails(server_guardrail_config)

    assert res == {
        "pii": {"tool_name": GuardrailMode.block, "tool_name2": GuardrailMode.block},
        "moderated": {"tool_name": GuardrailMode.paused, "tool_name2": GuardrailMode.paused},
    }


@pytest.mark.anyio
async def test_parse_default_guardrails():
    """Test that the parse_default_guardrails function parses default guardrails correctly."""
    server_guardrail_config = ServerGuardrailConfig(
        guardrails=GuardrailConfig(
            pii=GuardrailMode.block,
            moderated=GuardrailMode.log,
        ),
    )

    res = await _parse_default_guardrails(server_guardrail_config)

    assert res == {
        "pii": GuardrailMode.block,
        "moderated": GuardrailMode.log,
    }


@pytest.mark.anyio
async def test_parse_config_generates_correct_policies():
    """Test that the parse_config function generates the correct policies."""
    config = GuardrailConfigFile(
        cursor={
            "server1": ServerGuardrailConfig(
                guardrails=GuardrailConfig(
                    pii=GuardrailMode.block,
                ),
                tools={
                    "tool_name": ToolGuardrailConfig(
                        pii=GuardrailMode.log,
                    ),
                },
            )
        }
    )

    policies = await parse_config(config)

    # We should have a policy that is general and one that is for tool_name
    assert len(policies) == 2

    for policy in policies:
        if policy.id == "cursor-server1-pii":
            assert policy.action == GuardrailMode.block
            assert policy.enabled is True
        elif policy.id == "cursor-server1-pii-tool_name":
            assert policy.action == GuardrailMode.log
            assert policy.enabled is True
        else:
            raise ValueError(f"Unexpected policy: {policy.id}")


@pytest.mark.anyio
async def test_parse_config():
    """Test that the parse_config function parses the config file correctly."""
    config = GuardrailConfigFile(
        cursor={
            "server1": ServerGuardrailConfig(
                guardrails=GuardrailConfig(
                    pii=GuardrailMode.block,
                    moderated=GuardrailMode.log,
                    secrets=GuardrailMode.paused,
                ),
                tools={
                    "tool_name": ToolGuardrailConfig(
                        pii=GuardrailMode.block,
                        moderated=GuardrailMode.paused,
                        links=GuardrailMode.log,
                        enabled=True,
                    ),
                    "tool_name2": ToolGuardrailConfig(
                        pii=GuardrailMode.block,
                        moderated=GuardrailMode.block,
                        enabled=True,
                    ),
                },
            )
        }
    )
    config = await parse_config(config)

    # We should have 6 policies since:
    # pii creates 1 policy because the two tools defined the same pii action
    # moderated creates 3 policies (one general (log), one for tool_name(paused), one for tool_name2 (block))
    # secrets creates 1 policy (general (paused))
    # links creates 1 policy (tool_name (log))
    assert len(config) == 6
