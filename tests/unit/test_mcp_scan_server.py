import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml  # type: ignore
from fastapi import HTTPException
from fastapi.testclient import TestClient
from invariant.analyzer import LocalPolicy
from pydantic import ValidationError

from mcp_scan_server.format_guardrail import (
    REQUIRES_PATTERN,
    blacklist_tool_from_guardrail,
    whitelist_tool_from_guardrail,
)
from mcp_scan_server.models import (
    ClientGuardrailConfig,
    DatasetPolicy,
    GuardrailConfig,
    GuardrailConfigFile,
    GuardrailMode,
    ServerGuardrailConfig,
    ToolGuardrailConfig,
)
from mcp_scan_server.parse_config import (
    parse_config,
    parse_server_shorthand_guardrails,
    parse_tool_shorthand_guardrails,
)
from mcp_scan_server.routes.policies import check_policy, get_all_policies  # type: ignore
from mcp_scan_server.server import MCPScanServer

client = TestClient(MCPScanServer().app)


BASE_TEMPLATE_PATH = Path(__file__).parent.parent.parent / "src" / "mcp_scan_server" / "guardrail_templates"


def extract_tool_names(code: str) -> list[str]:
    """
    Extracts all tool names from a string that contains a line like:
    tool_call(tooloutput).function.name in ['tool1', "tool2"]

    Supports both single and double quotes.

    Args:
        code (str): The code-like string to parse.

    Returns:
        list[str]: A list of tool names found in the string.
    """
    # Pattern to match list of tools in the in clause
    list_pattern = r"tool_call\(.*?\)\.function\.name\s+in\s+\[([^\]]+)\]"
    list_match = re.search(list_pattern, code, re.DOTALL)
    if not list_match:
        return []

    tools_raw = list_match.group(1)

    # Extract individual names within quotes
    tool_names = re.findall(r"""['"]([^'"]+)['"]""", tools_raw)
    return tool_names


@patch("mcp_scan_server.parse_config.get_available_templates", return_value=("pii", "moderated", "links", "secrets"))
def get_number_of_guardrail_templates(mock_get_templates, path: Path | None = None) -> int:
    """Get the number of guardrail templates in the default_guardrails directory."""
    if path is None:
        path = BASE_TEMPLATE_PATH
    # Count the number of files in the directory that end with .gr
    return len(mock_get_templates(path))


def get_template_names(path: Path | None = None) -> list[str]:
    """Get the names of the guardrail templates in the default_guardrails directory."""
    if path is None:
        path = BASE_TEMPLATE_PATH
    return [f.replace(".gr", "") for f in os.listdir(path) if f.endswith(".gr")]


@pytest.fixture
def valid_guardrail_config_file(tmp_path):
    """Fixture that creates a temporary valid config file and returns its path."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
cursor:
  servers:
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


@pytest.mark.asyncio
async def test_get_all_policies_valid_config(valid_guardrail_config_file):
    """Test that the get_all_policies function returns the correct policies for a valid config file."""
    policies = await get_all_policies(valid_guardrail_config_file, "cursor", "server1")
    assert len(policies) == 5
    assert all(isinstance(policy, DatasetPolicy) for policy in policies)

    policies = await get_all_policies(valid_guardrail_config_file, "cursor", "server2")
    assert len(policies) == 4
    assert all(isinstance(policy, DatasetPolicy) for policy in policies)


@pytest.mark.asyncio
async def test_get_all_policies_invalid_config(invalid_guardrail_config_file):
    """Test that the get_all_policies function raises an HTTPException for an invalid config file."""
    with pytest.raises(HTTPException):
        await get_all_policies(invalid_guardrail_config_file)


def test_guardrail_config_file_is_validated_on_init_string(invalid_guardrail_config_file):
    """Test that the GuardrailConfigFile is validated on init."""
    with pytest.raises(ValidationError):
        with open(invalid_guardrail_config_file) as f:
            file_data = yaml.safe_load(f)
        GuardrailConfigFile(file_data)


def test_guardrail_config_file_is_validated_on_init_file(invalid_guardrail_config_file):
    """Test that the GuardrailConfigFile is validated on init."""
    with pytest.raises(ValidationError):
        GuardrailConfigFile.from_yaml(invalid_guardrail_config_file)


@pytest.mark.asyncio
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
        GuardrailConfigFile.model_validate(loaded_config)


@pytest.mark.asyncio
async def mock_get_all_policies(config_file_path: str, *args, **kwargs) -> list[str]:
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


@pytest.mark.asyncio
async def test_check_policy_raises_exception_when_trace_violates_policy(error_two_policy_str, simple_trace):
    """Test that the check_policy endpoint raises an exception when the trace violates the policy."""
    result = await check_policy(error_two_policy_str, simple_trace)
    assert len(result.result.errors) == 1
    assert result.result.errors[0].args[0] == "error_two"


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_check_policy_returns_success_when_trace_does_not_violate_policy(detect_random_policy_str, simple_trace):
    """Test that the check_policy endpoint returns success when the trace does not violate the policy."""
    result = await check_policy(detect_random_policy_str, simple_trace)
    assert len(result.result.errors) == 0
    assert result.error_message == ""


@pytest.mark.asyncio
async def test_check_policy_catches_flow_violations(detect_simple_flow_policy_str, simple_flow_trace):
    """Test that the check_policy endpoint catches flow violations."""
    result = await check_policy(detect_simple_flow_policy_str, simple_flow_trace)
    assert len(result.result.errors) == 1
    assert result.result.errors[0].args[0] == "error_flow"


@pytest.fixture
def default_guardrails() -> dict[str, str]:
    guardrails = {}
    for file in os.listdir(BASE_TEMPLATE_PATH):
        if file.endswith(".gr"):
            with open(os.path.join(BASE_TEMPLATE_PATH, file)) as f:
                guardrails[file.replace(".gr", "")] = f.read()
    return guardrails


def test_all_default_guardrails_have_blacklist_whitelist_statement(default_guardrails):
    """Test that all default guardrails have an blacklist/whitelist statement."""
    for guardrail_name, guardrail_content in default_guardrails.items():
        assert (
            "{{ BLACKLIST_WHITELIST }}" in guardrail_content
        ), f"""Default guardrail '{guardrail_name}' does not have an blacklist/whitelist statement.
            It must include exactly '{{ BLACKLIST_WHITELIST }}'."""


def test_all_default_guardrails_have_requires_statement(default_guardrails):
    """Test that all default guardrails have a requires statement."""
    for guardrail_name, guardrail_content in default_guardrails.items():
        match = re.search(REQUIRES_PATTERN, guardrail_content)
        assert match is not None, f"""Default guardrail '{guardrail_name}' does not have a requires statement.
            It must include exactly '{{ REQUIRES: [...]}}'."""


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
      {{ BLACKLIST_WHITELIST }}
      "error" in tooloutput.content
    """

    assert "{{ BLACKLIST_WHITELIST }}" in guardrail_content

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
      {{ BLACKLIST_WHITELIST }}
      "error" in tooloutput.content
    """

    assert "{{ BLACKLIST_WHITELIST }}" in guardrail_content

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


@pytest.mark.asyncio
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

    guardrails, disabled_tools = parse_tool_shorthand_guardrails(server_guardrail_config)

    assert guardrails == {
        "pii": {"tool_name": GuardrailMode.block, "tool_name2": GuardrailMode.block},
        "moderated": {"tool_name": GuardrailMode.paused, "tool_name2": GuardrailMode.paused},
    }

    assert disabled_tools == []


@pytest.mark.asyncio
async def test_parse_default_guardrails():
    """Test that the parse_default_guardrails function parses default guardrails correctly."""
    server_guardrail_config = ServerGuardrailConfig(
        guardrails=GuardrailConfig(
            pii=GuardrailMode.block,
            moderated=GuardrailMode.log,
        ),
    )

    res = parse_server_shorthand_guardrails(server_guardrail_config)

    assert res == {
        "pii": GuardrailMode.block,
        "moderated": GuardrailMode.log,
    }


# use mock of get_available_templates
@pytest.mark.parametrize("client", ["cursor", "browsermcp"])
@pytest.mark.parametrize("server", ["server1", "server2"])
@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=("pii", "moderated", "links", "secrets"))
async def test_empty_config_generates_default_guardrails(mock_get_templates, client, server):
    """Test that the parse_config function generates the correct policies."""
    config = GuardrailConfigFile()
    policies = await parse_config(config, client, server)

    assert len(policies) == get_number_of_guardrail_templates()
    assert {f"{client}-{server}-{template_name}-default" for template_name in get_template_names()} == {
        policy.id for policy in policies
    }
    assert all(policy.enabled is True for policy in policies)
    assert all(policy.action == GuardrailMode.log for policy in policies)


@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=("pii", "moderated", "links", "secrets"))
async def test_empty_string_config_generates_default_guardrails(mock_get_templates):
    """Test that the parse_config function generates the correct policies."""
    config_str = """
    """

    number_of_templates = get_number_of_guardrail_templates()

    config = GuardrailConfigFile.model_validate(config_str)
    policies = await parse_config(config)
    assert len(policies) == number_of_templates

    config_str = None
    config = GuardrailConfigFile.model_validate(config_str)
    policies = await parse_config(config)
    assert len(policies) == number_of_templates

    # Check that parsing in client and server args still works
    policies = await parse_config(config, "cursor", None)
    assert len(policies) == number_of_templates

    policies = await parse_config(config, None, "server1")
    assert len(policies) == number_of_templates

    policies = await parse_config(config, "cursor", "server1")
    assert len(policies) == number_of_templates


@pytest.mark.asyncio
async def test_server_shorthands_override_default_guardrails():
    """Test that server shorthands override default guardrails."""
    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                servers={
                    "server1": ServerGuardrailConfig(
                        guardrails=GuardrailConfig(
                            pii=GuardrailMode.block,
                            moderated=GuardrailMode.paused,
                        ),
                    ),
                },
            )
        }
    )
    policies = await parse_config(config, "cursor", "server1")

    assert len(policies) == get_number_of_guardrail_templates()

    for policy in policies:
        if policy.id == "cursor-server1-pii":
            assert policy.action == GuardrailMode.block
            assert policy.enabled is True
        elif policy.id == "cursor-server1-moderated":
            assert policy.action == GuardrailMode.paused
            assert policy.enabled is True


@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=("pii", "moderated", "links", "secrets"))
async def test_tools_partially_override_default_guardrails(mock_get_templates):
    """Test that tools partially override default guardrails."""
    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                servers={
                    "server1": ServerGuardrailConfig(
                        tools={
                            "tool_name": ToolGuardrailConfig(
                                pii=GuardrailMode.block,
                            ),
                        },
                    ),
                },
            )
        }
    )

    policies = await parse_config(config, "cursor", "server1")

    # One additional policy is created for the tool_name
    assert len(policies) == get_number_of_guardrail_templates() + 1

    for policy in policies:
        # Check that the specific tool shorthand is applied
        if policy.id == "cursor-server1-pii-tool_name":
            assert policy.action == GuardrailMode.block
            assert policy.enabled is True

            # extract whitelist from content
            whitelist = extract_tool_names(policy.content)
            assert whitelist == ["tool_name"]

        # Check that the default rule is still applied and blacklists is tool_name
        if policy.id == "cursor-server1-pii-default":
            assert policy.action == GuardrailMode.log
            assert policy.enabled is True

            # extract blacklist from content
            blacklist = extract_tool_names(policy.content)
            assert blacklist == ["tool_name"]


@pytest.mark.asyncio
async def test_parse_config():
    """Test that the parse_config function parses the config file correctly."""

    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                servers={
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
        }
    )
    policies = await parse_config(config, "cursor", "server1")

    # We should have 7 policies since:
    # pii creates 1 policy because the action (block) of all shorthands match
    # moderated creates 3 policies (one for each action)
    # secrets creates 1 policy because it is defined as a server shorthand
    # links creates 2 policies -- one for the tool_name shorthand and one default
    assert len(policies) == 7


@pytest.mark.asyncio
async def test_disable_tool():
    """Test that the disable_tool function disables a tool correctly."""
    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                servers={
                    "server1": ServerGuardrailConfig(
                        tools={
                            "tool_name": ToolGuardrailConfig(
                                enabled=False,
                            ),
                        },
                    ),
                },
            )
        }
    )
    policies = await parse_config(config, "cursor", "server1")

    found_disabled_tool = False
    disabled_policy_content = ""

    for policy in policies:
        if policy.id == "cursor-server1-tool_name-disabled":
            found_disabled_tool = True
            disabled_policy_content = policy.content
            break

    # Check that the disabled tool policy is found
    assert found_disabled_tool, "Disabled tool policy not found"

    policy = LocalPolicy.from_string(disabled_policy_content)

    # Check that no error is raised when the tool is not in the trace
    result = await policy.a_analyze([{"role": "user", "content": "Hello!"}])
    assert result.errors == []

    # Check that the tool is blocked
    result = await policy.a_analyze(
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "1", "type": "function", "function": {"name": "tool_name", "arguments": {}}}],
            }
        ]
    )
    assert len(result.errors) == 1, "Tool should be blocked"


@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=())
async def test_server_level_guardrails_are_applied_to_all_servers(mock_get_templates):
    """Test that server level guardrails are applied to all servers."""
    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                custom_guardrails=[
                    {
                        "name": "Guardrail 1",
                        "id": "guardrail_1",
                        "enabled": True,
                        "action": "block",
                        "content": "raise 'error' if: (msg: Message) 'error' in msg.content",
                    }
                ]
            )
        }
    )

    # Test that regardless of the server, the guardrail is applied when the client is cursor
    policies = await parse_config(config, "cursor", "server1")
    assert len(policies) == 1
    assert "error" in policies[0].content

    policies = await parse_config(config, "cursor", "server2")
    assert len(policies) == 1
    assert "error" in policies[0].content

    # Test that it is not applied when the client is not cursor
    policies = await parse_config(config, "not_cursor", "server1")
    assert len(policies) == 0


@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=())
async def test_server_level_guardrails(mock_get_templates):
    """Test that server level guardrails are applied correctly."""

    config = """
cursor:
  custom_guardrails:
    - name: "Guardrail 1"
      id: "guardrail_1"
      enabled: true
      action: "block"
      content: |
        raise "this is a custom error" if:
          (msg: Message)
          "error" in msg.content
"""
    config = GuardrailConfigFile.model_validate(yaml.safe_load(config))
    policies = await parse_config(config, "cursor", "server1")
    assert len(policies) == 1
    assert "this is a custom error" in policies[0].content


@pytest.mark.asyncio
@patch("mcp_scan_server.parse_config.get_available_templates", return_value=("pii",))
async def test_defaults_are_added_with_client_level_guardrails(mock_get_templates):
    """Test that defaults are added with client level guardrails."""
    config = GuardrailConfigFile(
        {
            "cursor": ClientGuardrailConfig(
                custom_guardrails=[
                    {
                        "name": "Guardrail 1",
                        "id": "guardrail_1",
                        "enabled": True,
                        "content": "raise 'custom error' if: (msg: Message)",
                    }
                ]
            )
        }
    )

    policies = await parse_config(config, "cursor", "server1")
    assert len(policies) == 2

    policy_ids = [policy.id for policy in policies]
    assert "guardrail_1" in policy_ids
    assert "cursor-server1-pii-default" in policy_ids
