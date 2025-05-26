import logging
import os
from functools import lru_cache
from pathlib import Path

import rich
from invariant.__main__ import shortname
from invariant.analyzer.extras import extras_available

from mcp_scan_server.format_guardrail import (
    blacklist_tool_from_guardrail,
    extract_requires,
    whitelist_tool_from_guardrail,
)
from mcp_scan_server.models import (
    ClientGuardrailConfig,
    DatasetPolicy,
    GuardrailConfigFile,
    GuardrailMode,
    ServerGuardrailConfig,
)

logger = logging.getLogger(__name__)

# Naming scheme for guardrails:
# - default guardrails are guardrails that are implicit and always applied
# - Custom guardrails refer to guardrails that are defined in the server config
# - tool shorthands are guardrails that are defined in the server config for a tool such as pii: "block"
# - server shorthands are guardrails that are defined in the server config for a server such as pii: "block"
# - shorthands are thus always of the form <guardrail>:<action> and refer to both tools and servers

# Constants
DEFAULT_GUARDRAIL_DIR = Path(__file__).with_suffix("").parents[1] / "mcp_scan_server" / "guardrail_templates"


@lru_cache
def load_template(name: str, directory: Path = DEFAULT_GUARDRAIL_DIR) -> str:
    """Return the content of 'name'.gr from directory (cached).

    Note that this is static after startup. If you update a template guardrail,
    you will need to restart the server.

    Args:
        name: The name of the guardrail template to load.
        directory: The directory to load the guardrail template from.

    Returns:
        The content of the guardrail template.
    """
    path = directory / f"{name}.gr"
    if not path.is_file():
        raise FileNotFoundError(f"Missing guardrail template: {path}")
    return path.read_text(encoding="utf-8")


def _print_missing_openai_key_message(template: str) -> None:
    rich.print(
        f"[yellow]Missing OPENAI_API_KEY for default guardrail [cyan bold]{template}[/cyan bold][/yellow]\n"
        f"[green]Hint: Please set the [bold white]OPENAI_API_KEY[/bold white] environment variable and try again.[/green]\n"
    )


def _print_missing_dependencies_message(template: str, missing_extras: list) -> None:
    short_extras = [shortname(extra.name) for extra in missing_extras]
    rich.print(
        f"[yellow]Missing dependencies for default guardrail [cyan bold]{template}[/cyan bold][/yellow]\n"
        f"[green]Hint: Install them with [bold white]--install-extras {' '.join(short_extras)}[/bold white][/green]\n"
        f"[green]Hint: Install all extras with [bold white]--install-extras all[/bold white][/green]\n"
    )


@lru_cache
def get_available_templates(directory: Path = DEFAULT_GUARDRAIL_DIR) -> tuple[str, ...]:
    """Get all guardrail templates in directory.

    Args:
        directory: The directory to load the guardrail templates from.

    Returns:
        A tuple of guardrail template names.
    """
    all_templates = {p.stem for p in directory.glob("*.gr")}
    available_templates = set(all_templates)  # Create a copy to modify

    for template in all_templates:
        extras_required = extract_requires(load_template(template))

        # Check for OpenAI API key requirement
        if any(extra.name == "OpenAI" for extra in extras_required) and not os.getenv("OPENAI_API_KEY"):
            _print_missing_openai_key_message(template)
            available_templates = available_templates - {template}

        # Check for missing dependencies
        missing_extras = [extra for extra in extras_required if not extras_available(extra)]
        if missing_extras:
            _print_missing_dependencies_message(template, missing_extras)
            available_templates = available_templates - {template}

    return tuple(available_templates)


def generate_disable_tool_policy(
    tool_name: str,
    client_name: str | None,
    server_name: str | None,
) -> DatasetPolicy:
    """Generate a guardrail policy to disable a tool.

    Args:
        tool_name: The name of the tool to disable.
        client_name: The name of the client.
        server_name: The name of the server.

    Returns:
        A DatasetPolicy object configured to disable the tool.
    """
    template = load_template("disable_tool", directory=DEFAULT_GUARDRAIL_DIR / "tool_templates")
    content = template.replace("{{ tool_name }}", tool_name)
    rule_id = f"{client_name}-{server_name}-{tool_name}-disabled"

    return DatasetPolicy(
        id=rule_id,
        name=rule_id,
        content=content,
        enabled=True,
        action=GuardrailMode.block,
    )


def generate_policy(
    name: str,
    mode: GuardrailMode,
    client: str | None = None,
    server: str | None = None,
    tools: list[str] | None = None,
    blacklist: list[str] | None = None,
) -> DatasetPolicy:
    """Generate a guardrail policy from a template.

    Args:
        name: The name of the guardrail template to use.
        mode: The mode to apply to the guardrail (log, block, paused).
        client: The client name.
        server: The server name.
        tools: Optional list of tools to whitelist.
        blacklist: Optional list of tools to blacklist.

    Returns:
        A DatasetPolicy object configured based on the parameters.
    """
    template = load_template(name)
    tools_list = list(tools or [])
    blacklist_list = list(blacklist or [])

    if tools_list:
        content = whitelist_tool_from_guardrail(template, tools_list)
        id_suffix = "-".join(sorted(tools_list))
    else:
        content = blacklist_tool_from_guardrail(template, blacklist_list)
        id_suffix = "default"

    # Remove client and server from the id if they are None
    policy_id = f"{client}-{server}-{name}-{id_suffix}"
    policy_id = policy_id.replace("-None", "").replace("None-", "")

    return DatasetPolicy(
        id=policy_id,
        name=name,
        content=content,
        action=mode,
        enabled=True,
    )


def collect_guardrails(
    server_shorthand_guardrails: dict[str, GuardrailMode],
    tool_shorthand_guardrails: dict[str, dict[str, GuardrailMode]],
    disabled_tools: list[str],
    client: str | None,
    server: str | None,
) -> list[DatasetPolicy]:
    """Collect all guardrails and resolve conflicts.

    Conflict resolution logic:
    1. Create tool-specific shorthand guardrails when defined
    2. Create server-level shorthand guardrails that don't conflict with tool-specifics
    3. Create catch-all log default guardrails for any shorthand guardrails not explicitly declared

    Args:
        server_shorthand_guardrails: Server-specific shorthand guardrails.
        tool_shorthand_guardrails: Tool-specific shorthand guardrails.
        disabled_tools: List of tools that are disabled.
        client: The client name.
        server: The server name.

    Returns:
        A list of DatasetPolicy objects with conflicts resolved.
    """
    policies: list[DatasetPolicy] = []
    remaining_templates = set(get_available_templates())

    # Process all guardrails mentioned in either server or tool shorthand configs
    for name in server_shorthand_guardrails.keys() | tool_shorthand_guardrails.keys():
        default_mode = server_shorthand_guardrails.get(name)
        per_tool = tool_shorthand_guardrails.get(name, {})

        # Case 1: No server-level shorthand, only tool-specific guardrails
        if default_mode is None:
            # Group tools by their mode
            mode_to_tools: dict[GuardrailMode, list[str]] = {}
            for tool, mode in per_tool.items():
                mode_to_tools.setdefault(mode, []).append(tool)

            # Create a policy for each mode with its tools
            for mode, tools in mode_to_tools.items():
                policies.append(generate_policy(name, mode, client, server, tools=tools))

            # Add a catch-all log policy for tools without specific rules
            policies.append(generate_policy(name, GuardrailMode.log, client, server, blacklist=list(per_tool.keys())))

        # Case 2: Only server-level shorthand, no tool-specific guardrails
        elif not per_tool:
            policies.append(generate_policy(name, default_mode, client, server))

        # Case 3: Both server-level shorthand and tool-specific guardrails exist
        else:
            # Find tools shorthands where the mode differs from the server shorthand
            differing_tools = [t for t, m in per_tool.items() if m != default_mode]

            # Create server-level shorthand policy that excludes differing tools
            policies.append(generate_policy(name, default_mode, client, server, blacklist=differing_tools))

            # Create tool-specific shorthand policies for tools with non-default modes
            for tool in differing_tools:
                policies.append(generate_policy(name, per_tool[tool], client, server, tools=[tool]))

        # Mark this template as processed
        remaining_templates.discard(name)

    # Apply default guardrails to any templates not explicitly configured
    for name in remaining_templates:
        policies.append(generate_policy(name, GuardrailMode.log, client, server))

    # Emit rules to disable disabled tools
    for tool_name in disabled_tools:
        policies.append(generate_disable_tool_policy(tool_name, client, server))

    return policies


def parse_custom_guardrails(
    config: ServerGuardrailConfig, client: str | None, server: str | None
) -> list[DatasetPolicy]:
    """Parse custom guardrails from the server config.

    Args:
        config: The server guardrail config.
        client: The client name.
        server: The server name.

    Returns:
        A list of DatasetPolicy objects from custom guardrails.
    """
    policies = []
    for policy in config.guardrails.custom_guardrails:
        if policy.enabled:
            policy.id = f"{client}-{server}-{policy.id}"
            policies.append(policy)
    return policies


def parse_server_shorthand_guardrails(
    config: ServerGuardrailConfig,
) -> dict[str, GuardrailMode]:
    """Parse server-specific shorthand guardrails from the server config.

    Args:
        config: The server guardrail config.

    Returns:
        A dictionary mapping guardrail names to their modes.
    """
    default_guardrails: dict[str, GuardrailMode] = {}
    for field, value in config.guardrails:
        if field == "custom_guardrails" or value is None:
            continue
        default_guardrails[field] = value

    return default_guardrails


def parse_tool_shorthand_guardrails(
    config: ServerGuardrailConfig,
) -> tuple[dict[str, dict[str, GuardrailMode]], list[str]]:
    """Parse tool-specific shorthand guardrails from the server config.

    Args:
        config: The server guardrail config.

    Returns:
        Tuple of:
        - A dictionary mapping guardrail names to tool names to modes.
        - A list of tool names that are disabled.
    """
    result: dict[str, dict[str, GuardrailMode]] = {}
    disabled_tools: list[str] = []

    for tool_name, tool_cfg in (config.tools or {}).items():
        for field, value in tool_cfg:
            if field not in {"custom_guardrails", "enabled"} and value is not None:
                result.setdefault(field, {})[tool_name] = value

            if field == "enabled" and isinstance(value, bool) and not value:
                disabled_tools.append(tool_name)

    return result, disabled_tools


def parse_client_guardrails(
    config: ClientGuardrailConfig,
) -> list[DatasetPolicy]:
    """Parse client-specific guardrails from the client config.

    Args:
        config: The client guardrail config.

    Returns:
        A list of DatasetPolicy objects from client guardrails.
    """
    return config.custom_guardrails or []


@lru_cache
async def parse_config(
    config: GuardrailConfigFile,
    client_name: str | None = None,
    server_name: str | None = None,
) -> list[DatasetPolicy]:
    """Parse a guardrail config file to extract guardrails and resolve conflicts.

    Args:
        config: The guardrail config file.
        client_name: Optional client name to include guardrails for.
        server_name: Optional server name to include guardrails for.

    Returns:
        A list of DatasetPolicy objects with all guardrails.
    """
    client_policies: list[DatasetPolicy] = []
    server_policies: list[DatasetPolicy] = []
    client_config = config.get(client_name)

    if client_config:
        # Add client-level (custom) guardrails directly to the policies
        client_policies.extend(parse_client_guardrails(client_config))
        server_config = client_config.servers.get(server_name)

        if server_config:
            # Parse guardrails for this client-server pair
            server_shorthands = parse_server_shorthand_guardrails(server_config)
            tool_shorthands, disabled_tools = parse_tool_shorthand_guardrails(server_config)
            custom_guardrails = parse_custom_guardrails(server_config, client_name, server_name)

            server_policies.extend(
                collect_guardrails(server_shorthands, tool_shorthands, disabled_tools, client_name, server_name)
            )
            server_policies.extend(custom_guardrails)

    # Create all default guardrails if no guardrails are configured
    if len(server_policies) == 0:
        logger.warning(
            "No guardrails found for client '%s' and server '%s'. Using default guardrails.", client_name, server_name
        )

        for name in get_available_templates():
            server_policies.append(generate_policy(name, GuardrailMode.log, client_name, server_name))

    return client_policies + server_policies
