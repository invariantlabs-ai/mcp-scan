import asyncio
from pathlib import Path
from typing import Optional

from mcp_scan_server.format_guardrail import (
    blacklist_tool_from_guardrail,
    whitelist_tool_from_guardrail,
)
from mcp_scan_server.models import (
    DatasetPolicy,
    GuardrailConfigFile,
    GuardrailMode,
    ServerGuardrailConfig,
)


class GuardrailLoader:
    """Singleton loader for guardrail templates."""

    _instance: Optional["GuardrailLoader"] = None

    def __new__(cls, guardrail_dir: Path):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init(guardrail_dir)
        return cls._instance

    def _init(self, guardrail_dir: Path) -> None:
        self._dir = guardrail_dir
        self._templates: dict[str, str] = {}

        allowed = [p.stem for p in guardrail_dir.glob("*.gr")]
        for name in allowed:
            path = guardrail_dir / f"{name}.gr"
            if not path.is_file():
                raise FileNotFoundError(f"Missing guardrail template: {path}")
            with open(path, "r") as f:
                self._templates[name] = f.read()

    def get(self, name: str) -> str:
        try:
            return self._templates[name]
        except KeyError:
            raise ValueError(f"Unknown guardrail '{name}'")


def _generate_policy(
    name: str,
    mode: GuardrailMode,
    client: str,
    server: str,
    tool: str | None = None,
    blacklist: list[str] | None = None,
) -> DatasetPolicy:
    """Generate a policy from a guardrail template.

    Args:
        name: The name of the guardrail template to use.
        mode: The mode of the guardrail template to use (log, block, paused).
        client: The name of the client.
        server: The name of the server.
        tool: The name of the tool. If provided, the guardrail will consider a tool guardrail.
        blacklist: The list of tools to blacklist.

    Returns:
        A DatasetPolicy object containing the policy.
    """
    loader = GuardrailLoader(Path(__file__).parents[1] / "mcp_scan_server" / "default_guardrails")
    template = loader.get(name)

    if tool:
        content = whitelist_tool_from_guardrail(template, [tool])
        policy_id = f"{client}-{server}-{name}-{tool}"
    else:
        content = blacklist_tool_from_guardrail(template, blacklist or [])
        policy_id = f"{client}-{server}-{name}"

    return DatasetPolicy(
        id=policy_id,
        name=name,
        content=content,
        action=mode,
        enabled=True,
    )


def _collect_guardrails(
    default_guardrails: dict[str, GuardrailMode],
    tool_guardrails: dict[str, dict[str, GuardrailMode]],
    client: str,
    server: str,
) -> list[DatasetPolicy]:
    """
    Collect all the templated guardrails for a given client and server context.

    This function will also resolve conflicts between default and tool guardrails, such that:
    - If a templated guardrail is set for both a default and a tool, the tool-specific guardrail will be used
      unless the mode is different.
    - If a templated guardrail is set for a default and not for a tool, the default guardrail will be used.

    Args:
        default_guardrails: All the default guardrails.
        tool_guardrails: All the tool guardrails.
        client: The name of the client.
        server: The name of the server.

    Returns:
        A list of DatasetPolicy objects.
    """
    policies: list[DatasetPolicy] = []

    # Iterate over the union of default and tool guardrails
    for name in default_guardrails.keys() | tool_guardrails.keys():
        default_mode = default_guardrails.get(name)
        tconfigs = tool_guardrails.get(name, {})

        # If the default guardrail is not defined, create a tool-only policy for each tool
        if default_mode is None:
            for t, mode in tconfigs.items():
                policies.append(_generate_policy(name, mode, client, server, tool=t))

        # If there are no tool-specific guardrails, create a default-only policy
        elif not tconfigs:
            policies.append(_generate_policy(name, default_mode, client, server, blacklist=[]))

        # If there are both default and tool-specific guardrails, create policies that are
        # complementary to each other IF the modes are different.
        else:
            # Find the tools that have a different guardrail mode
            diff = [t for t, m in tconfigs.items() if m != default_mode]

            # Create a default rule that
            #  1) covers all the tools with the same mode and
            #  2) blacklists the tools that have a different mode
            policies.append(_generate_policy(name, default_mode, client, server, blacklist=diff))

            # Finally, create policies for the tools that have a different guardrail mode
            for t in diff:
                policies.append(_generate_policy(name, tconfigs[t], client, server, tool=t))

    return policies


async def _parse_custom_guardrails(
    config: ServerGuardrailConfig,
    client: str,
    server: str,
) -> list[DatasetPolicy]:
    """Parse the custom guardrails for a given server. Simply loads the guardrail directly from the config.

    Args:
        config: The server guardrail config.
        client: The name of the client.
        server: The name of the server.

    Returns:
        A list of DatasetPolicy objects.
    """
    policies = []
    for policy in config.guardrails.custom_guardrails:
        if policy.enabled:
            policy.id = f"{client}-{server}-{policy.id}"
            policies.append(policy)
    return policies


async def _parse_default_guardrails(
    config: ServerGuardrailConfig,
) -> dict[str, GuardrailMode]:
    """Parse the default guardrails for a given server.

    Args:
        config: The server guardrail config.

    Returns:
        A dictionary of default guardrails.
    """
    default_guardrails: dict[str, GuardrailMode] = {}
    for field, value in config.guardrails:
        if field == "custom_guardrails" or value is None:
            continue
        default_guardrails[field] = value

    return default_guardrails


async def _parse_tool_guardrails(
    config: ServerGuardrailConfig,
) -> dict[str, dict[str, GuardrailMode]]:
    """
    Parse the tool guardrails for a given server.

    Args:
        config: The server guardrail config.

    Returns:
        A dictionary of tool guardrails.
    """
    tool_guardrails: dict[str, dict[str, GuardrailMode]] = {}

    if not config.tools:
        return tool_guardrails

    for tool_name, tool_config in config.tools.items():
        for field, value in tool_config:
            if field in ("custom_guardrails", "enabled") or value is None:
                continue
            print(f"tool_name: {tool_name}, field: {field}, value: {value} enabled: {tool_config.enabled}")
            tool_guardrails.setdefault(field, {})[tool_name] = value

    return tool_guardrails


async def parse_config(
    config: GuardrailConfigFile, client_names: list[str] | None = None, server_names: list[str] | None = None
) -> list[DatasetPolicy]:
    """Parse a guardrail config file to extract guardrails and resolve conflicts.

    Args:
        config: The guardrail config file.
        client_names: The list of clients to include.
        server_names: The list of servers to include.

    Returns:
        A list of DatasetPolicy objects.
    """
    result: list[DatasetPolicy] = []
    for client, client_config in config:
        if not client_config or client_names and client not in client_names:
            continue

        for server, server_config in client_config.items():
            if server_names and server not in server_names:
                continue

            default_guardrails, tool_guardrails, custom_guardrails = await asyncio.gather(
                _parse_default_guardrails(server_config),
                _parse_tool_guardrails(server_config),
                _parse_custom_guardrails(server_config, client, server),
            )

            result.extend(_collect_guardrails(default_guardrails, tool_guardrails, client, server))
            result.extend(custom_guardrails)

    return result
