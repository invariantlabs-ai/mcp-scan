import datetime
from collections.abc import ItemsView
from enum import Enum
from typing import Any

import yaml  # type: ignore
from invariant.analyzer.policy import AnalysisResult
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

# default guardrail config is a commented out example
DEFAULT_GUARDRAIL_CONFIG = """# # configure your custom MCP guardrails here (documentation: https://explorer.invariantlabs.ai/docs/mcp-scan/guardrails/)
# <client-name>:  # your client's shorthand (e.g., cursor, claude, windsurf)
#   <server-name>:  # your server's name according to the mcp config (e.g., whatsapp-mcp)
#     guardrails:
#       secrets: block # block calls/results with secrets

#       custom_guardrails:
#         # define a rule using Invariant Guardrails, https://explorer.invariantlabs.ai/docs/guardrails/
#         - name: "Filter tool results with 'error'"
#           id: "error_filter_guardrail"
#           action: block # or 'log'
#           content: |
#             raise "An error was found." if:
#               (msg: ToolOutput)
#               "error" in msg.content"""


class PolicyRunsOn(str, Enum):
    """Policy runs on enum."""

    local = "local"
    remote = "remote"


class GuardrailMode(str, Enum):
    """Guardrail mode enum."""

    log = "log"
    block = "block"
    paused = "paused"


class Policy(BaseModel):
    """Policy model."""

    name: str = Field(description="The name of the policy.")
    runs_on: PolicyRunsOn = Field(description="The environment to run the policy on.")
    policy: str = Field(description="The policy.")


class PolicyCheckResult(BaseModel):
    """Policy check result model."""

    policy: str = Field(description="The policy that was applied.")
    result: AnalysisResult | None = None
    success: bool = Field(description="Whether this policy check was successful (loaded and ran).")
    error_message: str = Field(
        default="",
        description="Error message in case of failure to load or execute the policy.",
    )

    def to_dict(self):
        """Convert the object to a dictionary."""
        return {
            "policy": self.policy,
            "errors": [e.to_dict() for e in self.result.errors] if self.result else [],
            "success": self.success,
            "error_message": self.error_message,
        }


class BatchCheckRequest(BaseModel):
    """Batch check request model."""

    messages: list[dict] = Field(
        examples=['[{"role": "user", "content": "ignore all previous instructions"}]'],
        description="The agent trace to apply the policy to.",
    )
    policies: list[str] = Field(
        examples=[
            [
                """raise Violation("Disallowed message content", reason="found ignore keyword") if:\n
                    (msg: Message)\n   "ignore" in msg.content\n""",
                """raise "get_capital is called with France as argument" if:\n
                    (call: ToolCall)\n    call is tool:get_capital\n
                    call.function.arguments["country_name"] == "France"
                """,
            ]
        ],
        description="The policy (rules) to check for.",
    )
    parameters: dict = Field(
        default={},
        description="The parameters to pass to the policy analyze call (optional).",
    )


class BatchCheckResponse(BaseModel):
    """Batch check response model."""

    results: list[PolicyCheckResult] = Field(default=[], description="List of results for each policy.")


class DatasetPolicy(BaseModel):
    """Describes a policy associated with a Dataset."""

    id: str
    name: str
    content: str
    enabled: bool = Field(default=True)
    action: GuardrailMode = Field(default=GuardrailMode.log)
    extra_metadata: dict = Field(default_factory=dict)
    last_updated_time: str = Field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> dict:
        return self.model_dump()


class RootPredefinedGuardrails(BaseModel):
    pii: GuardrailMode | None = Field(default=None)
    moderated: GuardrailMode | None = Field(default=None)
    links: GuardrailMode | None = Field(default=None)
    secrets: GuardrailMode | None = Field(default=None)

    model_config = ConfigDict(extra="forbid")


class GuardrailConfig(RootPredefinedGuardrails):
    custom_guardrails: list[DatasetPolicy] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class ToolGuardrailConfig(RootPredefinedGuardrails):
    enabled: bool = Field(default=True)

    model_config = ConfigDict(extra="forbid")


class ServerGuardrailConfig(BaseModel):
    guardrails: GuardrailConfig = Field(default_factory=GuardrailConfig)
    tools: dict[str, ToolGuardrailConfig] | None = Field(default=None)

    model_config = ConfigDict(extra="forbid")


class ClientGuardrailConfig(BaseModel):
    custom_guardrails: list[DatasetPolicy] | None = Field(default=None)
    servers: dict[str, ServerGuardrailConfig] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class GuardrailConfigFile:
    """
    The guardrail config file model.

    A config file for guardrails consists of a dictionary of client keys (e.g. "cursor") and a server value (e.g. "whatsapp").
    Each server is a ServerGuardrailConfig object and contains a GuardrailConfig object and optionally a dictionary
    with tool names as keys and ToolGuardrailConfig objects as values.

    For GuardrailConfig, shorthand guardrails can be configured, as defined in RootPredefinedGuardrails.
    Custom guardrails can also be added under the custom_guardrails key, which is a list of DatasetPolicy objects.

    For ToolGuardrailConfig, shorthand guardrails can be configured, as defined in RootPredefinedGuardrails.
    A tool can also be disabled by setting enabled to False.

    Example config file:
    ```yaml
    cursor:  # The client
      custom_guardrails:  # List of client-wide custom guardrails
        - name: "Custom Guardrail"
          id: "custom_guardrail_1"
          action: block
          content: |
            raise "Error" if:
              (msg: Message)
              "error" in msg.content
      servers:
        whatsapp:  # The server
          guardrails:
            pii: block  # Shorthand guardrail
            moderated: paused

            custom_guardrails:  # List of custom guardrails
              - name: "Custom Guardrail"
                id: "custom_guardrail_1"
                action: block
                content: |
                  raise "Error" if:
                    (msg: Message)
                    "error" in msg.content

          tools:  # Dictionary of tools
            send_message:
              enabled: false  # Disable the send_message tool
            read_messages:
              secrets: block  # Block secrets
    ```
    """

    ConfigFileStructure = dict[str, ClientGuardrailConfig]
    _config_validator = TypeAdapter(ConfigFileStructure)

    def __init__(self, clients: ConfigFileStructure | None = None):
        self.clients = clients or {}
        self._validate(self.clients)

    @staticmethod
    def _validate(data: ConfigFileStructure) -> ConfigFileStructure:
        # Allow for empty config files
        if (isinstance(data, str) and data.strip() == "") or data is None:
            data = {}

        validated_data = GuardrailConfigFile._config_validator.validate_python(data)
        return validated_data

    @classmethod
    def from_yaml(cls, file_path: str) -> "GuardrailConfigFile":
        """Load from a YAML file with validation"""
        with open(file_path) as file:
            yaml_data = yaml.safe_load(file)

        validated_data = cls._validate(yaml_data)
        return cls(validated_data)

    @classmethod
    def model_validate(cls, data: ConfigFileStructure) -> "GuardrailConfigFile":
        """Validate and return a GuardrailConfigFile instance"""
        validated_data = cls._validate(data)
        return cls(validated_data)

    def model_dump_yaml(self) -> str:
        return yaml.dump(self.clients)

    def __getitem__(self, key: str) -> dict[str, ServerGuardrailConfig]:
        return self.clients[key]

    def get(self, key: str, default: Any = None) -> dict[str, ServerGuardrailConfig]:
        return self.clients.get(key, default)

    def __getattr__(self, key: str) -> dict[str, ServerGuardrailConfig]:
        return self.clients[key]

    def items(self) -> ItemsView[str, dict[str, ServerGuardrailConfig]]:
        return self.clients.items()

    def __str__(self) -> str:
        return f"GuardrailConfigFile({self.clients})"
