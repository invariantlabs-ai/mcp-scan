import datetime
from enum import Enum

import yaml  # type: ignore
from invariant.analyzer.policy import AnalysisResult
from pydantic import BaseModel, Field


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
    enabled: bool
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


class GuardrailConfig(RootPredefinedGuardrails):
    custom_guardrails: list[DatasetPolicy] = Field(default_factory=list)


class ToolGuardrailConfig(RootPredefinedGuardrails):
    enabled: bool = Field(default=True)


class ServerGuardrailConfig(BaseModel):
    """Guardrail config for a server."""

    guardrails: GuardrailConfig = Field(default_factory=GuardrailConfig)
    tools: dict[str, ToolGuardrailConfig] | None = Field(default=None)


class GuardrailConfigFile(BaseModel):
    """Guardrail config file model."""

    cursor: dict[str, ServerGuardrailConfig] | None = Field(default=None)
    codeium: dict[str, ServerGuardrailConfig] | None = Field(default=None)
    claude: dict[str, ServerGuardrailConfig] | None = Field(default=None)
    vscode: dict[str, ServerGuardrailConfig] | None = Field(default=None)

    def model_dump_yaml(self) -> str:
        """Dump the model to a YAML string."""
        return yaml.dump(self.model_dump(exclude_none=True), indent=2)

    @classmethod
    def model_validate(cls, value):
        """Override to handle string and None input transparently."""
        if isinstance(value, str):
            parsed = yaml.safe_load(value) or {}
            return super().model_validate(parsed)
        if value is None:
            # Treat None as an empty config
            return super().model_validate({})
        return super().model_validate(value)
