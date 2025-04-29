import datetime
from enum import Enum
from typing import Optional

import yaml  # type: ignore
from invariant.analyzer.policy import AnalysisResult
from pydantic import BaseModel, ConfigDict, Field, RootModel


class PolicyRunsOn(str, Enum):
    """Policy runs on enum."""

    local = "local"
    remote = "remote"


class Policy(BaseModel):
    """Policy model."""

    name: str = Field(description="The name of the policy.")
    runs_on: PolicyRunsOn = Field(description="The environment to run the policy on.")
    policy: str = Field(description="The policy.")


class PolicyCheckResult(BaseModel):
    """Policy check result model."""

    policy: str = Field(description="The policy that was applied.")
    result: Optional[AnalysisResult] = None
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
    # whether this policy is enabled
    enabled: bool
    # the mode of this policy (e.g. block, log, etc.)
    action: str
    # extra metadata for the policy (can be used to store internal extra data about a guardrail)
    extra_metadata: dict = Field(default_factory=dict)

    last_updated_time: str = Field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> dict:
        """Represent the object as a dictionary."""
        return self.model_dump()


class ServerGuardrails(BaseModel):
    """Server guardrails model."""

    guardrails: list[DatasetPolicy]


class GuardrailConfig(RootModel[dict[str, dict[str, ServerGuardrails]]]):
    """Guardrail config model."""

    model_config = ConfigDict(populate_by_name=True)

    def model_dump_yaml(self) -> str:
        """Dump the object as a YAML string."""
        data = self.model_dump()
        return yaml.dump(data, sort_keys=False, default_flow_style=False)
