from datetime import datetime
from hashlib import md5
from typing import Any, Literal, TypeAlias

from mcp.types import Prompt, Resource, Tool
from pydantic import BaseModel, ConfigDict, RootModel, field_serializer, field_validator, model_serializer

Entity: TypeAlias = Prompt | Resource | Tool


def hash_entity(entity: Entity | None) -> str | None:
    if entity is None:
        return None
    if not hasattr(entity, "description") or entity.description is None:
        return None
    return md5((entity.description).encode()).hexdigest()


def entity_type_to_str(entity: Entity) -> str:
    if isinstance(entity, Prompt):
        return "prompt"
    elif isinstance(entity, Resource):
        return "resource"
    elif isinstance(entity, Tool):
        return "tool"
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")


class ScannedEntity(BaseModel):
    model_config = ConfigDict()
    hash: str
    type: str
    verified: bool | None
    timestamp: datetime
    description: str | None = None

    @field_validator("timestamp", mode="before")
    def parse_datetime(cls, value: str | datetime) -> datetime:
        if isinstance(value, datetime):
            return value

        # Try standard ISO format first
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass

        # Try custom format: "DD/MM/YYYY, HH:MM:SS"
        try:
            return datetime.strptime(value, "%d/%m/%Y, %H:%M:%S")
        except ValueError as e:
            raise ValueError(f"Unrecognized datetime format: {value}") from e


ScannedEntities = RootModel[dict[str, ScannedEntity]]


class SSEServer(BaseModel):
    model_config = ConfigDict()
    url: str
    type: Literal["sse"] | None = "sse"
    headers: dict[str, str] = {}


class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: list[str] | None = None
    type: Literal["stdio"] | None = "stdio"
    env: dict[str, str] = {}


class MCPConfig(BaseModel):
    def get_servers(self) -> dict[str, SSEServer | StdioServer]:
        raise NotImplementedError("Subclasses must implement this method")

    def set_servers(self, servers: dict[str, SSEServer | StdioServer]) -> None:
        raise NotImplementedError("Subclasses must implement this method")


class ClaudeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcpServers: dict[str, SSEServer | StdioServer]

    def get_servers(self) -> dict[str, SSEServer | StdioServer]:
        return self.mcpServers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer]) -> None:
        self.mcpServers = servers


class VSCodeMCPConfig(MCPConfig):
    # see https://code.visualstudio.com/docs/copilot/chat/mcp-servers
    model_config = ConfigDict()
    inputs: list[Any] | None = None
    servers: dict[str, SSEServer | StdioServer]

    def get_servers(self) -> dict[str, SSEServer | StdioServer]:
        return self.servers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer]) -> None:
        self.servers = servers


class VSCodeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcp: VSCodeMCPConfig

    def get_servers(self) -> dict[str, SSEServer | StdioServer]:
        return self.mcp.servers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer]) -> None:
        self.mcp.servers = servers


class ScanError(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    message: str | None = None
    exception: Exception | None = None

    @field_serializer("exception")
    def serialize_exception(self, exception: Exception | None, _info) -> str | None:
        return str(exception) if exception else None

    @property
    def text(self) -> str:
        return self.message or (str(self.exception) or "")


class EntityScanResult(BaseModel):
    model_config = ConfigDict()
    verified: bool | None = None
    changed: bool | None = None
    whitelisted: bool | None = None
    status: str | None = None
    messages: list[str] = []


class CrossRefResult(BaseModel):
    model_config = ConfigDict()
    found: bool | None = None
    sources: list[str] = []


class ServerScanResult(BaseModel):
    model_config = ConfigDict()
    name: str | None = None
    server: SSEServer | StdioServer
    prompts: list[Prompt] = []
    resources: list[Resource] = []
    tools: list[Tool] = []
    result: list[EntityScanResult] | None = None
    error: ScanError | None = None

    @model_serializer
    def serialize(self, _info):
        entities_with_result = self.entities_with_result
        prompts_with_result = entities_with_result[: len(self.prompts)]
        resources_with_result = entities_with_result[len(self.prompts) : len(self.prompts) + len(self.resources)]
        tools_with_result = entities_with_result[len(self.prompts) + len(self.resources) :]

        return {
            "name": self.name,
            "server": self.server,
            "prompts": prompts_with_result,
            "resources": resources_with_result,
            "tools": tools_with_result,
            "error": self.error,
        }

    @property
    def entities(self) -> list[Entity]:
        return self.prompts + self.resources + self.tools

    @property
    def is_verified(self) -> bool:
        return self.result is not None

    @property
    def entities_with_result(self) -> list[tuple[Entity, EntityScanResult | None]]:
        if self.result is not None:
            return list(zip(self.entities, self.result, strict=False))
        else:
            return [(entity, None) for entity in self.entities]


class ScanPathResult(BaseModel):
    model_config = ConfigDict()
    path: str
    servers: list[ServerScanResult] = []
    error: ScanError | None = None
    cross_ref_result: CrossRefResult | None = None
