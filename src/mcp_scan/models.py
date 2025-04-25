from datetime import datetime
from typing import Any, Literal, NamedTuple, TypeAlias

from mcp.types import Prompt, Resource, Tool
from pydantic import BaseModel, ConfigDict, RootModel, field_validator

Entity: TypeAlias = Prompt | Resource | Tool


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
    verified: bool
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
        except ValueError:
            raise ValueError(f"Unrecognized datetime format: {value}")


ScannedEntities = RootModel[dict[str, ScannedEntity]]


class Result(NamedTuple):
    value: Any = None
    message: str | None = None


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
