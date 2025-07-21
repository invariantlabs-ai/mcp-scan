from datetime import datetime
from hashlib import md5
from itertools import chain
from typing import Any, Literal, TypeAlias

from mcp.types import InitializeResult, Prompt, Resource, Tool
from pydantic import BaseModel, ConfigDict, Field, RootModel, field_serializer, field_validator

Entity: TypeAlias = Prompt | Resource | Tool
Metadata: TypeAlias = InitializeResult


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


class StreamableHTTPServer(BaseModel):
    model_config = ConfigDict()
    url: str
    type: Literal["http"] | None = "http"
    headers: dict[str, str] = {}


class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: list[str] | None = None
    type: Literal["stdio"] | None = "stdio"
    env: dict[str, str] | None = None


class MCPConfig(BaseModel):
    def get_servers(self) -> dict[str, SSEServer | StdioServer | StreamableHTTPServer]:
        raise NotImplementedError("Subclasses must implement this method")

    def set_servers(self, servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]) -> None:
        raise NotImplementedError("Subclasses must implement this method")


class ClaudeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcpServers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]

    def get_servers(self) -> dict[str, SSEServer | StdioServer | StreamableHTTPServer]:
        return self.mcpServers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]) -> None:
        self.mcpServers = servers


class VSCodeMCPConfig(MCPConfig):
    # see https://code.visualstudio.com/docs/copilot/chat/mcp-servers
    model_config = ConfigDict()
    inputs: list[Any] | None = None
    servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]

    def get_servers(self) -> dict[str, SSEServer | StdioServer | StreamableHTTPServer]:
        return self.servers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]) -> None:
        self.servers = servers


class VSCodeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcp: VSCodeMCPConfig

    def get_servers(self) -> dict[str, SSEServer | StdioServer | StreamableHTTPServer]:
        return self.mcp.servers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer | StreamableHTTPServer]) -> None:
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

    def clone(self) -> "ScanError":
        """
        Create a copy of the ScanError instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the exception. This is crucial to avoid issues with serialization of exceptions.
        """
        return ScanError(
            message=self.message,
            exception=self.exception,
        )


class Issue(BaseModel):
    code: str
    message: str
    reference: tuple[int, int] | None = Field(
        default=None,
        description="The index of the tool the issue references. None if it is global",
    )
    extra_data: dict[str, Any] | None = Field(
        default=None,
        description="Extra data to provide more context about the issue.",
    )


class ServerSignature(BaseModel):
    metadata: Metadata
    prompts: list[Prompt] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)

    @property
    def entities(self) -> list[Entity]:
        return self.prompts + self.resources + self.tools


class VerifyServerRequest(RootModel[list[ServerSignature | None]]):
    pass


class ServerScanResult(BaseModel):
    model_config = ConfigDict()
    name: str | None = None
    server: SSEServer | StdioServer | StreamableHTTPServer
    signature: ServerSignature | None = None
    error: ScanError | None = None

    @property
    def entities(self) -> list[Entity]:
        if self.signature is not None:
            return self.signature.entities
        else:
            return []

    @property
    def is_verified(self) -> bool:
        return self.result is not None

    def clone(self) -> "ServerScanResult":
        """
        Create a copy of the ServerScanResult instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the error. This is crucial to avoid issues with serialization of exceptions.
        """
        output = ServerScanResult(
            name=self.name,
            server=self.server.model_copy(deep=True),
            signature=self.signature.model_copy(deep=True) if self.signature else None,
            error=self.error.clone() if self.error else None,
        )
        return output


class ScanPathResult(BaseModel):
    model_config = ConfigDict()
    path: str
    servers: list[ServerScanResult] = Field(default_factory=list)
    issues: list[Issue] = Field(default_factory=list)
    error: ScanError | None = None

    @property
    def entities(self) -> list[Entity]:
        return list(chain.from_iterable(server.entities for server in self.servers))

    def clone(self) -> "ScanPathResult":
        """
        Create a copy of the ScanPathResult instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the error. This is crucial to avoid issues with serialization of exceptions.
        """
        output = ScanPathResult(
            path=self.path,
            servers=[server.clone() for server in self.servers],
            issues=[issue.model_copy(deep=True) for issue in self.issues],
            error=self.error.clone() if self.error else None,
        )
        return output


class ScanUserInfo(BaseModel):
    hostname: str | None = None
    username: str | None = None
    email: str | None = None
    ip_address: str | None = None
    anonymous_identifier: str | None = None


def entity_to_tool(
    entity: Entity,
) -> Tool:
    """
    Transform any entity into a tool.
    """
    if isinstance(entity, Tool):
        return entity
    elif isinstance(entity, Resource):
        return Tool(
            name=entity.name,
            description=entity.description,
            inputSchema={},
            annotations=None,
        )
    elif isinstance(entity, Prompt):
        return Tool(
            name=entity.name,
            description=entity.description,
            inputSchema={
                "type": "object",
                "properties": {
                    entity.name: {
                        "type": "string",
                        "description": entity.description,
                    }
                    for entity in entity.arguments or []
                },
                "required": [pa.name for pa in entity.arguments or [] if pa.required],
            },
        )
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")


class ToolReferenceWithLabel(BaseModel):
    reference: tuple[int, int]
    label_value: float


class ToxicFlowExtraData(RootModel[dict[str, list[ToolReferenceWithLabel]]]):
    pass


class AnalysisServerResponse(BaseModel):
    issues: list[Issue]
