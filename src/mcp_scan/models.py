from datetime import datetime
from hashlib import md5
from itertools import chain
from typing import Any, Literal, TypeAlias
import os

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
    env: dict[str, str] | None = None


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


class ServerSignature(BaseModel):
    metadata: Metadata
    prompts: list[Prompt] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)

    @property
    def entities(self) -> list[Entity]:
        return self.prompts + self.resources + self.tools


class VerifyServerResponse(RootModel):
    root: list[list[EntityScanResult]]


class VerifyServerRequest(RootModel):
    root: list[ServerSignature]


class ServerScanResult(BaseModel):
    model_config = ConfigDict()
    name: str | None = None
    server: SSEServer | StdioServer
    signature: ServerSignature | None = None
    result: list[EntityScanResult] | None = None
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

    @property
    def entities(self) -> list[Entity]:
        return list(chain.from_iterable(server.entities for server in self.servers))


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


class SimpleMCPConfig(MCPConfig):
    """Simple MCP 설정 파일 모델"""
    model_config = ConfigDict()
    mcpServers: dict[str, StdioServer]  # SSE 서버는 지원하지 않음

    def get_servers(self) -> dict[str, SSEServer | StdioServer]:
        return self.mcpServers

    def set_servers(self, servers: dict[str, SSEServer | StdioServer]) -> None:
        # SSE 서버가 포함되어 있으면 ValueError 발생
        for server_name, server in servers.items():
            if isinstance(server, SSEServer):
                raise ValueError(f"SimpleMCPConfig는 SSE 서버를 지원하지 않습니다: {server_name}")
        self.mcpServers = servers


async def scan_mcp_config_file(path: str) -> MCPConfig:
    logger.info("Scanning MCP config file: %s", path)
    path = os.path.expanduser(path)
    logger.debug("Expanded path: %s", path)

    def parse_and_validate(config: dict) -> MCPConfig:
        logger.debug("Parsing and validating config")
        models: list[type[MCPConfig]] = [
            SimpleMCPConfig,  # 새로운 모델을 첫 번째로 시도
            ClaudeConfigFile,  # used by most clients
            VSCodeConfigFile,  # used by vscode settings.json
            VSCodeMCPConfig,  # used by vscode mcp.json
        ]
        for model in models:
            try:
                logger.debug("Trying to validate with model: %s", model.__name__)
                return model.model_validate(config)
            except Exception:
                logger.debug("Validation with %s failed", model.__name__)
        error_msg = "Could not parse config file as any of " + str([model.__name__ for model in models])
        raise Exception(error_msg)
