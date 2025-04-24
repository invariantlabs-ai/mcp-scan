from pydantic import BaseModel, ConfigDict, field_validator
from typing import Any, Literal
from typing import Any
from typing import NamedTuple

class Result(NamedTuple):
    value: Any = None
    message: str | None = None

class SSEServer(BaseModel):
    model_config = ConfigDict()
    url: str
    type: Literal["sse"] | None = 'sse'
    headers: dict[str, str] = {}


class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: list[str] | None = None
    type: Literal["stdio"] | None = 'stdio'
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