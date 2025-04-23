from pydantic import BaseModel, ConfigDict, field_validator
from typing import Any
from collections import namedtuple


Result = namedtuple("Result", field_names=["value", "message"], defaults=[None, None])

class SSEServer(BaseModel):
    model_config = ConfigDict()
    url: str
    type: str | None = 'sse'
    headers: dict[str, str] = {}

    @field_validator('type', mode='before')
    def check_type(cls, v):
        if v is not None and v != 'sse':
            raise ValueError('type must be "sse"')
        return v

class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: list[str] | None = None
    type: str | None = 'stdio'
    env: dict[str, str] = {}

    @field_validator('type', mode='before')
    def check_type(cls, v):
        if v is not None and v != 'stdio':
            raise ValueError('type must be "stdio"')
        return v

class ClaudeConfigFile(BaseModel):
    model_config = ConfigDict()
    mcpServers: dict[str, SSEServer | StdioServer]

class VSCodeMCPConfig(BaseModel):
    # see https://code.visualstudio.com/docs/copilot/chat/mcp-servers
    model_config = ConfigDict()
    inputs: list[Any] | None = None
    servers: dict[str, SSEServer | StdioServer]

class VSCodeConfigFile(BaseModel):
    model_config = ConfigDict()
    mcp: VSCodeMCPConfig