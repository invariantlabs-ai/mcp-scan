import rich
import uvicorn
from fastapi import FastAPI

from .routes.policies import router as policies_router
from .routes.push import router as push_router
from .routes.trace import router as dataset_trace_router
from .routes.user import router as user_router


class MCPScanServer:
    """
    MCP Scan Server.

    Args:
        port: The port to run the server on.
        config_file_path: The path to the config file.
    """

    def __init__(self, port: int = 8000, config_file_path: str | None = None):
        self.port = port
        self.config_file_path = config_file_path

        self.app = FastAPI()
        self.app.state.config_file_path = config_file_path

        self.app.include_router(policies_router, prefix="/api/v1")
        self.app.include_router(push_router, prefix="/api/v1/push")
        self.app.include_router(dataset_trace_router, prefix="/api/v1/trace")
        self.app.include_router(user_router, prefix="/api/v1/user")

    def run(self):
        """Run the MCP scan server."""
        rich.print("[bold green]Starting MCP-scan server.[/bold green]")
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)
