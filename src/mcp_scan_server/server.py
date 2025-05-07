import inspect
from collections.abc import Callable
from typing import Literal

import rich
import uvicorn
from fastapi import FastAPI

from mcp_scan_server.activity_logger import setup_activity_logger

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
        on_exit: A callback function to be called on exit of the server.
        log_level: The log level for the server.
    """

    def __init__(
        self,
        port: int = 8000,
        config_file_path: str | None = None,
        on_exit: Callable | None = None,
        log_level: str = "error",
        pretty: Literal["oneline", "compact", "full"] = "compact",
    ):
        self.port = port
        self.config_file_path = config_file_path
        self.on_exit = on_exit
        self.log_level = log_level
        self.pretty = pretty

        self.app = FastAPI(lifespan=self.life_span)
        self.app.state.config_file_path = config_file_path

        self.app.include_router(policies_router, prefix="/api/v1")
        self.app.include_router(push_router, prefix="/api/v1/push")
        self.app.include_router(dataset_trace_router, prefix="/api/v1/trace")
        self.app.include_router(user_router, prefix="/api/v1/user")

    async def on_startup(self):
        """Startup event for the FastAPI app."""
        rich.print("[bold green]MCP-scan server started.[/bold green]")

        setup_activity_logger(self.app, pretty=self.pretty)

    async def life_span(self, app: FastAPI):
        """Lifespan event for the FastAPI app."""
        await self.on_startup()

        yield

        if callable(self.on_exit):
            if inspect.iscoroutinefunction(self.on_exit):
                await self.on_exit()
            else:
                self.on_exit()

    def run(self):
        """Run the MCP scan server."""
        uvicorn.run(self.app, host="0.0.0.0", port=self.port, log_level=self.log_level)
