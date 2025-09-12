import asyncio
import logging
import os
from collections import defaultdict
from collections.abc import Callable
from typing import Any
import re

from mcp_scan.models import Issue, ScanError, ScanPathResult, ServerScanResult
from mcp_scan.well_known_clients import get_client_from_path, get_builtin_tools

from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .Storage import Storage
from .verify_api import analyze_scan_path

# Set up logger for this module
logger = logging.getLogger(__name__)


class ContextManager:
    def __init__(
        self,
    ):
        logger.debug("Initializing ContextManager")
        self.enabled = True
        self.callbacks = defaultdict(list)
        self.running = []

    def enable(self):
        logger.debug("Enabling ContextManager")
        self.enabled = True

    def disable(self):
        logger.debug("Disabling ContextManager")
        self.enabled = False

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        logger.debug("Registering hook for signal: %s", signal)
        self.callbacks[signal].append(async_callback)

    async def emit(self, signal: str, data: Any):
        if self.enabled:
            logger.debug("Emitting signal: %s", signal)
            for callback in self.callbacks[signal]:
                self.running.append(callback(signal, data))

    async def wait(self):
        logger.debug("Waiting for %d running tasks to complete", len(self.running))
        await asyncio.gather(*self.running)


class MCPScanner:
    def __init__(
        self,
        files: list[str] | None = None,
        base_url: str = "https://mcp.invariantlabs.ai/",
        checks_per_server: int = 1,
        storage_file: str = "~/.mcp-scan",
        server_timeout: int = 10,
        suppress_mcpserver_io: bool = True,
        opt_out: bool = False,
        include_built_in: bool = False,
        verbose: bool = False,
        additional_headers: dict = {},
        **kwargs: Any,
    ):
        logger.info("Initializing MCPScanner")
        self.paths = files or []
        logger.debug("Paths to scan: %s", self.paths)
        self.base_url = base_url
        self.additional_headers = additional_headers
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        logger.debug("Storage file path: %s", self.storage_file_path)
        self.storage_file = Storage(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io
        self.context_manager = None
        self.opt_out_of_identity = opt_out
        self.include_built_in = include_built_in
        self.verbose = verbose
        logger.debug(
            "MCPScanner initialized with timeout: %d, checks_per_server: %d", server_timeout, checks_per_server
        )

    def __enter__(self):
        logger.debug("Entering MCPScanner context")
        if self.context_manager is None:
            self.context_manager = ContextManager()
        return self

    async def __aenter__(self):
        logger.debug("Entering MCPScanner async context")
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Exiting MCPScanner async context")
        if self.context_manager is not None:
            await self.context_manager.wait()
            self.context_manager = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Exiting MCPScanner context")
        if self.context_manager is not None:
            asyncio.run(self.context_manager.wait())
            self.context_manager = None

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        logger.debug("Registering hook for signal: %s", signal)
        if self.context_manager is not None:
            self.context_manager.hook(signal, async_callback)
        else:
            error_msg = "Context manager not initialized"
            logger.exception(error_msg)
            raise RuntimeError(error_msg)

    async def get_servers_from_path(self, path: str) -> ScanPathResult:
        logger.info("Getting servers from path: %s", path)
        result = ScanPathResult(path=path)
        try:
            servers = (await scan_mcp_config_file(path)).get_servers()
            logger.debug("Found %d servers in path: %s", len(servers), path)
            result.servers = [
                ServerScanResult(name=server_name, server=server) for server_name, server in servers.items()
            ]
        except FileNotFoundError as e:
            error_msg = "file does not exist"
            logger.exception("%s: %s", error_msg, path)
            result.error = ScanError(message=error_msg, exception=e)
        except Exception as e:
            error_msg = "could not parse file"
            logger.exception("%s: %s", error_msg, path)
            result.error = ScanError(message=error_msg, exception=e)
        return result

    def check_server_changed(self, path_result: ScanPathResult) -> list[Issue]:
        logger.debug("Checking server changed: %s", path_result.path)
        issues: list[Issue] = []
        for server_idx, server in enumerate(path_result.servers):
            logger.debug(
                "Checking for changes in server %d/%d: %s", server_idx + 1, len(path_result.servers), server.name
            )
            for entity_idx, entity in enumerate(server.entities):
                c, messages = self.storage_file.check_and_update(server.name or "", entity)
                if c:
                    logger.info("Entity %s in server %s has changed", entity.name, server.name)
                    issues.append(
                        Issue(
                            code="W003",
                            message="Entity has changed. " + ", ".join(messages),
                            reference=(server_idx, entity_idx),
                        )
                    )
        return issues

    def check_whitelist(self, path_result: ScanPathResult) -> list[Issue]:
        logger.debug("Checking whitelist for path: %s", path_result.path)
        issues: list[Issue] = []
        for server_idx, server in enumerate(path_result.servers):
            for entity_idx, entity in enumerate(server.entities):
                if self.storage_file.is_whitelisted(entity):
                    issues.append(
                        Issue(
                            code="X002", message="This entity has been whitelisted", reference=(server_idx, entity_idx)
                        )
                    )
        return issues

    async def emit(self, signal: str, data: Any):
        logger.debug("Emitting signal: %s", signal)
        if self.context_manager is not None:
            await self.context_manager.emit(signal, data)

    async def scan_server(self, server: ServerScanResult) -> ServerScanResult:
        logger.info("Scanning server: %s", server.name)
        result = server.clone()
        try:
            result.signature = await check_server_with_timeout(
                server.server, self.server_timeout, self.suppress_mcpserver_io
            )
            logger.debug(
                "Server %s has %d prompts, %d resources, %d resouce templates,  %d tools",
                server.name,
                len(result.signature.prompts),
                len(result.signature.resources),
                len(result.signature.resource_templates),
                len(result.signature.tools),
            )
        except Exception as e:
            error_msg = "could not start server"
            logger.exception("%s: %s", error_msg, server.name)
            result.error = ScanError(message=error_msg, exception=e)
        await self.emit("server_scanned", result)
        return result
    


    async def scan_path(self, path: str, inspect_only: bool = False) -> ScanPathResult:
        logger.info("Scanning path: %s, inspect_only: %s", path, inspect_only)
        path_result = await self.get_servers_from_path(path)

        for i, server in enumerate(path_result.servers):
            if server.server.type == "stdio":
                full_command = server.server.command + " " + " ".join(server.server.args or [])
                # check if pattern is contained in full_command
                if re.search(r"mcp[-_]scan.*mcp-server", full_command):
                    logger.info("Skipping scan of server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                    continue
            logger.debug("Scanning server %d/%d: %s", i + 1, len(path_result.servers), server.name)
            path_result.servers[i] = await self.scan_server(server)

        # add built-in tools
        if self.include_built_in:
            path_result = get_builtin_tools(path_result)

        if not inspect_only:
            path_result = await self.check_path(path_result)
        return path_result

    async def check_path(self, path_result: ScanPathResult) -> ScanPathResult:
        logger.debug(f"Check whitelisted {path_result.path}, {path_result.path is None}")
        path_result.issues += self.check_whitelist(path_result)
        logger.debug(f"Check changed: {path_result.path}, {path_result.path is None}")
        path_result.issues += self.check_server_changed(path_result)
        logger.debug(f"Verifying server path: {path_result.path}, {path_result.path is None}")
        path_result = await analyze_scan_path(
            path_result, base_url=self.base_url, additional_headers=self.additional_headers, opt_out_of_identity=self.opt_out_of_identity, verbose=self.verbose
        )
        await self.emit("path_scanned", path_result)
        return path_result

    async def scan(self) -> list[ScanPathResult]:
        logger.info("Starting scan of %d paths", len(self.paths))
        if self.context_manager is not None:
            self.context_manager.disable()

        result_awaited = []
        for i in range(self.checks_per_server):
            logger.debug("Scan iteration %d/%d", i + 1, self.checks_per_server)
            # intentionally overwrite and only report the last scan
            if i == self.checks_per_server - 1 and self.context_manager is not None:
                logger.debug("Enabling context manager for final iteration")
                self.context_manager.enable()  # only print on last run
            result = [self.scan_path(path) for path in self.paths]
            result_awaited = await asyncio.gather(*result)

        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Scan completed successfully")
        return result_awaited

    async def inspect(self) -> list[ScanPathResult]:
        logger.info("Starting inspection of %d paths", len(self.paths))
        result = [self.scan_path(path, inspect_only=True) for path in self.paths]
        result_awaited = await asyncio.gather(*result)
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Inspection completed successfully")
        return result_awaited
