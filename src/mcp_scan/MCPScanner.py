import asyncio
import logging
import os
import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from httpx import HTTPStatusError

from mcp_scan.direct_scanner import direct_scan, is_direct_scan
from mcp_scan.mcp_client import check_server_with_timeout, scan_mcp_config_file
from mcp_scan.models import (
    Issue,
    RemoteServer,
    ScanError,
    ScanPathResult,
    ServerScanResult,
    StdioServer,
    UnknownMCPConfig,
)
from mcp_scan.Storage import Storage
from mcp_scan.verify_api import analyze_machine
from mcp_scan.well_known_clients import get_builtin_tools

# Set up logger for this module
logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"


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
        analysis_url: str = "https://mcp.invariantlabs.ai/api/v1/public/mcp-analysis",
        checks_per_server: int = 1,
        storage_file: str = "~/.mcp-scan",
        server_timeout: int = 10,
        suppress_mcpserver_io: bool = True,
        opt_out: bool = False,
        include_built_in: bool = False,
        verbose: bool = False,
        additional_headers: dict | None = None,
        control_servers: list | None = None,
        **kwargs: Any,
    ):
        logger.info("Initializing MCPScanner")
        self.paths = files or []
        logger.debug("Paths to scan: %s", self.paths)
        self.analysis_url = analysis_url
        self.additional_headers = additional_headers or {}
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        logger.debug("Storage file path: %s", self.storage_file_path)
        self.storage_file = Storage(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io
        self.context_manager = None
        self.opt_out_of_identity = opt_out
        self.include_built_in = include_built_in
        self.control_servers = control_servers
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
            if not os.path.exists(path) and is_direct_scan(path):
                servers = (await direct_scan(path)).get_servers()
            else:
                mcp_config = await scan_mcp_config_file(path)
                if isinstance(mcp_config, UnknownMCPConfig):
                    result.error = ScanError(message=f"Unknown MCP config: {path}", is_failure=False)
                servers = mcp_config.get_servers()
            logger.debug("Found %d servers in path: %s", len(servers), path)
            result.servers = [
                ServerScanResult(name=server_name, server=server) for server_name, server in servers.items()
            ]
        except FileNotFoundError as e:
            error_msg = f"resource {path} not found" if is_direct_scan(path) else f"file {path} does not exist"
            logger.exception("%s: %s", error_msg, path)
            # This is a non failing error, so we set is_failure to False.
            result.error = ScanError(message=error_msg, exception=e, is_failure=False)
        except Exception as e:
            error_msg = f"could not scan {path}" if is_direct_scan(path) else f"could not parse file {path}"
            logger.exception("%s: %s", error_msg, path)
            result.error = ScanError(message=error_msg, exception=e, is_failure=True)
        return result

    def check_server_changed(self, path_result: ScanPathResult) -> list[Issue]:
        logger.debug("Checking server changed: %s", path_result.path)
        issues: list[Issue] = []
        if path_result.servers is None:
            return issues
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
        if path_result.servers is None:
            return issues
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
        except HTTPStatusError as e:
            error_msg = "server returned HTTP status code"
            logger.exception("%s: %s", error_msg, server.name)
            result.error = ScanError(message=error_msg, exception=e, is_failure=True)
        except Exception as e:
            error_msg = "could not start server"
            logger.exception("%s: %s", error_msg, server.name)
            result.error = ScanError(message=error_msg, exception=e, is_failure=True)
        await self.emit("server_scanned", result)
        return result

    def _redact_server(self, server_scan_result: ServerScanResult) -> ServerScanResult:
        """
        Redact sensitive information from the server scan result.
        """
        if isinstance(server_scan_result.server, StdioServer):
            # Redact all environment variables
            if server_scan_result.server.env:
                server_scan_result.server.env = dict.fromkeys(server_scan_result.server.env, REDACTED)
        elif isinstance(server_scan_result.server, RemoteServer):
            # Redact all headers
            if server_scan_result.server.headers:
                server_scan_result.server.headers = dict.fromkeys(server_scan_result.server.headers, REDACTED)
            # Redact all query parameter values in the URL
            try:
                parts = urlsplit(server_scan_result.server.url)
                if parts.query:
                    qs = parse_qsl(parts.query)
                    redacted_qs = [(k, REDACTED) for k, _ in qs]
                    new_query = urlencode(redacted_qs)
                    server_scan_result.server.url = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
                    )
            except Exception:
                logger.error("Failed to redact URL: %s", server_scan_result.server.url)
        return server_scan_result

    async def scan_path(self, path: str, inspect_only: bool = False) -> ScanPathResult:
        logger.info("Scanning path: %s, inspect_only: %s", path, inspect_only)
        path_result = await self.get_servers_from_path(path)

        if path_result.servers is not None:
            for i, server in enumerate(path_result.servers):
                if server.server.type == "stdio":
                    full_command = server.server.command + " " + " ".join(server.server.args or [])
                    # check if pattern is contained in full_command
                    if re.search(r"mcp[-_]scan.*mcp-server", full_command):
                        logger.info("Skipping scan of server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                        continue
                logger.debug("Scanning server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                path_result.servers[i] = self._redact_server(await self.scan_server(server))

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

        logger.debug("Calling Backend")
        result_verified = await analyze_machine(
            result_awaited,
            analysis_url=self.analysis_url,
            identifier=None,
            additional_headers=self.additional_headers,
            opt_out_of_identity=self.opt_out_of_identity,
            skip_pushing=bool(self.control_servers),
            verbose=self.verbose,
        )
        logger.debug("Result verified: %s", result_verified)
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Scan completed successfully")
        return result_verified

    async def inspect(self) -> list[ScanPathResult]:
        logger.info("Starting inspection of %d paths", len(self.paths))
        result = [self.scan_path(path, inspect_only=True) for path in self.paths]
        result_awaited = await asyncio.gather(*result)
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Inspection completed successfully")
        return result_awaited
