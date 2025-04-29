import asyncio
import os
from collections import defaultdict
from typing import Any, Callable

from mcp_scan.models import CrossRefResult, ScanException, ScanPathResult, ServerScanResult

from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .StorageFile import StorageFile
from .verify_api import verify_server


class ContextManager:
    def __init__(
        self,
    ):
        self.enabled = True
        self.callbacks = defaultdict(list)
        self.running = []

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        self.callbacks[signal].append(async_callback)

    async def emit(self, signal: str, data: Any):
        if self.enabled:
            for callback in self.callbacks[signal]:
                self.running.append(callback(signal, data))

    async def wait(self):
        await asyncio.gather(*self.running)


class MCPScanner:
    def __init__(
        self,
        files: list[str] = [],
        base_url: str = "https://mcp.invariantlabs.ai/",
        checks_per_server: int = 1,
        storage_file: str = "~/.mcp-scan",
        server_timeout: int = 10,
        suppress_mcpserver_io: bool = True,
        **kwargs: Any,
    ):
        self.paths = files
        self.base_url = base_url
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        self.storage_file = StorageFile(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io
        self.context_manager = None

    def __enter__(self):
        if self.context_manager is None:
            self.context_manager = ContextManager()
        return self

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context_manager is not None:
            await self.context_manager.wait()
            self.context_manager = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.context_manager is not None:
            asyncio.run(self.context_manager.wait())
            self.context_manager = None

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        if self.context_manager is not None:
            self.context_manager.hook(signal, async_callback)
        else:
            raise RuntimeError("Context manager not initialized")

    async def get_servers_from_path(self, path: str) -> ScanPathResult:
        result = ScanPathResult(path=path)
        try:
            servers = (await scan_mcp_config_file(path)).get_servers()
            result.servers = [
                ServerScanResult(name=server_name, server=server) for server_name, server in servers.items()
            ]
        except FileNotFoundError as e:
            result.error = ScanException(message="file does not exist", error=e)
        except Exception as e:
            print(e)
            result.error = ScanException(message="could not parse file", error=e)
        return result

    async def check_server_changed(self, server: ServerScanResult) -> ServerScanResult:
        result = server.model_copy(deep=True)
        for i, (entity, entity_result) in enumerate(server.entities_with_result):
            if entity_result is None:
                continue
            c, messages = self.storage_file.check_and_update(server.name or "", entity, entity_result.verified)
            result.result[i].changed = c
            if c:
                result.result[i].messages.extend(messages)
        return result

    async def check_whitelist(self, server: ServerScanResult) -> ServerScanResult:
        result = server.model_copy()
        for i, (entity, entity_result) in enumerate(server.entities_with_result):
            if entity_result is None:
                continue
            if self.storage_file.is_whitelisted(entity):
                result.result[i].whitelisted = True
            else:
                result.result[i].whitelisted = False
        return result

    async def emit(self, signal: str, data: Any):
        if self.context_manager is not None:
            await self.context_manager.emit(signal, data)

    async def scan_server(self, server: ServerScanResult, inspect_only: bool = False) -> ServerScanResult:
        result = server.model_copy(deep=True)
        try:
            entities = await check_server_with_timeout(server.server, self.server_timeout, self.suppress_mcpserver_io)
            result.prompts, result.resources, result.tools = entities
            if not inspect_only:
                result = await verify_server(result, base_url=self.base_url)
                result = await self.check_server_changed(result)
                result = await self.check_whitelist(result)
        except Exception as e:
            result.error = ScanException(error=e)
        await self.emit("server_scanned", result)
        return result

    async def scan_path(self, path: str, inspect_only: bool = False) -> ScanPathResult:
        path_result = await self.get_servers_from_path(path)
        for i, server in enumerate(path_result.servers):
            path_result.servers[i] = await self.scan_server(server, inspect_only)
        path_result.cross_ref_result = await self.check_cross_references(path_result)
        await self.emit("path_scanned", path_result)
        return path_result

    async def check_cross_references(self, path_result: ScanPathResult) -> CrossRefResult:
        cross_ref_result = CrossRefResult(found=False)
        for server in path_result.servers:
            other_servers = [s for s in path_result.servers if s != server]
            other_server_names = [s.name for s in other_servers]
            other_entity_names = [e.name for s in other_servers for e in s.entities]
            flagged_names = set(map(str.lower, other_server_names + other_entity_names))
            for entity in server.entities:
                tokens = (entity.description or "").lower().split()
                for token in tokens:
                    if token in flagged_names:
                        cross_ref_result.found = True
                        cross_ref_result.sources.append(token)
        return cross_ref_result

    async def scan(self) -> list[ScanPathResult]:
        if self.context_manager is not None:
            self.context_manager.disable()
        for i in range(self.checks_per_server):
            # intentionally overwrite and only report the last scan
            if i == self.checks_per_server - 1 and self.context_manager is not None:
                self.context_manager.enable()  # only print on last run
            result = [self.scan_path(path) for path in self.paths]
            result_awaited = await asyncio.gather(*result)
        self.storage_file.save()
        return result_awaited

    async def inspect(self) -> list[ScanPathResult]:
        result = [self.scan_path(path, inspect_only=True) for path in self.paths]
        result_awaited = await asyncio.gather(*result)
        self.storage_file.save()
        return result_awaited
