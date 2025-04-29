import os
from typing import Any

from mcp_scan.models import CrossRefResult, ScanException, ScanPathResult, ServerScanResult

from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .StorageFile import StorageFile
from .verify_api import verify_server


class ContextManager:
    def __init__(
        self,
    ):
        pass


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
        return self.context_manager

    async def __aenter__(self):
        return self.__enter__()

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

    async def scan_path(self, path: str, inspect_only: bool = False) -> ScanPathResult:
        path_result = await self.get_servers_from_path(path)
        for i, server in enumerate(path_result.servers):
            try:
                entities = await check_server_with_timeout(
                    server.server, self.server_timeout, self.suppress_mcpserver_io
                )
                server.prompts, server.resources, server.tools = entities
                if not inspect_only:
                    server = await verify_server(server, base_url=self.base_url)
                    server = await self.check_server_changed(server)
                    server = await self.check_whitelist(server)
            except Exception as e:
                server.error = ScanException(error=e)
                continue
            finally:
                path_result.servers[i] = server

            path_result.cross_ref_result = await self.check_cross_references(path_result)
        return path_result

    async def check_cross_references(self, path_result: ScanPathResult) -> CrossRefResult:
        cross_ref_result = CrossRefResult(found=False)
        cross_reference_sources = set()
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
                        cross_reference_sources.add(token)
        return cross_ref_result

    async def scan(self) -> list[ScanPathResult]:
        for _ in range(self.checks_per_server):
            # intentionally overwrite and only report the last scan
            result = [await self.scan_path(path) for path in self.paths]
        self.storage_file.save()
        return result

    async def inspect(self) -> list[ScanPathResult]:
        result = [await self.scan_path(path, inspect_only=True) for path in self.paths]
        self.storage_file.save()
        return result
