import asyncio
import logging
import os
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from mcp_scan.models import CrossRefResult, ScanError, ScanPathResult, ServerScanResult

from .mcp_client import check_server_with_timeout, scan_mcp_config_file
from .StorageFile import StorageFile
from .utils import calculate_distance
from .verify_api import verify_scan_path
from .logger import EnhancedLogger  # ← 추가된 import

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
        local_only: bool = False,
        **kwargs: Any,
    ):
        logger.info("Initializing MCPScanner")
        self.paths = files or []
        logger.debug("Paths to scan: %s", self.paths)
        self.base_url = base_url
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        logger.debug("Storage file path: %s", self.storage_file_path)
        self.storage_file = StorageFile(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io
        self.context_manager = None
        self.local_only = local_only
        
        # ← 여기에 EnhancedLogger 추가
        self.enhanced_logger = EnhancedLogger()
        
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
            # ← Enhanced Logger로 사용자 친화적 에러 표시
            self.enhanced_logger.error(f"설정 파일을 찾을 수 없습니다: {path}")
            result.error = ScanError(message=error_msg, exception=e)
        except Exception as e:
            error_msg = "could not parse file"
            logger.exception("%s: %s", error_msg, path)
            # ← Enhanced Logger로 사용자 친화적 에러 표시
            self.enhanced_logger.error(f"설정 파일 파싱 실패: {path}")
            result.error = ScanError(message=error_msg, exception=e)
        return result

    async def check_server_changed(self, server: ServerScanResult) -> ServerScanResult:
        logger.debug("Checking for changes in server: %s", server.name)
        result = server.model_copy(deep=True)
        for i, (entity, entity_result) in enumerate(server.entities_with_result):
            if entity_result is None:
                continue
            c, messages = self.storage_file.check_and_update(server.name or "", entity, entity_result.verified)
            result.result[i].changed = c
            if c:
                logger.info("Entity %s in server %s has changed", entity.name, server.name)
                # ← Enhanced Logger로 변경 사항 표시
                self.enhanced_logger.warning(f"서버 '{server.name}'의 엔티티 '{entity.name}'가 변경되었습니다")
                result.result[i].messages.extend(messages)
        return result

    async def check_whitelist(self, server: ServerScanResult) -> ServerScanResult:
        logger.debug("Checking whitelist for server: %s", server.name)
        result = server.model_copy()
        for i, (entity, entity_result) in enumerate(server.entities_with_result):
            if entity_result is None:
                continue
            if self.storage_file.is_whitelisted(entity):
                logger.debug("Entity %s is whitelisted", entity.name)
                result.result[i].whitelisted = True
            else:
                result.result[i].whitelisted = False
        return result

    async def emit(self, signal: str, data: Any):
        logger.debug("Emitting signal: %s", signal)
        if self.context_manager is not None:
            await self.context_manager.emit(signal, data)

    async def scan_server(self, server: ServerScanResult, inspect_only: bool = False) -> ServerScanResult:
        logger.info("Scanning server: %s, inspect_only: %s", server.name, inspect_only)
        result = server.model_copy(deep=True)
        try:
            # ← Enhanced Logger로 스캔 시작 표시
            self.enhanced_logger.info(f"🔍 서버 스캔 중: {server.name}")
            
            result.signature = await check_server_with_timeout(
                server.server, self.server_timeout, self.suppress_mcpserver_io
            )
            logger.debug(
                "Server %s has %d prompts, %d resources, %d tools",
                server.name,
                len(result.signature.prompts),
                len(result.signature.resources),
                len(result.signature.tools),
            )

            # ← Enhanced Logger로 스캔 성공 표시
            self.enhanced_logger.success(f"서버 '{server.name}' 스캔 완료")

            if not inspect_only:
                logger.debug("Checking if server has changed: %s", server.name)
                result = await self.check_server_changed(result)
                logger.debug("Checking whitelist for server: %s", server.name)
                result = await self.check_whitelist(result)
                
        except Exception as e:
            error_msg = "could not start server"
            logger.exception("%s: %s", error_msg, server.name)
            # ← Enhanced Logger로 서버 시작 실패 표시
            self.enhanced_logger.error(f"서버 '{server.name}' 시작 실패: {str(e)}")
            result.error = ScanError(message=error_msg, exception=e)
            
        await self.emit("server_scanned", result)
        return result

    async def scan_path(self, path: str, inspect_only: bool = False) -> ScanPathResult:
        logger.info("Scanning path: %s, inspect_only: %s", path, inspect_only)
        
        # ← Enhanced Logger로 경로 스캔 시작 표시
        self.enhanced_logger.info(f"📁 경로 스캔 시작: {path}")
        
        path_result = await self.get_servers_from_path(path)
        
        # ← 진행률 바 시작 (서버가 있는 경우에만)
        task_id = None
        if path_result.servers:
            total_servers = len(path_result.servers)
            task_id = self.enhanced_logger.start_progress(
                f"MCP 서버 스캔 중...", 
                total_servers
            )
        
        try:
            for i, server in enumerate(path_result.servers):
                logger.debug("Scanning server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                
                # ← 진행률 업데이트
                if task_id is not None:
                    self.enhanced_logger.update_progress(
                        task_id, 
                        description=f"스캔 중: {server.name}"
                    )
                
                path_result.servers[i] = await self.scan_server(server, inspect_only)
                
                # ← 진행률 한 단계 전진
                if task_id is not None:
                    self.enhanced_logger.update_progress(task_id)
                    
        finally:
            # ← 진행률 바 종료
            if task_id is not None:
                self.enhanced_logger.finish_progress()
        
        logger.debug("Verifying server path: %s", path)
        # ← Enhanced Logger로 검증 단계 표시
        self.enhanced_logger.info("🔍 서버 검증 중...")
        
        path_result = await verify_scan_path(path_result, base_url=self.base_url, run_locally=self.local_only)
        path_result.cross_ref_result = await self.check_cross_references(path_result)
        
        # ← Enhanced Logger로 경로 스캔 완료 표시
        self.enhanced_logger.success(f"경로 '{path}' 스캔 완료")
        
        await self.emit("path_scanned", path_result)
        return path_result

    async def check_cross_references(self, path_result: ScanPathResult) -> CrossRefResult:
        logger.info("Checking cross references for path: %s", path_result.path)
        
        # ← Enhanced Logger로 교차 참조 검사 표시
        self.enhanced_logger.info("🔗 교차 참조 검사 중...")
        
        cross_ref_result = CrossRefResult(found=False)
        for server in path_result.servers:
            other_servers = [s for s in path_result.servers if s != server]
            other_server_names = [s.name for s in other_servers]
            other_entity_names = [e.name for s in other_servers for e in s.entities]
            flagged_names = set(map(str.lower, other_server_names + other_entity_names))
            logger.debug("Found %d potential cross-reference names", len(flagged_names))

            if len(flagged_names) < 1:
                logger.debug("No flagged names found, skipping cross-reference check")
                continue

            for entity in server.entities:
                tokens = (entity.description or "").lower().split()
                for token in tokens:
                    best_distance = calculate_distance(reference=token, responses=list(flagged_names))[0]
                    if ((best_distance[1] <= 2) and (len(token) >= 5)) or (token in flagged_names):
                        logger.warning("Cross-reference found: %s with token %s", entity.name, token)
                        # ← Enhanced Logger로 교차 참조 발견 표시
                        self.enhanced_logger.warning(f"교차 참조 발견: {entity.name} - {token}")
                        cross_ref_result.found = True
                        cross_ref_result.sources.append(f"{entity.name}:{token}")

        if cross_ref_result.found:
            logger.info("Cross references detected with %d sources", len(cross_ref_result.sources))
            # ← Enhanced Logger로 교차 참조 결과 표시
            self.enhanced_logger.warning(f"⚠️ 교차 참조 {len(cross_ref_result.sources)}개 발견됨")
        else:
            logger.debug("No cross references found")
            # ← Enhanced Logger로 교차 참조 없음 표시
            self.enhanced_logger.success("교차 참조 문제 없음")
            
        return cross_ref_result

    async def scan(self) -> list[ScanPathResult]:
        logger.info("Starting scan of %d paths", len(self.paths))
        
        # ← Enhanced Logger로 전체 스캔 시작 표시
        self.enhanced_logger.info(f"🚀 MCP 보안 스캔 시작 (총 {len(self.paths)}개 경로)")
        
        if self.context_manager is not None:
            self.context_manager.disable()

        result_awaited = []
        for i in range(self.checks_per_server):
            logger.debug("Scan iteration %d/%d", i + 1, self.checks_per_server)
            
            # ← Enhanced Logger로 반복 스캔 표시
            if self.checks_per_server > 1:
                self.enhanced_logger.info(f"스캔 반복 {i + 1}/{self.checks_per_server}")
            
            # intentionally overwrite and only report the last scan
            if i == self.checks_per_server - 1 and self.context_manager is not None:
                logger.debug("Enabling context manager for final iteration")
                self.context_manager.enable()  # only print on last run
            result = [self.scan_path(path) for path in self.paths]
            result_awaited = await asyncio.gather(*result)

        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Scan completed successfully")
        
        # ← Enhanced Logger로 전체 스캔 완료 및 요약 표시
        total_servers = sum(len(path.servers) for path in result_awaited)
        successful_servers = sum(
            len([s for s in path.servers if s.error is None]) 
            for path in result_awaited
        )
        
        self.enhanced_logger.print_summary("🎉 스캔 완료", {
            "총 경로 수": len(self.paths),
            "총 서버 수": total_servers,
            "스캔 성공": successful_servers,
            "성공률": f"{(successful_servers/total_servers)*100:.1f}%" if total_servers > 0 else "0%"
        })
        
        return result_awaited

    async def inspect(self) -> list[ScanPathResult]:
        logger.info("Starting inspection of %d paths", len(self.paths))
        
        # ← Enhanced Logger로 검사 모드 시작 표시
        self.enhanced_logger.info(f"🔍 MCP 서버 검사 시작 (총 {len(self.paths)}개 경로)")
        
        result = [self.scan_path(path, inspect_only=True) for path in self.paths]
        result_awaited = await asyncio.gather(*result)
        
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Inspection completed successfully")
        
        # ← Enhanced Logger로 검사 완료 표시
        self.enhanced_logger.success("🎉 검사 완료")
        
        return result_awaited