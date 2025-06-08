import pytest
from src.mcp_scan.logger import EnhancedLogger

class TestEnhancedLogger:
    def test_logger_initialization(self):
        """로거 초기화 테스트"""
        logger = EnhancedLogger()
        assert logger.console is not None
        assert logger.progress is None
    
    def test_message_methods_exist(self):
        """메시지 메서드 존재 확인"""
        logger = EnhancedLogger()
        assert hasattr(logger, 'success')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'info')