# tests/test_cli_help.py
import pytest
from io import StringIO
import sys
from src.mcp_scan.help_formatter import HelpFormatter
from src.mcp_scan.error_handler import ErrorHandler

class TestHelpFormatter:
    def test_show_examples(self, capsys):
        """예시 출력 테스트"""
        HelpFormatter.show_examples()
        captured = capsys.readouterr()
        
        # 기본 내용이 포함되어 있는지 확인
        assert "기본 명령어" in captured.out
        assert "고급 옵션" in captured.out
        assert "mcp-scan scan" in captured.out
    
    def test_show_troubleshooting(self, capsys):
        """문제 해결 가이드 테스트"""
        HelpFormatter.show_troubleshooting()
        captured = capsys.readouterr()
        
        assert "문제 해결 가이드" in captured.out
        assert "설정 파일을 찾을 수 없음" in captured.out

class TestErrorHandler:
    def test_file_not_found_error(self):
        """파일 없음 에러 처리 테스트"""
        error = FileNotFoundError("test file not found")
        result = ErrorHandler.handle_error(error)
        
        assert "📁" in result
        assert "설정 파일을 찾을 수 없습니다" in result
        assert "파일 경로가 올바른지 확인하세요" in result
    
    def test_json_decode_error(self):
        """JSON 디코드 에러 처리 테스트"""
        import json
        try:
            json.loads("{ invalid json }")
        except json.JSONDecodeError as e:
            result = ErrorHandler.handle_error(e)
            
            assert "📝" in result
            assert "JSON 형식이 올바르지 않습니다" in result
            assert "jsonlint.com" in result
    
    def test_unknown_error(self):
        """알 수 없는 에러 처리 테스트"""
        error = RuntimeError("unknown error")
        result = ErrorHandler.handle_error(error)
        
        assert "예상치 못한 오류가 발생했습니다" in result
        assert "GitHub 이슈를 등록해주세요" in result