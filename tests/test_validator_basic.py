import pytest
import tempfile
import json
from src.mcp_scan.validator import ConfigValidator

class TestConfigValidatorBasic:
    def test_file_exists_validation(self):
        """파일 존재 검증 테스트"""
        with pytest.raises(FileNotFoundError) as exc_info:
            ConfigValidator.validate_file_exists("nonexistent.json")
        assert "설정 파일을 찾을 수 없습니다" in str(exc_info.value)
    
    def test_valid_json_parsing(self):
        """유효한 JSON 파싱 테스트"""
        valid_config = {"mcpServers": {"test": {"command": "echo"}}}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(valid_config, f)
            f.flush()
            
            result = ConfigValidator.validate_json_format(f.name)
            assert result == valid_config