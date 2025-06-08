import json
import os
from pathlib import Path
from typing import Dict, Any, List

class ConfigValidator:
    """MCP 설정 파일 검증 클래스"""
    
    REQUIRED_FIELDS = ['mcpServers']
    
    @staticmethod
    def validate_file_exists(file_path: str) -> None:
        """파일 존재 여부 확인"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"❌ 설정 파일을 찾을 수 없습니다: {file_path}\n"
                f"💡 해결방법: 파일 경로를 확인하거나 기본 설정 파일을 생성하세요."
            )
    
    @staticmethod
    def validate_json_format(file_path: str) -> Dict[str, Any]:
        """JSON 형식 유효성 검사"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except json.JSONDecodeError as e:
            raise ValueError(
                f"❌ JSON 형식이 올바르지 않습니다: {e}\n"
                f"💡 해결방법: JSON 검증 도구로 형식을 확인하세요 (jsonlint.com)"
            )
        except UnicodeDecodeError:
            raise ValueError(
                f"❌ 파일 인코딩 오류입니다.\n"
                f"💡 해결방법: 파일을 UTF-8 형식으로 저장하세요."
            )
    @staticmethod
    def validate_required_fields(config: Dict[str, Any]) -> None:
        """필수 필드 검증"""
        missing_fields = []
        
        if 'mcpServers' not in config:
            missing_fields.append('mcpServers')
        elif not isinstance(config['mcpServers'], dict):
            raise ValueError(
                "❌ 'mcpServers' 필드는 객체 형태여야 합니다.\n"
                "💡 예시: {\"mcpServers\": {\"서버명\": {\"command\": \"...\"}}} "
            )
        
        # 각 서버 설정 검증
        for server_name, server_config in config.get('mcpServers', {}).items():
            if not isinstance(server_config, dict):
                raise ValueError(f"❌ 서버 '{server_name}' 설정이 올바르지 않습니다.")
            
            if 'command' not in server_config:
                missing_fields.append(f"{server_name}.command")
        
        if missing_fields:
            raise ValueError(
                f"❌ 필수 필드가 누락되었습니다: {', '.join(missing_fields)}\n"
                f"💡 해결방법: MCP 서버 설정 문서를 참고하여 필수 필드를 추가하세요."
            )
    
    @classmethod
    def validate_complete(cls, file_path: str) -> Dict[str, Any]:
        """전체 검증 프로세스"""
        cls.validate_file_exists(file_path)
        config = cls.validate_json_format(file_path)
        cls.validate_required_fields(config)
        return config