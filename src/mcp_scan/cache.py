import json
import hashlib
import time
import os
from pathlib import Path
from typing import Any, Dict, Optional

class SimpleCache:
    """파일 기반 간단한 캐싱 시스템"""
    
    def __init__(self, cache_dir: str = "~/.mcp-scan/cache", ttl: int = 1800):
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl  # 30분 기본값
    
    def _get_cache_key(self, file_path: str) -> str:
        """파일 경로와 수정 시간으로 캐시 키 생성"""
        try:
            file_stat = os.stat(file_path)
            content = f"{file_path}:{file_stat.st_mtime}:{file_stat.st_size}"
            return hashlib.md5(content.encode()).hexdigest()
        except OSError:
            # 파일이 없으면 경로만으로 키 생성
            return hashlib.md5(file_path.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """캐시 유효성 확인"""
        if not cache_file.exists():
            return False
        
        try:
            cache_age = time.time() - cache_file.stat().st_mtime
            return cache_age < self.ttl
        except OSError:
            return False
    
    def get(self, file_path: str) -> Optional[Dict[str, Any]]:
        """캐시에서 결과 조회"""
        cache_key = self._get_cache_key(file_path)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not self._is_cache_valid(cache_file):
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)
            return cached_data.get('result')
        except (json.JSONDecodeError, OSError, KeyError):
            # 손상된 캐시 파일 삭제
            try:
                cache_file.unlink()
            except OSError:
                pass
            return None