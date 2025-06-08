import pytest
import tempfile
import json
import time
from pathlib import Path
from src.mcp_scan.cache import SimpleCache

class TestSimpleCache:
    def test_cache_initialization(self):
        """캐시 초기화 테스트"""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = SimpleCache(cache_dir=temp_dir)
            assert cache.cache_dir.exists()
            assert cache.ttl == 1800
    
    def test_cache_key_generation(self):
        """캐시 키 생성 테스트"""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = SimpleCache(cache_dir=temp_dir)
            
            # 테스트 파일 생성
            test_file = Path(temp_dir) / "test.json"
            test_file.write_text('{"test": "data"}')
            
            key1 = cache._get_cache_key(str(test_file))
            key2 = cache._get_cache_key(str(test_file))
            
            # 동일한 파일은 동일한 키 생성
            assert key1 == key2
            assert len(key1) == 32  # MD5 해시 길이