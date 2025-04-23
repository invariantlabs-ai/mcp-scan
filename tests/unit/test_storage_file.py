from tempfile import TemporaryDirectory
import os
from mcp_scan.StorageFile import StorageFile

def test_whitelist():
    with TemporaryDirectory() as tempdir:
        path = os.path.join(tempdir, "storage.json")
        storage_file = StorageFile(path)
        storage_file.add_to_whitelist("test", "test")
        storage_file.add_to_whitelist("test", "test2")
        storage_file.add_to_whitelist("asdf", "test2")
        assert len(storage_file.whitelist) == 2
        assert storage_file.whitelist == {
            "test": "test2",
            "asdf": "test2",
        }
        storage_file.save()
        
        storage_file.reset_whitelist()
        assert len(storage_file.whitelist) == 0
        
        storage_file = StorageFile(path)
        assert len(storage_file.whitelist) == 2
        
        
        
        