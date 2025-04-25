import os
from tempfile import TemporaryDirectory

from mcp_scan.StorageFile import StorageFile


def test_whitelist():
    with TemporaryDirectory() as tempdir:
        path = os.path.join(tempdir, "storage.json")
        storage_file = StorageFile(path)
        storage_file.add_to_whitelist("tool", "test", "test")
        storage_file.add_to_whitelist("tool", "test", "test2")
        storage_file.add_to_whitelist("tool", "asdf", "test2")
        assert len(storage_file.whitelist) == 2
        assert storage_file.whitelist == {
            "tool.test": "test2",
            "tool.asdf": "test2",
        }
        storage_file.save()

        # test reload
        storage_file = StorageFile(path)
        assert len(storage_file.whitelist) == 2

        # test reset
        storage_file.reset_whitelist()
        assert len(storage_file.whitelist) == 0
