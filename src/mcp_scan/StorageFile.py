import os
import json
from datetime import datetime
from hashlib import md5
from .models import Result

class StorageFile:
    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path, "r") as f:
                self.data = json.load(f)
    
    @property
    def whitelist(self):
        return self.data.get("__whitelist", {})

    def reset_whitelist(self):
        self.data["__whitelist"] = {}
        
    def compute_hash(self, tool):
        return md5(tool.description.encode()).hexdigest()

    def check_and_update(self, server_name, tool, verified):
        key = f"{server_name}.{tool.name}"
        hash = self.compute_hash(tool)
        new_data = {
            "hash": hash,
            "timestamp": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            "description": tool.description,
        }
        changed = False
        message = None
        prev_data = None
        if key in self.data:
            prev_data = self.data[key]
            changed = prev_data["hash"] != new_data["hash"]
            if changed:
                message = (
                    "tool description changed since previous scan at "
                    + prev_data["timestamp"]
                )
        self.data[key] = new_data
        return Result(changed, message), prev_data

    def print_whitelist(self):
        whitelist_keys = sorted(self.whitelist.keys())
        for key in whitelist_keys:
            rich.print(key, self.whitelist[key])
        rich.print(f"[bold]{len(whitelist_keys)} entries in whitelist[/bold]")

    def add_to_whitelist(self, name, hash):
        if "__whitelist" not in self.data:
            self.reset_whitelist()
        self.data["__whitelist"][name] = hash
        self.save()

    def is_whitelisted(self, tool):
        hash = self.compute_hash(tool)
        return hash in self.whitelist.values()

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f)

