import os
import json
from datetime import datetime
from hashlib import md5
from .models import Result
import rich
from .utils import upload_whitelist_entry

class StorageFile:
    def __init__(self, path):
        self.path = os.path.expanduser(path)
        # if path is a file
        self.scanned_tools = {}
        self.whitelist = {}
        if os.path.isfile(path):
            rich.print(f"[bold]Legacy storage file detected at {path}, converting to new format[/bold]")
            # legacy format
            with open(path, "r") as f:
                legacy_data = json.load(f)
            if "__whitelist" in legacy_data:
                self.whitelist = legacy_data["__whitelist"]
                del legacy_data["__whitelist"]
            self.scanned_tools = legacy_data
            os.remove(path)
        
        if os.path.exists(path) and os.path.isdir(path):
            if os.path.exists(os.path.join(path, "scanned_tools.json")):
                with open(os.path.join(path, "scanned_tools.json"), "r") as f:
                    self.scanned_tools = json.load(f)
            if os.path.exists(os.path.join(path, "whitelist.json")):
                with open(os.path.join(path, "whitelist.json"), "r") as f:
                    self.whitelist = json.load(f)
    
    def reset_whitelist(self):
        self.whitelist = {}
        self.save()
        
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
        if key in self.scanned_tools:
            prev_data = self.scanned_tools[key]
            changed = prev_data["hash"] != new_data["hash"]
            if changed:
                message = (
                    "tool description changed since previous scan at "
                    + prev_data["timestamp"]
                )
        self.scanned_tools[key] = new_data
        return Result(changed, message), prev_data

    def print_whitelist(self):
        whitelist_keys = sorted(self.whitelist.keys())
        for key in whitelist_keys:
            rich.print(key, self.whitelist[key])
        rich.print(f"[bold]{len(whitelist_keys)} entries in whitelist[/bold]")

    def add_to_whitelist(self, name, hash, base_url=None):
        self.whitelist[name] = hash
        self.save()
        if base_url is not None:
            upload_whitelist_entry(
                name, hash, base_url
            )

    def is_whitelisted(self, tool):
        hash = self.compute_hash(tool)
        return hash in self.whitelist.values()

    def save(self):
        os.makedirs(self.path, exist_ok=True)
        with open(os.path.join(self.path, "scanned_tools.json"), "w") as f:
            json.dump(self.scanned_tools, f)
        with open(os.path.join(self.path, "whitelist.json"), "w") as f:
            json.dump(self.whitelist, f)
        

