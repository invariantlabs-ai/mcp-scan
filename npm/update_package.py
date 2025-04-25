# read pyproject.toml
import json

from mcp_scan.version import version_info

with open("npm/package.json", "r") as f:
    package = json.load(f)
package["version"] = version_info
with open("npm/package.json", "w") as f:
    json.dump(package, f, indent=2)
