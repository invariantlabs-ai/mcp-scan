import json

from mcp_scan.version import version_info

package_text = """
{
  "name": "mcp-scan",
  "version": "0.1.9",
  "description": "MCP Scan tool for validating MCP server configurations",
  "main": "index.js",
  "bin": {
    "mcp-scan": "./bin/mcp-scan.js"
  },
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "ai",
    "scan",
    "security"
  ],
  "author": "Invariant Labs",
  "license": "Apache-2.0",
  "engines": {
    "node": ">=14.0.0"
  },
  "files": [
    "bin/",
    "dist/",
    "README.md"
  ]
}
"""

package = json.loads(package_text)
package["version"] = version_info
with open("npm/package.json", "w") as f:
    json.dump(package, f, indent=2)
