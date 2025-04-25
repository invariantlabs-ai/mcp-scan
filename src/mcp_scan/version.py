from importlib.metadata import PackageNotFoundError, version

try:
    version_info = version("mcp-scan")
except PackageNotFoundError:
    version_info = "unknown"
