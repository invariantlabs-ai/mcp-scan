from mcp_scan_server.server import MCPScanServer

app = MCPScanServer(port=8129, config_file_path="/Users/luca/.mcp-scan/guardrails_config.yml", pretty="full").app

# run with 'uv run uvicorn mcp_scan_server.entry:app --reload'