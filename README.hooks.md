# Cursor Hooks 

Hooks Documentation: https://cursor.com/docs/agent/hooks#beforereadfile

# Quickstart

```
# install hook-gateway.py as Cursor Hooks
uv run python install-hook.py

# launch mcp-scan proxy server (dev mode)
uv run uvicorn mcp_scan_server.entry:app --reload --port 8129 --log-level error
```

This will allow you to observe what the Cursor agent is doing (via Hooks). 

You can also impose Guardrails on the agent (tested user prompt, read_file so far).