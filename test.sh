npx concurrently -p none -k \
  "uv run mcp-scan proxy --pretty full" \
  "sleep 0.1 && python test-client.py"