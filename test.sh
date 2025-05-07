npx concurrently -p none -k \
  "uv run mcp-scan proxy --pretty full --gateway-dir /Users/luca/Developer/invariant-gateway cursor" \
  "sleep 0.1 && python test-client.py"