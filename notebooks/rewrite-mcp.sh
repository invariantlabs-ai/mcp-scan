# change the path to your mcp-scan directory
cat << EOF > ~/.vscode/mcp.json
{
    "mcpServers": {
        "MyServer": {
            "command": "python3",
            "args": ["/home/leg/Documents/study/mcp-scan/notebooks/servers/my_mcp_server.py"]
        },
        "Test1": {
            "command": "python3",
            "args": ["/home/leg/Documents/study/mcp-scan/notebooks/servers/direct-poisoning.py"]
        }
    }
}
EOF

uv run prompt-injection-demo.py
uv run poc-scanner-fooling.py