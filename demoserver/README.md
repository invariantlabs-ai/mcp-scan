# Small MCP Demo Server

A minimal MCP server built with [fast-mcp](https://github.com/modelcontextprotocol/python-sdk) for testing and demonstrating mcp-scan security detection capabilities.

⚠️ **This is a demo server with intentional security vulnerabilities for testing purposes. Do not use in production.**

## Available Tools

- **`get_current_time()`** - Returns the current timestamp
- **`sum(a, b)`** - Adds two numbers (contains prompt injection in description)
- **`multiply(a, b)`** - Multiplies two numbers (rug pull behavior - changes after first run)
- **`get_comments()`** - Returns website comments (toxic flow potential)
- **`get_api_key()`** - Returns an API key (security risk)
- **`send_email(to, subject, body)`** - Sends email (potential data exfiltration)
- **`delete_file(file_path)`** - Deletes files (destructive operation)

## Security Issues Demonstrated

This server intentionally includes several security anti-patterns that mcp-scan should detect:

1. **Prompt Injection**: Tool descriptions contain malicious instructions
2. **Rug Pull**: The `multiply` tool changes behavior after first run
3. **Toxic Flows**: Combination of tools that could leak sensitive data
4. **Destructive Operations**: File deletion capabilities
5. **Data Exfiltration**: Email sending with external access

## Quick Start

### Install Dependencies
```bash
pip install 'mcp[cli]'
```

### Run the Server
```bash
python server.py
```
