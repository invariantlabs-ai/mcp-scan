# MCP Scan

MCP Scan is a tool for validating Model Context Protocol (MCP) server configurations.

## Installation

You can run MCP Scan directly without installation using npx:

```bash
npx mcp-scan [command] [options]
```

Or you can install it globally:

```bash
npm install -g mcp-scan
mcp-scan [command] [options]
```

## Requirements

- Python 3.10 or later
- Node.js 14 or later

## Commands

- `scan` - Scan MCP configuration files (default command)
- `inspect` - Inspect MCP servers without verification
- `whitelist` - Manage the whitelist of approved tools

For more details, run:

```bash
npx mcp-scan help
```

## License

MIT
