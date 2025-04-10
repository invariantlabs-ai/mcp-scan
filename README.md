# MCP-Scan: An MCP Security Scanner

<a href="https://discord.gg/dZuZfhKnJ4"><img src="https://img.shields.io/discord/1265409784409231483?style=plastic&logo=discord&color=blueviolet&logoColor=white" height=18/></a>

MCP-Scan is a security scanning tool designed to go over your installed MCP servers and check them for common security vulnerabilities like [prompt injections](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [cross-origin escalations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).

## Quick Start
To run MCP-Scan, use the following command:

```bash
uvx mcp-scan@latest
```

### Example Output
```bash
> uvx mcp-scan@latest
scanning ~/.codeium/windsurf/mcp_config.json found 0 servers

scanning ~/.cursor/mcp.json found 5 servers
│
├── wcgw
│   ├── tool Initialize                ✅ verified
│   ├── tool BashCommand               ✅ verified
│   ├── tool ReadFiles                 ✅ verified
│   ├── tool ReadImage                 ✅ verified
│   ├── tool FileWriteOrEdit           ✅ verified
│   ├── tool ContextSave               ✅ verified
│   └── prompt KnowledgeTransfer          skipped
├── add
│   └── tool add                       ❌ failed - attempted instruction overwrite
├── browsermcp
│   ├── tool browser_navigate          ✅ verified
│   ├── tool browser_go_back           ✅ verified
│   ├── tool browser_go_forward        ✅ verified
│   ├── tool browser_snapshot          ✅ verified
│   ├── tool browser_click             ✅ verified
│   ├── tool browser_hover             ✅ verified
│   ├── tool browser_type              ✅ verified
│   ├── tool browser_select_option     ✅ verified
│   ├── tool browser_press_key         ✅ verified
│   ├── tool browser_wait              ✅ verified
│   └── tool browser_get_console_logs  ✅ verified
├── email-mcp SSE servers not supported yet...
└── zapier SSE servers not supported yet...

scanning ~/Library/Application Support/Claude/claude_desktop_config.json file not found
```

## Features

- Scanning of Claude, Cursor, Windsurf, and other file-based MCP client configurations
- Scanning for prompt injection attacks in tool descriptions and [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) using [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant?tab=readme-ov-file#analyzer)
- Detection of cross-origin escalation attacks ([tool shadowing](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
- _Tool Pinning_ to detect and prevent [MCP rug pull attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), i.e. detects changes to MCP tools via hashing
- Inspecting the tool descriptions of installed tools via `uvx mcp-scan@latest inspect`

## How It Works
MCP-Scan searches through your configuration files to find MCP server configurations. It connects to these servers and retrieves tool descriptions.

It then scans tool descriptions, both with local checks and by invoking Invariant Guardrailing via an API. For this, tool names and descriptions are shared with invariantlabs.ai. By using MCP-Scan, you agree to the invariantlabs.ai [terms of use](https://explorer.invariantlabs.ai/terms) and [privacy policy](https://invariantlabs.ai/privacy-policy).

Invariant Labs is collecting data for security research purposes (only about tool descriptions and how they change over time, not your user data). Don't use MCP-scan if you don't want to share your tools.

MCP-scan does not store or log any usage data, i.e. the contents and results of your MCP tool calls.

## Contributing

We welcome contributions to MCP-Scan. If you have suggestions, bug reports, or feature requests, please open an issue on our GitHub repository.

## Development Setup
To run this package from source, follow these steps:

```
uv run pip install -e .
uv run -m src.mcp_scan.cli
```

## Further Reading
- [MCP Security Notification Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
- [MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)

## Changelog
- `0.1.4.0` initial public release
