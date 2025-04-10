# MCP-Scan: An MCP Security Scanner

MCP-Scan is a security scanning tool designed to go over your installed MCP servers and check them for common [security vulnerabilities like prompt injections, tool poisoning and cross-origin escalations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).

## Quick Start
To run MCP-Scan, use the following command:

```bash
uvx mcp-scan@latest
```

### Example Output
```bash
(base)
% uvx mcp-scan@latest
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

To list all tools you can run `uvx mcp-scan@latest inspect`.

## How It Works
MCP-Scan searches through your configuration files to find MCP server configurations. It connects to these servers and retrieves tool descriptions.

The scans are conducted both locally and via an invariantlabs.ai server. Tool names and descriptions are sent to invariantlabs.ai and stored there. By using MCP-Scan, you agree to the invariantlabs.ai [terms of use](https://explorer.invariantlabs.ai/terms) and [privacy policy](https://invariantlabs.ai/privacy-policy).

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
