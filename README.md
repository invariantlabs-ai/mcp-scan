# MCP-Scan: An MCP Security Scanner

[<img src="https://devin.ai/assets/deepwiki-badge.png" alt="Ask DeepWiki.com" height="20"/>](https://deepwiki.com/invariantlabs-ai/mcp-scan)
<a href="https://discord.gg/dZuZfhKnJ4"><img src="https://img.shields.io/discord/1265409784409231483?style=plastic&logo=discord&color=blueviolet&logoColor=white" height=18/></a>

MCP-Scan is a security scanning tool designed to go over your installed MCP servers and check them for common security vulnerabilities like [prompt injections](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [cross-origin escalations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).

## Quick Start
To run MCP-Scan, use the following command:

```bash
uvx mcp-scan@latest
```

or

```
npx mcp-scan@latest
```

### Example Run
[![demo](demo.svg)](https://asciinema.org/a/716858)


## Features

- Scanning of Claude, Cursor, Windsurf, and other file-based MCP client configurations
- Scanning for prompt injection attacks in tool descriptions and [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) using [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant?tab=readme-ov-file#analyzer)
- Detection of cross-origin escalation attacks ([tool shadowing](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
- _Tool Pinning_ to detect and prevent [MCP rug pull attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), i.e. detects changes to MCP tools via hashing
- Inspecting the tool descriptions of installed tools via `inspect` command (e.g., `uvx mcp-scan@latest inspect`)

## How It Works
MCP-Scan searches through your configuration files to find MCP server configurations. It connects to these servers and retrieves tool descriptions.

It then scans tool descriptions, both with local checks and by invoking Invariant Guardrailing via an API. For this, tool names and descriptions are shared with invariantlabs.ai. By using MCP-Scan, you agree to the invariantlabs.ai [terms of use](https://explorer.invariantlabs.ai/terms) and [privacy policy](https://invariantlabs.ai/privacy-policy).

Invariant Labs is collecting data for security research purposes (only about tool descriptions and how they change over time, not your user data). Don't use MCP-scan if you don't want to share your tools.

MCP-scan does not store or log any usage data, i.e. the contents and results of your MCP tool calls.

## CLI parameters

MCP-scan provides the following commands:

```
mcp-scan - Security scanner for Model Context Protocol servers and tools
```

### Common Options

These options are available for all commands:

```
--storage-file FILE    Path to store scan results and whitelist information (default: ~/.mcp-scan)
--base-url URL         Base URL for the verification server
--verbose              Enable detailed logging output
--print-errors         Show error details and tracebacks
--json                 Output results in JSON format instead of rich text
```

### Commands

#### scan (default)

Scan MCP configurations for security vulnerabilities in tools, prompts, and resources.

```
mcp-scan [CONFIG_FILE...]
```

Options:
```
--checks-per-server NUM       Number of checks to perform on each server (default: 1)
--server-timeout SECONDS      Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL  Suppress stdout/stderr from MCP servers (default: True)
```

#### inspect

Print descriptions of tools, prompts, and resources without verification.

```
mcp-scan inspect [CONFIG_FILE...]
```

Options:
```
--server-timeout SECONDS      Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL  Suppress stdout/stderr from MCP servers (default: True)
```

#### whitelist

Manage the whitelist of approved entities. When no arguments are provided, this command displays the current whitelist.

```
# View the whitelist
mcp-scan whitelist

# Add to whitelist
mcp-scan whitelist TYPE NAME HASH

# Reset the whitelist
mcp-scan whitelist --reset
```

Options:
```
--reset                       Reset the entire whitelist
--local-only                  Only update local whitelist, don't contribute to global whitelist
```

Arguments:
```
TYPE                          Type of entity to whitelist: "tool", "prompt", or "resource"
NAME                          Name of the entity to whitelist
HASH                          Hash of the entity to whitelist
```

#### help

Display detailed help information and examples.

```
mcp-scan help
```

### Examples

```bash
# Scan all known MCP configs
mcp-scan

# Scan a specific config file
mcp-scan ~/custom/config.json

# Just inspect tools without verification
mcp-scan inspect

# View whitelisted tools
mcp-scan whitelist

# Whitelist a tool
mcp-scan whitelist tool "add" "a1b2c3..."
```

## Contributing

We welcome contributions to MCP-Scan. If you have suggestions, bug reports, or feature requests, please open an issue on our GitHub repository.

## Development Setup
To run this package from source, follow these steps:

```
uv run pip install -e .
uv run -m src.mcp_scan.cli
```

## Including MCP-scan results in your own project / registry

If you want to include MCP-scan results in your own project or registry, please reach out to the team via `mcpscan@invariantlabs.ai`, and we can help you with that.
For automated scanning we recommend using the `--json` flag and parsing the output.

## Further Reading
- [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [MCP Security Notification Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
- [MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)

## Changelog
See [CHANGELOG.md](CHANGELOG.md).
