# MCP-Scan: An MCP Security Scanner

[Documentation](https://explorer.invariantlabs.ai/docs/mcp-scan) | [Support Discord](https://discord.gg/dZuZfhKnJ4)


MCP-Scan is a security scanning tool to both statically and dynamically scan and monitor your MCP connections. It checks them for common security vulnerabilities like [prompt injections](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [toxic flows](https://invariantlabs.ai/blog/mcp-github-vulnerability).

It operates in two main modes which can be used jointly or separately:

1. `mcp-scan scan` statically scans all your installed servers for malicious tool descriptions and tools (e.g. [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), cross-origin escalation, rug pull attacks, toxic flows).

    [Quickstart →](#server-scanning).

2. `mcp-scan proxy` continuously monitors your MCP connections in real-time, and can restrict what agent systems can do over MCP (tool call checking, data flow constraints, PII detection, indirect prompt injection etc.).

    [Quickstart →](#server-proxying).

<br/>
<br/>

<div align="center">
<img src="https://explorer.invariantlabs.ai/docs/mcp-scan/assets/proxy.svg" width="420pt" align="center"/>
<br/>
<br/>

_mcp-scan in proxy mode._

</div>

## Features

- Scanning of Claude, Cursor, Windsurf, and other file-based MCP client configurations
- Scanning for prompt injection attacks in tools and [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) using [Guardrails](https://github.com/invariantlabs-ai/invariant?tab=readme-ov-file#analyzer)
- [Enforce guardrailing policies](https://explorer.invariantlabs.ai/docs/mcp-scan/guardrails) on MCP tool calls and responses, including PII detection, secrets detection, tool restrictions and entirely custom guardrailing policies.
- Audit and log MCP traffic in real-time via [`mcp-scan proxy`](#proxy)
- Detect cross-origin escalation attacks (e.g. [tool shadowing](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)), and detect and prevent [MCP rug pull attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), i.e. mcp-scan detects changes to MCP tools via hashing


## Quick Start

### Server Scanning

To run a static MCP scan, use the following command:

```bash
uvx mcp-scan@latest
```

This will scan your installed servers for security vulnerabilities in tools, prompts, and resources. It will automatically discover a variety of MCP configurations, including Claude, Cursor and Windsurf.

#### Example Run
[![demo](demo.svg)](https://asciinema.org/a/716858)

### Server Proxying

Using `mcp-scan proxy`, you can monitor, log, and safeguard all MCP traffic on your machine. This allows you to inspect the runtime behavior of agents and tools, and prevent attacks from e.g., untrusted sources (like websites or emails) that may try to exploit your agents. mcp-scan proxy is a dynamic security layer that runs in the background, and continuously monitors your MCP traffic.

#### Example Run

<img width="903" alt="image" src="https://github.com/user-attachments/assets/63ac9632-8663-40c3-a765-0bfdfbdf9a16" />

#### Enforcing Guardrails

You can also add guardrailing rules, to restrict and validate the sequence of tool uses passing through proxy.

For this, create a `~/.mcp-scan/guardrails_config.yml` with the following contents:

```yml
<client-name>:  # your client's shorthand (e.g., cursor, claude, windsurf)
  <server-name>:  # your server's name according to the mcp config (e.g., whatsapp-mcp)
    guardrails:
      secrets: block # block calls/results with secrets

      custom_guardrails:
        - name: "Filter tool results with 'error'"
          id: "error_filter_guardrail"
          action: block # or just 'log'
          content: |
            raise "An error was found." if:
              (msg: ToolOutput)
              "error" in msg.content
```
From then on, all calls proxied via `mcp-scan proxy` will be checked against your configured guardrailing rules for the current client/server.

Custom guardrails are implemented using Invariant Guardrails. To learn more about these rules, [see this playground environment](https://explorer.invariantlabs.ai/docs/guardrails/) and the [official documentation](https://explorer.invariantlabs.ai/docs/).

## How It Works

### Scanning

MCP-Scan `scan` searches through your configuration files to find MCP server configurations. It connects to these servers and retrieves tool descriptions.

It then scans tool descriptions, both with local checks and by invoking Invariant Guardrailing via an API. For this, tool names and descriptions are shared with invariantlabs.ai. By using MCP-Scan, you agree to the invariantlabs.ai [terms of use](https://explorer.invariantlabs.ai/terms) and [privacy policy](https://invariantlabs.ai/privacy-policy).

Invariant Labs is collecting data for security research purposes (only about tool descriptions and how they change over time, not your user data). Don't use MCP-scan if you don't want to share your tools. Additionally, a unique, persistent, and anonymous ID is assigned to your scans for analysis. You can opt out of sending this information using the `--opt-out` flag.

MCP-scan does not store or log any usage data, i.e. the contents and results of your MCP tool calls.

### Proxying

For runtime monitoring using `mcp-scan proxy`, MCP-Scan can be used as a proxy server. This allows you to monitor and guardrail system-wide MCP traffic in real-time. To do this, mcp-scan temporarily injects a local [Invariant Gateway](https://github.com/invariantlabs-ai/invariant-gateway) into MCP server configurations, which intercepts and analyzes traffic. After the `proxy` command exits, Gateway is removed from the configurations.

You can also configure guardrailing rules for the proxy to enforce security policies on the fly. This includes PII detection, secrets detection, tool restrictions, and custom guardrailing policies. Guardrails and proxying operate entirely locally using [Guardrails](https://github.com/invariantlabs-ai/invariant) and do not require any external API calls.

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
--full-toxic-flows     Show all tools that could take part in toxic flow. By default only the top 3 are shown.
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

#### proxy

Run a proxy server to monitor and guardrail system-wide MCP traffic in real-time. Temporarily injects [Gateway](https://github.com/invariantlabs-ai/invariant-gateway) into MCP server configurations, to intercept and analyze traffic. Removes Gateway again after the `proxy` command exits.

```
mcp-scan proxy [CONFIG_FILE...] [--pretty oneline|compact|full]
```

Options:
```
CONFIG_FILE...                  Path to MCP configuration files to setup for proxying.
--pretty oneline|compact|full   Pretty print the output in different formats (default: compact)
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
We welcome suggestions, bug reports, or feature requests as GitHub issues.

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
- [Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis)

## Changelog
See [CHANGELOG.md](CHANGELOG.md).
