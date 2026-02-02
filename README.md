# env-debug-mcp

*An MCP server that lets you inspect environment variables without leaking
secrets.*

______________________________________________________________________

## Why env-debug-mcp?

When debugging Claude Code or other MCP clients, you often need to check what
environment variables are available. But dumping `env` risks exposing API keys,
tokens, and passwords in logs or screenshots.

- **Safe inspection**: Variables containing KEY, TOKEN, CRED, or PASS have
  their values automatically redacted
- **Preserves structure**: Special characters, hyphens, and underscores remain
  visible so you can see the shape of values
- **Zero configuration**: Just add the server and call `debug_env`

______________________________________________________________________

## Quick start

### Installation

```bash
uv pip install env-debug-mcp
```

### Add to Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "env-debug-mcp": {
      "command": "env-debug-mcp"
    }
  }
}
```

### Usage

Once configured, ask Claude to call the `debug_env` tool. You'll get back all
environment variables with sensitive values redacted:

```text
HOME=/home/user
PATH=/usr/bin:/bin
API_KEY=**_******_***
GITHUB_TOKEN=***_************************************
```

______________________________________________________________________

## Features

- Redacts values for variables containing KEY, TOKEN, CRED, or PASS
  (case-insensitive)
- Replaces only alphanumeric characters, preserving punctuation structure
- Built on [FastMCP](https://gofastmcp.com) for easy integration
- Runs over stdio transport

______________________________________________________________________

## Learn more

- [Users' Guide](docs/users-guide.md) — full documentation

______________________________________________________________________

## Licence

ISC — see [LICENSE](LICENSE) for details.

______________________________________________________________________

## Contributing

Contributions welcome! Please see [AGENTS.md](AGENTS.md) for guidelines.
