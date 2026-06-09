# MCP server

[← README](../README.md)

`sudo-proxy-mcp` is an MCP (Model Context Protocol) server that exposes
sudo-proxy as tools over stdio JSON-RPC. Any MCP-capable AI client
(Claude Code, Claude Desktop, etc.) can call these tools.

## Tools

**`start_server`** — start a sudo-proxy instance.
- No arguments: opens a terminal window with `sudo-proxy` and its TUI for
  command approval.
- `host`: opens a terminal window with `ssh -t HOST sudo-proxy` and an SSH
  tunnel so that subsequent `execute` calls reach the remote host.
- If the server is already running (socket exists and is connectable), returns
  immediately without spawning a new terminal.
- Terminal detection tries `x-terminal-emulator`, `gnome-terminal`, `konsole`,
  `xfce4-terminal`, `xterm` in order.

**`execute`** — run a command through sudo-proxy with human approval.
- `argv` (required): command as an argument array.
- `host`: target host (omit for localhost; must match a prior `start_server`).
- `timeout`: timeout in ms (default 120 000, max 600 000).
- `description`: what this command does (shown in the TUI approval prompt).
- `privileged`: whether to escalate privileges (default `true`).
- `env`: environment variables to pass.

**`update_host`** — record metadata about a known host.
- `host` (required): hostname to update.
- `description`: human-readable description (e.g. "CI server").
- `os`: operating system info (e.g. "Ubuntu 24.04").

## Claude Code configuration

Add to `~/.claude/claude_desktop_config.json` or the project's
`.mcp.json`:

```json
{
  "mcpServers": {
    "sudo-proxy": {
      "command": "sudo-proxy-mcp"
    }
  }
}
```

Or if the binary is not in `$PATH`, use the full path to
`target/release/sudo-proxy-mcp`.

## Known hosts

The MCP server remembers hosts you connect to in
`~/.config/sudo-proxy/hosts.json`. Each `start_server` or `execute` call
updates the `last_connected` timestamp for the relevant host.

This data is used in two ways:

1. **Dynamic instructions** — when a new MCP session starts, the server's
   instructions include a "Known hosts" section listing all previously
   connected hosts with their description and last connection time. The model
   sees this automatically without the user having to re-specify hostnames.

2. **MCP resource** — the host list is exposed as the `sudo-proxy://hosts`
   resource, readable via `ListMcpResourcesTool` / `ReadMcpResourceTool`.

The model can call `update_host` to record a host's description and OS info
after learning them during a session.

If the `sudo-proxy` binary is not found in PATH or next to the MCP server
binary, the instructions include a link to the installation section.
