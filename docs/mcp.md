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

## Registry introspection (Glama)

The [Glama](https://glama.ai/mcp/servers/tarides/sudo-proxy) MCP registry scores
a server by building it, running it, and calling `tools/list` — the quality
score is derived from the enumerated tool definitions, so the tools must
enumerate for the server to be scored
([methodology](https://glama.ai/mcp/methodology)).

Glama does **not** build a `Dockerfile` from this repo. The build is configured
on the server's Glama admin page (`.../admin/dockerfile`) as *build steps* + a
*CMD*, run inside Glama's `debian:trixie-slim` base (Node and `mcp-proxy`
preinstalled, but no Rust). Enter these as JSON arrays — the values below use no
embedded double quotes, so they paste without being flagged invalid (call
`cargo` by its full path instead of sourcing `$HOME/.cargo/env`):

Build steps:

```json
["apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config", "curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.96.0 --profile minimal && $HOME/.cargo/bin/cargo build --release --bin sudo-proxy-mcp"]
```

CMD arguments:

```json
["/app/target/release/sudo-proxy-mcp"]
```

After changing the config press **Build and release** (plain *Release*
republishes the previous artifact). To check that the server introspects
correctly (no Docker needed):

```sh
cargo test --test mcp_introspection
```

It should enumerate `execute`, `start_server`, and `update_host`.

## Glama terminology

Glama describes MCP servers with three terms — here is how they map to
sudo-proxy:

| Glama term    | sudo-proxy |
| ------------- | ---------- |
| **Server**    | the `sudo-proxy-mcp` binary — the stdio MCP server, listed as `tarides/sudo-proxy`. |
| **Tools**     | `execute`, `start_server`, `update_host`. |
| **Connector** | *none* — a connector is a **remote/hosted** MCP server (a managed HTTP endpoint). sudo-proxy is local-only, so it is a server but never a connector. |

Two caveats:

- **"Connector" does not apply by design.** It is Glama's word for a hosted,
  remote MCP endpoint with managed credentials. sudo-proxy needs a live local
  daemon and a human at the approval TUI, so it cannot be hosted this way (the
  same reason Glama's "try in browser" only ever returns "sudo-proxy is not
  running").
- **Mind the word "server".** Glama's *server* is the `sudo-proxy-mcp` MCP
  process. sudo-proxy's own *server* — what the `start_server` tool spawns — is
  the `sudo-proxy` host daemon (Unix socket + TUI) that the MCP server proxies
  to. That daemon, `sudo-request`, `pkexec-cache`, and target *hosts* all sit
  below Glama's vocabulary; in MCP terms sudo-proxy is one server exposing three
  tools.
