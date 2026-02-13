# sudo-proxy

Privileged command execution proxy. Receives requests over a Unix socket,
shows a **single-keypress TUI prompt** for human approval, then escalates
via **sudo**. Designed for integration with an MCP server so that an AI
agent can request root commands with explicit human approval.

## Architecture

```
AI model ──► sudo-proxy-mcp ──► Unix socket ──► sudo-proxy ──► TUI Y/N ──► sudo
             (MCP server)       │
                                └── local socket, or SSH tunnel
                                    (sudo-request --host sets up both
                                     the tunnel and the remote server)
```

The TUI prompt asks for approval (single keypress), then `sudo` handles
privilege escalation. The password prompt appears in the same terminal.
This flow is identical for local and remote hosts.

**Non-privileged mode** (`privileged: false` in the request):
runs the command directly as the current user, without sudo.
By default, no confirmation is needed. Pass `--confirm-unprivileged` to the
server to require a TUI Y/N prompt.

## Usage

```bash
# Start in auto-detected mode (TUI prompt + pkexec or sudo)
sudo-proxy

# Quiet by default; verbose prints startup info and logs each request
sudo-proxy -v

# Require confirmation for non-privileged commands too
sudo-proxy --confirm-unprivileged

# Custom socket path
sudo-proxy --socket /tmp/my-proxy.sock

# Send a request (debug client)
sudo-request id
sudo-request --reason "install web server" apt install nginx

# Run without privilege escalation
sudo-request --no-privilege ls /etc

# Remote: SSH in, start sudo-proxy, tunnel the socket, send request — all at once
sudo-request --host remotehost id
sudo-request --host remotehost -v id     # --verbose: echo the ssh command
```

`--host` starts `ssh -t -L <tunnel> HOST sudo-proxy`, waits for the tunnel
socket to appear, sends the request, then cleans up. The remote sudo-proxy's
TUI prompt and sudo password prompt appear in your terminal via SSH's PTY.
No prior SSH session or manual server start needed — just an account with SSH
access and sudo-proxy installed on the remote host.

## Protocol

JSON lines over Unix socket. One request per connection, processed sequentially.

**Request:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "workstation.local",
  "session": "claude-code-project-alpha",
  "time": "2026-02-13T14:30:00Z",
  "argv": ["apt", "install", "nginx"],
  "env": {"DEBIAN_FRONTEND": "noninteractive"},
  "reason": "Install nginx to set up a web server",
  "privileged": true
}
```

`privileged` defaults to `true` if omitted. Set to `false` to run the command
as the current user without sudo/pkexec.

**Response:**
```json
{"id":"550e...","status":"ok","exit_code":0,"stdout":"<base64>","stderr":"<base64>"}
{"id":"550e...","status":"denied"}
{"id":"550e...","status":"timeout"}
{"id":"550e...","status":"error","message":"..."}
```

## Project structure

```
src/
  lib.rs                  re-exports shared modules
  protocol.rs             Request, Response, Status (serde)
  mode.rs                 Local / Remote detection
  executor.rs             pkexec/sudo/direct dispatch, which(), env sanitization
  gui.rs                  zenity/kdialog/tui auto-detect confirmation dialog
  hosts.rs                Known hosts config (~/.config/sudo-proxy/hosts.json)
  tui.rs                  /dev/tty Y/N prompt, result display
  server.rs               Unix socket listener, validation, dispatch
  mcp.rs                  MCP server: tools, resources, socket client, response formatting
  bin/
    sudo-proxy.rs         server entry point
    sudo-request.rs       debug client
    sudo-proxy-mcp.rs     MCP server entry point (stdio transport)
    pkexec-cache.rs       polkit rule manager
```

## Implementation status

Functional but minimal.

**Implemented:**
- TUI approval prompt + sudo for privilege escalation (local and remote)
- Non-privileged mode (direct execution, no escalation)
- `--verbose` / `-v` on server: prints startup info, logs each request
- `--confirm-unprivileged` on server: prompt before non-privileged commands
- `--no-privilege` on client: sends request with `privileged: false`
- `--host` flag: SSHs into remote, starts sudo-proxy, tunnels socket, sends request
- `--verbose` / `-v` on client: echoes the SSH command
- `--print` mode for human-readable output on stdout
- JSON-line protocol with base64-encoded output and `timeout` status
- Environment sanitization (blocklist + allowlist)
- Input validation (control chars, bidi overrides, zero-width chars)
- Replay protection (UUID dedup, 60s request age)
- Socket permissions (0600)
- Execution isolation (cwd `/`, umask 0077, stdin null)
- Single-keypress TUI prompt with 60s timeout, resolved path display
- TUI result echo (stdout/stderr/exit code, truncated to 3 lines)
- Signal handler for socket cleanup on SIGINT/SIGTERM
- MCP server (`sudo-proxy-mcp`) with `execute`, `start_server`, and `update_host` tools
- MCP resources: known hosts list (`sudo-proxy://hosts`)
- Dynamic MCP instructions with known hosts and install guidance
- `--pkexec` mode and `pkexec-cache` tool (see [pkexec section](#pkexec-mode))

**Not yet implemented:**
- Command/argument allowlisting (needs policy framework)
- Inode pinning for TOCTOU on resolved paths
- Risk scoring display
- Audit log to file
- Per-session socket isolation

## Security considerations

**Environment:** dangerous variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`,
etc.) are stripped. Only an allowlist of known-safe names (`LANG`, `LC_*`, `TZ`,
`HOME`, `DEBIAN_FRONTEND`, `TERM`) passes through; anything else is rejected.

**No shell invocation:** commands are executed via `Command::new(argv[0]).args(…)`,
never `sh -c`. This prevents `;`, `|`, `&&` injection.

**Input validation:** argv and env strings are rejected if they contain control
characters (0x00–0x1F except tab), zero-width characters (U+200B–U+200F), or
bidi override characters (U+202A–U+202E, U+2066–U+2069) that could mislead
the user during TUI approval.

**Replay protection:** a bounded set of the last 1000 request UUIDs is tracked.
Duplicate IDs are rejected. Requests with a `time` older than 60 seconds are
rejected.

**Socket security:** the socket file is created with mode 0600 (owner-only).
`$XDG_RUNTIME_DIR` is already restricted to the user.

**Execution isolation:** child processes run with cwd `/`, umask 0077, stdin
null, and stdout/stderr piped — they do not inherit the socket file descriptor.

**TUI hardening:** the Y/N prompt reads a single keypress in non-canonical
terminal mode (no Enter required) and times out after 60 seconds (default deny).
The resolved absolute path of argv[0] is displayed alongside the requested name
so symlink tricks are visible.

## pkexec mode

By default, sudo-proxy separates approval (TUI prompt) from privilege
escalation (sudo). The TUI shows the command for single-keypress Y/N
approval, then sudo handles password authentication — both in the same
terminal window.

The `--pkexec` flag bypasses the TUI entirely and lets pkexec handle both
authentication and approval in its own dialog. This mode exists but is not
recommended because polkit conflates authentication (proving who you are) and
authorization (approving what to do):

- **Without auth caching**: pkexec asks for a password on every single
  request. This is safe but impractical for an AI agent workflow that may
  run dozens of commands.

- **With auth caching**: pkexec skips its dialog entirely for the cache
  duration — commands run silently with no approval prompt. This is unsafe
  and defeats sudo-proxy's human-in-the-loop design.

There is no middle ground in polkit. The TUI mode solves this by always
prompting for approval (one keypress, no password) while letting the OS
handle password authentication separately.

### pkexec authentication caching

If you do use `--pkexec` mode, you can optionally configure polkit to cache
authentication for a few minutes, similar to `sudo`'s default behavior.

**This is a user decision.** The rule applies to all `pkexec` calls from your
user, not just those from sudo-proxy — polkit has no way to distinguish the
calling program. Evaluate whether this trade-off is acceptable for your setup.

The `pkexec-cache` tool manages this rule:

```bash
# Check if the rule is installed
pkexec-cache

# Install the rule (detects your username from SUDO_USER)
sudo pkexec-cache --create

# Remove the rule
sudo pkexec-cache --delete
```

The rule is written to `/etc/polkit-1/rules.d/50-pkexec-cache.rules`
and caches authentication for the calling user with these conditions:
- `subject.active` — only the foreground session (not background terminals)
- `subject.local` — only local sessions (not SSH)
- `AUTH_ADMIN_KEEP` — cache the admin password for ~5 minutes

polkitd monitors its rules directory and reloads automatically — no service
restart is needed.

There is no GUI tool to manage polkit rules on any distribution. On current
Ubuntu and Debian, polkit uses the JavaScript `.rules` format — the older
`.pkla` format is deprecated. The
[Arch Wiki polkit page](https://wiki.archlinux.org/title/Polkit) is the most
comprehensive reference.

## MCP server

`sudo-proxy-mcp` is an MCP (Model Context Protocol) server that exposes
sudo-proxy as tools over stdio JSON-RPC. Any MCP-capable AI client
(Claude Code, Claude Desktop, etc.) can call these tools.

### Tools

**`start_server`** — start a sudo-proxy instance.
- No arguments: opens a terminal window with `sudo-proxy` and its TUI for
  command approval.
- `host`: opens a terminal window with `ssh -t HOST sudo-proxy` and an SSH
  tunnel so that subsequent `execute` calls reach the remote host.

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

### Claude Code configuration

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

### Known hosts

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

### Why not just use the Bash tool?

| | Bash tool | sudo-proxy MCP |
|---|---|---|
| Privilege escalation | Not possible | pkexec / sudo with human approval |
| Human review | None — executes immediately | Every privileged command shown in TUI |
| Timeout | Up to 10 min, no user prompt | 60 s TUI prompt + configurable overall timeout |
| Remote hosts | Not supported | SSH tunnel with TUI on remote terminal |
| Environment | Inherits shell env | Sanitized allowlist only |
| Audit trail | None | Server logs each request (with `-v`) |

The Bash tool is fine for non-privileged commands. sudo-proxy fills the gap
when a model needs to install packages, edit system files, or manage
services — with the human always in the loop.

## Installation

### From source (with Rust toolchain)

```bash
# Core binaries only (sudo-proxy, sudo-request, pkexec-cache)
cargo install --git ssh://git@github.com/tarides/sudo-proxy.git

# Everything including the MCP server
cargo install --git ssh://git@github.com/tarides/sudo-proxy.git --features mcp
```

The MCP server depends on `rmcp`, `tokio`, and `schemars`. These are
behind the `mcp` Cargo feature so the core binaries stay lean and compile
fast.

| Binary | Feature | Purpose |
|---|---|---|
| `sudo-proxy` | — | Server: socket listener, approval UI, execution |
| `sudo-request` | — | Debug client / SSH tunnel helper |
| `pkexec-cache` | — | Optional polkit rule manager |
| `sudo-proxy-mcp` | `mcp` | MCP server (stdio, for AI agents) |

### Prebuilt static binaries (no Rust needed)

Download from [GitHub Releases](https://github.com/tarides/sudo-proxy/releases).
Each release includes a tarball with statically-linked x86_64 Linux binaries
(MUSL) that run on any distribution regardless of glibc version.

### Deploying to a remote host

The remote host only needs the `sudo-proxy` binary. A single static file,
no runtime dependencies, no config:

```bash
# Download the latest release tarball, extract, and copy
scp sudo-proxy remote:/usr/local/bin/
```

When an AI agent calls `start_server(host="remote")`, the MCP server SSHs
in and runs `sudo-proxy` on the remote. The only prerequisites on the
remote side are SSH access and the `sudo-proxy` binary in `$PATH`.

### Local workstation setup

Install all binaries and optionally set up polkit auth caching:

```bash
cargo install --git ssh://git@github.com/tarides/sudo-proxy.git --features mcp

# Optional: cache pkexec auth for ~5 minutes (like sudo)
sudo pkexec-cache --create
```

Then configure your MCP client — see [Claude Code configuration](#claude-code-configuration)
above.

### Building locally

```bash
cargo build --release                 # core only
cargo build --release --features mcp  # all
```

### Cargo dependencies

Core: `serde`, `serde_json`, `base64`, `uuid`, `libc`.
MCP feature: adds `rmcp`, `tokio`, `schemars`.

## License

[MIT](LICENSE)
