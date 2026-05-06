# sudo-proxy

Privileged command execution proxy with an **MCP server** for AI agent
integration. Receives requests over a Unix socket, shows a **single-keypress
TUI prompt** for human approval, then escalates via **sudo**. Configure
`sudo-proxy-mcp` in Claude Code or any MCP client and the model can run
privileged commands — with explicit human approval on every one.

## Architecture

```
AI model ──► sudo-proxy-mcp ──► Unix socket ──► sudo-proxy ──► TUI Y/N ──► sudo
             (MCP server)         │
                                  │
                            local socket, or SSH tunnel
                        (start_server spawns sudo-proxy --host
                         which sets up the tunnel and remote
                         server)
```

The TUI prompt asks for approval (single keypress), then `sudo` handles
privilege escalation. The password prompt appears in the same terminal.
This flow is identical for local and remote hosts.

**Non-privileged mode** (`privileged: false` in the request):
runs the command directly as the current user, without sudo. The TUI Y/N
gate fires by default — same human review as the privileged path, just
no password step. Pass `--no-confirm-unprivileged` to the server to skip
the gate (useful for batch/automation flows where the operator has
already accepted the risk).

## Why not just use the Bash tool?

| | Bash tool | sudo-proxy MCP |
|---|---|---|
| Privilege escalation | Not possible | sudo with human approval |
| Human review | None — executes immediately | TUI Y/N gate on every command (privileged and unprivileged) |
| Timeout | Up to 10 min, no user prompt | 60 s TUI prompt + configurable overall timeout |
| Remote hosts | Not supported | SSH tunnel with TUI on remote terminal |
| Environment | Inherits shell env | Sanitized allowlist only |
| Audit trail | None | Server logs each request (with `-v`) |

sudo-proxy fills the gap when a model needs to install packages, edit
system files, manage services, or run any other command — with the human
always in the loop, even when Claude Code is run with
`--dangerously-skip-permissions`.

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
| `sudo-request` | — | Debug client (local socket only) |
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
below.

### Building locally

```bash
cargo build --release                 # core only
cargo build --release --features mcp  # all
```

### Cargo dependencies

Core: `serde`, `serde_json`, `base64`, `uuid`, `libc`.
MCP feature: adds `rmcp`, `tokio`, `schemars`.

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

## Usage

```bash
# Start the server (TUI prompt + sudo)
sudo-proxy

# Quiet by default; verbose prints startup info and logs each request
sudo-proxy -v

# Connect to a remote host via SSH tunnel
# Resolves remote UID, sets up tunnel, execs into SSH running sudo-proxy
sudo-proxy --host remotehost
sudo-proxy --host remotehost -v     # prints the ssh command before connecting

# Skip the confirmation prompt for unprivileged commands
# (default is to prompt for both privileged and unprivileged)
sudo-proxy --no-confirm-unprivileged

# Custom socket path
sudo-proxy --socket /tmp/my-proxy.sock

# Send a request (debug client)
sudo-request id
sudo-request --reason "install web server" apt install nginx

# Run without privilege escalation
sudo-request --no-privilege ls /etc

# Tag the request with a session name (default: sudo-request-cli)
sudo-request --session my-project apt update
```

`sudo-proxy --host HOST` resolves the remote UID (cached in
`~/.config/sudo-proxy/hosts.json`), sets up an SSH tunnel to the remote
`sudo-proxy.sock`, and execs into `ssh -t -L <tunnel> HOST sudo-proxy`.
The remote TUI prompt and sudo password prompt appear in your terminal.
The MCP server uses this internally via `start_server(host=...)`.

The equivalent without `--host` (useful if only the remote has sudo-proxy
installed, or for understanding what happens under the hood):

```bash
ssh -t -L /tmp/sudo-proxy-HOST.sock:/run/user/$(ssh HOST id -u)/sudo-proxy.sock HOST sudo-proxy
```

This allocates a PTY (`-t`), forwards the local socket to the remote
`sudo-proxy.sock`, and runs `sudo-proxy` on the remote end. Clients then
connect to `/tmp/sudo-proxy-HOST.sock` locally.

### SSH agent forwarding for `git clone` of private repos

Cloning a private GitHub repository on the remote host requires the
remote `git` to authenticate with your local SSH key. `sudo-proxy`
supports this in a tightly scoped way:

```bash
# 1. Start the tunnel with agent forwarding (-A) enabled.
sudo-proxy --host HOST --forward-agent

# 2. Per-request opt-in. Privileged commands cannot use the agent.
sudo-request --no-privilege --forward-agent -- \
    git clone git@github.com:org/private-repo.git
```

Through the MCP server:

```jsonc
start_server({"host": "HOST", "forward_agent": true})
execute({
  "argv": ["git", "clone", "git@github.com:org/private-repo.git"],
  "privileged": false,
  "forward_agent": true
})
```

Security model:

- The `SSH_AUTH_SOCK` injected into the child process is taken from the
  daemon's *own* environment (set by `sshd` when `-A` was used). It is
  never read from the request — a local peer cannot point your `git`
  invocation at a different agent socket.
- `forward_agent: true` is honored only when `privileged: false`. The
  daemon rejects the request otherwise; sudo/pkexec children never see
  the socket.
- Without `--forward-agent` on the launcher, requests with
  `forward_agent: true` still run, but no `SSH_AUTH_SOCK` is set on the
  child (the daemon has no socket to inject).

## Protocol

JSON lines over Unix socket. One request per connection, processed sequentially.
Maximum request size: 1 MB.

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

## Security considerations

**Environment:** the request `env` is gated by a hard allowlist
(`LANG`, `LC_*`, `TZ`, `HOME`, `DEBIAN_FRONTEND`, `TERM`). Anything else —
including `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, etc. — produces an
error response; nothing is silently stripped. For pkexec and direct
execution the process environment is cleared before applying the
allowlist. For sudo mode the process environment is inherited, but
sudo's own `env_reset` policy handles cleanup. `SSH_AUTH_SOCK` is
rejected with a specific error; agent forwarding goes through the
dedicated `forward_agent` field instead (see "SSH agent forwarding"
above).

**No shell invocation:** commands are executed via `Command::new(argv[0]).args(…)`,
never `sh -c`. This prevents `;`, `|`, `&&` injection.

**Input validation:** argv and env strings are rejected if they contain control
characters (0x00–0x1F except tab), zero-width characters (U+200B–U+200F), or
bidi override characters (U+202A–U+202E, U+2066–U+2069) that could mislead
the user during TUI approval.

**Replay protection:** request UUIDs are tracked in a set that is cleared every
1000 entries. Duplicate IDs are rejected. Requests with a `time` older than
60 seconds are rejected.

**Socket security:** the socket file is created with mode 0600 (owner-only).
`$XDG_RUNTIME_DIR` is already restricted to the user.

**Execution isolation:** child processes run with cwd `/`, umask 0077, and
stdout/stderr piped — they do not inherit the socket file descriptor. stdin is
null except for sudo mode, which inherits the terminal so sudo can prompt for a
password.

**TUI hardening:** the Y/N prompt reads a single keypress in non-canonical
terminal mode (no Enter required) and times out after 60 seconds (default deny).
The resolved absolute path of argv[0] is displayed alongside the requested name,
followed by `->` and the canonical target when it differs (i.e. when the
PATH-found file is itself a symlink), so a same-UID adversary who substitutes
`/usr/local/bin/foo -> /tmp/evil` cannot hide the redirection by either
relying on a PATH search or passing the absolute path directly. If
`canonicalize` fails (broken symlink, EACCES) the prompt says so explicitly
rather than silently displaying the as-found name. If argv[0] is not found in
PATH, the prompt shows `(not found in PATH)` as a warning.

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

## Project structure

```
src/
  lib.rs                  re-exports shared modules
  protocol.rs             Request, Response, Status (serde)
  mode.rs                 Local / Remote detection
  executor.rs             pkexec/sudo/direct dispatch, which(), env sanitization
  gui.rs                  zenity/kdialog/tui auto-detect (unused, TUI is default)
  hosts.rs                Known hosts config (~/.config/sudo-proxy/hosts.json)
  tui.rs                  /dev/tty Y/N prompt, result display
  server.rs               Unix socket listener, validation, dispatch
  mcp.rs                  MCP server: tools, resources, socket client, response formatting
  bin/
    sudo-proxy.rs         server entry point (local and --host remote)
    sudo-request.rs       debug client (local socket only)
    sudo-proxy-mcp.rs     MCP server entry point (stdio transport)
    pkexec-cache.rs       polkit rule manager
```

## Implementation status

Functional but minimal.

**Implemented:**
- TUI approval prompt + sudo for privilege escalation (local and remote)
- Non-privileged mode (direct execution, no escalation) — also TUI-gated by default
- `--verbose` / `-v` on server: prints startup info, logs each request
- `--no-confirm-unprivileged` on server: skip the Y/N gate for unprivileged commands
  (`--confirm-unprivileged` is accepted as a no-op for backwards compat)
- `--no-privilege` on client: sends request with `privileged: false`
- `--host` flag on server: SSHs into remote, starts sudo-proxy, tunnels socket (used by MCP `start_server`)
- `--print` mode for human-readable output on stdout
- JSON-line protocol with base64-encoded output and `timeout` status
- Environment sanitization (hard-allowlist; non-allowlisted vars produce an error)
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

## License

[MIT](LICENSE)
