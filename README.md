# sudo-proxy

Privileged command execution proxy. Receives requests over a Unix socket and
delegates to **pkexec** (local, graphical) or **sudo** (remote, terminal TUI).
Designed for integration with an MCP server so that an AI agent can request
root commands with explicit human approval.

## Architecture

```
MCP Server ──► Unix socket ──► sudo-proxy ──► pkexec / sudo
              (local or SSH                    (local)  (remote)
               tunnel)
```

**Local mode** (graphical session detected via `$DISPLAY` / `$WAYLAND_DISPLAY`):
passthrough to `pkexec`, which shows its own auth dialog.

**Remote mode** (no display, or `--tui` flag):
displays the request on the terminal, asks `[y/N]` with a 60-second timeout,
then runs via `sudo` if approved. stdout, stderr and exit code are echoed
locally after execution.

## Usage

```bash
# Start in auto-detected mode
sudo-proxy

# Force TUI mode even with a display
sudo-proxy --tui

# Custom socket path
sudo-proxy --socket /tmp/my-proxy.sock

# Send a request (debug client)
sudo-request id
sudo-request --reason "install web server" apt install nginx
sudo-request --host remotehost id        # sets up an SSH tunnel
```

### SSH tunnel for remote access

```bash
ssh -L /tmp/sudo-proxy.sock:/run/user/1000/sudo-proxy.sock remotehost
```

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
  "reason": "Install nginx to set up a web server"
}
```

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
  executor.rs             pkexec/sudo dispatch, which(), env sanitization
  tui.rs                  /dev/tty Y/N prompt, result display
  server.rs               Unix socket listener, validation, dispatch
  bin/
    sudo-proxy.rs         server entry point
    sudo-request.rs       debug client
    pkexec-cache.rs  polkit rule manager
```

## Implementation status

This is v0.1 — functional but minimal.

**Implemented:**
- Local mode (pkexec) and remote mode (sudo + TUI)
- `--tui` flag to force terminal prompt mode
- JSON-line protocol with base64-encoded output
- Environment sanitization (blocklist + allowlist)
- Input validation (control chars, bidi overrides, zero-width chars)
- Replay protection (UUID dedup, 60s request age)
- Socket permissions (0600)
- Execution isolation (cwd `/`, umask 0077, stdin null)
- TUI prompt with 60s timeout (poll-based), resolved path display
- TUI result echo (stdout/stderr/exit code, truncated to 3 lines)
- Signal handler for socket cleanup on SIGINT/SIGTERM
- Debug client with SSH tunnel support

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

**TUI hardening:** the Y/N prompt times out after 60 seconds (default deny).
The resolved absolute path of argv[0] is displayed alongside the requested name
so symlink tricks are visible.

## Polkit authentication caching (local mode)

By default, `pkexec` asks for a password on every request. You can optionally
configure polkit to cache authentication for a few minutes, similar to `sudo`'s
default behavior. This is done by creating a polkit rule file.

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

## Building

```bash
cargo build
```

Dependencies: `serde`, `serde_json`, `base64`, `uuid`, `libc`.

## License

TBD
