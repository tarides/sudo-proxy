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
{"id":"550e...","status":"error","message":"..."}
```

## Project structure

```
src/
  lib.rs               re-exports shared modules
  protocol.rs          Request, Response, Status (serde)
  mode.rs              Local / Remote detection
  executor.rs          pkexec/sudo dispatch, which(), env sanitization
  tui.rs               /dev/tty Y/N prompt, result display
  server.rs            Unix socket listener, validation, dispatch
  bin/
    sudo-proxy.rs      server entry point
    sudo-request.rs    debug client
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

## Building

```bash
cargo build
```

Dependencies: `serde`, `serde_json`, `base64`, `uuid`, `libc`.

## License

TBD
