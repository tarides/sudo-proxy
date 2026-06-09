# Architecture & status

[← README](../README.md)

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
- Per-host policy in `hosts.json`: pressing `a` at an unprivileged prompt
  writes `policy.confirm_unprivileged=false` so the daemon skips the gate
  on this host from then on
- `--no-confirm-unprivileged` / `--confirm-unprivileged` on server:
  explicit overrides of the persisted policy
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
- `--pkexec` mode and `pkexec-cache` tool (see [pkexec.md](pkexec.md))

**Not yet implemented:**
- Command/argument allowlisting (needs policy framework)
- Inode pinning for TOCTOU on resolved paths
- Risk scoring display
- Audit log to file
- Per-session socket isolation

### Design note: allowlisting (when it lands)

When command/argument allowlisting is built, allowlist concrete **argument
patterns**, not command-name prefixes. CVE-2025-66032 (the "8 ways to pwn
Claude Code" research) showed that prefix matching on allowlisted binaries is
escapable because the binary does more than its name implies: `man --html=CMD`,
`sort --compress-program=sh`, `sed s///e`, git abbreviated flags
(`--upload-pa=`), `rg --pre=sh`, and bash `@P`/`$IFS` expansion all turn an
innocuous-looking prefix into arbitrary execution. A policy framework must
account for each binary's own flag parsing (abbreviations, `=value` forms, and
exec-capable options) rather than trusting the leading tokens. This does not
affect sudo-proxy today: there is no auto-approve path — every command hits the
human TUI gate — and requests carry structured argv (never a shell string), so
there is no prefix matcher or shell expansion to defeat. The risk reappears
only if allowlisting (or a "remember this command" per-host policy) introduces
an auto-approve surface.
