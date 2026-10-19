# Architecture & status

[← README](../README.md)

## Security model vs. agent harnesses

sudo-proxy and the permission model of an agent CLI harness (Claude Code, Codex
CLI, and similar) differ on two axes. Getting these straight explains why
sudo-proxy leans so hard on the displayed-equals-executed guarantee.

**1. The gatekeeper (human vs. software).** Both are *mediated*: the model never
executes anything itself — it only emits a *request* that something else decides
on and runs. The difference is what sits in the gate:

- A **harness** gates with **software**: configured permission rules
  (allow / ask / deny), optionally a safety classifier, and a human prompt only
  on the "ask" path. The designed-for case is **automated** — an allowlisted
  command runs with no human in the loop.
- **sudo-proxy** gates with a **mandatory human keypress** on `/dev/tty` for
  *every* command, fail-closed (default deny, 60 s timeout). There is **no
  classifier and no auto-approve** for privileged commands; software only
  *rejects* (dangerous characters, structural invalidity, replay/freshness) — it
  never *approves*. The human is the sole approving authority.

**2. Privilege direction (escalate vs. confine).** This is the deeper difference
in assumption:

- A **harness** performs capability *restriction*. The agent already runs **as
  you**, with your ambient privileges; the harness *narrows* that to a safe
  subset. Its executor (the Bash tool) runs **unprivileged** — no escalation.
- **sudo-proxy** performs capability *escalation*. The client/agent has **no
  privilege of its own**; sudo-proxy *grants* one it otherwise lacks —
  `sudo` / `pkexec` to **root or another user** — and binds each grant to a
  human who read the exact command.

| | Agent harness (Claude Code, Codex CLI) | sudo-proxy |
|---|---|---|
| Model's role | emits a tool request | emits a request (MCP / socket client) |
| Gate | permission rules + optional classifier + optional human | **mandatory human** per command; no classifier |
| Default decision | can be fully automated | never automated (always a keypress) |
| Executor privilege | your own (ambient) | **escalated** (root / other user) |
| Purpose | **confine** an agent that runs as you | **escalate** beyond what the agent has |
| Failure mode | depends on policy | fail-closed to a human (default deny) |

Both start from the same premise — the model's output is an *untrusted request*,
not an authorization — and answer "who authorizes it?" differently: **software
policy** (harness) vs. **a human reading the literal command** (sudo-proxy).
Because the authorizer is a human rather than a classifier, sudo-proxy's entire
security reduces to *what that human can see and comprehend at the prompt* —
hence invariants **G1** (nothing privileged runs without a human approving the
exact command shown) and the per-stage resolved-binary rendering
([REVIEWING.md](../REVIEWING.md)).

The two are **complementary, not competing**: the harness confines the agent to
your privileges; sudo-proxy is how the agent reaches *past* them for a rare
privileged action — with a human, not a classifier, as the escalation authority.

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
- Per-daemon policy in `hosts.json` (`policy.unattended_eligible`, default
  false): whether the daemon may offer the session-scoped `a` answer. Read once
  at startup, immutable at runtime — an out-of-band operator opt-in (invariant
  G7, barrier 1). Pressing `a` on an eligible daemon flips an in-memory,
  never-persisted session grant (barrier 2); on a non-eligible daemon `a`
  approves just the one command
- `--unattended-eligible` on server: makes the daemon eligible without editing
  the file (the session grant still needs the `a` keypress and is never persisted)
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
