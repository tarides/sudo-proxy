# sudo-proxy

> An MCP server that lets an agent run privileged, mutating commands —
> locally or over SSH — with a human keypress required on every one and
> no credential ever stored.

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
This flow is identical for local and remote hosts. A non-privileged mode
runs commands directly as the current user, still behind the same Y/N
gate — see [docs/usage.md](docs/usage.md).

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

For how this relates to mcp-firewall, sandboxing, polkit, doas, and other
neighboring tools, see [docs/comparison.md](docs/comparison.md).

## Features and non-features

What sudo-proxy does:

- **Per-command human approval** — a single-keypress Y/N TUI gate on
  every command, privileged and unprivileged, with no way to bypass it.
- **Real privilege escalation** via `sudo` — installs packages, edits
  system files, manages services; not limited to read-only diagnostics.
- **Local and remote over one flow** — the same approval TUI whether the
  command runs on this machine or on a remote host over an SSH tunnel.
- **Stores no secret** — the `sudo` password is typed live into the
  terminal; nothing is cached, encrypted-at-rest, or written to disk.
- **Explicit `argv`** — commands are passed and displayed exactly as they
  run, with no shell-string interpolation.
- **Sanitized environment** — a fixed allowlist, not the inherited shell
  environment.
- **Audit trail** — each request is logged by the server (`-v`).
- **Works under `--dangerously-skip-permissions`** — the human gate holds
  even when the agent's own permission prompts are disabled.

What sudo-proxy deliberately does *not* do:

- **No stored or managed credentials** — it is not a password cache or a
  secrets manager.
- **No unattended execution** — there is no auto-approve mode; a human
  approves each command or it does not run.
- **Not a sandbox** — it grants real privilege rather than isolating or
  faking it.
- **Not a policy engine or ACL** — the human at the keypress is the
  policy; there are no rules to write or maintain.
- **Not read-only** — it is not restricted to a whitelist of safe
  diagnostic commands.
- **No hosted service** — it runs on your own machine; commands never
  transit a third-party relay.
- **Not a general remote shell** — no persistent interactive sessions,
  SFTP browser, or fleet manager; just gated one-shot commands.

## Quickstart

Install the binaries (needs a Rust toolchain; prebuilt static binaries are
on [Releases](https://github.com/tarides/sudo-proxy/releases)):

```bash
cargo install sudo-proxy
```

Or fetch the prebuilt static binaries without compiling, via
[`cargo binstall`](https://github.com/cargo-bins/cargo-binstall):

```bash
cargo binstall sudo-proxy
```

`cargo binstall` downloads the release tarball from GitHub and **verifies
its minisign signature** (public key `RWT7gwtBU0v4puI76u0oYwMAT9nmYwGimSOnqJJ+kHExsjTDQj1eZkMW`,
key ID `A6F84B53410B83FB`) before installing; a missing or bad signature
aborts the install. Prefer `cargo install` if you'd rather build from
source.

Point your MCP client at the server — add to the project's `.mcp.json` or
`~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sudo-proxy": {
      "command": "sudo-proxy-mcp"
    }
  }
}
```

Then the model starts a server (opening a terminal with the approval TUI)
and runs commands through it:

```jsonc
start_server()
execute({"argv": ["apt", "install", "nginx"], "description": "Install nginx"})
```

Each `execute` shows the exact command in the TUI; press `y` to approve,
`N` (default) to deny. For remote hosts, pass `host` to `start_server` and
`execute`.

## MCP Registry

Listed in the official [MCP Registry](https://registry.modelcontextprotocol.io)
as `mcp-name: io.github.tarides/sudo-proxy`.

## Documentation

- [docs/install.md](docs/install.md) — install variants, remote deploy, building from source
- [docs/mcp.md](docs/mcp.md) — MCP tools (`start_server`, `execute`, `update_host`), config, known hosts
- [docs/usage.md](docs/usage.md) — CLI flags, non-privileged mode, SSH tunnels, agent forwarding
- [docs/protocol.md](docs/protocol.md) — JSON-line wire protocol over the Unix socket
- [docs/security.md](docs/security.md) — security model; [docs/security-audit.md](docs/security-audit.md) — point-in-time audit; [docs/threat-model.md](docs/threat-model.md) — STRIDE + attack tree; [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md) — graduated-assurance plan; [docs/assurance-case.md](docs/assurance-case.md) — GSN argument
- [proofs/](proofs/) — machine-checked models: [TLA+/PlusCal approval state machine](proofs/tla/) (TLC, Rung 4) and [ProVerif SSH-channel model](proofs/proverif/) (Rung 4); Kani bounded proofs live in [src/proofs.rs](src/proofs.rs) (Rung 3)
- [docs/pkexec.md](docs/pkexec.md) — `--pkexec` mode and polkit auth caching (not recommended)
- [docs/architecture.md](docs/architecture.md) — source layout and implementation status
- [docs/comparison.md](docs/comparison.md) — how sudo-proxy relates to other tools

## AI-assisted development

sudo-proxy was developed with substantial AI assistance using
[Claude Code](https://claude.com/claude-code). Commits where AI
contributed materially carry a `Co-Authored-By` trailer naming the
specific model. All design decisions, threat modeling, and the final
form of every committed change were reviewed and approved by the
human maintainer, who takes responsibility for the codebase.

This disclosure is provided in line with emerging industry practice
around transparency about generative-AI involvement in software
development. It is not a statement that the project is "AI-generated":
the human-in-the-loop principle that the tool itself enforces at
runtime is also the principle under which it was built.

## License

[MIT](LICENSE)
