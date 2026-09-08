# Comparison with other tools

[← README](../README.md)

How sudo-proxy relates to neighboring tools that show up in the same
search ("approval gate for AI-driven command execution", "MCP security",
"human-in-the-loop for agents"). Each section places the tool on the
request path, lists what overlaps, what diverges, and when to pick which.

Tools covered:

**Direct alternatives** (full template)

- [mcp-firewall](#mcp-firewall)
- [mac-shell-mcp](#mac-shell-mcp)
- [code-sandbox-mcp](#code-sandbox-mcp)
- [Anthropic sandbox-runtime](#anthropic-sandbox-runtime)
- [AgentSudo](#agentsudo)

**MCP Registry alternatives** (servers found on the registry)

- [mcp-sudo](#mcp-sudo)
- [agent-sudo-mcp](#agent-sudo-mcp)
- [SSH command executors](#ssh-command-executors)
- [Read-only SSH diagnostics](#read-only-ssh-diagnostics)
- [Arbitrary command runners](#arbitrary-command-runners)
- [Generic approval gates](#generic-approval-gates)

**Adjacent and building-block tools** (short prose)

- [LangGraph HITL middleware](#langgraph-hitl-middleware)
- [AgentWard](#agentward)
- [Permit.io HITL](#permitio-hitl)
- [pkttyagent](#pkttyagent)
- [plain sudo + sudoers](#plain-sudo--sudoers)
- [OpenSnitch](#opensnitch)
- [doas](#doas)

---

## mcp-firewall

[github.com/ressl/mcp-firewall](https://github.com/ressl/mcp-firewall) —
AGPL-3.0, Python, wraps any MCP server with policy / detection / audit.

### Where each tool sits

```
AI client ──► mcp-firewall ──► (some MCP server) ──► …backend…
                                       │
                                       └─► sudo-proxy-mcp ──► sudo-proxy daemon ──► sudo ──► OS
```

mcp-firewall is a **generic MCP proxy**: it wraps any stdio MCP server
and filters every tool call through a pipeline. sudo-proxy **is one
specific MCP server** (plus a Unix-socket daemon and a privilege
boundary). The two layers are orthogonal and can compose — mcp-firewall
in front of sudo-proxy-mcp is a sensible deployment.

### Side-by-side

|                          | sudo-proxy                                                                                                                              | mcp-firewall                                                                                              |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Layer                    | One specific MCP server + execution daemon                                                                                              | Generic MCP wrapper in front of any MCP server                                                            |
| Primary purpose          | Run privileged OS commands with per-call human approval                                                                                 | Enforce policy, detect injection, scrub secrets in MCP traffic                                            |
| Approval UX              | Single-keypress TUI on `/dev/tty`, same terminal as the daemon; 60 s default-deny                                                       | "Optional interactive prompt" — surface unspecified in docs                                               |
| Privilege escalation     | First-class: sudo (default), optional pkexec, password prompt in the same terminal                                                      | None — filters MCP RPC; does not invoke `sudo` or own the privileged side                                 |
| Remote hosts             | Built-in: `start_server(host=…)` opens SSH with `-t -L`, runs the daemon remotely, TUI surfaces on the local terminal                   | No SSH/remote story; local stdio wrapper                                                                  |
| Process model            | Long-lived Unix-socket daemon (`sudo-proxy`) + stdio MCP shim (`sudo-proxy-mcp`)                                                        | Wrapper command (`mcp-firewall wrap -- <server>`), optional dashboard on :9090, SDK lib mode              |
| Policy model             | None (intentional) — every call is an interactive human decision                                                                        | OPA/Rego + YAML allowlists/denylists, rate limits, chain detection, RBAC, kill switch                     |
| Inbound checks           | Argv/env validation (control chars, bidi, zero-width), hard env allowlist, replay protection (UUID dedup + 60 s age), no-shell exec    | Kill switch, RBAC, rate limiting, 50+ injection patterns, egress/SSRF, policy engine, chain detection     |
| Outbound checks          | Output size cap (16 MiB) + truncation flags; base64 framing                                                                             | Secret scanner, PII detector, exfiltration detection, content policy                                      |
| Audit                    | `-v` logs each request to stderr                                                                                                        | Built-in audit logging for compliance                                                                     |
| Language / footprint     | Rust, focused codebase, single static MUSL binary deployable via `scp`                                                                  | Python, broader feature surface                                                                           |
| License                  | MIT                                                                                                                                     | AGPL-3.0 (commercial license available)                                                                   |

### Where they overlap

One row, really: **interactive human approval before a tool call runs.**
sudo-proxy treats this as the core loop — every command, always, via a
hardened TUI. mcp-firewall lists it as one of eight inbound checks; the
docs don't specify where the prompt surfaces.

### Where they diverge

- **Privilege model.** sudo-proxy is built around the OS privilege
  boundary: argv/env sanitization, sudo password handling, pkexec
  discussion, polkit caching rule manager, scoped SSH agent forwarding.
  mcp-firewall lives above this — it has no concept of UIDs, sudoers,
  or PTYs.
- **Remote execution.** sudo-proxy's `--host` mode + SSH tunnel is the
  headline non-local feature. mcp-firewall is a local stdio wrapper.
- **Policy vs. consent.** mcp-firewall's center of gravity is *codified
  policy* (OPA/Rego, RBAC, rate limits) so most calls flow through
  unattended. sudo-proxy is the inverse: no policy framework, every call
  is a keypress. The README explicitly rejects polkit auth caching
  because silent execution "defeats sudo-proxy's human-in-the-loop
  design."
- **Output handling.** mcp-firewall scrubs secrets/PII from responses.
  sudo-proxy truncates at 16 MiB and base64-encodes — content
  inspection isn't its job.

### When to pick which

- **Model needs to run `apt install`, edit `/etc`, or manage services on
  a box (local or remote) with a human pressing Y/N each time** →
  sudo-proxy.
- **Guardrails around an existing fleet of MCP servers** — filesystem,
  GitHub, databases — **with policy, secret redaction, rate limits, and
  audit** → mcp-firewall.
- **Both** — run sudo-proxy-mcp as the privileged-command MCP server
  and place mcp-firewall in front of it (and the rest of your MCP
  servers). mcp-firewall's wrapper model is designed for this.

---

## mac-shell-mcp

[github.com/cfdude/mac-shell-mcp](https://github.com/cfdude/mac-shell-mcp) —
MIT, TypeScript/Node.js. MCP server for `zsh` on macOS with a
three-tier allowlist (safe / requires-approval / forbidden) plus
interactive approval for the middle tier.

### Where each tool sits

```
AI client ──► mac-shell-mcp (stdio MCP) ──► zsh ──► local macOS
                       │
                       └─ if tier = "requires approval":
                          tool returns a pending-call id;
                          operator approves via a follow-up tool call
                          (no separate TUI, no sudo)
```

### Side-by-side

|                      | sudo-proxy                                                | mac-shell-mcp                                                                    |
|----------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------|
| Layer                | MCP server + execution daemon                             | Stdio MCP server only                                                            |
| Primary purpose      | Privileged commands with per-call approval                | Approval/whitelist gate for shell commands on macOS                              |
| Approval UX          | TUI on `/dev/tty`, single keypress, 60 s default-deny     | Tool-call-driven (`get_pending_commands`, approve/deny tools); no separate TUI   |
| Privilege escalation | sudo (default), pkexec optional                           | None — `sudo` is on the forbidden list, never executed                           |
| Remote hosts         | SSH tunnel built in                                       | None                                                                             |
| Process model        | Long-lived Unix-socket daemon + stdio MCP shim            | Stdio MCP shim                                                                   |
| Policy model         | None (every call asks)                                    | Static three-tier (safe / requires-approval / forbidden)                         |
| Platform             | Linux (Rust binary, MUSL)                                 | macOS only                                                                       |
| License              | MIT                                                       | MIT                                                                              |

### Where they overlap

Both expose a "run a shell command" MCP tool and both have a notion
of human approval for some commands. Both decline to do anything
clever with `sudo` by default — though for opposite reasons:
mac-shell-mcp forbids `sudo` entirely; sudo-proxy makes `sudo` the
whole point and gates it with a keypress.

### Where they diverge

- **Platform.** Linux + remote-by-SSH vs. macOS-only.
- **Privilege strategy.** If your model needs to install packages or
  edit `/etc`, mac-shell-mcp can't help by design.
- **Approval surface.** Single-keypress TUI vs. tool-call-based
  approval that loops back through the model. The latter keeps the
  approver in-band (another tool call) rather than out-of-band (a
  keypress on a terminal).
- **Policy.** mac-shell-mcp ships with a categorized allowlist;
  sudo-proxy ships without one by design.

### When to pick which

- **macOS workstation, unprivileged commands, want a static safe-list
  with occasional approval prompts** → mac-shell-mcp.
- **Privileged commands, Linux, or remote hosts** → sudo-proxy.
- **Both** — possible in principle, but the OS split makes
  co-deployment niche.

---

## code-sandbox-mcp

[github.com/Automata-Labs-team/code-sandbox-mcp](https://github.com/Automata-Labs-team/code-sandbox-mcp) —
MIT, Go. MCP server that runs model-generated code inside Docker
containers; isolation is the safety boundary, not approval.

### Where each tool sits

```
AI client ──► code-sandbox-mcp (stdio MCP) ──► local Docker engine ──► throwaway container
                                                                       (code runs unprivileged
                                                                        inside the image)
```

### Side-by-side

|                      | sudo-proxy                                                | code-sandbox-mcp                                                  |
|----------------------|-----------------------------------------------------------|-------------------------------------------------------------------|
| Layer                | MCP server + execution daemon                             | Stdio MCP server + Docker engine                                  |
| Primary purpose      | Run host commands with per-call approval                  | Run model-generated code in an ephemeral container                |
| Approval UX          | TUI on `/dev/tty`, single keypress                        | None — containment is the gate                                    |
| Privilege escalation | sudo / pkexec                                             | Not addressed; container user only                                |
| Remote hosts         | SSH tunnel                                                | Not documented                                                    |
| Process model        | Long-lived daemon + stdio MCP shim                        | Stdio MCP shim talking to local Docker                            |
| Policy model         | None                                                      | Container image acts as the policy boundary                       |
| Audit                | `-v` logs each request                                    | Not documented                                                    |
| Requirements         | Linux + sudo                                              | Docker engine                                                     |
| License              | MIT                                                       | MIT                                                               |

### Where they overlap

Both are MCP servers that wrap "let the model run things" with a
safety boundary. Beyond that they sit on opposite sides of a
strategic choice: **approve every call** (sudo-proxy) vs. **contain
the blast radius and skip approval** (code-sandbox-mcp).

### Where they diverge

- **Strategy.** Approval vs. isolation.
- **What's affected.** sudo-proxy commands change real host state.
  code-sandbox-mcp commands run inside a throwaway container —
  perfect for "execute the model's Python script", useless for
  "install nginx on this server".
- **Privilege.** sudo-proxy is built for privileged commands;
  sandboxing inverts the problem by running everything unprivileged
  inside a container.

### When to pick which

- **Model writes and runs scratch code (Python, JS) without touching
  the host** → code-sandbox-mcp.
- **Model operates the host — services, packages, files** →
  sudo-proxy.
- **Both** — separate MCP servers, separate purposes; compose
  freely.

---

## Anthropic sandbox-runtime

[code.claude.com/docs/en/sandboxing](https://code.claude.com/docs/en/sandboxing)
(source: [github.com/anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime))
— open-source npm package, Claude Code's native Bash sandbox.
Enforces filesystem and network isolation at the OS level
(Seatbelt on macOS, bubblewrap on Linux/WSL2).

### Where each tool sits

```
Claude Code Bash tool ──► sandbox-runtime ──► Seatbelt / bubblewrap ──► child process
                                  │
                                  └─ network proxy (allowlisted domains)

Commands that need to escape the sandbox fall back to the regular
permission flow (the "dangerouslyDisableSandbox" escape hatch).
```

### Side-by-side

|                      | sudo-proxy                                                                                | sandbox-runtime                                                                                                |
|----------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Layer                | MCP server + execution daemon                                                             | Wraps Claude Code's Bash tool (and optionally arbitrary commands via `npx @anthropic-ai/sandbox-runtime …`)    |
| Primary purpose      | Per-call human approval + sudo escalation                                                 | Confine bash subprocesses to a defined FS/network boundary                                                     |
| Approval UX          | TUI on `/dev/tty`                                                                         | Auto-allow inside sandbox; standard permission flow outside                                                    |
| Privilege escalation | sudo / pkexec                                                                             | None; docs note FS-write-to-`$PATH` paths as a privilege-escalation risk                                       |
| Remote hosts         | SSH tunnel                                                                                | Local only                                                                                                     |
| Process model        | Long-lived daemon + MCP shim                                                              | OS sandbox (bubblewrap, Seatbelt) + outbound HTTP/SOCKS proxy for network                                      |
| Policy model         | None                                                                                      | Allowlists for FS paths and network domains, merged across settings.json scopes                                |
| Inbound checks       | argv/env validation, replay protection, no-shell exec                                     | OS-level FS/network confinement at the syscall boundary                                                        |
| Requirements         | Linux + sudo                                                                              | macOS (Seatbelt), Linux + `bubblewrap`+`socat`, WSL2; not WSL1, not native Windows yet                         |
| License              | MIT                                                                                       | Open-source npm package                                                                                        |

### Where they overlap

Both are responses to the same observation, and Anthropic's docs
state it bluntly: *"Approval fatigue: repeatedly clicking 'approve'
can cause users to pay less attention to what they're approving."*
sudo-proxy and sandbox-runtime answer this opposite ways —
sandbox-runtime makes approval unnecessary inside its boundary;
sudo-proxy keeps approval but reduces it to one keypress so it
stays salient.

### Where they diverge

- **Strategy.** Isolate vs. approve. Inside the sandbox, commands
  run silently; sudo-proxy never runs silently.
- **Privilege.** sandbox-runtime doesn't help with `sudo apt
  install`; its security model assumes the commands inside the
  sandbox are unprivileged.
- **Surface area.** sandbox-runtime is for Claude Code's Bash tool.
  It can wrap arbitrary commands via the npm CLI, but that's
  opt-in and not the headline use case.

### When to pick which

- **Want the model running unprivileged commands all day without
  prompting, and trust an OS sandbox to contain mistakes** →
  sandbox-runtime.
- **Want every privileged command human-approved, and need
  remote-host reach** → sudo-proxy.
- **Both** — natural composition. Sandbox the Bash tool; reach for
  sudo-proxy when the model needs to break out of the sandbox under
  human approval.

---

## AgentSudo

[agentsudo.dev](https://agentsudo.dev/) /
[github.com/xywa23/agentsudo](https://github.com/xywa23/agentsudo) —
MIT, Python. Worth a section specifically to disambiguate the
name: AgentSudo is *not* an OS-level sudo. It is a Python decorator
(`@sudo`) that gates **agent-framework tool calls** with scopes
and out-of-band approval (Slack).

### Where each tool sits

```
LangChain / LlamaIndex / FastAPI agent
            │
            ▼
    @sudo decorator  ──► (if high-risk) Slack message to approver
            │              └─► approve / deny ──► continue or refuse
            ▼
   wrapped Python function (DB call, API call, business logic)
```

### Side-by-side

|                      | sudo-proxy                                                            | AgentSudo                                                              |
|----------------------|-----------------------------------------------------------------------|------------------------------------------------------------------------|
| Layer                | OS-level (sudo + MCP)                                                 | Python function decorator inside an agent framework                    |
| What it gates        | `argv` reaching `exec()` on the host                                  | Calls to specific Python functions by specific agent identities        |
| Approval UX          | TUI on `/dev/tty`, single keypress, 60 s default-deny                 | Slack message with approve/deny; also a dashboard                      |
| Privilege escalation | sudo / pkexec                                                         | None — runs in agent process                                           |
| Remote hosts         | SSH tunnel                                                            | N/A                                                                    |
| Process model        | Long-lived daemon + stdio MCP shim                                    | Library import                                                         |
| Policy model         | None (every call asks)                                                | Scope-based (`read:orders`, `write:refunds`), session TTLs, audit log  |
| Framework coupling   | MCP (works with any MCP client)                                       | LangChain / LlamaIndex / FastAPI / custom                              |
| Implementation       | Rust                                                                  | Python                                                                 |
| License              | MIT                                                                   | MIT                                                                    |

### Where they overlap

The name and the slogan. Both call themselves "sudo for AI agents"
and both implement human-in-the-loop. The similarity ends there.

### Where they diverge

- **Layer.** sudo-proxy gates `argv` reaching the OS. AgentSudo
  gates a Python function call reaching a database, API, or piece
  of business logic.
- **Approval channel.** TUI on the operator's terminal vs. Slack
  message to a (possibly remote) approver.
- **Policy.** AgentSudo is *policy-first* (scopes, RBAC, TTLs).
  sudo-proxy is *consent-first* (no scopes; every call is a
  keypress).
- **Audience.** sudo-proxy is for an operator running an agent
  against their own machine. AgentSudo is for a team running an
  agent against a shared service.

### When to pick which

- **Building a LangChain/LlamaIndex/FastAPI app, want scoped,
  Slack-approved access to your own Python tools** → AgentSudo.
- **MCP-aware human approval gate for shell/sudo commands** →
  sudo-proxy.
- **Both** — they sit on different layers and don't conflict.

---

## MCP Registry alternatives

A scan of the official
[MCP Registry](https://registry.modelcontextprotocol.io) for servers
tagged around `sudo`, `root`, `privilege`, `ssh`, and `command`
surfaces the servers below. Only the first is a true head-to-head
competitor; the rest either delegate the trust decision elsewhere,
restrict themselves to read-only work, or don't escalate at all.
sudo-proxy occupies the otherwise-empty quadrant: **privileged,
mutating execution + a mandatory per-command human keypress + local or
remote + no stored secret.**

### mcp-sudo

`io.github.KamaruSama/mcp-sudo`
([github.com/KamaruSama/mcp-sudo](https://github.com/KamaruSama/mcp-sudo))
— PyPI, Python. The closest analog on the registry, and a deliberate
inversion of sudo-proxy's thesis: it caches the sudo password
(Fernet-encrypted, keyed to machine-id + user, in
`~/.config/claude-sudo-mcp/credential.enc`) so that a `sudo_exec` tool
can run privileged commands *without prompting a human*. Convenience by
removing the operator; sudo-proxy is accountability by keeping them.

|                      | sudo-proxy                                                 | mcp-sudo                                                        |
|----------------------|------------------------------------------------------------|-----------------------------------------------------------------|
| Approval             | Single-keypress TUI on every command, no bypass            | None — auto-executes once the password is cached                |
| Credential handling  | Typed live into the terminal; nothing stored               | Sudo password encrypted at rest on disk                         |
| Threat surface       | No secret at rest to steal                                 | Author notes: copy the machine-id → recover the password        |
| Remote hosts         | SSH tunnel, TUI on the remote terminal                     | Single-user local workstation only                              |
| Audit                | `-v` logs each request                                     | None documented                                                 |

The pitch writes itself the moment `--dangerously-skip-permissions` is
in play: that is exactly when an unattended, disk-stored sudo password
is most dangerous, and exactly when sudo-proxy's keypress still holds.

### agent-sudo-mcp

`io.github.Kisyntra/agent-sudo-mcp` — PyPI, Python. Despite the name,
this is *not* an OS sudo. It bills itself as a "local permission
gateway and security policy engine for MCP tool execution"
(authorization, delegation, provenance, verifiable audit). It gates
*other* tools' calls; it does not itself escalate privilege or run
privileged commands. It sits in front of executors rather than being
one — a policy layer that could wrap sudo-proxy-mcp, not a substitute
for it. (Conceptually adjacent to the [AgentSudo](#agentsudo) decorator
above, but at the MCP-transport layer.)

### SSH command executors

`com.browserssh/browser-ssh`
([browserssh.com](https://browserssh.com)),
`com.pulsemcp/ssh` (`ssh-agent-mcp-server`,
[github.com/pulsemcp/mcp-servers](https://github.com/pulsemcp/mcp-servers)),
and `dev.aicommander/mcp` ("an SSH/Ansible alternative") all give an
agent the reach to run commands on remote hosts. What none of them add
is a synchronous per-command human gate: the trust decision is
delegated to the SSH ACL / agent key up front, and calls then flow
unattended. sudo-proxy also reaches remote hosts over SSH, but keeps a
keypress on every command and surfaces the TUI on the remote terminal.

### Read-only SSH diagnostics

`io.github.Areso/safe-ssh-mcp`
([github.com/Areso/safe-ssh-mcp](https://github.com/Areso/safe-ssh-mcp))
and `io.github.Easton-OU/rootpilot-ssh-diagnose`
([github.com/Easton-OU/rootpilot-mcp](https://github.com/Easton-OU/rootpilot-mcp),
a fixed 38-command whitelist, secrets redacted) buy their safety by
being **read-only**: they run diagnostic commands and refuse anything
mutating. That is a real safety story, but it means they cannot install
a package, edit a config, or restart a service. sudo-proxy does that
mutating, privileged work and gets its safety from the human gate
instead of a read-only restriction.

### Arbitrary command runners

`io.github.bytedance/mcp-server-commands` (npm
`@agent-infra/mcp-server-commands`, part of ByteDance's
[UI-TARS-desktop](https://github.com/bytedance/UI-TARS-desktop/tree/main/packages/agent-infra/mcp-servers/commands)
monorepo — "run arbitrary commands"),
`io.github.domdomegg/shell-exec-mcp`
([github.com/domdomegg/shell-exec-mcp](https://github.com/domdomegg/shell-exec-mcp)),
and `app.desktopcommander/remote-desktop-commander` expose raw command
execution with no approval step — the registry embodiment of the "Why
not just use the Bash tool?" case in the README. They also typically
run a script string through an interpreter rather than an explicit
`argv`. sudo-proxy is the gated, no-shell counterpart.

### Generic approval gates

`dev.1pass/logi-approval`
([docs.1pass.dev](https://docs.1pass.dev/agent-approval/quickstart),
phone approval before high-risk actions) and the `com.clauxel.*`
approval MCPs gate *arbitrary* agent actions with human sign-off and
receipts, but they do not execute or escalate anything themselves. Like
[agent-sudo-mcp](#agent-sudo-mcp), they are a wrappable consent layer,
not a privileged executor — complementary to sudo-proxy rather than a
replacement.

---

## Adjacent and building-block tools

These come up in the same search but don't compete with sudo-proxy
directly — they live at a different layer of the stack or solve a
related-but-distinct problem.

### LangGraph HITL middleware

[LangChain HITL docs](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)
— framework-internal middleware that pauses a LangGraph agent
before a tool call and lets a human approve, edit, reject, or
respond. Same HITL philosophy as sudo-proxy, but the gate is
*inside the agent runtime*, not at the OS boundary. Use this to
gate a LangGraph agent's tool calls in general; you'd still want
sudo-proxy (or equivalent) underneath when one of those tool calls
is `sudo apt install ...`.

### AgentWard

[agentward.ai](https://www.agentward.ai/) — commercial permission
enforcement for AI agents. Governance/policy layer aimed at
organizations deploying many agents across many services.
Different audience from sudo-proxy; no privilege-escalation focus.

### Permit.io HITL

[Permit.io HITL guide](https://www.permit.io/blog/human-in-the-loop-for-ai-agents-best-practices-frameworks-use-cases-and-demo)
— authorization-as-a-service platform with HITL workflows. Sits
above runtime as a policy decision point and integrates with
multiple agent frameworks. Like AgentWard, this is governance
plumbing rather than a substitute for sudo-proxy's per-call OS
gate.

### pkttyagent

[polkit reference (polkit.8)](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html)
— polkit's textual authentication agent, the off-the-shelf "TUI
prompt for privilege" piece. The sudo-proxy README has a full
section ([pkexec mode](pkexec.md)) explaining why it
doesn't go this route: polkit conflates authentication and
authorization, so cached auth means commands run silently —
defeating the human gate. Building block, not alternative.

### plain sudo + sudoers

The baseline. `sudoers` covers privilege escalation, including
narrow allowlists (`NOPASSWD: /usr/bin/apt update`) and command
logging via `sudoreplay`. What it lacks is an *AI-aware* approval
surface: no per-call Y/N prompt for an MCP-issued command, no
request metadata, no remote tunnel. sudo-proxy uses `sudo`
underneath — it adds the human-in-the-loop layer on top.

### OpenSnitch

[github.com/evilsocket/opensnitch](https://github.com/evilsocket/opensnitch)
— GPL-3.0 interactive application firewall for Linux: every
outbound connection from an unrecognized process raises a prompt
asking the user to allow/deny. Same UX pattern as sudo-proxy ("ask
before this happens"), different domain (network connections, not
commands). Worth a mention as prior art for the per-action-consent
UX, not because it overlaps functionally.

### doas

[doas(1) on OpenBSD](https://man.openbsd.org/doas) — minimalist
`sudo` alternative from OpenBSD, also packaged on Linux. Same
layer as `sudo` (privilege escalation primitive), simpler config,
no AI integration. sudo-proxy could in principle call `doas`
instead of `sudo`, but nothing about `doas` displaces sudo-proxy's
role.
