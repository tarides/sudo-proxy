# Threat model

[← README](../README.md) · see also [security-audit.md](security-audit.md) · [assurance-case.md](assurance-case.md) · [formalisation-roadmap.md](formalisation-roadmap.md)

This is the structured threat enumeration for sudo-proxy — **Rung 0** of the
[formalisation roadmap](formalisation-roadmap.md#the-rigor-ladder). It does two
things the prose audit did not: a **STRIDE pass per trust boundary**, and an
**attack tree** whose root is the negation of the security invariant. Every leaf
is cross-referenced to the sub-goal in [assurance-case.md](assurance-case.md)
that discharges it and to the relevant audit finding, so the threat side and the
assurance side stay traceable to each other.

## Scope

The invariant under attack is **G1**:

> Nothing privileged runs without a human deliberately approving the exact
> command shown.

The Target of Evaluation, the three adversaries (**A1** prompt-injected MCP
caller, **A2** same-UID local process, **A3** network MITM / malicious remote),
and the trust assumptions (**A1–A4** in the assurance case) are defined in
[security-audit.md](security-audit.md#threat-model) and
[assurance-case.md](assurance-case.md). They are not restated here; this
document classifies *how* those adversaries act at each boundary.

## Trust boundaries

The data-flow boundaries an attacker's input crosses on the way to root
execution:

| ID | Boundary | Primary adversary |
|----|----------|-------------------|
| **B1** | model → `sudo-proxy-mcp` (MCP stdio) | A1 |
| **B2** | MCP server / direct client → Unix socket → daemon | A2 |
| **B3** | daemon → `/dev/tty` → human (display + keypress) | A1 (content), A2 |
| **B4** | daemon → `sudo` / `pkexec` / exec → root | A1 |
| **B5** | local daemon → SSH tunnel → remote daemon | A3 |
| **B6** | daemon ↔ `hosts.json` / policy persistence | A2 |

## STRIDE per boundary

For each boundary, the STRIDE categories that bear on the invariant, the
concrete threat, the existing control, and the cross-reference
(G-node in [assurance-case.md](assurance-case.md); finding in
[security-audit.md](security-audit.md)). Categories that do not threaten the
invariant at a given boundary are omitted.

### B1 — MCP caller → server (A1)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | Caller identity is unauthenticated. | By design any caller is treated as adversarial; safety does not depend on caller identity — the human gate does. | G5, G6.1 |
| Tampering | Crafted `argv`/`env`/`description` misrepresents intent. | argv/env validation; `description`→`reason` sanitized at the daemon. | G3.3, G4.1 / F1 |
| Repudiation | No per-request record of what was approved. | Server `-v` request log (audit-log-to-file not yet implemented). | — (gap) |
| DoS | Oversized / flooding requests block the gate. | 1 MiB request cap, 64 in-flight cap. | G6.4 |
| Elevation | Obtain root without approval. | Unconditional human gate on `privileged:true`. | G5, G6.1 |

### B2 — Unix socket → daemon (A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | A different-UID process connects. | `SO_PEERCRED` check + 0600 socket. | G2.3 |
| Tampering | Direct client sets `host`/`session`/`id`/`version` to inject display content, bypassing client-side `validate_host`. | Display-field sanitization moved into daemon-side `validate_request`. | G4.1, G6.2 / F1 |
| DoS | Replay of a captured request; connection flooding. | UUID dedup; in-flight cap. | G2.1, G6.4 |
| Elevation | Bypass the MCP layer's `validate_host`. | Daemon-side controls do not depend on it. | G6.2 |

### B3 — daemon → TTY → human (A1 content, A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | ANSI / control / bidi sequences forge a benign-looking command in the prompt. | `has_dangerous_chars()` rejects control/zero-width/bidi on every displayed field; resolved absolute path of argv[0] shown with `-> target` on symlinks. | G4.1, G4.2 / F1 |
| Tampering | A huge argument pushes the real command and `[y/N]` off-screen. | Displayed command length bounded with a hidden-bytes marker. | G4.3 / F3 |
| DoS | Operator never answers, leaving the gate open. | 60 s timeout, default **deny**. | G5.2 |
| Elevation | Social-engineer the human into approving. | Covered by G4; residual printable-range look-alikes accepted. | G4.4 (residual) |

### B4 — daemon → exec → root (A1)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Tampering | Executed command differs from the validated/shown argv (shell injection). | No shell on the privileged path; `Command::new(argv[0]).args(…)`. | G3.1 |
| Elevation | Environment-based escalation (`LD_PRELOAD`, `IFS`, `BASH_ENV`); agent-socket abuse. | Hard-reject env allowlist; `privileged + forward_agent` rejected; request `SSH_AUTH_SOCK` rejected. | G3.2 |
| Info disclosure | Child inherits the socket fd or secrets. | Execution isolation: cwd `/`, umask 0077, stdin null, no fd inheritance. | A2 (assumption), G3.x |
| DoS | Runaway child floods output. | 16 MiB per-stream output cap. | G6.4 |

### B5 — SSH tunnel → remote (A3)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | MITM impersonates the remote host on first contact. | SSH host-key / `known_hosts` (assumption A4); **gap:** no `StrictHostKeyChecking` set. | G6.3 (residual A4) |
| Tampering | Channel tampering. | SSH transport integrity (assumption A4). | A4 |
| Elevation | SSH option injection via a crafted `host`. | `validate_host` allowlist `[A-Za-z0-9._@:-]`, rejects leading `-`; host is a trailing positional; remote UID digit-only + length-capped. | G6.3 |
| Info disclosure | Eavesdropping on the tunnel. | SSH transport confidentiality (assumption A4). | A4 |

### B6 — policy / config persistence (A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Tampering | Another user rewrites `hosts.json` to flip `confirm_unprivileged`. | File owned by the user; dir not group/other-writable; after F4 fix 0600/0700. The **privileged** gate is never relaxed by policy regardless. | G5.3 / F4, F2 |
| Info disclosure | World-readable `hosts.json` leaks host inventory, cached UIDs, policy. | After F4 fix: 0600 file / 0700 dir, mirroring the socket-bind umask pattern. | F4 |
| Elevation | Flip the privileged gate via the persisted policy. | Only an interactive keypress writes policy; policy relaxes only the **unprivileged** gate. | G5.1, G5.3 / F2 |

## Attack tree

Root is the negation of G1. Children are OR-decomposed (any one path achieves
the root). Each leaf is annotated with `[control → G-node / finding · status]`.

```
A  A root command runs that the human did NOT approve
│  (= ¬G1)
│
├─ 1  Forge an authentic-looking request that skips approval   (defeat G2 / G5)
│   ├─ 1.1 Replay a previously approved request
│   │        [UUID dedup → G2.1 · blocked]
│   ├─ 1.2 Backdate / forge a fresh timestamp
│   │        [monotone freshness, checked arith → G2.2 · blocked (regr #11/#14)]
│   ├─ 1.3 Connect as a non-owner UID
│   │        [SO_PEERCRED + 0600 → G2.3 · blocked]
│   └─ 1.4 Flip persisted policy to auto-approve a privileged command
│            [privileged gate never relaxed by policy → G5.1/G5.3 / F2
│             · blocked (residual: unprivileged auto-approve, by design)]
│
├─ 2  Make the executed command differ from what was validated  (defeat G3)
│   ├─ 2.1 Shell-metacharacter injection (;, |, &&, $(...))
│   │        [no shell; structured argv → G3.1 · blocked]
│   ├─ 2.2 Environment escalation (LD_PRELOAD / IFS / BASH_ENV)
│   │        [hard-reject env allowlist → G3.2 · blocked]
│   └─ 2.3 Control / zero-width / bidi characters in argv
│            [has_dangerous_chars → G3.3 · blocked]
│
├─ 3  Deceive the human into approving the wrong thing           (defeat G4)
│   ├─ 3.1 ANSI / control / bidi in reason/host/session/id/version
│   │        [daemon-side sanitization of all display fields → G4.1 / F1 · blocked]
│   ├─ 3.2 Symlink redirection of argv[0] (/usr/local/bin/foo -> /tmp/evil)
│   │        [resolved path + "-> target" shown → G4.2 · blocked]
│   ├─ 3.3 Push the real command / [y/N] off-screen with a huge arg
│   │        [length bound + hidden-bytes marker → G4.3 / F3 · blocked]
│   └─ 3.4 Printable-range Unicode look-alike / NBSP in reason
│            [cannot hide the real command → G4.4 · residual (accepted)]
│
└─ 4  Execute around the gate entirely                      (defeat G5 / G6)
    ├─ 4.1 Direct same-UID socket client bypassing MCP validate_host
    │        [validation is daemon-side → G6.2 · blocked]
    ├─ 4.2 SSH option injection / remote impersonation
    │        [validate_host + known_hosts → G6.3
    │         · blocked (residual: first-contact MITM, assumption A4)]
    ├─ 4.3 Exhaust resources to make the gate fail open
    │        [caps + default-deny timeout → G5.2 / G6.4 · blocked]
    └─ 4.4 Tamper hosts.json to weaken the gate
             [file perms / F4; privileged gate independent → G5.3 · blocked
              (residual: unprivileged auto-approve, by design)]
```

## Coverage and residuals

Every leaf maps to a sub-goal in [assurance-case.md](assurance-case.md); no leaf
is unaccounted for. The residuals — already on record and accepted — are:

- **1.4 / 4.4 — `confirm_unprivileged` (F2).** Once a human presses `a`, later
  *unprivileged* commands run without a prompt. The **privileged** gate is never
  affected. By-design trade-off; see
  [security-audit.md](security-audit.md) finding F2.
- **3.4 — look-alike `reason` (F1 residual).** Printable Unicode can mislead but
  cannot conceal the real command line, which is printed separately.
- **4.2 — SSH first-contact MITM (assumption A4).** The ssh invocation sets no
  `StrictHostKeyChecking`; safety depends on the remote being in `known_hosts`
  first, or configuring `StrictHostKeyChecking=accept-new`.
- **B1 Repudiation gap.** There is no audit-log-to-file yet (listed under "Not
  yet implemented" in [architecture.md](architecture.md)); the `-v` server log
  is the only record.

These residuals are the natural inputs to the higher
[roadmap rungs](formalisation-roadmap.md#the-rigor-ladder): the policy-transition
residual (1.4/4.4) is what a TLA+/Alloy model (Rung 4) would pin down, and the
SSH residual (4.2) is what a Tamarin/ProVerif model (Rung 4) would make explicit.
