# Security assurance case

[← README](../README.md) · see also [formalisation-roadmap.md](formalisation-roadmap.md) · [threat-model.md](threat-model.md) · [security.md](security.md) · [security-audit.md](security-audit.md)

> The G2–G6 sub-goals below are the assurance (defence) side of the argument.
> Their threat-side counterpart — a STRIDE-per-boundary pass and an attack tree
> rooted at ¬G1, with every leaf cross-referenced back to these G-nodes — is in
> [threat-model.md](threat-model.md) (Rung 0).

This is a **security assurance case** for sudo-proxy, written in
[Goal Structuring Notation (GSN)](https://etn-sas.eu/2020/06/26/assurance-case-notations/).
It states one top-level claim, decomposes it into sub-claims by adversary and by
control, and attaches to each leaf the *evidence* that currently discharges it —
together with the [roadmap rung](formalisation-roadmap.md#the-rigor-ladder) at
which that evidence sits. As evidence strengthens (a leaf moving from "fuzz
test" to "machine-checked proof") the argument structure is unchanged; only the
**Solution** nodes are upgraded.

## Notation

GSN node kinds used here:

- **G** — *Goal*: a claim to be established.
- **S** — *Strategy*: the reasoning step linking a goal to its sub-goals.
- **C** — *Context*: a definition or scope statement.
- **A** — *Assumption*: a statement taken as true without proof (a trust
  boundary of the argument).
- **J** — *Justification*: rationale for a strategy.
- **Sn** — *Solution*: a reference to evidence.

Solution nodes carry a status: **[discharged]** (evidence exists today),
**[partial]** (some evidence, strengthening planned), **[planned]** (claim
asserted, evidence not yet produced).

## Top-level claim

> **G1 — Nothing privileged runs without a human deliberately approving the
> exact command shown.**

```
                                  ┌──────────────────────────────────────┐
   C1 TOE: daemon + MCP server    │  G1  No privileged execution without  │
   + SSH-tunnel path  ───────────▶│      deliberate human approval of     │◀── J1 Single invariant;
                                   │      the exact command shown          │      every control serves it
   A1..A4 trust assumptions ─────▶└──────────────────────────────────────┘
                                                   │
                                          ┌────────┴ S1: argue over the path
                                          │   from request to root execution
        ┌──────────────┬─────────────────┼──────────────────┬─────────────────┐
        ▼              ▼                  ▼                  ▼                 ▼
      G2             G3                 G4                 G5                G6
  Authenticity   Integrity of      Faithful display   Approval is        Adversary
  of requests    what is run       at the gate        necessary &        cannot bypass
  (no replay,    (no injection,    (TUI shows the     binding           the gate
  fresh, right   no shell, env     real command)      (privileged ⇒     (A1/A2/A3
  peer)          sanitized)                            keypress)         coverage)
```

## Context, assumptions, justification

| Node | Kind | Statement |
|------|------|-----------|
| **C1** | Context | The Target of Evaluation is the `sudo-proxy` daemon, the `sudo-proxy-mcp` server, and the `--host` SSH-tunnel path. Out of scope: the AI model, the operator's judgement when reading the prompt. |
| **C2** | Context | Adversaries: **A1** prompt-injected MCP caller; **A2** same-UID local process (direct socket); **A3** network MITM / malicious remote. (See [security-audit.md](security-audit.md#threat-model).) |
| **A1** | Assumption | `/dev/tty` is trusted: what the daemon writes is what the human sees, and the keypress read is the human's. |
| **A2** | Assumption | `sudo` (and `pkexec`) correctly enforce escalation and `env_reset`; the kernel enforces socket permissions and `SO_PEERCRED`. |
| **A3** | Assumption | The host is effectively single-user *or* the operator accepts that any same-UID process is already inside the trust boundary for non-privileged actions (finding F2). |
| **A4** | Assumption | For the SSH path, remote hosts are in `known_hosts` before first use (or `StrictHostKeyChecking=accept-new` is configured) — this gives payload confidentiality and lets the daemon reach the genuine remote; **and** the daemon authenticates to the remote by key (the remote's `authorized_keys`), which gives command authenticity at the remote. The ProVerif model ([`proofs/proverif/`](../proofs/proverif/)) makes both halves explicit and shows which guarantee rests on which. |
| **J1** | Justification | The whole security model reduces to G1 (see [security-audit.md](security-audit.md#summary)); structuring the argument around the single invariant keeps every control traceable to it. |
| **S1** | Strategy | Argue over the causal path from an inbound request to root execution: a request must be *authentic* (G2), what executes must be *the thing that was validated* (G3), the human must *see the real command* (G4), approval must be *necessary and binding* (G5), and no adversary may *bypass* the gate (G6). |

## Sub-goals and evidence

### G2 — Authenticity of requests

*Only fresh, non-replayed requests from the authorised peer are accepted.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G2.1** | Replayed request UUIDs are rejected. `SeenIds` check-and-insert is atomic. | — | |
| **Sn2.1** | `src/server.rs` dedup set; regression test in suite. | 1–2 | [discharged] |
| **G2.2** | Stale requests are rejected; freshness is monotone (no integer-wrap bypass, regressions #11/#14). | — | |
| **Sn2.2** | `parse_age` fuzzed with 20000 random + extreme inputs (`server::tests::fuzz_parse_age_*`); `checked_*` arithmetic throughout. | 2 | [partial] → Kani bounded proof (Rung 3) |
| **G2.3** | The connecting peer is the daemon UID. | — | |
| **Sn2.3** | `SO_PEERCRED` on the accepted connection; cross-UID rejected; 0600 socket via umask-around-bind + chmod (no TOCTOU). `src/server.rs`. | 1 | [discharged] |

### G3 — Integrity of what is run

*The command that executes is exactly the validated argv, with no injection and
a sanitized environment.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G3.1** | No shell is invoked on the privileged path; metacharacters cannot inject. | — | |
| **Sn3.1** | `Command::new(argv[0]).args(…)`, never `sh -c` (`src/executor.rs`); the multi-stage `shell_escape` fuzzed with 5000 inputs, round-tripped through `/bin/sh` byte-for-byte. | 2 | [partial] → Flux boundary type (Rung 3) |
| **G3.2** | The environment is a hard-reject allowlist; `LD_PRELOAD`/`LD_*`/`IFS`/`BASH_ENV`/`SSH_AUTH_SOCK` are rejected, not stripped. | — | |
| **Sn3.2** | `src/executor.rs` env sanitization; login defaults from `getpwuid(geteuid())`, not the request. | 1–2 | [discharged] |
| **G3.3** | Inputs carrying control / zero-width / bidi characters are rejected before use. | — | |
| **Sn3.3** | `has_dangerous_chars()` over every `pipeline` arg and `env` key/value; `tests/validation.rs`. | 2 | [discharged] |

### G4 — Faithful display at the gate

*The TUI shows the operator the real command and nothing that misrepresents it.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G4.1** | No request field rendered to `/dev/tty` can inject ANSI / control / bidi sequences. | — | |
| **Sn4.1** | After **F1** fix: `has_dangerous_chars()` is applied to `reason`, `session`, `host`, `version`, `id` in `validate_request`, covering both MCP and direct-socket paths; regression test. | 2 | [discharged] |
| **G4.2** | The resolved absolute path of argv[0] is shown, with `-> target` when it is a symlink, so redirection cannot be hidden. | — | |
| **Sn4.2** | `src/tui.rs` path canonicalisation + explicit failure message. | 1 | [discharged] |
| **G4.3** | A large command cannot push the real command or the `[y/N]` line off-screen. | — | |
| **Sn4.3** | After **F3** fix: displayed command length is bounded with an explicit hidden-bytes marker. | 1 | [discharged] |
| **G4.4** | Residual: printable-range Unicode look-alikes / NBSP in `reason` (passive, cannot hide the real command). | — | |
| **Sn4.4** | Documented residual in [security-audit.md](security-audit.md) (F1). | 0 | [accepted-risk] |

### G5 — Approval is necessary and binding

*A privileged command executes only after an interactive keypress, and the
keypress binds to the command shown.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G5.1** | `privileged:true` always reaches the Y/N gate regardless of any policy. | — | |
| **Sn5.1** | TLC-checked: the `PolicyFlipsOnlyOnKeypress` invariant of [`proofs/tla/`](../proofs/tla/) proves the policy flag flips only via an interactive `a` keypress on an unprivileged request — never a request field, replay, MCP flag, or timeout — over all attacker forgeries/replays and operator choices. `src/server.rs`. | 4 | [discharged] (model-checked) |
| **G5.2** | The prompt reads a single keypress in non-canonical mode and times out after 60 s (default **deny**). | — | |
| **Sn5.2** | `src/tui.rs` prompt; timeout test. | 1 | [discharged] |
| **G5.3** | The `confirm_unprivileged=false` policy relaxes only the **non-privileged** gate, never the privileged one, and only via an interactive `a` keypress. | — | |
| **Sn5.3** | TLC-checked: `NoExecWithoutApproval` + `PrivilegedGateIndependentOfPolicy` ([`proofs/tla/`](../proofs/tla/)) prove the privileged gate requires a `y` keypress for *any* value the policy flag took, so `confirm_unprivileged` relaxes only the non-privileged gate. Audit finding **F2** by-design trade-off still documented; `display_banner` reliability is a separate backlog item. | 4 | [discharged] (model-checked) |

### G6 — Adversary cannot bypass the gate

*Each named adversary is covered; no path reaches root execution around G2–G5.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G6.1** | **A1** (MCP caller): all attacker-controlled fields are validated; structured argv (never a shell string); HITL gate is unconditional for privileged. | — | |
| **Sn6.1** | OWASP MCP HITL + structured-invocation controls realised; `tests/validation.rs`, F1 fix. | 0–2 | [partial] |
| **G6.2** | **A2** (same-UID direct socket): daemon-side validation does not depend on client-side `validate_host`; display fields validated at the daemon. | — | |
| **Sn6.2** | F1 fix moves sanitization into `validate_request` (daemon side); `SO_PEERCRED` + 0600. | 2 | [discharged] |
| **G6.3** | **A3** (network / remote): `validate_host` allowlist `[A-Za-z0-9._@:-]`, rejects leading `-` (ssh option injection); host is a trailing positional; remote UID digit-only + length-capped; ssh via argv. | — | |
| **Sn6.3** | `src/server.rs`, `src/bin/sudo-proxy.rs`, `src/hosts.rs`. ProVerif model ([`proofs/proverif/`](../proofs/proverif/)) makes **A4 explicit** by modelling the real host-key + client-key material: it **derives** the first-contact MITM from host-key substitution (payload secrecy `false` unpinned — leaf 4.2), and disentangles confidentiality (rides on host-key pinning) from command authenticity (rides on client auth, so it holds even on first contact); the separation theorem shows a channel compromise does not bypass the local keypress gate. Residual A4 (no `StrictHostKeyChecking`) now formally characterised, not closed. | 4 | [discharged] (residual A4 made explicit) |
| **G6.4** | Resource exhaustion cannot force-open the gate: 1 MiB request cap, 64 in-flight, 16 MiB output cap. | — | |
| **Sn6.4** | `src/server.rs`, `src/executor.rs`; cap test (flaky **S2**, control sound). | 1–2 | [partial] |

## Open items tracked against the case

These are the leaves where the argument is currently weakest, drawn from
[security-audit.md](security-audit.md) and the rungs not yet climbed:

- **Sn2.2** — the freshness arithmetic is discharged by **Kani** (Rung 3);
  `Sn5.1 / Sn5.3` (the approval + policy transitions) are now discharged by the
  **TLC-checked** state machine ([`proofs/tla/`](../proofs/tla/), Rung 4).
- **Sn6.3** — the A3 channel guarantees rest on assumption **A4**; the
  **ProVerif** model ([`proofs/proverif/`](../proofs/proverif/), Rung 4) now
  makes that dependency explicit by *deriving* the first-contact MITM from
  host-key substitution (a *characterised residual*, not a closed one — see leaf
  4.2), and attributes confidentiality to host-key pinning vs command
  authenticity to client auth.
- **Sn6.4 / S2** — stabilise the flaky resource-cap test so the cap stays
  covered in CI.
- **Sn4.4 / Sn5.3** — accepted residual risks (look-alike `reason`, the
  `confirm_unprivileged` trade-off); revisit if an auto-approve surface is ever
  added (see the [allowlisting note](architecture.md#design-note-allowlisting-when-it-lands)).

## How to use this document

1. When a control changes, update the corresponding **Solution** node and its
   status — not the goal structure.
2. When climbing a [roadmap rung](formalisation-roadmap.md), the deliverable is
   a stronger Solution node here (e.g. a Kani proof replacing a fuzz test under
   Sn2.2), with the Rung column bumped.
3. When adding a feature that introduces a new path to execution (notably any
   auto-approve / allowlist surface), add the sub-goals it must satisfy under
   G5/G6 *before* merging, so the case never silently develops a gap.
