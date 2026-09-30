# Reviewing sudo-proxy

A 15-minute on-ramp for security reviewers. sudo-proxy grants an LLM agent a
path to `root`, so it deserves hostile scrutiny. This document is written to
make that scrutiny cheap: here is the exact claim, here is the small amount of
code that has to hold it up, and — most importantly — here is where we have
**no** assurance and would most like you to look.

If you find a way to break any numbered claim below, that is a security finding;
see [SECURITY.md](SECURITY.md) for where to send it.

## The claims

The privileged surface reduces to a single invariant (**G1**):

> **Nothing privileged runs without a human deliberately approving the exact
> command shown.**

A second invariant (**G7**) guards the *unprivileged* surface — the part that
was historically weaker than the agent's own Bash tool:

> **No unprivileged command runs with less human scrutiny than the agent's Bash
> tool would apply: every unprivileged command faces a live human gate unless an
> operator has *out-of-band* made its host eligible AND a human gave a
> *session-scoped* confirmation; and a self/loopback target cannot route around
> that gate by naming an alias of "localhost".**

We would rather you try to falsify these than "review the project." Below they
are broken into concrete, falsifiable sub-claims (C1–C7 for G1, C8–C10 for G7).

## Falsify one of these

Each item is a specific claim with the file to attack. Breaking any one is a
finding.

- **C1 — Displayed = executed.** The command that runs is byte-identical to the
  `argv` shown at the approval prompt. Commands are run via
  `Command::new(argv[0]).args(…)` — never `sh -c` — so there is no second round
  of shell parsing. *Attack:* find any input where the executed bytes differ
  from the displayed bytes. → `src/executor.rs` (`exec_pkexec`/`exec_sudo`/
  `exec_direct`), `src/tui.rs` (`prompt_tty`).
- **C2 — No exec without a keypress.** No privileged command runs without an
  interactive single keypress on `/dev/tty`; the prompt is default-**deny** on a
  60 s timeout. *Attack:* reach `exec_*` for a `privileged` request without a
  keypress. → `src/tui.rs` (`classify_key`, `tui.rs:130`), `src/server.rs`
  (`handle_connection`, `server.rs:422`).
- **C3 — No approval reuse.** An approval cannot be replayed. Request UUIDs are
  deduplicated and every request must carry a `time` within 60 s. *Attack:*
  cause the same approval to authorise two executions, or make a stale request
  pass. → `src/server.rs` (`check_freshness` `:58`, `try_insert` `:213`).
- **C4 — Unattended mode can't be enabled from the wire.** A daemon becomes
  eligible for unattended unprivileged execution *only* via an out-of-band edit
  of `hosts.json` (`policy.unattended_eligible`), which is read once at startup
  and never mutated at runtime; and the session grant flips *only* on an
  interactive `a` keypress, and *only* when eligible. No request field, MCP tool
  flag, or replay can enable either barrier. *Attack:* enable unattended mode, or
  flip the session grant, from the wire. → `src/hosts.rs` (`Policy`),
  `src/tui.rs` (`classify_key`), `src/server.rs` (dispatch).
- **C5 — No stored credential.** sudo-proxy never stores or caches a secret;
  authentication is owned entirely by `sudo`/`pkexec`. *Attack:* find any path
  where sudo-proxy holds, caches, or replays a credential. → `src/executor.rs`.
- **C6 — Display fields can't lie.** Fields shown at the prompt are rejected if
  they contain control (0x00–0x1F bar tab), zero-width (U+200B–U+200F), or bidi
  override (U+202A–U+202E, U+2066–U+2069) characters, so shown text cannot be
  made to diverge from real `argv` via those classes. *Attack:* get a
  divergence-causing character past the scanner to the prompt. →
  `src/protocol.rs` (`ValidatedRequest::validate`, `:172`), `has_dangerous_chars`.
- **C7 — Same-UID caller still gated.** A same-UID local process (adversary A2)
  can connect straight to the `0600` socket, bypassing the MCP layer — and still
  cannot execute without the keypress. *Attack:* execute via the raw socket
  without approval. → `src/server.rs` (`peer_uid`/`SO_PEERCRED` `:244`,
  `handle_connection`).

The G7 sub-claims (unprivileged surface):

- **C8 — No unattended unprivileged exec except behind two human acts; the grant
  never persists.** No unprivileged command reaches `exec_direct` without a
  per-command keypress *unless* (a) its daemon is `unattended_eligible` (barrier
  1, config-only) *and* (b) a human answered `a` this session (barrier 2). The
  grant lives only in memory, is never written to `hosts.json`, and dies with the
  daemon/tunnel. *Attack:* reach `exec_direct` unattended on a non-eligible
  daemon; make an `a` press grant a session without eligibility; make the grant
  survive a session/tunnel boundary or a restart; or make a stale
  `confirm_unprivileged` key re-enable it. → `src/server.rs` (dispatch),
  `src/hosts.rs` (`Policy`, migration), `tests/approval.rs`.
- **C9 — Self/loopback can't dodge local policy.** A request naming any loopback
  alias of the daemon's own machine (`localhost`, `127.0.0.0/8`, `::1`,
  `localhost.`, the machine's own hostname) routes to the *local* path, not an
  SSH tunnel, and a local unprivileged command is refused (delegated to the Bash
  tool). *Attack:* make `execute(host="127.0.0.1")` (or `::1`, or the own
  hostname) open an SSH-to-self tunnel, or slip a local unprivileged command past
  the Bash-delegation refusal. → `src/server.rs` (`is_local_host`), `src/mcp.rs`
  (`normalize_host`, `execute`).
- **C10 — Backstop composition (soundness).** `is_local_host` is best-effort, so
  an *undetectable* self-alias (ssh-config alias, NAT hairpin) may still route
  SSH-to-self. That cannot yield unattended exec, because C8 holds on *every*
  daemon: the tunnel lands on a daemon whose only unattended path is the
  eligible + session-confirmed grant. *Attack:* find a host string that is really
  the local box, escapes C9, *and* runs unprivileged unattended. → composition of
  `src/mcp.rs` routing and `src/server.rs` dispatch.

## The trust boundary (what to actually read)

The security-critical path is four files; almost everything else (the MCP
surface in `src/mcp.rs`, host bookkeeping in `src/hosts.rs`, the GUI fallback,
CLI parsing) is plumbing you can skim.

| File | Read | Why it's in the boundary |
|------|------|--------------------------|
| `src/server.rs` | `handle_connection` (`:422`) and the gate chain it calls: `peer_uid` (`:244`), `ValidatedRequest::validate` (`:480`), `check_freshness` (`:505`), `try_insert` (`:530`) | The whole request lifecycle and every gate |
| `src/protocol.rs` | `ValidatedRequest::validate` (`:172`) | The one validation boundary; a typestate makes reaching dispatch unvalidated a compile error |
| `src/tui.rs` | `classify_key` (`:130`), `prompt_tty` (`:140`) | The human gate: what is displayed, and how a keypress becomes approval |
| `src/executor.rs` | `exec_pkexec` (`:138`), `exec_sudo` (`:171`), `exec_direct` (`:184`) | What actually runs, and the environment/isolation applied |

If you read only one function, read `handle_connection` — it is the linear
sequence of gates from "bytes arrive on the socket" to "a keypress authorises
exec," and each claim above maps to one step in it.

## Where we have NO assurance — please start here

We have a threat model, static-analysis gating, property tests, Kani bounded
proofs, and TLA+/ProVerif models (see
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)). That is more
than most projects — and it can read as "already solved." It is not. Here is
what carries **no proof**, roughly in order of how much it worries us:

1. **The TUI rendering layer.** `has_dangerous_chars` blocks control, bidi, and
   zero-width characters — but it does **not** prove that what a real terminal
   *renders* matches the `argv` that will execute. Ambiguous- or full-width
   glyphs, combining marks, right-to-left scripts within *allowed* ranges,
   line-wrapping, and terminal-specific escape handling could all let displayed
   text diverge from executed text. This is the softest spot and the one we most
   want broken. → `src/tui.rs`.
2. **Human comprehension.** The gate is only as strong as the operator actually
   reading the command. A long, plausible-looking but hostile `argv` that a
   human approves at a glance defeats the whole design, and nothing in the code
   can prevent it. UX proposals welcome.
3. **SSH first contact.** The `ssh` invocation sets no `StrictHostKeyChecking`;
   a first-contact MITM is an *accepted, characterised* residual (see the
   ProVerif model). `known_hosts` must be pre-populated before first use. →
   `src/executor.rs` SSH path, `docs/threat-model.md`.
4. **The handoff to `sudo`/`pkexec`, `/dev/tty`, and the kernel.** These are
   trusted by assumption (the honest boundary of any such tool). We verify the
   daemon's own logic, not the things it hands off to.
5. **`base64` / `serde_json` decoding.** Panic-freedom of the decode paths rests
   on the upstream crates' `Result`-returning APIs and our `.unwrap()`-free call
   sites — an assumption, not a proof.
6. **The unattended window on an eligible daemon.** The old persisted, global
   auto-approve (finding F2) is gone. What remains is bounded: on a daemon an
   operator has *deliberately* made `unattended_eligible`, one `a` keypress opens
   a session-scoped, non-persistent window in which unprivileged commands run
   with only an audit-log line. Inside that window the gate is the operator's
   two prior decisions (the config edit and the `a` press) plus the audit log —
   there is no per-command human check. We judge this at Bash parity (a Bash
   allow-rule is a similar, and less bounded, operator opt-in), but the window is
   real: an operator who enables eligibility and presses `a` on a hostile-looking
   command is not protected by the code. → `src/server.rs` dispatch, finding F2
   in `docs/security-audit.md`.

## Run it in a container

To poke at it without installing a sudo-adjacent daemon on your own machine:

```sh
docker run --rm -it rust:1-bookworm bash -c '
  git clone https://github.com/tarides/sudo-proxy && cd sudo-proxy &&
  cargo build --release &&
  echo "binaries in target/release: sudo-proxy, sudo-proxy-mcp, sudo-request, pkexec-cache"'
```

Inside the container there is no `pkexec`/`sudo` password prompt to satisfy, so
use the direct/non-privileged path to exercise the protocol and the TUI without
real escalation. See [docs/usage.md](docs/usage.md) for flags and
[docs/protocol.md](docs/protocol.md) for the wire format you can drive by hand.

## Status

sudo-proxy has **not** yet had an independent third-party security review. The
assurance above is self-produced. If you are interested in doing — or funding —
such a review, please reach out via [SECURITY.md](SECURITY.md).
