# Reviewing sudo-proxy

A 15-minute on-ramp for security reviewers. sudo-proxy grants an LLM agent a
path to `root`, so it deserves hostile scrutiny. This document is written to
make that scrutiny cheap: here is the exact claim, here is the small amount of
code that has to hold it up, and — most importantly — here is where we have
**no** assurance and would most like you to look.

If you find a way to break any numbered claim below, that is a security finding;
see [SECURITY.md](SECURITY.md) for where to send it.

## The one claim

Everything reduces to a single invariant:

> **Nothing privileged runs without a human deliberately approving the exact
> command shown.**

We would rather you try to falsify that than "review the project." Below it is
broken into concrete, falsifiable sub-claims.

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
- **C4 — Policy flips only on a keypress.** The `confirm_unprivileged` policy
  flag can be changed *only* by an interactive keypress — never by a request
  field, MCP tool flag, or replay. *Attack:* flip it from the wire. →
  `src/tui.rs` (`classify_key`), `src/server.rs`.
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
6. **Auto-approve, if ever enabled.** The "remember this command" surface (audit
   finding F2) is off by design; the moment it exists, prefix-matching escapes
   become live. → `docs/architecture.md` allowlisting note.

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
