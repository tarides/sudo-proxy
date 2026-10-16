# Backlog

Ordered; the first item is the current/next task. One item per session — capture
unrelated ideas at the end, don't chase them mid-session. Items below continue
the assurance ladder defined in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md); each names its
rung.

## Cap far-future request timestamps, then re-climb the ladder to Rung 4

The replay-protection residual surfaced **during PR #35** by the Extended Rung 4
`ReplayWindow` TLA+ model (its `NoFutureReplay` invariant exhibits a concrete
trace). `parse_age` (`server.rs:146`) clamps a future-dated timestamp to age 0
with **no upper bound**, so a request dated beyond `REPLAY_RETENTION` into the
future passes the freshness gate indefinitely while its id ages out of
`SeenIds` — making it replayable every retention window *regardless of how large
retention is*. The 60s↔120s window relationship does not help here. Low severity
(needs the request onto the channel — SSH pinning guards that — and privileged
commands still gate the first run on a keypress), but for auto-approved
unprivileged commands it is a real repeatable replay.

**The fix.** In `check_freshness` / `parse_age`, reject timestamps more than a
small clock-skew allowance into the future instead of clamping to age 0.

**Re-climb the ladder to the same level (Rung 4).** The fix touches code that
several already-discharged rungs cover, so re-establish each so assurance
returns to where PR #35 left it — do *not* leave the proofs trailing the code:

- **Rung 1 (CI):** the existing gate should stay green; add a regression test
  for the rejected far-future timestamp.
- **Rung 2 (property):** extend the freshness property in `src/prop.rs` so it
  asserts a sufficiently-future timestamp is *rejected*, not silently fresh.
- **Rung 3 (Kani):** re-drive the `ymd_hms_to_epoch` monotonicity/totality
  proofs against the new gate (the bounded-future rejection must stay
  panic-free over the full domain).
- **Rung 4 (TLA+):** flip the `ReplayWindow` model's `NoFutureReplay` from a
  surfaced-gap witness to a *held* invariant, and re-check the sibling models
  are unaffected.

Done = the code rejects far-future timestamps **and** every rung above is
re-discharged against the fixed code (negative controls re-run where they
exist).

## Rung 5 — Deductive verification of the trusted core

Creusot / Verus / Prusti contracts on `validate_request`, the dispatch path, and
the env-allowlist enforcement, proved against the Rung 2 properties. Scope to the
smallest trusted core, not the whole tree.

## Write the CC-structured Security Target document

The remaining Rung 0 / paper step: a Common Criteria Security Target (TOE,
threats, assumptions, SFRs, SARs) consolidating `security.md` / `security-audit.md`
/ `threat-model.md` / `assurance-case.md` into the standard ST structure.

## Stabilize the flaky S2 resource-cap test

`tests/concurrency.rs:burst_connections_above_cap_get_busy_response` fails ~2/3
locally — the *setup* assertion ("in_flight reached ≥4") is timing-flaky, not the
security assertion. Stabilize so the in-flight cap stays covered by CI.

## Make the post-trust banner reliable (F2)

When `confirm_unprivileged=false`, `display_banner` is printed under a `try_lock`
and may be dropped under TTY contention, so silent execution can be invisible.
Make the banner reliable and state the residual risk plainly at the `a`-key
prompt and in the README.

## Re-evaluate the RUSTSEC-2026-0189 ignore if an HTTP transport is added

`deny.toml` and the `cargo audit` step ignore RUSTSEC-2026-0189 (DNS rebinding
in rmcp's Streamable HTTP server transport) because sudo-proxy enables only
rmcp's `transport-io` feature and serves over stdio, so the vulnerable code is
not compiled in. If an HTTP/streamable-http transport is ever added, drop the
ignore and require a patched rmcp instead. Captured follow-up, not active work.

## Submit the plugin to the claude-plugins-community directory

Optional discoverability step, added after the plugin packaging landed (PR #53).
The decentralized flow (`/plugin marketplace add tarides/sudo-proxy` →
`/plugin install sudo-proxy@tarides`) already works with no registration; this
would additionally list sudo-proxy in Anthropic's curated community marketplace.
Submit via the in-app form (claude.ai admin directory, or the Console plugin
submission page). Expect **extra security scrutiny** because the plugin executes
`sudo` — link the threat model, security audit, and the "no auto-approve"
non-features from the plugin README so reviewers find them. Captured follow-up,
not active work.

## Emit audit records to the system logger (syslog / journald)

Today there is **no durable record of requests**. The daemon writes audit lines
only to its own stderr — the per-command line (`[id] [priv] [client] <pipeline>`,
`server.rs:640`) solely under `--verbose`, and the unconditional `[unattended]`
line (`server.rs:687`) only while a session `a`-grant is active. Both land in the
terminal window's scrollback and vanish with it; nothing is written to disk, the
systemd journal, or any audit facility. For a tool whose whole purpose is gating
privileged execution, the absence of a tamper-evident, admin-controlled trail is
a gap.

**The fix.** Emit a structured audit record for every request — approved, denied,
timed out, unattended — to the **system logger** (`syslog`/journald via `libc`
`openlog`/`syslog`, or the `systemd` journal API under a feature flag), not a
self-managed file. System-level is the point: records then inherit the host's
journald rotation, retention, access control, and optional forwarding/sealing,
and survive the terminal window closing. Record at least: request id, host,
privileged flag, client version, the pipeline (argv), decision, and the
decision path (prompted / unattended-grant / pkexec). Keep stderr lines as-is
for live visibility. Decide the default (log-to-syslog on by default vs opt-in
via a flag) and document the privacy/retention implications in the README.
Captured follow-up, not active work.

---

## Rung 6 — seL4-style end-to-end refinement (aspirational)

Long-horizon: prove the daemon's logic refines an abstract approval spec, with
trust assumptions (`/dev/tty`, `sudo`, kernel, SSH) stated explicitly as the
boundary of the proof. Value even unrealised: forces a complete enumeration of
what is trusted-by-assumption.
