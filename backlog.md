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

---

## Rung 6 — seL4-style end-to-end refinement (aspirational)

Long-horizon: prove the daemon's logic refines an abstract approval spec, with
trust assumptions (`/dev/tty`, `sudo`, kernel, SSH) stated explicitly as the
boundary of the proof. Value even unrealised: forces a complete enumeration of
what is trusted-by-assumption.
