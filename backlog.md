# Backlog

Ordered; the first item is the current/next task. One item per session — capture
unrelated ideas at the end, don't chase them mid-session. Items below continue
the assurance ladder defined in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md); each names its
rung.

## Extended Rung 4 — Concurrent-handler interleaving (TLA+)

The shipped state-machine model handles one request to completion atomically, so
the concurrent dedup TOCTOU (which `SeenIds::try_insert`'s single critical
section closes) and the TTY-lock serialisation are out of scope. Model 2+ daemon
handlers interleaving on the shared `seen` set and the TTY lock, and check that
no double-exec slips through the race and dedup stays correct under all
interleavings — i.e. *verify* the atomicity fix is sufficient. This is the
canonical model-checking use case; the current one-at-a-time model cannot see it.

## Extended Rung 4 — SSH key-acceptance model (ProVerif)

The shipped `proofs/proverif/` model *declares* the tunnel private when pinned
(channel-toggle), so it assumes rather than derives the MITM. Replace with the
key-acceptance encoding: give the remote a host keypair, have the local daemon
accept a key (pinned ⇒ only the honest key; unpinned ⇒ whatever arrives), and
encrypt the request to the accepted key. ProVerif then *derives* the first-
contact MITM from the attacker substituting its key, showing *why* pinning
matters rather than *that* we assumed it — strengthening the model's whole point
(make A4 load-bearing). Nice-to-have, not essential.

## Cap far-future request timestamps (replay-protection gap)

Surfaced by the Extended Rung 4 `ReplayWindow` TLA+ model. `parse_age`
(`server.rs:146`) clamps a future-dated timestamp to age 0 with **no upper
bound**, so a request dated beyond `REPLAY_RETENTION` into the future passes the
freshness gate indefinitely while its id ages out of `SeenIds` — making it
replayable every retention window *regardless of how large retention is*. The
60s↔120s window relationship does not help here. Low severity (needs the request
onto the channel — SSH pinning guards that — and privileged commands still gate
the first run on a keypress), but for auto-approved unprivileged commands it is a
real repeatable replay. Fix: in `check_freshness` / `parse_age`, reject
timestamps more than a small clock-skew allowance into the future instead of
clamping to age 0; extend the Rung 2 freshness property and the `ReplayWindow`
model's `NoFutureReplay` invariant to cover it.

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
