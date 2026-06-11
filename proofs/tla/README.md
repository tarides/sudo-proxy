# Rung 4 — TLA+/PlusCal models

[← formalisation roadmap](../../docs/formalisation-roadmap.md) · [threat model](../../docs/threat-model.md) · [assurance case](../../docs/assurance-case.md)

This directory holds **three** TLA+/PlusCal models, all model-checked by TLC:

1. **`ApprovalStateMachine`** (below) — the approval state machine: the four
   safety properties of the gate chain and `classify_key`.
2. **[`ReplayWindow`](#window-sizing--freshness--replay-retention) (Extended Rung 4)** —
   the temporal freshness ↔ replay-retention **window-sizing** property that the
   first model deliberately abstracts away (it never evicts). Restores a small
   concrete clock + real TTL eviction and proves the genuinely temporal claim.
3. **[`ConcurrentHandlers`](#concurrent-handlers--dedup-toctou--tty-lock-serialisation) (Extended Rung 4)** —
   *concurrent* handler threads interleaving on the shared `seen` set and the TTY
   lock. Proves the atomic `try_insert` critical section is *sufficient* (no
   double-exec under any interleaving) and that the TTY lock serialises /dev/tty —
   the canonical model-checking case the two atomic, one-request-at-a-time models
   above cannot express.

---

## Approval state machine

A TLA+/PlusCal model of sudo-proxy's approval state machine, model-checked by
TLC. It discharges **Rung 4** (state-machine half) of the
[formalisation roadmap](../../docs/formalisation-roadmap.md): the temporal /
relational properties that are not per-function and that the Rung 0 threat model
routed here — attack-tree leaves **1.4 / 4.4** (the `confirm_unprivileged`
policy transition, finding **F2**) and the unconditional human gate on
privileged execution.

`ApprovalStateMachine.tla` carries the PlusCal algorithm in a comment block (the
source of truth) followed by the `pcal.trans`-generated TLA+ translation that TLC
checks. `ApprovalStateMachine.cfg` is the bounded model. The Rung 3 Kani sibling
lives in [`src/proofs.rs`](../../src/proofs.rs); this is the protocol-level
analogue.

## The four properties

Tracked by bounded **monitor variables** — a violation flag is raised at the
exact site the bad thing would happen, and the invariant asserts the flag stays
`FALSE`. (This keeps every variable bounded, so the reachable state space is
finite and small with *no* history-length constraint: once `seen` fills, further
requests are rejected as replays and only revisit states.)

| # | Invariant | Claim | Maps to |
|---|-----------|-------|---------|
| **P1** | `NoExecWithoutApproval` | A privileged exec happens only on a `y` keypress — never on timeout, denial, replay, or any policy state. | leaf 1.4 · G5 |
| **P2** | `ReplayImpossible` | The same request id never causes two executions. | leaf 1.1 · G2.1 |
| **P3** | `PolicyFlipsOnlyOnKeypress` (+ action property `FlagMonotone`) | The policy flag flips only via an `a` keypress on an *unprivileged* request — never a request field, replay, MCP flag, or timeout — and once `FALSE` stays `FALSE`. | leaf 1.4 / 4.4 · F2 |
| **P4** | `PrivilegedGateIndependentOfPolicy` | No privileged exec without a `y` keypress, for *any* value the policy flag took. The privileged branch structurally never reads the flag; stated separately for traceability. | leaf 4.4 · G5.1 |

`Classify(k, priv)` in the spec is a direct transcription of
[`tui::classify_key`](../../src/tui.rs); the daemon's gate chain mirrors the
ordering in [`server.rs` `handle_connection`](../../src/server.rs).

## Running TLC

Needs a JRE (21+) and `tla2tools.jar` (pin a release, e.g. `v1.8.0`):

```sh
curl -sSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar

# (only if you edited the PlusCal) re-generate the translation, then commit both:
java -cp tla2tools.jar pcal.trans ApprovalStateMachine.tla

java -cp tla2tools.jar tlc2.TLC -nowarning \
     -config ApprovalStateMachine.cfg -workers auto ApprovalStateMachine.tla
```

Expected: `Model checking completed. No error has been found.` (~9k distinct
states, well under a second). The committed `.tla` already contains the
translation, so CI does not re-run `pcal.trans`.

## Negative controls — that the model has teeth

The analogue of the Kani negative controls: documented mutations that **must**
each make TLC produce a counterexample. Apply by hand to the PlusCal, re-run
`pcal.trans`, re-check, then revert. **Do not commit the mutations.** Each was
verified to violate exactly the listed invariant.

| # | Mutation (in the PlusCal) | Violates |
|---|---------------------------|----------|
| **NC1** | Privileged `Timeout` branch: replace `skip;` with `NoteExec(TRUE);` (exec on timeout). | `NoExecWithoutApproval` |
| **NC2** | Wire the flag into the privileged gate: prepend `if confirmUnpriv then NoteExec(TRUE); elsif …` to the privileged dispatch. | `NoExecWithoutApproval` (= `PrivilegedGateIndependentOfPolicy` — same witness) |
| **NC3** | Remove the dedup gate: change `elsif req.id \in seen then` to `elsif FALSE then`. | `ReplayImpossible` |
| **NC4** | Flip the flag illegitimately: replace the `skip;` in the unprivileged `Timeout` branch with `FlipFlag();`. | `PolicyFlipsOnlyOnKeypress` |

Note NC4 leaves `FlagMonotone` *satisfied* (a `TRUE→FALSE` flip is monotone-OK):
it is the provenance monitor `PolicyFlipsOnlyOnKeypress`, not monotonicity, that
catches an illegitimate flip — which is the point of having both.

## Faithfulness ledger

What the model claims, and what it does not — the analogue of the Kani "Scope"
note in the [roadmap](../../docs/formalisation-roadmap.md).

**Modelled faithfully**

- The gate chain *ordering* (validate → forward_agent+privileged → freshness →
  env allowlist → replay dedup → dispatch), so a reordering regression is
  observable.
- `classify_key`'s exact decision table (`Classify`), including that
  `ApprovedAlways` is emitted iff `a` ∧ unprivileged.
- Both dispatch branches, the defensive `ApprovedAlways → Denied` fold on the
  privileged path, and that `confirm_unprivileged` is written by exactly one
  primitive (`FlipFlag`).
- Replay rejection via a monotonically-growing `seen` set.
- The attacker and the operator are both fully nondeterministic, so the
  properties are universally quantified over all field forgeries / replays and
  all operator choices.

**Abstracted (sound for these four properties)**

- The clock / freshness check → a boolean `fresh`; env contents → `envOk`;
  decode + peer-auth → `wellFormed`. The properties don't depend on the contents
  these gates inspect, only on pass/reject.
- `SeenIds` retention/eviction → never evict. This is *conservative* for
  `ReplayImpossible`: remembering ids forever can only add rejections within the
  model's horizon, never remove one. A replay accepted *after* the 120 s
  retention window is by-design and is not what leaves 1.4 / 4.4 are about. The
  **window relationship** that makes this safe — that an id stays remembered for
  as long as a replay of it could still pass the freshness gate — is exactly what
  the [`ReplayWindow`](#window-sizing--freshness--replay-retention) model proves,
  lifting this abstraction.

**Out of scope (covered by other rungs)**

- Concurrent TTY-lock interleavings and the `try_insert` TOCTOU — one request is
  handled to completion here; covered by the
  [`ConcurrentHandlers`](#concurrent-handlers--dedup-toctou--tty-lock-serialisation)
  sibling model.
- Freshness arithmetic monotonicity (`ymd_hms_to_epoch`) — Rung 3 Kani.
- Per-field dangerous-char scanning (`has_dangerous_chars`) — Rung 3 Kani.
- The SSH first-contact MITM residual (leaf 4.2 / A4) — the separate Rung 4
  ProVerif model in [`../proverif/`](../proverif/).

---

## Window-sizing — freshness ↔ replay retention

[`ReplayWindow.tla`](ReplayWindow.tla) / [`ReplayWindow.cfg`](ReplayWindow.cfg) —
the **Extended Rung 4** model. The approval-state-machine model above models
`seen` as never evicting (conservative, by its own admission). That conservatism
*hides* the one property the daemon genuinely depends on: the relationship
between the two time windows in [`server.rs`](../../src/server.rs):

| constant | value | role |
|----------|-------|------|
| `MAX_REQUEST_AGE` | 60 s | freshness gate (`check_freshness`) |
| `REPLAY_RETENTION` | 120 s | seen-id eviction TTL (`SeenIds::evict_stale`) |

This model restores a **small abstract clock** and the **real TTL eviction**, and
proves the temporal claim: *a captured request cannot evade replay-dedup by
waiting for its id to be evicted while still passing the freshness gate.* Only the
window **relationship** matters, not the absolute seconds, so the constants are
`Freshness = 2`, `Retention = 4` (= 2·Freshness), `MaxTime = 6`, `Ids = {r1}`.

### The theorem

| Invariant | Claim | Maps to |
|-----------|-------|---------|
| **`PastReplayImpossible`** | No captured **past-dated** request is ever re-executed. | leaf 1.1 · G2.1 (temporal half) |
| `AcceptWasFresh` | The daemon only ever accepts a request that was fresh at acceptance. | modeling hygiene |
| `TypeOK` | Type invariant. | — |

**The window arithmetic.** An id is inserted at `acceptedAt ≥ firstTs` (you accept
no earlier than the request was created) and evicted only once
`clock − insertedAt > Retention`. A replay re-uses the fixed `firstTs`, so it
passes freshness only while `clock − firstTs ≤ Freshness`. Since
`insertedAt = acceptedAt ≥ firstTs` and `Retention ≥ Freshness`, eviction
(`clock > firstTs + Retention ≥ firstTs + Freshness`) cannot co-occur with
freshness (`clock ≤ firstTs + Freshness`). So a captured replay can never win the
race — proved exhaustively by TLC (442 distinct states, sub-second).

**Why a monitor, not a `seen`-membership invariant.** Eviction is **lazy** — an id
is pruned only inside `try_insert`, and a replay-accept removes then re-inserts the
id in one atomic step. A membership predicate (`∃ rec ∈ seen : …`) therefore can
never observe the gap; the re-insertion masks it. Only an event monitor (`vReplay`
raised at the re-exec site) is a robust witness — the same rationale behind the
approval-state-machine model's monitor variables.

### Finding 1 — the tight bound is `Retention ≥ Freshness`, not `2×`

The code comment says retention is "twice `MAX_REQUEST_AGE` so that any id that
could still pass the freshness check is also still in the set." The arithmetic
above shows `Retention ≥ Freshness` already suffices (max acceptance lag only
pushes eviction *later*, never earlier). TLC confirms it: the theorem **holds** at
`Retention = Freshness` and **fails** at `Retention = Freshness − 1`. So the
shipped `120 s = 2 × 60 s` is **conservative margin, not a necessity** — *not a
bug*; the daemon is, if anything, safer than its comment claims.

### Finding 2 — future-dated timestamps defeat replay protection after eviction

`parse_age` **clamps future-dated timestamps to age 0** (`server.rs:146`) with no
upper cap, so a request dated beyond `Retention` into the future keeps passing the
freshness gate *forever* while its id ages out of `seen`. It is then replayable
**every `Retention` units regardless of how large `Retention` is** — the
window-sizing relationship does not help here at all. The model exposes this: with
the past-dated guard dropped (`NoFutureReplay`), TLC returns a concrete trace —
e.g. a request dated `ts = 3` accepted at `clock = 0`, evicted at `clock = 5`, then
replayed and re-executed at `clock = 5` (still fresh: `5 − 3 = 2 ≤ Freshness`).

How exploitable this is depends on the threat model (it needs the request onto the
channel — which SSH pinning guards — and for privileged commands the human still
gates the first run), but for auto-approved unprivileged commands it is a real
repeatable replay. The fix is cheap: also reject timestamps too far in the
*future* (a small clock-skew allowance, then reject rather than clamp). Logged as a
**separate backlog item** — not fixed in this (proofs-only) session.

### Negative controls — that the model has teeth

Apply by hand to the model / cfg, re-check, then revert. **Do not commit.**

| # | Mutation | Violates |
|---|----------|----------|
| **NC1** | `Retention = Freshness − 1` (window relationship broken) | `PastReplayImpossible` |
| **Tight-bound** | run at `Retention = Freshness` (holds) vs `Freshness − 1` (fails) | confirms `Retention ≥ Freshness` is the tight threshold (finding 1) |
| **NC2** | freshness gate disabled (`FreshAt(ts) == TRUE`) | `AcceptWasFresh` **and** `PastReplayImpossible` (freshness is load-bearing) |
| **Finding 2** | add `NoFutureReplay` to `INVARIANTS` | future-dated counterexample (finding 2) — a real property of the code, not a model mutation |

> Note NC2 is *disable freshness*, not *evict by the wrong field*: at
> `Retention ≥ Freshness`, evicting by the request timestamp instead of the
> insertion time is **also** safe for past-dated requests (it expires them up to
> `Freshness` earlier, but freshness has already lapsed), so it is not a valid
> negative control here — a small result the model also settles.

### Faithfulness ledger

**Modelled faithfully**

- The gate order at acceptance: freshness → evict → dedup → insert, mirroring
  `try_insert` (`evict_stale` runs first, then the membership check, then the
  stamped insert).
- Eviction keyed on **insertion** time (`Live(rec) == ¬(clock − insertedAt > Retention)`).
- `parse_age`'s future-timestamp **clamp** (`FreshAt(ts) == IF ts > clock THEN TRUE …`).
- The attacker replays the **captured bytes** (same id, same timestamp); the honest
  client submits the one genuine request. Both, plus the clock, are nondeterministic.

**Abstracted (sound for the window property)**

- The clock and the windows → small integers preserving `Retention = 2·Freshness`;
  the property depends only on the *relationship*, exhaustively checked to `MaxTime`.
- One id (`Ids = {r1}`): the property is per-id; the two-distinct-ids interaction is
  the approval-state-machine model's job.
- Atomic handling, no clock tick mid-request — faithful because `check_freshness`
  runs at handler *entry*, before the TTY lock (`server.rs:499`), precisely so a
  request cannot age past the gate while queued.

**Out of scope**

- Concurrent `try_insert` interleavings — the
  [`ConcurrentHandlers`](#concurrent-handlers--dedup-toctou--tty-lock-serialisation)
  sibling model.
- The approval/keypress gate (the approval-state-machine model).

### Running TLC

```sh
# (only if you edited the PlusCal) re-generate the translation, then commit both:
java -cp tla2tools.jar pcal.trans ReplayWindow.tla

java -cp tla2tools.jar tlc2.TLC -nowarning \
     -config ReplayWindow.cfg -workers auto ReplayWindow.tla
```

Expected: `No error has been found` (442 distinct states, sub-second).

---

## Concurrent handlers — dedup TOCTOU & TTY-lock serialisation

[`ConcurrentHandlers.tla`](ConcurrentHandlers.tla) /
[`ConcurrentHandlers.cfg`](ConcurrentHandlers.cfg) — the second **Extended Rung 4**
model. The two models above each handle one request to completion *atomically*, so
by construction they cannot see the hazards that only exist when the daemon runs
many [`handle_connection`](../../src/server.rs) threads at once. This is the
canonical model-checking use case: a property over *interleavings*, not over one
sequential run.

`server::run` spawns a thread per connection, all sharing two pieces of state via
`Arc<Mutex<…>>`:

| shared state | guarded by | the hazard if mishandled |
|--------------|------------|--------------------------|
| `seen` (`SeenIds`) | `seen_ids` mutex; `try_insert` is one critical section | two threads race the same id, both pass dedup, both exec (double-exec TOCTOU) |
| `/dev/tty` | `tty_lock` (`Arc<Mutex<()>>`) | two threads drive the terminal at once → background-pgrp EIO (PR #22) |

The model runs `Handlers = {h1, h2}` concurrent handlers, each picking its request
(`id` ∈ `Ids`, `privileged`, key) nondeterministically — so TLC explores every
interleaving, including both handlers racing the **same** id. PlusCal labels are
the atomicity boundaries: the mutex acquire/release and each critical section are
labelled steps, so TLC interleaves exactly where the real threads can.

### The two properties

| Invariant | Claim | Maps to |
|-----------|-------|---------|
| **`NoDoubleExec`** | No request id ever executes twice, under **any** interleaving — the atomic `try_insert` critical section is *sufficient* to serialise the same-id race. | leaf 1.1 · G2.1 (concurrent half of `ReplayImpossible`) |
| **`TtyMutualExclusion`** | At most one handler is in the interactive TTY region (prompt or foreground exec) at a time — `tty_lock` serialises /dev/tty across all interleavings. | Sn5.x · G6 |

**How they are witnessed.** `NoDoubleExec` is a monitor flag (`vDoubleExec`), raised
at an exec site if the id already ran — the same idiom as the sibling models.
`TtyMutualExclusion` is a bounded witness counter (`ttyActive`, 0..|Handlers|),
incremented inside the lock on entering the interactive region and decremented on
leaving; the invariant asserts it never exceeds 1. Both keep every variable
bounded, so the state space is finite and small.

**Faithful to the dispatch's lock discipline.** The privileged path takes
`tty_lock` for the prompt, **releases it before exec**, then `ForegroundGuard`
**re-takes** it for the foreground swap (two separate critical sections —
`server.rs:553` / `executor.rs`). `exec_direct` (unprivileged) takes **no** TTY
lock. The no-confirm banner uses a best-effort `try_lock` (modelled as a momentary,
non-overlapping hold). So `ttyActive` legitimately goes 1→0→1 across a privileged
request, and another handler may prompt in the released gap — never *simultaneously*.

### Result — the atomic critical section is sufficient

TLC checks both invariants exhaustively with **no error**: 5116 distinct states at
`Handlers = {h1, h2}` (sub-second), 238 590 at `{h1, h2, h3}`. Two handlers is the
minimal witness for the pairwise dedup TOCTOU and the TTY race; a third only adds
symmetric interleavings (the larger run is a one-line `.cfg` change, kept out of CI
for speed). The same-id race **is** exercised — both handlers can pick the same id,
one wins `try_insert` and execs, the other sees `dup` and is rejected — so the
property is non-vacuous, as NC1 below confirms by making it fail.

### Negative controls — that the model has teeth

Apply by hand to the PlusCal, re-run `pcal.trans`, re-check, then revert. **Do not
commit the mutations.** Each was verified to violate exactly the listed invariant.

| # | Mutation (in the PlusCal) | Violates |
|---|---------------------------|----------|
| **NC1** | Split the atomic `TryInsert` into `CheckSeen` (contains, then **release** the lock) and `InsertAcq`/`InsertSeen` (re-acquire, insert) — re-introducing the TOCTOU `try_insert` closes. | `NoDoubleExec` |
| **NC2** | Drop the `tty_lock` acquire/release around `PrivPrompt` (prompt without the lock). | `TtyMutualExclusion` |

NC1 is the load-bearing one: it shows the model genuinely *sees* the TOCTOU, so the
clean run's `NoDoubleExec` is a real verification of the atomic critical section, not
a vacuous pass. NC2 reproduces the PR #22 hazard the TTY lock exists to prevent.

### Faithfulness ledger

**Modelled faithfully**

- Two pieces of `Arc<Mutex<…>>`-shared state (`seen`, `tty_lock`) and N handler
  threads interleaving on them at mutex-acquire/release granularity.
- `try_insert` as **one** critical section under the `seen_ids` lock (the atomicity
  that closes the TOCTOU — the whole point of the model).
- The dispatch's TTY-lock discipline: privileged prompt holds then **releases**
  before exec, `ForegroundGuard` re-takes for the foreground swap, `exec_direct`
  takes no lock, the no-confirm banner is best-effort `try_lock`.
- Both handlers may race the **same** id (the TOCTOU) or handle distinct ids.

**Abstracted (sound for these two properties)**

- The per-request gate chain (validate → freshness → env allowlist) → assumed
  passed: it is per-handler and sequential, covered by the
  [`ApprovalStateMachine`](#the-four-properties) model. The focus here is the
  shared-state races.
- `SeenIds` eviction → never evict (the [`ReplayWindow`](#window-sizing--freshness--replay-retention)
  model owns the TTL); irrelevant to a concurrency race within the model's horizon.
- `confirm_unprivileged` → a read-only init-free boolean (no `a` key), so its flip
  semantics stay with the `ApprovalStateMachine` model; both dispatch paths are
  still covered.
- Handler count bounded to 2 (3 also checked); the keypress set to `{y, other}`.

**Out of scope**

- The approval/keypress decision table and the flag-flip transition — the
  [`ApprovalStateMachine`](#the-four-properties) model.
- The freshness ↔ retention window sizing — the
  [`ReplayWindow`](#window-sizing--freshness--replay-retention) model.

### Running TLC

```sh
# (only if you edited the PlusCal) re-generate the translation, then commit both:
java -cp tla2tools.jar pcal.trans ConcurrentHandlers.tla

java -cp tla2tools.jar tlc2.TLC -nowarning \
     -config ConcurrentHandlers.cfg -workers auto ConcurrentHandlers.tla
```

Expected: `No error has been found` (5116 distinct states, sub-second).
