# Rung 4 — TLA+/PlusCal approval state machine

[← formalisation roadmap](../../docs/formalisation-roadmap.md) · [threat model](../../docs/threat-model.md) · [assurance case](../../docs/assurance-case.md)

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
  retention window is by-design and is not what leaves 1.4 / 4.4 are about.

**Out of scope (covered by other rungs)**

- Concurrent TTY-lock interleavings and the `try_insert` TOCTOU — atomic by
  construction and unit-tested; one request is handled to completion here.
- Freshness arithmetic monotonicity (`ymd_hms_to_epoch`) — Rung 3 Kani.
- Per-field dangerous-char scanning (`has_dangerous_chars`) — Rung 3 Kani.
- The SSH first-contact MITM residual (leaf 4.2 / A4) — the separate Rung 4
  ProVerif model in [`../proverif/`](../proverif/).
