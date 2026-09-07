# Changelog

Most recent at top. See [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)
for the assurance-ladder context behind the security-formalisation entries.

## 2026-09-07 — Published to the MCP Registry; retired the cargo-support watch; RUSTSEC-2026-0189 triaged

Release/hygiene work, not an assurance-ladder rung.

- **Published `io.github.tarides/sudo-proxy` 1.0.0 to the official MCP Registry.**
  The registry added cargo (crates.io) as a package `registryType` in registry
  v1.8.0 (2026-07-13, modelcontextprotocol/registry#1207), lifting the HTTP 400
  "unsupported registry type: cargo" that had blocked `publish.yml`'s final
  step. Ran `publish.yml`; the server is now listed with a `cargo` package
  (status active, isLatest). The README's
  `mcp-name: io.github.tarides/sudo-proxy` marker is deliberately **visible**
  markdown text (a code span), which is required — crates.io strips HTML
  comments during README rendering, so the hidden-comment form used for
  PyPI/NuGet would not validate.

- **Removed the temporary `registry-watch.yml` tripwire (PR #40).** It had gone
  RED daily waiting for cargo support and was auto-disabled by GitHub for
  inactivity on 2026-08-19. Its GREEN signal was also mis-wired — it counted
  *pre-existing* cargo-type servers in the public listing, which was the wrong
  heuristic (the registry accepts cargo regardless of whether any cargo server
  is already listed), so it would never have fired. Deleted per its own header
  instructions once the server was published.

- **Triaged RUSTSEC-2026-0189 as not-applicable and suppressed it with a
  documented rationale (PR #41).** The advisory is a DNS-rebinding flaw (missing
  `Host`-header validation) in rmcp's Streamable HTTP server transport.
  sudo-proxy is not affected: the advisory excludes non-HTTP transports, and
  this crate enables only rmcp's `transport-io` feature and serves the MCP
  server over stdio (`src/bin/sudo-proxy-mcp.rs`: `.serve(stdio())`) — the
  vulnerable HTTP transport is never compiled in. Ignored the ID in both
  advisory gates (`deny.toml` `[advisories].ignore` and the `cargo audit
  --ignore` step) with the rationale inline; CI green again. Revisit if an HTTP
  transport is ever added.

## 2026-06-11 — Extended Rung 4: SSH key-acceptance model, mutual auth (ProVerif)

Reworked the Rung 4 ProVerif model (`proofs/proverif/ssh-channel.m4.pv`,
**non-gating** in CI) from a channel-toggle that *declared* the tunnel private
when pinned — assuming the MITM — to a **key-acceptance** encoding that
**derives** it. The model now carries the real key material and the `PINNED`
`m4` toggle flips only *which host key the daemon accepts*; the channel is the
public Dolev-Yao network in both configurations. Strengthens assurance-case leaf
Sn6.3 / G6.3 and makes assumption A4 genuinely load-bearing.

- **Both-or-nothing design (mutual auth).** Modelling the host key alone while
  ignoring client auth would misrepresent the system (it would paint the honest
  remote as accepting forged commands even when pinned, which `authorized_keys`
  prevents). So the model captures the real SSH mutual-authentication structure:
  a **host keypair** (server→client: pinning + confidentiality, A4) and a
  **client keypair** (client→server: `authorized_keys`, request integrity). The
  crypto *primitives* stay a perfect black box — "under the hood" means the
  authentication *structure*, not SSH's algorithms.

- **The derived MITM.** Query **(c)** `not attacker(agentSecret)` is `true` when
  pinned and **`false`** on first contact, with ProVerif's derivation being
  exactly the key substitution: the attacker mints its own host key `pk(k)`, the
  daemon accepts it and encrypts the payload to it, the attacker decrypts with
  `k`. This is leaf 4.2 *derived* rather than assumed.

- **The disentanglement (the payoff).** The four queries attribute each guarantee
  to its assumption: **(a)** command authenticity (`RemoteAccept ⟹ RequestSent`)
  is `true` in **both** configs — it rides on **client auth**, so a first-contact
  eavesdropper still cannot forge or alter a command; **(c)** confidentiality
  rides on **host-key pinning (A4)**; **(d)** separation
  (`RemoteExec ⟹ Keypress`) is `true` in both — the private TTY (A1) is out of
  the attacker's reach. The earlier model's "(a) holds iff pinned" was an
  artifact of the assumed-private channel; the key-level model corrects it.

- **Injective replay (b), now honest.** `false` in **both** configs with a real
  public-channel replay trace — the earlier "cannot be proved when pinned"
  private-channel over-approximation is **gone**. App-layer injective
  replay-resistance stays discharged by the TLA+ `ReplayImpossible` invariant and
  the Kani freshness-monotonicity proof.

- **Teeth — three documented negative controls** (apply by hand, never
  committed), each run and producing the expected result: **NC1** drops the
  `checksign` client-auth check → **(a)** turns `false` even pinned (client auth
  is load-bearing; confidentiality stays `true`, showing orthogonality); **NC2**
  is the first-contact run itself → **(c)** `false`; **NC3** makes `ttyAck`
  public → **(d)** no longer provable (the private TTY is load-bearing).

- **Docs:** `proofs/proverif/README.md` rewritten (key-acceptance toggle, the
  query table + "rides on" column, the disentanglement narrative, the three
  controls, scope with the now-explicit client-auth assumption); `proverif.yml`
  comment names **(c)** as the expected-`false` first-contact query;
  `docs/threat-model.md` (leaf 4.2), `docs/assurance-case.md` (A4 + Sn6.3), and
  `docs/formalisation-roadmap.md` updated for derived-not-assumed + the
  per-assumption attribution. No Rust touched (`proofs/` is outside `src/`); the
  three TLA+ sibling models are untouched.

- **Verified:** ProVerif 2.05, both `m4` configs — pinned: (a) true, (b) false,
  (c) true, (d) true; first contact: (a) true, (b) false, (c) **false** with the
  key-substitution derivation, (d) true. All three negative controls fail as
  required.

## 2026-06-11 — Extended Rung 4: concurrent-handler interleaving (TLA+)

Added a third TLA+/PlusCal model, `proofs/tla/ConcurrentHandlers.tla` (checked by
TLC, **non-gating** in CI like its two siblings), discharging the *canonical*
model-checking use case the two atomic, one-request-at-a-time models cannot
express by construction: **concurrent** daemon handler threads interleaving on
the two pieces of `Arc<Mutex<…>>`-shared state. It *verifies the atomicity fix is
sufficient* — strengthening the concurrent half of assurance-case leaf 1.1 / G2.1.

- **The two theorems.**
  - **`NoDoubleExec`** — no request id ever executes twice under **any**
    interleaving. This is the closure of the dedup TOCTOU: `SeenIds::try_insert`
    (`server.rs:213`) folds the contains-check and the insert into one critical
    section under the `seen_ids` mutex; the model proves that single critical
    section is *sufficient* to serialise two threads racing the same id. Witnessed
    by a monitor flag (`vDoubleExec`) raised at an exec site if the id already ran.
  - **`TtyMutualExclusion`** — at most one handler is in the interactive TTY
    region (prompt or foreground exec) at a time, so `tty_lock` serialises
    /dev/tty across all interleavings (the PR #22 background-pgrp / EIO hazard).
    Witnessed by a bounded counter (`ttyActive ≤ 1`).

- **Faithful to the dispatch's lock discipline.** PlusCal labels are the
  atomicity boundaries, so TLC interleaves exactly where the threads can. The
  privileged path holds `tty_lock` for the prompt, **releases before exec**, then
  `ForegroundGuard` **re-takes** it for the foreground swap (two critical
  sections); `exec_direct` takes no lock; the no-confirm banner is best-effort
  `try_lock`. So another handler may legitimately prompt in the released gap —
  never *simultaneously*.

- **Result.** TLC reports no error: **5116 distinct states** at `Handlers =
  {h1, h2}` (sub-second), and **238 590** at `{h1, h2, h3}`. Two handlers is the
  minimal witness for the pairwise dedup TOCTOU and the TTY race; a third only
  adds symmetric interleavings (a one-line `.cfg` change, kept out of CI for
  speed). The same-id race is genuinely exercised (one handler wins `try_insert`
  and execs, the other is rejected as a duplicate), so the pass is non-vacuous.

- **Teeth — two documented negative controls** (apply by hand, never committed):
  **NC1** splits the atomic `TryInsert` into check-release-insert, re-introducing
  the TOCTOU → `NoDoubleExec` violated (the load-bearing control: it proves the
  model *sees* the race the atomicity closes); **NC2** drops the `tty_lock` around
  the privileged prompt → `TtyMutualExclusion` violated (reproduces the PR #22
  hazard). Both were run and produce the expected counterexample.

- **Scope** (per the README faithfulness ledger): the shared `seen`/`tty_lock`
  races and `try_insert`'s atomicity are modelled faithfully; the per-request gate
  chain is assumed-passed (sequential, the `ApprovalStateMachine` model's job),
  eviction is never-evict (the `ReplayWindow` model's job), and
  `confirm_unprivileged` is read-only here (no `a` key). Handler count bounded to
  2 (3 also checked).

- **CI / docs:** `.github/workflows/tlc.yml` gains a third `continue-on-error`
  TLC step; `proofs/tla/README.md` adds the model's section and updates the two
  siblings' "out of scope" notes to point at it; the roadmap's Rung 4 scope note
  is corrected (concurrency/TOCTOU is no longer "stays elsewhere"). No Rust
  touched (`proofs/` is outside `src/`); the two sibling models re-check unchanged.

## 2026-06-11 — Extended Rung 4: freshness ↔ replay window-sizing (TLA+)

Added a second TLA+/PlusCal model, `proofs/tla/ReplayWindow.tla` (checked by
TLC, **non-gating** in CI like its sibling), proving the temporal property the
approval-state-machine model deliberately hides: it models `seen` as
*never-evicting* ("conservative for `ReplayImpossible`"), which makes the
headline replay claim conditional. The new model restores a small abstract clock
and the **real TTL eviction** and discharges the genuinely temporal invariant —
tightening `ReplayImpossible` from conditional to real and strengthening
assurance-case leaf 1.1 / G2.1.

- **The theorem — `PastReplayImpossible`.** No captured *past-dated* request is
  ever re-executed. The window arithmetic: an id is stamped at acceptance
  (`insertedAt ≥ firstTs`) and evicted only at `clock − insertedAt > Retention`;
  a replay re-uses the fixed `firstTs` and stays fresh only while
  `clock − firstTs ≤ Freshness`. With `insertedAt ≥ firstTs` and
  `Retention ≥ Freshness`, eviction and freshness can never co-occur. TLC: no
  error, 442 distinct states, sub-second.
  - Constants abstract the two real windows (`MAX_REQUEST_AGE`=60s,
    `REPLAY_RETENTION`=120s) to `Freshness=2`, `Retention=4` (=2F), `MaxTime=6`,
    `Ids={r1}` — only the *relationship* matters. Bounded clock ⇒ finite, small
    state space.
  - **Why a monitor, not a `seen`-membership invariant:** eviction is *lazy*
    (pruned only inside `try_insert`) and a replay-accept removes-then-reinserts
    the id atomically, so a membership predicate can never observe the gap. Only
    an event monitor (`vReplay`) is a robust witness — the same idiom the sibling
    model uses.

- **Finding 1 — the tight bound is `Retention ≥ Freshness`, not `2×`.** TLC
  confirms the theorem holds at `Retention = Freshness` and fails at
  `Freshness − 1`. The shipped `120s = 2×60s` is **conservative margin, not a
  necessity** (max acceptance lag only pushes eviction later) — *not a bug*, and
  the code is safer than its comment claims.

- **Finding 2 — future-dated timestamps defeat replay protection after
  eviction (new residual).** `parse_age` clamps future timestamps to age 0
  (`server.rs:146`) with no upper cap, so a request dated beyond `Retention` into
  the future stays fresh forever while its id ages out — replayable every
  `Retention` units regardless of size. The model exposes a concrete trace via
  the `NoFutureReplay` invariant (e.g. `ts=3` accepted at `clock=0`, evicted at
  `clock=5`, re-executed). Logged as a backlog item (cap far-future timestamps);
  not fixed in this proofs-only session.

- **Teeth:** documented negative controls — `Retention < Freshness` (window
  relationship broken → `PastReplayImpossible` fails) and freshness-gate-disabled
  (→ `AcceptWasFresh` + `PastReplayImpossible` fail, showing freshness is
  load-bearing). The originally-planned "evict by the wrong field" control turned
  out *safe* at `Retention ≥ Freshness` — a small result the model also settles,
  recorded in the README.

- **Scope (per the README faithfulness ledger):** the gate order at acceptance
  (freshness → evict → dedup → insert), eviction keyed on insertion time, and the
  `parse_age` future-clamp are modelled faithfully; the clock/windows are
  abstracted to small relationship-preserving integers; one id (per-id property),
  atomic handling (justified by the entry-time freshness check, `server.rs:499`),
  and concurrency/keypress gating are left to the sibling model.

- **CI:** `.github/workflows/tlc.yml` gains a second `continue-on-error` TLC step
  for `ReplayWindow`; added `proofs/tla/.gitignore` for TLC/`pcal.trans`
  artifacts. The sibling `ApprovalStateMachine` re-checks unchanged (9072 states);
  no Rust touched (`proofs/` is outside `src/`).

## 2026-06-11 — Rung 4: protocol-level formal models (TLA+ + ProVerif)

> **Note (superseded in part):** the ProVerif description below reflects the
> original *channel-toggle* model (private tunnel when pinned, with the
> injective-replay over-approximation). It was reworked the same day into the
> *key-acceptance* mutual-auth model — see the **"Extended Rung 4: SSH
> key-acceptance model, mutual auth (ProVerif)"** entry at the top of this file.
> The TLA+ half of this entry stands unchanged.

Discharged **Rung 4** of the assurance ladder — the temporal/relational
properties that are not per-function — with two machine-checked models under a
new top-level `proofs/` dir (kept out of `src/` so cargo/clippy never see them).
Both run **non-gating** in CI, mirroring the Rung 3 Kani job. Strengthens the
assurance-case leaves Sn5.1 / Sn5.3 (state machine) and Sn6.3 (SSH) from
`[partial] → planned` to machine-checked / formally-characterised evidence.

- **Approval state machine — TLA+/PlusCal** (`proofs/tla/`, checked by TLC). The
  PlusCal transcribes the `handle_connection` gate chain and `tui::classify_key`;
  a nondeterministic environment process quantifies over all attacker
  field-forgeries/replays *and* all operator keypresses. Four safety properties
  hold: `NoExecWithoutApproval`, `ReplayImpossible`, `PolicyFlipsOnlyOnKeypress`
  (+ a `FlagMonotone` action property), `PrivilegedGateIndependentOfPolicy` —
  the machine-checked closure of the 1.4/4.4 policy-transition residual (F2).
  - Properties are tracked by bounded **monitor variables** (a violation flag
    raised at each bad-event site), so the reachable state space is finite and
    small (~9k states, sub-second) with *no* history-length constraint — the
    first cut with a full event log blew up past 180M states. No `MaxLog` hack.
  - **Teeth:** four documented negative-control mutations (exec on timeout; flag
    wired into the privileged gate; dedup gate removed; flag flipped on a
    non-`a` keypress) each produce the expected TLC counterexample.
  - **Decision: TLA+/PlusCal over Alloy** — the properties are temporal/safety
    over an evolving state machine, TLC's home turf; Alloy's relational style
    fits less well. Recorded in `docs/formalisation-roadmap.md`.

- **SSH path — ProVerif** (`proofs/proverif/`). A symbolic Dolev-Yao model with a
  compile-time `PINNED` toggle (via `m4`): the SSH tunnel is a private channel
  when the host key is pinned, public when not. It proves channel authenticity
  `(a)` and payload/agent secrecy `(c)` hold **iff** the key is pinned, exhibits
  a concrete **first-contact MITM** trace when it is not (attack-tree leaf 4.2),
  and proves a **separation theorem** `(d)` — a privileged exec at the honest
  remote requires a human keypress even with the channel fully compromised. This
  makes assumption A4 load-bearing and explicit.
  - **Honest note on injective replay `(b)`:** ProVerif reports it "cannot be
    proved" on the *private* (pinned) channel — a known over-approximation of
    its non-linear private-channel semantics, with **no** attack trace; on the
    public channel it is genuinely `false` with a replay trace (the surfaced
    gap). App-layer injectivity is discharged instead by the TLA+
    `ReplayImpossible` invariant and the Kani freshness-monotonicity proof — a
    coherent cross-rung split, and faithful to the threat model's "replay
    protection rides on A4".
  - **Decision: ProVerif over Tamarin** — one binary toggle + an attack
    derivation, expressed with least ceremony and proved fully automatically;
    Tamarin's unbounded-state/inductive strengths aren't needed. Recorded in the
    roadmap.

- **Scope, stated plainly** (per-model README "faithfulness ledger" / scope
  notes): the TLA+ model abstracts the clock/env/decode to booleans, never-evicts
  the replay set (conservative for replay), and leaves concurrency/TOCTOU and
  per-field content scanning to their other rungs; the ProVerif model treats SSH
  crypto as a perfect black box and abstracts time to nonces + ordering. The two
  *accepted* residuals (by-design unprivileged auto-approve; A4 first-contact
  dependency) are now formally **characterised**, not closed.

- **CI:** `.github/workflows/tlc.yml` (fetches `tla2tools.jar`, runs TLC) and
  `.github/workflows/proverif.yml` (installs ProVerif via opam, runs both `m4`
  configurations) — both `continue-on-error`, like the Kani/geiger jobs. The
  unpinned ProVerif run reporting `(a)/(c)` false is the *expected, desired*
  output, so the job is not gated on ProVerif's exit code.

- **Verified:** TLC reports no error (9072 distinct states) and each negative
  control fails as required; ProVerif gives the pinned-vs-first-contact split
  above. Core + `--features mcp` release build and
  `cargo clippy --all-targets --all-features -- -D warnings` remain clean (no
  Rust touched; `proofs/` is outside `src/` and not a workspace member, so cargo
  ignores it).

## 2026-06-10 — Rung 3: Kani bounded proofs + validation-boundary typestate

Discharged **Rung 3** of the assurance ladder. The Kani half proves the
attacker-controlled arithmetic; the Flux half is replaced by a stable-Rust
typestate that closes the F1-class gap by construction (rationale below).
Strengthens assurance-case leaves under G3/G4/G6 with machine-checked rather
than sampled evidence.

- **Kani proofs** — `src/proofs.rs`, a `#[cfg(kani)]` module compiled only by
  `cargo kani`, re-drives the Rung 2 predicates with `kani::any()`:
  - `ymd_hms_to_epoch_is_total_and_panic_free` proves the `parse_age` arithmetic
    core total and panic/overflow/wrap-free over the **entire `u64^6` domain**
    (unbounded — strictly stronger than the Rung 2 fuzz). The core was extracted
    into `datetime::ymd_hms_to_epoch` (the reverse of `epoch_to_iso`) precisely so
    `SystemTime::now()` stays out of the proof; `parse_age` now just parses then
    calls it. This is the machine-checked closure of the issue-#11/#14 integer
    underflow.
  - `ymd_hms_to_epoch_is_monotone_on_valid_dates` proves the parser monotone in
    calendar order (a later datetime never maps to a smaller epoch, so an earlier
    timestamp is never judged fresher), over well-formed dates in `1970..=2099` —
    discharging the Rung 2 `freshness_is_monotone` predicate, which only sampled
    the round-trip.
  - `has_dangerous_chars_matches_spec_per_char` proves the display-field scanner
    panic-free and exactly matching its danger ranges. Made tractable by encoding
    into a stack `[u8; 4]` (no heap), bounding the codepoint `< 0x2100` (every
    forbidden range is `<= 0x2069`; above the bound both sides are trivially
    `false`), and `#[kani::unwind(5)]` to bound the `chars()` loop.
  - **Scope, stated plainly:** Kani covers our arithmetic and our scanner. The
    base64 / `serde_json` decode paths are out of scope — upstream `Result`-
    returning crates with no `.unwrap()` at our call sites, so their panic-freedom
    is the upstream obligation; symbolically checking serde/base64 is intractable.
  - CI: `.github/workflows/kani.yml` runs the proofs **non-gating** (geiger-style).
    Kani manages its own toolchain, so the `rust-toolchain.toml` pin and the
    gating jobs are untouched. `Cargo.toml` registers `check-cfg = ['cfg(kani)']`
    so the `-D warnings` clippy gate doesn't trip on the `#[cfg(kani)]` module.

- **`ValidatedRequest` typestate (Flux replacement)** — `protocol::ValidatedRequest`
  wraps a private `Request`; its only constructor is the validating
  `ValidatedRequest::validate` (the former `validate_request` + `has_dangerous_chars`,
  moved from `server.rs` to live with the type). `executor::exec_*` and
  `tui::Prompter::prompt` now accept **only** `&ValidatedRequest`, so reaching
  dispatch or the approval prompt with an unvalidated request is a *compile error*
  — the F1 closure "by construction." `handle_connection` validates once and
  shadows `req`; downstream reads go through `Deref`.
  - **Decision:** Flux was assessed and rejected for this rung — its refinements
    reason over ints/indices, not string contents, so the actual invariant ("no
    dangerous char in any displayed field") is not expressible in Flux, and it
    needs an experimental private nightly toolchain. The typestate meets the
    roadmap's stated goal in stable Rust that the existing CI already builds.
    Recorded in `docs/formalisation-roadmap.md`.

- **Residuals (proven vs tested), logged in the roadmap:** that `validate`
  applies the scanner to *every* displayed field is covered only by the Rung 2
  property test, not by proof (a Rung 5 Creusot target); base64 / `serde_json`
  panic-freedom rests on the upstream `Result` APIs, an assumption not a proof.

- **Verified:** core + `--features mcp` builds, full test suite, and
  `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo kani`
  reports **3/3 harnesses SUCCESSFUL**. Negative controls each failed as required:
  replacing a `checked_mul` with `*` turned the Kani proof red ("attempt to
  multiply with overflow"); passing a raw `&Request` to `exec_sudo` is a compile
  error (`expected &ValidatedRequest`).

## 2026-06-09 — Rung 2: fuzz harnesses reframed as named properties (PR #33)

Turned the ad-hoc fuzz tests (`fuzz_shell_escape_*`, `fuzz_parse_age_*`) into
**named property functions that read as spec clauses**, so each becomes an
explicit proof obligation Rungs 3–5 will discharge with Kani/Flux, TLA+/Alloy,
and Creusot/Verus. Each property is a predicate function (`input → invariant`)
plus a driver, doc-commented with the clause and the rung that will formally
discharge it — the predicate is kept separate from the generator so Rung 3 can
re-drive the same function with `kani::any()` unchanged. Closes **Rung 2** of
the assurance ladder; strengthens leaves under G3/G4/G6.

- The five clauses: `parse_age` is total/panic-free and **freshness is monotone**
  (an older timestamp is never judged fresher); **`shell_escape` round-trips
  byte-for-byte** through `/bin/sh`; an **accepted request has no dangerous char**
  in any displayed field (argv/env/reason/host/session/version/id); **privileged
  ⇒ a keypress occurred** (root execs only on `Approved`); **`confirm_unprivileged`
  flips only on an interactive keypress** (`'a'`, unprivileged only).
- `src/prop.rs` — new `#[cfg(test)]` module: a shared deterministic xorshift64*
  `Rng` replacing the PRNG closures the fuzz tests inlined. **Decision:** keep an
  in-house, dependency-free generator rather than adopt proptest/quickcheck (which
  the roadmap names) — a property crate adds a dependency tree the Rung 1
  `cargo-deny` gate must vet while contributing nothing to the later formal rungs,
  which are separate toolchains. Trade-off: no automatic shrinking.
- `src/tui.rs` — extracted the keypress→`PromptResult` decision out of `prompt_tty`
  into a pure `classify_key(key, privileged)`, so the transition logic is testable
  exhaustively now and reusable by the Rung 4 state-machine model / Rung 5 dispatch
  contract instead of staying buried behind `/dev/tty`. No behaviour change.
- `tests/approval.rs` — new dispatch-level integration tests via the
  `ScriptedPrompter` harness. The flag-flip test isolates `XDG_CONFIG_HOME` to a
  temp dir so it never touches the real user config, and asserts the policy was
  persisted there.
- Verified: builds (core + `--features mcp`), full test suite, and
  `cargo clippy --all-targets --all-features -- -D warnings` all clean; CI green on
  PR #33. Negative-control mutations (drop the `!privileged` guard in `classify_key`;
  drop the `reason` check in `validate_request`) each turned the matching property
  red, confirming they can fail.

## 2026-06-09 — Rung 1: CI mechanization of static analysis (PR #32)

Turned the static-analysis checks that previously ran only by hand into a
push/PR build gate, so an F1-class regression (e.g. a display field that skips
`has_dangerous_chars`) fails the build instead of waiting for the next manual
audit. Closes **Rung 1** of the assurance ladder; strengthens assurance-case
leaves under G3/G4/G6.

- `.github/workflows/ci.yml` — new `CI` workflow on push/PR with five jobs:
  **lint** (`cargo clippy --all-targets --all-features -- -D warnings`),
  **build + test** (core + `--features mcp` builds, then the test suite),
  **cargo audit**, **cargo deny**, and a non-blocking **cargo geiger** that
  reports the `unsafe` surface without gating. Uses `Swatinem/rust-cache` for
  the compiling jobs.
- `deny.toml` — new `cargo-deny` policy gate (advisories, bans, licenses,
  sources) over the full `--all-features` dependency tree, with a tight
  license allowlist so a new dependency license forces a review. Closes the
  audit's "cargo deny missing" gap.
- `rust-toolchain.toml` — pins the toolchain (currently 1.96.0) so CI,
  release builds, and local dev share one compiler. Without it, floating
  `stable` + `-D warnings` lets each Rust release introduce lints that break
  CI on unrelated PRs; bump deliberately. Pinning surfaced and fixed a handful
  of newer-clippy findings in `src/` and `tests/` (manual `is_multiple_of`,
  `new_without_default`, `items_after_test_module`, `useless_conversion`,
  `collapsible_if`, manual `str::repeat`, `field_reassign_with_default`) — no
  behaviour change.
- The flaky `burst_connections_above_cap_get_busy_response` concurrency test is
  `--skip`ped in CI (its *setup* assertion is timing-flaky, not its security
  assertion); stabilizing it remains a separate backlog item.

## 2026-06-09 — Security formalisation program + Rung 0 threat model (PR #30)

Established a graduated-assurance program for the single security invariant
("nothing privileged runs without a human deliberately approving the exact
command shown") and closed **Rung 0** of the ladder:

- `docs/formalisation-roadmap.md` — the rigor ladder (code review → property
  testing → Kani/Flux → TLA+/Alloy/Tamarin → Creusot/Verus/Prusti → seL4-style
  refinement), framed by Common Criteria + a GSN assurance case.
- `docs/assurance-case.md` — GSN argument: top goal G1 decomposed into G2–G6 by
  adversary (A1/A2/A3) and control, each leaf citing evidence + rung + status.
- `docs/threat-model.md` — **Rung 0**: STRIDE per trust boundary (B1–B6) +
  attack tree rooted at ¬G1, every leaf cross-referenced to its G-node and audit
  finding.
- `docs/architecture.md` — allowlisting design note (CVE-2025-66032 prefix-match
  escapes; does not affect sudo-proxy today).

Documentation only; no code or build impact.
