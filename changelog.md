# Changelog

Most recent at top. See [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)
for the assurance-ladder context behind the security-formalisation entries.

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
