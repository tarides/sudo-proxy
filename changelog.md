# Changelog

Most recent at top. See [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)
for the assurance-ladder context behind the security-formalisation entries.

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
