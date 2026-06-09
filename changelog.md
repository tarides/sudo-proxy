# Changelog

Most recent at top. See [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)
for the assurance-ladder context behind the security-formalisation entries.

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
