# Security formalisation roadmap

[← README](../README.md) · see also [security.md](security.md) · [security-audit.md](security-audit.md) · [assurance-case.md](assurance-case.md)

This document lays out a *graduated assurance program* for sudo-proxy: a path
that starts at the code review and adversarial audit we already do and grows,
rung by rung, toward mechanized formal verification. It is deliberately
incremental — every rung re-proves the **same** top-level claim with stronger
evidence, so partial progress is always useful and nothing is wasted.

## The one invariant

The [security audit](security-audit.md) distilled the whole security model to a
single sentence:

> **Nothing privileged runs without a human deliberately approving the exact
> command shown.**

sudo-proxy is unusually well-suited to formalisation precisely because it
reduces to this one invariant, evaluated against three adversaries that the
audit already named:

- **A1 — Malicious / prompt-injected MCP caller.** Controls `argv`, `pipeline`,
  `env`, `host`, `description`(→`reason`), `privileged`, `forward_agent`,
  `timeout`.
- **A2 — Same-UID local process.** Can connect to the `0600` +
  `SO_PEERCRED`-gated socket directly, bypassing the MCP layer and its
  client-side `validate_host`.
- **A3 — Network MITM / malicious remote.** On the SSH path or controlling the
  remote end.

Everything below is about taking that one claim and re-discharging it, against
those three adversaries, with progressively stronger forms of evidence.

## Two backbones: vocabulary + rigor ladder

Before the rungs, two established frameworks give the program its shape. One
provides the *vocabulary* for writing down the model; the other provides the
*ladder* of increasing rigor.

### Backbone 1 — Common Criteria / ISO-IEC 15408 (the documents and the ladder)

Common Criteria gives us the formal documents this roadmap is meant to produce,
and it is explicitly graduated:

- A **Security Target (ST)** = the **Target of Evaluation** (the daemon, the MCP
  server, the SSH-tunnel path), the **threats** (A1/A2/A3), the
  **assumptions / constraints** (single-user host trust, `known_hosts`
  pre-populated before first contact, a trusted `/dev/tty`, a trusted `sudo`),
  and the **Security Functional Requirements (SFRs)** — the concrete controls
  enumerated in [security-audit.md](security-audit.md): environment allowlist,
  no-shell on the privileged path, replay protection, `SO_PEERCRED` auth,
  display-field sanitization, resource caps.
- The **Evaluation Assurance Levels (EAL 1→7)** *are* the roadmap spine. They
  scale from "functionally tested" up through "methodically designed and
  tested" to **EAL5–6 (semiformally verified design)** and **EAL7 (formally
  verified design and tested)**. We are not pursuing certification — we *borrow
  the ladder*. "Gradually strengthen" maps almost 1:1 onto CC's **Security
  Assurance Requirements (SARs)**.

### Backbone 2 — A security assurance case in GSN (the argument that holds it together)

For day-to-day work, a **security assurance case** in **Goal Structuring
Notation (GSN)** is the more practical instrument, and it lives alongside this
document in [assurance-case.md](assurance-case.md).

- Make the invariant the top-level **Goal**.
- Decompose it by adversary (A1/A2/A3) and by control into sub-goals
  (**Strategies** linking parent claims to child claims).
- Attach each piece of evidence — a code-review note, a fuzz harness, a Kani
  proof, a TLA+ model — as a **Solution** node.

The point for *this* program: the argument structure stays fixed while the
evidence under each leaf gets stronger over time. "Grow from code review up to
formal verification" becomes a concrete artifact you can diff in git — a leaf
that today cites a fuzz test tomorrow cites a machine-checked proof, and the
surrounding argument is unchanged. The OMG **Structured Assurance Case
Metamodel (SACM)** standardizes the notation if tooling is wanted later.

So: use the **CC Security Target** to *write down* the model, threats,
requirements, and constraints; use the **GSN assurance case** to *hold the
argument together* as the evidence strengthens.

## The rigor ladder

Each rung re-proves the same invariant with a stronger class of evidence. Rungs
are roughly ordered by assurance-per-unit-effort; you can climb them
independently per leaf of the assurance case.

### Rung 0 — Formalise the threat model (paper) — **complete**

Delivered in [threat-model.md](threat-model.md): a **STRIDE pass per trust
boundary** (B1–B6) and an **attack tree** whose root is the *negation* of the
invariant ("a root command runs that the human did not approve"). Every attack-
tree leaf is cross-referenced to the GSN sub-goal that discharges it
([assurance-case.md](assurance-case.md)) and to the relevant audit finding, and
the accepted residuals are listed explicitly. This is what told us which higher
rungs are load-bearing — notably that the policy-transition residual points at
Rung 4 (TLA+/Alloy) and the SSH first-contact residual at Rung 4
(Tamarin/ProVerif).

### Rung 1 — Code review + static analysis (current state, mechanized)

Keep the adversarial multi-skeptic review the audit already uses, but make it
*repeatable in CI*:

- `cargo clippy --all-targets --all-features` (security-relevant lints).
- `cargo audit` (RUSTSEC advisories).
- Add `cargo deny` (license / ban / source policy — the audit flagged it as not
  yet wired up) and `cargo geiger` (track the `unsafe` libc surface over time).
- Consider Semgrep / MIRAI rules for sudo-proxy-specific anti-patterns: any
  `sh -c` on the privileged path, any display field that reaches `/dev/tty`
  without passing `has_dangerous_chars`.

This turns F1-class regressions (a display field skipping sanitization) into
build failures rather than findings in the next audit.

### Rung 2 — Property-based testing as explicit specifications

sudo-proxy already fuzzes `shell_escape` and `parse_age`. Reframe these as
**named properties** (proptest / quickcheck) that read like clauses of the
specification:

- freshness is monotone (a stale timestamp never becomes fresh — regressions
  #11/#14);
- `shell_escape` round-trips through `/bin/sh` byte-for-byte;
- every field displayed at the approval prompt is dangerous-char-free;
- `privileged:true` ⇒ an interactive keypress occurred before exec;
- the `confirm_unprivileged` policy flag is flippable *only* by an interactive
  keypress, never by a request field.

This is the cheap bridge to formal methods: these properties become the proof
obligations for the higher rungs.

### Rung 3 — Lightweight / automated formal methods on Rust

Two tools fit sudo-proxy directly and require no proof-engineering background:

- **Kani** (bit-precise bounded model checker): verify that the
  attacker-controlled parsers (`parse_age`, base64 decoding, request decoding)
  have *no* panic, overflow, or integer-wrap for all inputs up to a bound —
  strictly stronger than fuzzing for the bounded domain, and fully automatic.
- **Flux** (refinement / liquid types for Rust): annotate the validation
  boundary so the type system enforces invariants such as "a `Request` reaching
  `dispatch` has passed `validate_request`." This makes an F1-style omission (a
  field that skips sanitization) a *type error* rather than a runtime gap.

**Status: done.** As built, Rung 3 keeps the Kani half and *replaces* the Flux
half with a stable-Rust typestate (rationale below).

- **Kani** — `src/proofs.rs` (a `#[cfg(kani)]` module, compiled only by
  `cargo kani`) re-drives the Rung 2 predicates with `kani::any()`:
  - `ymd_hms_to_epoch_is_total_and_panic_free` proves the `parse_age`
    arithmetic core — extracted into `datetime::ymd_hms_to_epoch` precisely so
    the `SystemTime::now()` side effect stays out of the proof — total and
    panic/overflow/wrap-free over the *entire* `u64^6` domain (unbounded, so
    strictly stronger than the Rung 2 fuzz). This is the machine-checked closure
    of the issue-#11/#14 integer-underflow class.
  - `ymd_hms_to_epoch_is_monotone_on_valid_dates` proves the parser is monotone
    in calendar order — a later civil datetime never maps to a smaller epoch, so
    an earlier timestamp can never be judged *fresher* (the general invariant the
    issue-#11/#14 stale-not-fresh case is one witness of). Proven over well-formed
    dates in `1970..=2099` (the window where the approximate leap rule is exact,
    and the domain the freshness path's `epoch_to_iso` actually produces). This
    discharges the Rung 2 `freshness_is_monotone` predicate, which only sampled
    the round-trip.
  - `has_dangerous_chars_matches_spec_per_char` proves the display-field scanner
    panic-free and exactly matching its documented danger ranges, per character.
  - *Scope, stated plainly:* Kani covers our arithmetic and our scanner. The
    base64 and `serde_json` decode paths are **out of scope** — they are upstream
    crates returning `Result`, and our call sites contain no `.unwrap()` on them
    (`if let Ok`/`?` throughout), so their panic-freedom is the upstream
    obligation; symbolically model-checking serde/base64 is intractable.
  - CI: `.github/workflows/kani.yml` runs the proofs non-gating (geiger-style).
    Kani manages its own toolchain, so the `rust-toolchain.toml` pin and the
    gating jobs are untouched. Local run: `cargo install --locked kani-verifier
    && cargo kani`.

- **Flux — assessed and rejected for this rung.** Flux refinements reason over
  integers, indices, and booleans, *not* string contents, so the actual F1
  invariant ("every prompt-displayed field is free of control/bidi characters")
  is not expressible as a Flux refinement; Flux also requires an experimental
  private nightly toolchain that the Rung 1 pinned-toolchain / `cargo-deny` gates
  would have to accommodate. The roadmap's stated *goal* — make "a request
  reaching `dispatch` skipped validation" a type error — is instead met in stable
  Rust by a **typestate newtype**: `protocol::ValidatedRequest` wraps a private
  `Request`, its only constructor is the validating `ValidatedRequest::validate`,
  and `executor::exec_*` plus `tui::Prompter::prompt` accept *only*
  `&ValidatedRequest`. Reaching dispatch or the approval prompt with an
  unvalidated request is therefore a compile error, not a runtime gap — the F1
  closure "by construction" the rung asked for. Flux remains available to a later
  rung for the numeric/index refinements it *is* suited to.

- **Residuals carried past Rung 3** (recorded so the assurance argument stays
  honest about proven-vs-tested):
  - *`validate` field coverage.* The typestate proves `validate` is *invoked*
    before dispatch, and Kani proves `has_dangerous_chars` is correct — but that
    `validate` applies the scanner to *every* displayed field (argv, env
    keys/values, reason/session/host/version/id) and rejects empty pipelines is
    covered **only by the Rung 2 property test**, not by proof. A future edit
    dropping a field from the loop would be caught by that test alone. Formal
    discharge is a **Rung 5** Creusot contract on `validate`.
  - *base64 / `serde_json` decoding.* Out of Kani scope as above; their
    panic-freedom rests on the upstream crates' `Result`-returning APIs and our
    `.unwrap()`-free call sites — an assumption, not a proof.

### Rung 4 — Protocol-level formal verification

The most interesting properties are temporal and relational, not per-function:

- Model the **approval state machine** — request → freshness check → dedup →
  prompt → keypress → exec, plus the `confirm_unprivileged` policy transition
  (finding F2) — in **TLA+/PlusCal** or **Alloy**, and model-check: replay is
  impossible; no exec without approval; the policy flag transitions *only* on an
  interactive keypress (never via a request field, replay, or MCP tool flag).
- For the A3 / SSH-tunnel path, model freshness + replay + channel assumptions
  in the symbolic-protocol provers **Tamarin** or **ProVerif**. These are the
  standard instruments for "what does the tunnel actually guarantee," and they
  will surface the first-contact MITM gap the audit noted (the ssh invocation
  sets no `StrictHostKeyChecking`).

**Status: done.** Both halves are built and run non-gating in CI
(`.github/workflows/tlc.yml`, `proverif.yml`), mirroring the Rung 3 Kani job.

- **Approval state machine — TLA+/PlusCal** ([`proofs/tla/`](../proofs/tla/),
  checked by TLC). The PlusCal transcribes the `handle_connection` gate chain and
  `tui::classify_key`; a nondeterministic environment process quantifies over all
  attacker field-forgeries / replays *and* all operator keypresses. Four safety
  properties hold: `NoExecWithoutApproval`, `ReplayImpossible`,
  `PolicyFlipsOnlyOnKeypress` (+ a `FlagMonotone` action property), and
  `PrivilegedGateIndependentOfPolicy` — discharging the 1.4/4.4 policy-transition
  residual. Properties are tracked by bounded *monitor variables* so the state
  space is finite without a history bound; four documented negative-control
  mutations each produce the expected counterexample (the model has teeth). Full
  faithfulness ledger in [`proofs/tla/README.md`](../proofs/tla/README.md).
  - **Decision: TLA+/PlusCal over Alloy.** The properties are temporal/safety
    over an evolving state machine, which TLC checks directly; Alloy's relational
    style fits structural questions less well here.

- **SSH path — ProVerif** ([`proofs/proverif/`](../proofs/proverif/)). A symbolic
  Dolev-Yao model with a compile-time `PINNED` toggle (via `m4`): the tunnel is a
  private channel when the host key is pinned, public when not. It proves channel
  authenticity and payload/agent secrecy hold **iff** the key is pinned, exhibits
  a concrete **first-contact MITM** trace when it is not (leaf 4.2), and proves a
  **separation theorem** — a privileged exec at the honest remote requires a human
  keypress even with the channel fully compromised. This makes assumption A4
  load-bearing and explicit. Scope and the honest note on injective replay (a
  ProVerif private-channel over-approximation, discharged instead by the TLA+
  `ReplayImpossible` + Kani freshness proofs) are in
  [`proofs/proverif/README.md`](../proofs/proverif/README.md).
  - **Decision: ProVerif over Tamarin.** The model's job is one binary toggle
    plus producing an attack derivation, which ProVerif's applied-pi calculus
    expresses with least ceremony and proves fully automatically; Tamarin's
    unbounded-state / inductive strengths aren't needed.

- **Scope / residuals carried past Rung 4:** the TLA+ model abstracts the clock,
  env contents and decode to booleans and never-evicts the replay set
  (conservative for replay); concurrency/TOCTOU and per-field content scanning
  stay with their other rungs. The ProVerif model treats SSH crypto as a perfect
  black box and abstracts time to nonces + ordering. The two *accepted* residuals
  (the by-design unprivileged auto-approve, and the A4 first-contact dependency)
  are now formally **characterised**, not closed.

### Rung 5 — Deductive verification of the core (EAL5–7 territory)

For the few functions that *are* the invariant, prove functional correctness
with a deductive verifier — **Creusot** (→ Why3 / SMT), **Verus**, or **Prusti**
(→ Viper / separation logic). Targets: `validate_request`, the dispatch path,
and the environment-allowlist enforcement, each proved against contracts derived
from the Rung 2 properties. This is genuine proof-engineering effort: scope it
to the smallest trusted core, not the whole tree.

### Rung 6 — End-to-end machine-checked refinement (aspirational endpoint)

The **seL4** methodology — an abstract specification, a refinement chain, and a
machine-checked proof that the implementation refines the spec, with the trust
assumptions (the C compiler, the hardware) stated explicitly — is the reference
model for "fully formally verified." For sudo-proxy the honest version states
plainly what stays *unverified-by-assumption*: the terminal / `/dev/tty`, `sudo`
itself, the kernel, SSH — and proves that the daemon's own logic refines the
abstract approval spec. This is a research-grade goal; even unrealised, its
value is forcing a complete enumeration of the trust assumptions.

## The MCP / LLM-specific layer

A1 is a prompt-injected caller, so the requirements must be anchored to current
agentic-AI guidance, not only classic application security. The **OWASP Top 10
for LLM Applications** (prompt injection is the #1 entry) and the **OWASP MCP
Security Cheat Sheet** name four controls: *structured tool invocation*,
*human-in-the-loop checkpoints*, *LLM-as-a-judge approval*, and *context
compartmentalization*. sudo-proxy is essentially a hardened implementation of
the first two — structured argv that is never a shell string, and a mandatory
human-in-the-loop gate on every command. Cite these as the source of the
human-in-the-loop SFRs, and track the MCP-era attack patterns: **tool
poisoning** (malicious instructions in tool descriptions) and **rug-pull**
description mutation. The latter maps directly onto finding F2's "remember this
command" auto-approve risk — the moment an auto-approve surface exists, the
prefix-matching escapes documented in the
[architecture allowlisting note](architecture.md) become live.

## Recommended near-term sequence

1. **Done** — the **GSN assurance case** ([assurance-case.md](assurance-case.md))
   and the **Rung 0 threat model** ([threat-model.md](threat-model.md)) convert
   the existing `security.md` / `security-audit.md` prose into the formal
   model / threats / requirements / constraints artifact, with no code change. A
   full CC-structured **Security Target** document is the remaining paper step.
2. **Done** — CI-ified Rung 1 and turned the existing fuzz tests into **named
   properties** (Rung 2).
3. **Done** — **Kani** on the parsers (Rung 3) and a **TLA+/PlusCal** model of
   the approval + policy state machine plus a **ProVerif** model of the SSH path
   (Rung 4) — the highest assurance-per-effort steps, directly targeting findings
   F1/F2, the replay invariant, and the A4 first-contact gap.
4. Treat **Creusot / Verus** (Rung 5) and **seL4-style refinement** (Rung 6) as
   a stated long-horizon goal in the assurance case, with the trust assumptions
   written down now.

## Mapping summary

| Rung | Technique | Tools | sudo-proxy target | CC analogue |
|------|-----------|-------|-------------------|-------------|
| 0 ✓ | Threat modelling | STRIDE, attack trees ([threat-model.md](threat-model.md)) | A1/A2/A3 per boundary B1–B6 | ST threats |
| 1 | Review + static analysis | clippy, cargo-audit, cargo-deny, cargo-geiger, Semgrep/MIRAI | display sanitization, `unsafe` surface | EAL1–3 |
| 2 | Property-based testing | proptest, quickcheck | `shell_escape`, `parse_age`, display fields, policy flag | EAL3–4 |
| 3 | Automated formal | Kani, Flux | parsers (no panic/overflow), validation boundary | EAL4–5 |
| 4 ✓ | Protocol verification | TLA+/PlusCal (TLC), ProVerif ([`proofs/`](../proofs/)) | approval state machine, replay, SSH path | EAL5–6 |
| 5 | Deductive verification | Creusot, Verus, Prusti | `validate_request`, dispatch, env allowlist | EAL6–7 |
| 6 | Machine-checked refinement | seL4-style (Isabelle/Coq, Iris) | daemon logic refines abstract approval spec | EAL7 |

## References

- Surveying the Rust Verification Landscape — <https://arxiv.org/pdf/2410.01981>
- Rust Formal Methods Interest Group — <https://rust-formal-methods.github.io/>
- Flux: Liquid Types for Rust — <https://arxiv.org/pdf/2207.04034>
- Common Criteria CC:2022 Part 5 (assurance) —
  <https://www.commoncriteriaportal.org/files/ccfiles/CC2022PART5R1.pdf>
- Common Criteria EAL 1–4 (CCLab) —
  <https://www.cclab.com/news/common-criteria-evaluation-assurance-levels-from-eal-1-to-eal-4>
- ISO/IEC 15408 overview — <https://pacificcert.com/iso-15408-evaluation-criteria-it-security/>
- Assurance Case overview (ScienceDirect) —
  <https://www.sciencedirect.com/topics/computer-science/assurance-case>
- Model-Based System Assurance with SACM — <https://arxiv.org/pdf/1905.02427>
- GSN for safety / security cases (SAFER Autonomous Systems) —
  <https://etn-sas.eu/2020/06/26/assurance-case-notations/>
- OWASP MCP Security Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html>
- MCP Prompt Injection Controls: HITL & LLM-as-Judge (FlowHunt) —
  <https://www.flowhunt.io/blog/mcp-prompt-injection-controls-hitl-llm-judge/>
- Prompt Injection in 2026 — OWASP #1 LLM vulnerability —
  <https://www.kunalganglani.com/blog/prompt-injection-2026-owasp-llm-vulnerability>
