# Security policy

sudo-proxy grants an AI agent a gated path to `root`. We take reports
seriously and we welcome adversarial scrutiny.

> **Not yet independently audited.** The security assurance in this repository
> is self-produced (threat model, static-analysis gating, property tests, Kani
> bounded proofs, TLA+/ProVerif models). It has **not** had an independent
> third-party review. If you would like to do — or fund — one, please get in
> touch (below).

## Reporting a vulnerability

Please report privately, not in a public issue:

- **Preferred:** GitHub **private vulnerability reporting** — open
  <https://github.com/tarides/sudo-proxy/security/advisories/new>. This keeps
  the report confidential and gives it a place to be tracked and fixed.
- **Alternative:** contact the maintainer, [@cuihtlauac](https://github.com/cuihtlauac).

**Response:** best-effort. This is not a funded program with a guaranteed SLA;
expect an acknowledgement within a few days. We will keep you informed as we
triage, and we are happy to credit you in the advisory unless you prefer
otherwise.

## What we're most interested in

Before reporting, [REVIEWING.md](REVIEWING.md) lists the falsifiable security
claims (C1–C7) and — more usefully — the areas that carry **no** assurance
(the TUI rendering layer, human comprehension of long commands, SSH
first-contact, the handoff to `sudo`/`/dev/tty`/kernel). Breaking any numbered
claim, or an attack in an unassured area, is exactly the kind of report we want.

## Scope

In scope: the daemon (`sudo-proxy`), the MCP server (`sudo-proxy-mcp`), the
approval TUI, the wire protocol, and the SSH-tunnel path — anything that could
let a privileged command run that the human did not deliberately approve, or
that undermines the invariant in [REVIEWING.md](REVIEWING.md).

Out of scope (trusted by assumption, documented in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)): `sudo`/`pkexec`
themselves, the kernel, the terminal emulator, and SSH's own cryptography. A
report that reduces to "we assume `sudo` is correct" is a known, stated
assumption rather than a finding — but if you can show the *handoff* to `sudo`
is exploitable, that is in scope.

## Supported versions

Security fixes target the latest released version. See
[crates.io](https://crates.io/crates/sudo-proxy) and
[releases](https://github.com/tarides/sudo-proxy/releases).
