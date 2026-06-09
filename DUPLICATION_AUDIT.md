# Code Duplication Audit — sudo-proxy

Prompted by review feedback that the codebase carried copy-pasted logic
(notably `is_leap` defined in several places). This is the measured baseline,
the remediation applied, and the result.

## Metric

The industry-standard measure is **duplicated-lines density** (popularized by
SonarQube):

```
duplicated_lines_density (%) = duplicated lines / total lines × 100
```

Detection is **token-based clone detection** with thresholds `--min-tokens 50`,
`--min-lines 5`, run with `jscpd`/`cpd` over all tracked `*.rs`
(`scratch/creusot/` is gitignored third-party tutorial code and is excluded).

## Before → After

| Metric                     | Before  | After   | Δ            |
|----------------------------|---------|---------|--------------|
| Duplicated lines (density) | 206 (**2.82%**) | 133 (**1.85%**) | **−35%** |
| Duplicated tokens          | 1738 (3.86%) | 1222 (2.78%) | −30% |
| Clone blocks               | 22      | 18      | −4 |
| Total lines (tracked)      | 7298    | 7179    | −119 (despite +2 new modules) |

## What was de-duplicated

| Concept | Before | Fix |
|---|---|---|
| Epoch→date math (`now_iso8601`/`days_to_ymd`/`is_leap`) — the largest clone (50L/317T) | 5 copies (`hosts`, `mcp`, `sudo-request`, inline in `server::parse_age`, test `iso_format`) | New `src/datetime.rs`; all sites call it |
| `default_true` serde default | 3 copies | One `protocol::default_true` |
| `--version` handler | 4 copies | `cli::print_version` |
| `SUDO_*_TIMEOUT_SECS` env lookup | 2 copies | `cli::env_timeout` |
| `Request { id/time/version … }` builder | 2 copies | `Request::new` (centralizes the id/time/version invariant) |
| `HostInfo { …all empty… }` literal | 4 copies | `#[derive(Default)]` + `.or_default()` |
| Test `which_or_skip` / base64 stdout decode | 2 copies each | Shared in `tests/common/mod.rs` |

## Accepted remaining duplication (deliberately not refactored)

The 18 remaining clones are tight, context-specific blocks where extraction
would obscure more than it shares:

- **Per-binary arg-parsing loops** — flag sets differ; only the shared
  primitives (`--version`, timeout) were extracted. Unifying on `clap` was out
  of scope.
- **Test scaffolds** (10 of the 18) — two-client concurrency timing harnesses,
  raw-socket edge-case blocks, and env-override preludes. Each carries unique
  timing/assertion logic.
- **`executor`/`server`/`tui`/`mcp` internal blocks** — fd/pipe setup, socket
  timeout calls, render blocks, and MCP tool-handler boilerplate. Candidates for
  a later pass, not behavior-preserving one-liners.

## Verification

`cargo build` (core) and `cargo build --features mcp` both clean; full test
suite green on both feature sets (one timing-sensitive concurrency test flaked
once under parallel build load, passes 3/3 in isolation). `--version` confirmed
on all four binaries.
