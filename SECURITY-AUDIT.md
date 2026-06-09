# Security Audit — sudo-proxy

**Date:** 2026-06-09
**Scope:** Full source tree (`src/`, binaries, dependencies). Comprehensive +
adversarial methodology: per-boundary finders, each candidate finding attacked by
two independent skeptics, plus dependency/`unsafe`/lint sweeps and randomized
fuzzing of the attacker-controlled parsers.
**Version audited:** 0.11.2 (`Cargo.toml`).

## Summary

`sudo-proxy` escalates to root after a single human keypress at a TUI prompt, driven
by an MCP caller that must be treated as adversarial (prompt injection). The whole
security model reduces to one invariant: **nothing privileged runs without a human
deliberately approving the exact command shown.**

The core mechanics are sound: command construction never uses a shell on the
privileged path; the multi-stage `shell_escape` survives heavy fuzzing; the
environment allowlist hard-rejects `LD_PRELOAD`/`IFS`/etc.; socket auth
(`SO_PEERCRED` + 0600), replay protection, and timestamp-freshness all hold up; and
dependencies carry no known advisories.

The one structural weakness is in the **approval prompt's display integrity**: the
control-character/bidi sanitization that protects `pipeline` and `env` is *not*
applied to the other request fields rendered to the terminal (`reason`, and — for a
direct socket client — `session`/`host`/`id`/`version`). This lets an attacker inject
raw ANSI/escape sequences into the root-approval prompt and misrepresent what is being
approved. This is the project's own threat (it already blocks bidi overrides on argv
for exactly this reason); the fix re-applies that existing control consistently.

## Threat model

- **A1 — Malicious/prompt-injected MCP caller.** Controls `argv`, `pipeline`, `env`,
  `host`, `description`(→`reason`), `privileged`, `forward_agent`, `timeout`.
- **A2 — Same-UID local process.** The socket is `0600` + `SO_PEERCRED`-gated to the
  daemon UID, so any process running as the user can connect *directly*, bypassing the
  MCP layer (and therefore bypassing MCP-side `validate_host`).
- **A3 — Network MITM / malicious remote.** On the SSH path or controlling the remote
  end.

## Findings

| ID | Severity | Title | Attacker | Status |
|----|----------|-------|----------|--------|
| F1 | **High** | Approval-prompt ANSI/control-char injection via unvalidated display fields | A1, A2 | **Fixed** |
| F2 | Low | `confirm_unprivileged=false` runs later commands with only a best-effort banner | A1, A2 | Accepted-risk / doc |
| F3 | Low | Approval prompt has no length bound; huge argv can push the command off-screen | A1 | **Fixed** |
| F4 | Low | `hosts.json` created world-readable (0644); leaks host inventory/UIDs/policy | A2 | **Fixed** |
| S1 | Low | Signal handler calls `CString::new` (malloc) — not async-signal-safe | local | **Fixed** |
| S2 | Info | `burst_connections_above_cap` test is timing-flaky (~2/3 fail) | — | Note (open) |

**Fixes applied (this audit):** F1, F3, F4, S1 — each with a regression test;
`cargo build --release --features mcp` and the full suite pass (the only failing
test is the pre-existing, unrelated flaky S2). F2 and S2 remain open as a
documentation change and a test-stabilization task respectively.

---

### F1 — Approval-prompt injection via unvalidated display fields (High)

**Location:** `src/server.rs:70-98` (`validate_request`), `src/tui.rs:87-101`
(`prompt_tty` renders `session`/`host`/`version`/`id`/`reason`), `src/mcp.rs:188`
(`reason = params.description`).

**The gap.** `validate_request` runs `has_dangerous_chars()` — which rejects control
chars `0x00-0x1F` (except tab), zero-width chars, and bidi overrides — over every
`pipeline` argument and every `env` key/value. It does **not** run it over
`req.reason`, `req.session`, `req.host`, `req.version`, or `req.id`. Yet `prompt_tty`
writes all of those straight to `/dev/tty`:

```
src/tui.rs:91   "From:    {} @ {}", req.session, req.host
src/tui.rs:95   "Client:  sudo-proxy {client_ver}"     // req.version
src/tui.rs:99   "ID:      {}", req.id
src/tui.rs:101  "Reason:  {bold}{}{reset}", req.reason  // attacker-controlled, raw
```

`validate_host` (which would reject metacharacters/control in `host`) is only called
in `src/mcp.rs` and `src/bin/sudo-proxy.rs` — i.e. on the client side. A **direct
same-UID socket client (A2)** never passes through it, so `host`/`session`/`id`/
`version` are also attacker-controlled and unvalidated at the daemon.

**Attack path.**
1. A1 calls the `execute` tool with a crafted `description`; it becomes `req.reason`
   verbatim (`mcp.rs:188`) and is displayed raw (`tui.rs:101`). (A2 can additionally
   poison `session`/`host`/`id`/`version` via a direct socket request.)
2. Because the control-char filter never sees these fields, `reason` may contain raw
   `ESC` (`0x1B`), `CR`, `LF`, and bidi characters.
3. With ANSI sequences the attacker actively hides the truth rather than relying on
   look-alikes: e.g. emit a convincing fake `Command: apt-get update` block within the
   reason, then `\x1b[8m` (conceal) / a scroll-region / colour-match so the real
   `Command:` line printed afterward is invisible or buried; or flood newlines to push
   the real command and the `[y/N]` line out of view.
4. The human approves what looks benign; the *real* `pipeline` (privileged) executes
   as root.

**Why it's real / severity.** The validated fields prove the designers treat
display-deception as in-scope (bidi overrides are blocked on argv precisely to stop
viewer deception). `reason` is simply the field that escaped that control, and it is
the most attacker-controllable one over MCP. Rated **High** because the target is a
root-escalation gate and the deception can be *active* (ANSI conceal/scroll-region),
not merely a passive look-alike.

*Adversarial dissent (recorded for honesty):* both skeptics argued the practical
impact is lower (Low–Medium) because (a) the command line is printed *after* `reason`,
so `reason` cannot retroactively overwrite it, and (b) a careful human who reads the
whole prompt still sees the real command. This is fair for the trivial "overwrite"
variant; it does not neutralize the conceal/scroll-region/newline-flood variants, and
the fix is cheap and clearly intended either way.

**Remediation (proposed fix).** In `validate_request`, additionally reject
`has_dangerous_chars()` in `req.reason`, `req.session`, `req.host`, `req.version`, and
`req.id`. This re-applies the existing control consistently, fails the request early,
and covers both the MCP and direct-socket paths. Residual after fix: printable-range
Unicode look-alikes/NBSP in `reason` — a far weaker, passive social-engineering vector
that cannot hide the real command (documented, see F3 for the length dimension).
Regression test mirrors the existing argv bidi/control tests in `tests/validation.rs`.

---

### F2 — `confirm_unprivileged=false` silent execution (Low, by-design)

**Location:** `src/server.rs:631-662`, `src/hosts.rs` (policy persistence).

Once a human presses `a` at an unprivileged prompt, `policy.confirm_unprivileged` is
set `false` and persisted; subsequent **unprivileged** requests skip the Y/N gate and
run after only a best-effort banner (`display_banner`, printed under a `try_lock`, so
it may not appear under TTY contention). An "unprivileged" command still runs arbitrary
code *as the user* — read private files, rewrite `~/.ssh/authorized_keys`, install
cron/systemd-user units, `curl … | sh`. A1/A2 can drive these with misleading
descriptions and no prompt.

This is a deliberate trust trade-off, correctly never relaxing the **privileged**
gate (verified: `privileged:true` always prompts regardless of policy; only an
interactive keypress can set the policy — no request field, replay, or MCP tool flips
it). Severity **Low**: the residual risk is real but gated behind an explicit human
choice. Recommendations: (1) state the residual risk plainly in the README and at the
`a`-key prompt (it currently reads as benign); (2) make the post-trust banner reliable
(don't drop it on `try_lock` failure) so silent execution is always at least visible.

---

### F3 — Unbounded command display (Low, defense-in-depth)

**Location:** `src/tui.rs:12-32` (`shell_join`/`pipeline_join`), `tui.rs:109-113`.

`pipeline_join` concatenates all stages with no length cap and `prompt_tty` writes it
in a single `writeln!` with no terminal-width handling. A single multi-kilobyte
argument wraps over many lines and can push the `Command:` line and the `[y/N]` prompt
off-screen. Same display-integrity theme as F1. The codebase already truncates command
*output* (`print_truncated`, `MAX_DISPLAY_LINES`) but not the command itself.
Recommendation: cap the displayed command length (with an explicit `… (N bytes
hidden)` marker) and/or reject individual arguments above a sane size for display.

---

### F4 — `hosts.json` world-readable (Low, info disclosure)

**Location:** `src/hosts.rs:311-335` (`save_to`).

`save_to` uses `create_dir_all` + `File::create` with no umask tightening, so on a
typical `umask 022` the config lands at mode `0644` (file) / `0755` (dir). By contrast
the socket path explicitly tightens `umask(0o077)` around bind. `hosts.json` holds the
host inventory, cached remote UIDs, and the `confirm_unprivileged` policy — readable by
*other* local users on a shared host. No escalation (others cannot write it: file 0644,
dir owned by the user), and no impact on single-user systems. Severity **Low**.
Remediation (proposed fix): tighten `umask` around the write and/or `chmod` the file to
`0600` and the directory to `0700`, mirroring the socket-bind pattern.

---

### S1 — Signal handler is not async-signal-safe (Low)

**Location:** `src/bin/sudo-proxy.rs:208-220` (`signal_hook_cleanup::handler`).

The handler comment says "Only async-signal-safe operations here", but
`CString::new(path.to_string_lossy().as_bytes().to_vec())` allocates (malloc) inside
the handler. If a signal interrupts an allocation, the handler's malloc can deadlock,
hanging daemon shutdown. Impact is limited to shutdown robustness (not a security
boundary). Remediation: precompute the `CString` at registration time and store it in
the `OnceLock`, so the handler only calls the async-signal-safe `libc::unlink` on a
pre-built pointer.

---

### S2 — Flaky resource-cap test (Info)

`tests/concurrency.rs:burst_connections_above_cap_get_busy_response` fails ~2 of 3
runs locally — the *setup* assertion "in_flight reached ≥4" times out (it reached 3),
not the security assertion. The underlying control (reject with "busy" once
`in_flight == max_in_flight`, single-threaded accept loop, `InFlightGuard` on unwind)
is sound; this is a test-timing assumption, not a product defect. Worth stabilizing so
the cap stays covered by CI.

## Verified controls (attacked and found adequate)

- **No shell on the privileged path.** Single-stage `sudo`/direct exec build argv via
  `Command::arg`/`env`; no `sh -c`. (`executor.rs:223-270`)
- **`shell_escape` (multi-stage `sh -c`).** Fuzzed with 5000 random metacharacter-heavy
  inputs + targeted vectors (`$(...)`, backticks, `'; …`, embedded quotes), each
  round-tripped through `/bin/sh` byte-for-byte. No break. (`executor.rs:764`; harness
  in `executor::tests::fuzz_shell_escape_roundtrips_through_sh`)
- **Env sanitization.** Hard-reject allowlist (`LANG TZ HOME DEBIAN_FRONTEND TERM
  LC_*`); `LD_PRELOAD`/`LD_*`/`IFS`/`BASH_ENV`/`SSH_AUTH_SOCK` rejected, not stripped;
  login defaults (PATH/USER/LOGNAME) sourced from `getpwuid(geteuid())`, not the
  request; caller `HOME` override is visible in the prompt. (`executor.rs:40-117`)
- **Timestamp freshness / anti-replay.** `parse_age` fuzzed with 20000 random + extreme
  inputs: never panics, uses `checked_*` throughout, stale timestamps stay stale (no
  integer-wrap freshness bypass — regressions #11/#14). `SeenIds` check-and-insert is
  atomic; freshness is checked at handler entry before the prompt wait.
  (`server.rs:104-218,260-306`; harness in `server::tests::fuzz_parse_age_*`)
- **Socket auth.** `SO_PEERCRED` read from the accepted connection; cross-UID rejected;
  0600 bind via umask-around-bind + chmod (no TOCTOU). (`server.rs:308-362,499-511`)
- **Resource limits.** 1 MiB request cap (saturating), 64 in-flight (checked before
  thread spawn), 16 MiB per-stream output cap. (`server.rs`, `executor.rs`)
- **Host/SSH (A3).** `validate_host` allowlist `[A-Za-z0-9._@:-]`, rejects leading `-`
  (ssh option-injection) and metacharacters; ssh invoked via argv (no `sh -c`); host is
  a trailing positional after `-o` options; remote UID is digit-only + length-capped
  before entering a socket path. (`server.rs:244`, `sudo-proxy.rs`, `hosts.rs:129`)
  *Operational note:* the ssh invocation sets no `StrictHostKeyChecking`, so
  first-contact MITM depends on the user's ssh config — document the requirement that
  remote hosts be in `known_hosts` before use, or pin `StrictHostKeyChecking=accept-new`.
- **Agent forwarding.** `forward_agent` defaults false; privileged+forward_agent
  hard-rejected; request-supplied `SSH_AUTH_SOCK` rejected; socket sourced from the
  daemon's own env. (`server.rs:549-556`, `executor.rs:263-266`)

## Dependency & tooling results

- **`cargo audit`:** 101 crate dependencies scanned, **0 advisories** (RUSTSEC db).
- **`cargo clippy --all-targets --all-features`:** clean of security-relevant lints;
  only style suggestions (`is_multiple_of`, `Default` impl, collapsible `if`).
- **`cargo deny`:** not installed locally; recommend adding to CI for license/ban/source
  policy in addition to advisories.
- **`unsafe` inventory:** all blocks are thin `libc` FFI (`getpwuid`, `geteuid`,
  `setpgid`, `setsid`, `umask`, `SO_PEERCRED`, `tc[gs]etattr`, `poll`, `read`,
  `pre_exec`, signal handling). Invariants hold except **S1** (handler allocation).

## Methodology notes

Phases 1–2 ran as a multi-agent workflow: six finders (one per trust boundary) reading
the relevant files in full, then two independent skeptics per candidate finding,
prompted to refute. A finding was kept only if not unanimously refuted; severities here
reflect auditor judgment reconciled against the skeptic votes (notably F1, raised back
to High). Phase 3 (deps/lint/`unsafe`) and Phase 4 (parser fuzzing) ran directly. Fuzz
harnesses are committed as ordinary `#[cfg(test)]` tests so they run under `cargo test`
and guard against regressions.
