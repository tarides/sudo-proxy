# Backlog

Ordered; the first item is the current/next task. One item per session — capture
unrelated ideas at the end, don't chase them mid-session. Items below continue
the assurance ladder defined in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md); each names its
rung.

## 1.3.0 critical path: #105, then #101, then `v1.3.0-rc.1`

Tracked in [#89](https://github.com/tarides/sudo-proxy/issues/89) (release
plan). Done before this: 1.2.3 (GHSA-gx9w-4f7x-2gcp, helpers never looked up
on the daemon's PATH), merged into `main` in #106; #107 (root-owned sticky
directories accepted in the helper check, so `--pkexec` works on NixOS).

1. **#105: resolve each program once and pin it** from the `no_shell` check
   through the prompt to the spawn: path, canonical target and `(dev, ino)`,
   refusing the spawn if the identity changed. Wrapped programs
   (`env VAR=… just`, `nice`, `timeout`) are pinned too, by rewriting the
   wrapped word to its resolved absolute path (basename kept; applets
   excluded). `#!` scripts cannot go through `fexecve` on a close-on-exec fd
   (`ENOENT`), so they need a path-based spawn plus the identity check. No
   security impact on its own today (see the issue); a prerequisite for #101.
2. **#101: `--inherit-path` / `--inherit-env=PATTERN,…`.** The design was
   reviewed twice and posted on #101
   ([comment](https://github.com/tarides/sudo-proxy/issues/101#issuecomment-7161219003),
   "Full design" section); that comment is the spec. It includes two changes
   outside the flags: the `env -C` probe (`env_supports_chdir`) clears its
   environment and sets `PATH` to `HELPER_PATH`, and the `sudo` process gets a
   cleared environment (`TERM`, `LANG`, `LC_*` only) for every daemon, with a
   changelog note. Build #105 and #101 together if that avoids reworking
   resolution twice.
3. **Tag `v1.3.0-rc.1`** (release flow: version bump in `Cargo.toml` and the
   three JSON files, tag). The #101 reporter tests it; also run `--pkexec` on
   a real NixOS host, since #107 was only reproduced in a container.

Housekeeping: the remote daemons on the registered hosts still run an older
version until restarted (binaries are 1.2.3). Local branches `release/1.2.3`,
`merge/release-1.2.3` and `fix/helper-sticky-dirs` are merged and can be
deleted.

## Automate the manual end-to-end tests through a pty

Issue [#68](https://github.com/tarides/sudo-proxy/issues/68). The checks in
[docs/testing.md](docs/testing.md) (real daemon, real TUI prompt, keypress by
hand) and the `tests/manual/ui/*.json` display checks are verified only by eye;
the integration suite stops at `ScriptedPrompter`. A proof of concept drove the
real daemon under `script(1)` with keys fed through a FIFO, and a fake `sudo` on
`PATH` covered the privileged path. Plan:

Plan, revised after a code review (full notes in the
[issue comment](https://github.com/tarides/sudo-proxy/issues/68#issuecomment-6952577695)):

1. **PR 1 — harness + 3 scenarios.** Done in #69: `tests/common/pty.rs`,
   `tests/shims/sudo`, `tests/pty_e2e.rs` (approve, deny, privileged approve).
   #72 reused it for the advisory regressions (`tests/pty_policy.rs`,
   `tests/pty_future.rs`); `pty_policy.rs` already checks that `a` is
   *offered* only with a trusted `hosts.json` policy.
2. **PR 2 — goldens.** Done: `tests/pty_ui_golden.rs` snapshots the prompt for
   `tests/manual/ui/*.json` (colour and `NO_COLOR`) into
   `tests/manual/ui/golden/`, regenerated with `UPDATE_GOLDEN=1`, and asserts the
   escalation colours directly.
3. **PR 3 — remaining scenarios:** done in `tests/pty_unattended.rs`: `a`, with
   and without `--unattended-eligible` (grant keyed by session), and the
   timeout, `#[ignore]`d (a real 60 s wait; no prompt-timeout knob on the human
   gate). The `--no-shell` scenario (asserted by ordering) goes with the feature
   in PR #67.
4. **Extras:** stray input before the prompt is flushed; termios is restored;
   two prompts on one tty are shown one at a time; the foreground handoff
   doesn't hang; SIGTERM removes the socket; control/bidi characters never
   reach the tty.

Dropped: the `pkexec` shim. The pkexec path clears the env and sets a fixed
`PATH`, so a shim is never found, and that path has no TUI. Separate: a CI job
with real `sudo -n`. Stays manual: how colours, bell and blink look in a real
terminal, real sudo passwords, the pkexec dialog, the remote SSH tunnel.

## Priority #1 — plan-model follow-ups (consolidated)

The next work, pulled to the front. These surfaced while building and
live-testing the structured-plan prompt rework this session; detailed write-ups
remain in the sections further down, linked here. Tackle in roughly this order:

Sub-items "close the `exec sh -c` loophole" and "strict `no_shell` policy mode"
shipped in PR #67 (see changelog).

1. **Shell-tail ops: `detach` and read-file.** A `detach` op (backgrounding +
   structured pid, replacing `nohup … & echo $!` — campaign observation **O1**;
   the only gap that still forced the `system` hatch live) and a read-file op
   (replacing `$(cat /proc/…)`). See *"Structured plan: remaining
   shell-tail gaps"* and the remaining lever of the shell-hatch section.
2. **`sudo-request --print` exit code (O2).** With `--print` the client exits `0`
   even on an error `Response` (it prints the result); without `--print` an error
   exits `1`. Make `--print` propagate a non-zero exit on `Status::Error` /
   `Denied` / `Timeout` (or document the discrepancy). Found during the test
   campaign; had no backlog home until now.
3. **Treat whole-command `privileged` as sugar for an ambient `run-as root`.**
   It already *is* semantically (`compile_plan` seeds ambient root from the flag,
   ≡ a `run-as root` wrapping the whole plan). Steer callers toward per-stage
   `run-as` so pipes stay unprivileged and dodge the sudo-credential-in-pipe
   caveat (the blunt flag escalates *every* leaf, including pipe stages → the
   caveat bites). Consider deprecating the flag once the plan path is primary;
   keep it meanwhile for flat-`pipeline` wire-compat. (Raised in discussion this
   session; not previously recorded.)
4. **Soften the sudo-credential-in-pipe caveat + partial-`run` retry hazard.**
   See *"Partial-`run` retry hazard and the sudo-credential-in-pipe caveat"* for
   the mitigation menu (auth-probe before stateful stages, surface the partial
   boundary so callers resume rather than replay, advisory non-idempotency flag).
5. **`env` wrapper: what remains after #87.** The wrapper-aware unwrap shipped
   (#87): `env VAR=… opam …` now lists `opam`, and wrapped shells /
   interpreters are opaque. Remaining: allow non-allowlisted names in `setenv`
   for non-root subtrees, so callers need no `env` wrapper (corpus cases 06,
   22); and the residuals — `awk`/`sed` `e`/`system()`, `git -c`, `make`,
   `opam exec`, `dune exec` and other open-ended runners, interpreters running
   a script file, env names only some programs interpret (`PYTHONSTARTUP`, …).
6. **pkexec dialog names `/usr/bin/env`** (left over from #88). Use
   `pkexec --keep-cwd` when polkit ≥ 121 (probe once, like
   `env_supports_chdir`), or skip `env -C` when the cwd is the target user's
   home.
7. **Does a single-leaf plan's `setenv` reach the program under `--pkexec`?**
   pkexec resets the environment. If it does not, either pass it as `env K=V`
   arguments (so the dialog shows it) or route `setenv` plans to the TUI and
   sudo. Found in the #88 plan review.

## Cap far-future request timestamps, then re-climb the ladder to Rung 4

The replay-protection residual surfaced **during PR #35** by the Extended Rung 4
`ReplayWindow` TLA+ model (its `NoFutureReplay` invariant exhibits a concrete
trace). `parse_age` (`server.rs:146`) clamps a future-dated timestamp to age 0
with **no upper bound**, so a request dated beyond `REPLAY_RETENTION` into the
future passes the freshness gate indefinitely while its id ages out of
`SeenIds` — making it replayable every retention window *regardless of how large
retention is*. The 60s↔120s window relationship does not help here. Low severity
(needs the request onto the channel — SSH pinning guards that — and privileged
commands still gate the first run on a keypress), but for auto-approved
unprivileged commands it is a real repeatable replay.

**The fix.** In `check_freshness` / `parse_age`, reject timestamps more than a
small clock-skew allowance into the future instead of clamping to age 0.

**Re-climb the ladder to the same level (Rung 4).** The fix touches code that
several already-discharged rungs cover, so re-establish each so assurance
returns to where PR #35 left it — do *not* leave the proofs trailing the code:

- **Rung 1 (CI):** the existing gate should stay green; add a regression test
  for the rejected far-future timestamp.
- **Rung 2 (property):** extend the freshness property in `src/prop.rs` so it
  asserts a sufficiently-future timestamp is *rejected*, not silently fresh.
- **Rung 3 (Kani):** re-drive the `ymd_hms_to_epoch` monotonicity/totality
  proofs against the new gate (the bounded-future rejection must stay
  panic-free over the full domain).
- **Rung 4 (TLA+):** flip the `ReplayWindow` model's `NoFutureReplay` from a
  surfaced-gap witness to a *held* invariant, and re-check the sibling models
  are unaffected.

Done = the code rejects far-future timestamps **and** every rung above is
re-discharged against the fixed code (negative controls re-run where they
exist).

## Rung 5 — Deductive verification of the trusted core

Creusot / Verus / Prusti contracts on `validate_request`, the dispatch path, and
the env-allowlist enforcement, proved against the Rung 2 properties. Scope to the
smallest trusted core, not the whole tree.

## Display fidelity — Option A: daemon-owned syntax, runtime self-check, echo

Tracking issue #89. Decided 2026-11-20 after a display-fidelity review:
callers send only the structured plan, never shell text; the daemon owns every
byte of syntax at the prompt, checks its own rendering against the compiled plan
before prompting, and echoes what was shown back to the caller. Rejected:
caller-supplied bash (displayed or checked; it gives the attacker the syntax
layer and adds a parser of attacker text to the TCB) and bash-as-authoritative
(the daemon becomes a shell; G3.1 falls). The rung-by-rung background is in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md#display-fidelity-across-the-rungs).
One PR per item; each moves its evidence status in `docs/assurance-case.md`;
every prompt-touching PR gets the pty goldens plus a live manual run.

**Phase 0 — close the current gaps** (independent; patch releases 1.2.x):
~~#86 `has_dangerous_chars` gaps~~ (done, see changelog) · #85 bound
each `Steps:` line like `Command:` · #88 `--pkexec` multi-leaf plans (item 6
above) · #87 wrapper-aware `runs_shell` (item 5 above; done).

Done: #88.
Done: #85.
Done: #90.

**Phase 1 — state the invariant, make it literally true** (release 1.3.0):
1. Docs first: G4.6 *"syntax is daemon-owned"* (no wire field printed verbatim
   in the command slot); split Sn4.5 into a syntactic half (render ⇒ shell
   tree) and a semantic half (shell tree ⇒ executor); threat-model rows
   "caller supplies syntax" (blocked by design) and "unknown plan key silently
   dropped"; roadmap gains the self-check and echo rungs.
2. Render `Steps:`/`Command:` from `Compiled`, not a second walk of `Plan`
   (`src/tui.rs` `layout(&req.exec_plan())`). Pure refactor: goldens and audit
   output byte-identical.
3. `deny_unknown_fields` on `Plan` only. `run-as` uses `#[serde(flatten)]`,
   which serde cannot combine with it, so un-flatten via a custom impl that
   keeps the wire form. `Request` stays lenient (documented forward-compat).
4. Echo: optional `shown` + `shown_truncated` in `Response`, the exact
   `Command:` text written to the TTY, for `ok`/`denied`/`timeout` and
   post-validation errors (never pre-validation; omit `Resolves:`). Surfaced by
   `format_response`; MCP tolerates its absence. Property:
   `response.shown == audit.command == TTY text`.
5. Rung-1 lint (Semgrep/grep): request-derived strings reach the TTY only via
   `shquote` or the fixed label lines; review-checklist item for rendering /
   plan-op / composition changes.

**Phase 2 — runtime self-check** (release 1.4.0):
1. `src/shellgram.rs`: in-crate parser for the shell subset the renderer
   emits, test-only at first — `parse(render(P))` = layout tree over
   `random_any`, cross-checked against bash on that subset. Removes bash as the
   oracle for the syntax half.
2. Before prompting, re-parse the text to be shown and compare to the compiled
   plan; fail closed (no bypass flag). Enable only after 2.1 has been green in CI
   for a while.

**Phase 3 — proofs** (no release coupling):
1. Mock spawner → trace-equality differential test (leaf, uid, cwd, env, stdio,
   exit status), covering `run-as` and file redirections / `with-stdin-from` —
   closes the Rung 2 gap. Settle the **failed-`cd` divergence** here (G4.5
   residual: the executor aborts the whole plan, a pasted `Command:` goes on
   past `;`): make them agree or justify it in the assurance case.
2. Kani: validation domain restrictions (no double redirect, stdin only on the
   first pipe stage, absolute paths).
3. Kani (Rung 3): render total and `parse(render(P)) = P` on bounded plans;
   `shquote` round-trip.
4. Rung 5: Creusot/Verus proof that the renderer and the executor refine one
   shell-semantics model (extends the Rung 5 item above). After 3.1–3.3.

Not doing unless evidence changes: a byte-equality "conformance" field for
caller-sent bash (revisit only if the echo shows frequent model-side mismatches).

## Write the CC-structured Security Target document

The remaining Rung 0 / paper step: a Common Criteria Security Target (TOE,
threats, assumptions, SFRs, SARs) consolidating `security.md` / `security-audit.md`
/ `threat-model.md` / `assurance-case.md` into the standard ST structure.

## Stabilize the flaky S2 resource-cap test

`tests/concurrency.rs:burst_connections_above_cap_get_busy_response` fails ~2/3
locally — the *setup* assertion ("in_flight reached ≥4") is timing-flaky, not the
security assertion. Stabilize so the in-flight cap stays covered by CI.

## Make the post-trust banner reliable (F2)

When `confirm_unprivileged=false`, `display_banner` is printed under a `try_lock`
and may be dropped under TTY contention, so silent execution can be invisible.
Make the banner reliable and state the residual risk plainly at the `a`-key
prompt and in the README.

## Re-evaluate the RUSTSEC-2026-0189 ignore if an HTTP transport is added

`deny.toml` and the `cargo audit` step ignore RUSTSEC-2026-0189 (DNS rebinding
in rmcp's Streamable HTTP server transport) because sudo-proxy enables only
rmcp's `transport-io` feature and serves over stdio, so the vulnerable code is
not compiled in. If an HTTP/streamable-http transport is ever added, drop the
ignore and require a patched rmcp instead. Captured follow-up, not active work.

## Drop the RUSTSEC-2026-0543 ignore once rmcp no longer needs `chrono`

`deny.toml` and the `cargo audit` step ignore RUSTSEC-2026-0543 (`chrono`
unmaintained). `rmcp` depends on `chrono` unconditionally, using it for model
timestamps and for timeout-error formatting, and it enables `schemars`'
`chrono04` feature. Upstream tracks the fix in
[modelcontextprotocol/rust-sdk#1469](https://github.com/modelcontextprotocol/rust-sdk/issues/1469):
either a move to `jiff`/`time` or an optional `chrono` feature. When an `rmcp`
release lands either change:
- upgrade `rmcp`, and turn off its `chrono` feature if it is made optional;
- check that `cargo tree -i chrono --all-features` comes back empty;
- remove the ignore from both `deny.toml` and `.github/workflows/ci.yml`.

Patching `rmcp` locally, or writing the MCP layer ourselves, costs more than it
gains while the advisory is only an unmaintained notice. Reconsider if a
`chrono` vulnerability advisory is published. Rung: supply chain. Captured
follow-up, not active work.

## Submit the plugin to the claude-plugins-community directory

Optional discoverability step, added after the plugin packaging landed (PR #53).
The decentralized flow (`/plugin marketplace add tarides/sudo-proxy` →
`/plugin install sudo-proxy@tarides`) already works with no registration; this
would additionally list sudo-proxy in Anthropic's curated community marketplace.
Submit via the in-app form (claude.ai admin directory, or the Console plugin
submission page). Expect **extra security scrutiny** because the plugin executes
`sudo` — link the threat model, security audit, and the "no auto-approve"
non-features from the plugin README so reviewers find them. Captured follow-up,
not active work.

## Emit audit records to the system logger (syslog / journald)

Today there is **no durable record of requests**. The daemon writes audit lines
only to its own stderr — the per-command line (`[id] [priv] [client] <pipeline>`,
`server.rs:640`) solely under `--verbose`, and the unconditional `[unattended]`
line (`server.rs:687`) only while a session `a`-grant is active. Both land in the
terminal window's scrollback and vanish with it; nothing is written to disk, the
systemd journal, or any audit facility. For a tool whose whole purpose is gating
privileged execution, the absence of a tamper-evident, admin-controlled trail is
a gap.

**The fix.** Emit a structured audit record for every request — approved, denied,
timed out, unattended — to the **system logger** (`syslog`/journald via `libc`
`openlog`/`syslog`, or the `systemd` journal API under a feature flag), not a
self-managed file. System-level is the point: records then inherit the host's
journald rotation, retention, access control, and optional forwarding/sealing,
and survive the terminal window closing. Record at least: request id, host,
privileged flag, client version, the pipeline (argv), decision, and the
decision path (prompted / unattended-grant / pkexec). Keep stderr lines as-is
for live visibility. Decide the default (log-to-syslog on by default vs opt-in
via a flag) and document the privacy/retention implications in the README.
Captured follow-up, not active work.

## Structured plan: remaining shell-tail gaps

The plan model shipped in PR #59 (see the changelog). These shell features still
have no structured op, so they still need the `system` escape hatch:

- **Backgrounding / detach with pid return** (`nohup … & echo $!`, campaign
  observation **O1**). Plan steps run synchronously. Add launch-and-detach that
  returns the pid as a structured field, not a shell `$!`.
- **Runtime substitution** (`$(cat /proc/…)`, `$!`, `$?`). Promote the common
  cases to first-class ops (a read-file op for `$(cat …)`; the launcher already
  knows the background pid) and leave the rest to the explicit `system` hatch.

**Reject unresolvable steps.** With every step resolved and rendered, an "opaque
blob" is no longer a string pattern to deny: it is any step the daemon cannot
resolve. Such steps are already flagged at the prompt; a policy mode should
reject them, making `no-opaque-blob` a special case enforced in the daemon for
every client rather than by a regex in one user's hook. See the strict-mode lever
in the next section.

## Make the shell escape hatch avoidable (plan-model design goal + remaining levers)

**The design goal.** The `Plan` type's *raison d'être* is to make its `Shell`
constructor (the opaque escape hatch, formerly `System`) unnecessary: every
structured op exists so a given shell feature need not be expressed by shelling
out. The real invariant is **no shell on the privileged path**; `Shell` is the
one node that breaks displayed-equals-executed — it resolves only the shell
binary, so its inner commands are invisible at the prompt. The goal is therefore
not to *delete* `Shell` (the shell tail — runtime `$(…)`, `$!`, globbing,
word-splitting, profile functions — is open-ended) but to **shrink-and-flag**:
drive real usage into structured ops, and keep every remaining shell use loud,
countable, and policy-rejectable. Read each `Shell` node as measurable debt — a
prompt to ask "what op would have avoided this?" That loop already produced `alt`
(for `||`) and `seq` (for `;`). See
[docs/architecture.md](docs/architecture.md) ("Security model vs. agent
harnesses") for the framing.

**Remaining levers** (rough payoff order):

Levers 1 (flag `exec` of a shell as opaque) and 2 (the strict `no_shell`
policy) shipped in PR #67; wrapper-hidden shells: see #87 (shipped); residuals
in item 5 of the plan-model follow-ups.

- **Catalogue the shell tail as first-class op proposals.** The two most common
   forces in the log.1 trail that still require the hatch: a `detach` op
   (backgrounding + a structured pid return, replacing `nohup … & echo $!`) and a
   read-file op (replacing `$(cat /proc/…)`). See *"Structured plan: remaining
   shell-tail gaps"* above. Each retired force converts an opaque stage into reviewable ones.

Captured follow-up, not active work.

## Move the `no-opaque-blob` floor into the daemon (interim, ahead of the plan model)

**Why.** `no-opaque-blob` is currently a Claude Code PreToolUse hook (matcher
`mcp__sudo-proxy__execute`) living in one user's `~/.claude/hooks/`. It blocks
`echo … | base64 -d | bash`-style payloads an approver cannot review. But it sits
on the *untrusted* end of the airlock: it protects only that one client, only
that one machine, and only the MCP path — another MCP client, a fresh install
without the hook, or a direct socket caller all bypass it. sudo-proxy's trusted
components are the daemon and the human at the TTY, so a reviewability *guarantee*
can only be enforced daemon-side; a client hook can't provide it.

**Interim fix** (small, lands before the full structured-plan work). Have the
daemon detect the obvious opaque shape in an incoming `argv`/`pipeline` — a
decode step (`base64 -d`, `xxd -r`, `openssl enc -d`, …) piped into an
interpreter (`bash`/`sh`/`python`/`perl`/`eval`) — and either hard-reject it or
mark it loudly at the approval prompt. This holds the floor for *all* clients and
the direct-socket path, not just this user's hook. Keep the hook as an optional
outer layer: it gives the agent a faster pre-round-trip rejection and is the
natural home for stricter-than-baseline, site-specific policy.

**Residual / handoff.** This interim check is still a denylist — a hostile client
can obfuscate around any pattern. It is a stopgap, not the answer: the sound,
allowlist-shaped enforcement is *reject-unresolvable-stages* in the structured
plan model (now landed; see *"Structured plan: remaining shell-tail gaps"*), which
this item should be folded into. The
daemon failing open must never be the difference between safe and unsafe; the
hook failing open (misconfig, different client) likewise must not — the daemon is
the backstop. Captured follow-up, not active work.

## Partial-`run` retry hazard and the sudo-credential-in-pipe caveat

Surfaced while reviewing the structured-plan executor (the plan model above,
first increment landed). Two interacting behaviours deserve a safer story than
"the caller must know."

**The retry hazard.** A `run` (≈ `&&`) runs its steps in order and stops at the
first non-accepted failure (`executor.rs`, `run_seq` → `SeqNode::Run`). When a later
step fails, the earlier steps' side effects are **already committed**. The
response marks which stages ran (per-stage exit codes; a skipped stage carries
the `-1` not-run sentinel), but nothing stops a caller from resubmitting the
*same* plan — which replays the already-committed early steps. For
non-idempotent effects (`mkdir`, append-redirects, counters, `git commit`) that
double-applies or errors on the second pass. This is the classic
partial-failure/retry footgun of any `set -e` script; the plan model makes the
partial state *visible* but does not prevent the replay.

**The sudo-credential compounding.** The most likely "later step fails" cause is
a privileged stage with no cached sudo credential. A **single** privileged stage
runs with `setpgid` + the foreground-tty guard and *can* prompt; a privileged
stage **inside a pipe** runs with `setsid` (detached, no controlling tty) and
**cannot** prompt — it relies on a cached credential. Whether a leading
`sudo true`-style prime carries into a `setsid` pipe child depends on the host's
sudoers `timestamp_type` (`global` → yes; the common `tty` default → likely
not). So a pipe whose privileged stage is neither NOPASSWD nor already-cached
fails fast with "no tty present," and credential-priming is not a reliable fix
*inside a pipe*.

**Mitigations available today** (caller-side): order privileged stages first;
make early stages idempotent (`mkdir -p`, truncate not append); rely on
NOPASSWD / cached creds; prefer a single privileged stage over `sudo`-inside-a-
pipe; and use the per-stage exit-code array to resubmit only the not-run stages
rather than replaying the whole plan.

**Potential improvements to weigh** (none a full fix — idempotency stays the
caller's responsibility): (1) surface the partial-execution boundary
prominently in the response/prompt so a caller resumes rather than replays;
(2) an optional executor-inserted auth-probe for privileged plans that fails
fast *before* any stateful stage, documenting the `timestamp_type` caveat;
(3) advisory flagging of obviously-non-idempotent leading stages. Captured
follow-up, not active work.

## (Optional) Root daemon with direct `setuid` instead of per-step `sudo`

An option to weigh, not a commitment. The first plan increment (PR #59) keeps the
daemon running as the user and escalates each step through `sudo [-u user] --
argv` (or `pkexec`). The other design runs the daemon as root and switches
user for each step itself (`setuid`/`setgid`/`initgroups` before `exec`), with no
`sudo` binary involved.

- **Gains:** no sudo-credential-in-pipe caveat (pipe stages need no cached
  credential); no `sudo`/`pkexec` argv or env handling in the trusted path; the
  run-as user for each step is set directly by the executor.
- **Costs:** the daemon becomes a root process, so the socket and client
  authentication and the whole daemon join the privileged TCB. The deployment
  changes (system service instead of a user process) and so does the threat
  model (`threat-model.md`, boundaries B1–B6). The step-by-step approval prompt
  becomes the only gate, with no `sudo` password behind it.

This needs its own gate: an updated threat model and assurance case before any
code. (The original structured-plan design, now in the changelog, said "`setuid`
to a run-as user". That describes this option, not what shipped.)

---

## Rung 6 — seL4-style end-to-end refinement (aspirational)

Long-horizon: prove the daemon's logic refines an abstract approval spec, with
trust assumptions (`/dev/tty`, `sudo`, kernel, SSH) stated explicitly as the
boundary of the proof. Value even unrealised: forces a complete enumeration of
what is trusted-by-assumption.
