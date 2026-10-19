# Backlog

Ordered; the first item is the current/next task. One item per session — capture
unrelated ideas at the end, don't chase them mid-session. Items below continue
the assurance ladder defined in
[docs/formalisation-roadmap.md](docs/formalisation-roadmap.md); each names its
rung.

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

## Structured composite-execution plan (retire the `bash -lc` opaque wrapper)

**The gap.** A captured approval trail from a registered host (24 consecutive
requests, all from one `sudo-proxy-mcp` client, 2026-10-16) showed **every**
command wrapped as
`argv = ["bash", "-lc", "<script>"]`. Two consequences hollow out the approval
gate: (1) the path-resolution guarantee is vacuous — every `Resolves:` line is
`/usr/bin/bash`, and the real binaries (`opam`, `dune`, `sysctl`, `git`, `pkill`)
are chosen *inside* the script by `$PATH` lookup in a login shell the proxy never
inspected; (2) a single root approval authorizes many effects — e.g. requests
`8ab05131` (13:58) and `4ce9cd4c` (12:14) each bundled `sysctl -w
vm.mmap_rnd_bits=28`, a nested `sudo -H -u <user> bash -lc '…'`, and a sysctl
restore under one "Execute as root? y". This is the softer sibling of what the
`no-opaque-blob` hook already blocks: an un-reviewable payload defeats the gate.

**The fix.** Generalize `execute`'s existing `pipeline`/`env` into a **structured
plan** that the daemon executes *directly* (fork/exec per stage: pipes,
redirections, env, `setuid` to a run-as user, sequencing) with **no shell in the
privileged path**. The load-bearing invariant: *the structure the human approves
is literally the structure that runs.* This rules out the tempting-but-unsound
alternative of parsing the `bash -lc` string for display while still executing it
via bash — parser/bash divergence (quoting, globbing, `$(…)`, and `-l` profile
functions/aliases) would let the approved interpretation differ from the executed
one. Executing a literal-argv plan also *shrinks* the TCB: no word-splitting, glob
expansion, command substitution, or profile functions on the privileged path. The
prompt then renders each stage with its resolved real binary, its run-as context
(`[ROOT]` / `[as user]`), and its redirections — so the two sysctl toggles above
appear as two explicit, isolated root effects instead of hiding in a wall of text.

**Prior art — Dune's action DSL** (checked
`dune.readthedocs.io/en/stable/reference/actions/`). Dune already defines a
proven, shell-free, S-expression command grammar for the same reason (reproducible,
no-shell builds). It covers ~80% of the log's composition vocabulary directly:
`run` (literal prog+args), `setenv`, `chdir`, `with-stdout-to` / `with-stderr-to`
/ `with-outputs-to` (redirection; `with-outputs-to` = `2>&1`), `with-stdin-from`,
`ignore-stdout`/`-stderr`/`-outputs` (= `>/dev/null`), `pipe-stdout`/`pipe-outputs`
(= `|`), `progn` (sequence; fails on first error ≈ `&&`), `concurrent`,
`write-file` (= `printf > file`), `echo`, `cat`, `copy`, and
`with-accepted-exit-codes` (bound allowed exit codes). Critically, its `system` /
`bash` forms are exactly the "explicitly opaque shell escape hatch" we want:
adopt Dune's grammar as the plan schema, and render `system`/`bash` stages at the
prompt as *opaque — resolves only the shell* (the `no-opaque-blob` philosophy),
not hidden.

**Gaps Dune does NOT cover — the security- and lifecycle-critical axes we must add
on top:**

- **Per-stage run-as / privilege** (`[ROOT]` vs `[as <user>]`). Dune runs
  everything as the invoking user; it has no privilege notion. This is the single
  most important field for us — it replaces the nested `sudo -H -u` and makes each
  root effect explicit and isolated. (No equivalent in Dune.)
- **Backgrounding / detach with pid return** (`nohup … & echo $!`, used in
  requests `3a7cb1f9`, `e6aeb649`, `942cd83f`, `b1f6294a`). Dune actions are
  synchronous; `concurrent` still joins. We need launch-and-detach returning the
  pid as a structured field (not a shell `$!`).
- ~~**`||` fallback.**~~ *Landed:* the `alt` op (dual of `seq`) runs steps until
  one succeeds, covering `pgrep … || echo none`. A first-class op, not a fold
  into `with-accepted-exit-codes`.
- ~~**Append redirection (`>>`).**~~ *Landed:* `redirect` takes `mode:"append"`
  alongside `"truncate"` (and `stream:"both"` for `2>&1`).
- **Runtime substitution** (`$(cat /proc/…)`, `$!`, `$?`). Dune resolves
  `%{…}` at rule-eval, not runtime — so it has no runtime `$(…)` either, which
  *confirms* our plan: promote the common cases to first-class ops (a read-file op
  for `$(cat …)`; the launcher already knows the background pid), and route the
  rest to the explicit `raw_shell`/`system` escape hatch.

This subsumes rather than sits beside the `bash -lc` concern. Cost: a small
in-daemon plan executor (fork/exec + pipes + redir + setuid + sequencing),
bounded, and it removes the shell from the privileged path. Captured follow-up,
not active work.

It also subsumes the `no-opaque-blob` guard (see the interim item below):
once the daemon resolves and renders every stage, "opaque blob" stops being a
denylisted string pattern and becomes the general case "a stage I cannot
resolve." The plan executor flags any such stage (`opaque — resolves only the
shell`) and a policy mode rejects it — making `no-opaque-blob` a special case of
daemon-side *reject-unresolvable-stages*, enforced structurally and for every
client rather than by regex in one user's hook.

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

1. **Close the `exec sh -c` loophole** (highest payoff). The goal is quietly
   defeated today not by `Shell` but by its dishonest sibling: a plain `Exec`
   leaf (or pipe stage) `["sh","-c","<script>"]` puts a full shell on the path
   **without** the opaque flag — it renders as a tame `exec` stage with
   `/usr/bin/sh` resolved while a whole script hides in one argv element. (Seen
   in the live campaign: C1/C2 used `sh -c "…;…"` leaves to sequence what the
   type couldn't yet express.) Fix: have `validate_tree` recognize an
   `Exec`/pipe-stage whose `argv[0]` is a shell (`sh`/`bash`/`dash`/`zsh`/…) with
   a `-c` and treat it exactly like a `Shell` node — same opaque flag at the
   prompt, same strict-mode fate. Without this, every other lever is bypassable.
2. **Implement the documented strict policy mode.** `protocol.rs` already promises
   "a strict policy mode rejects it," but no such mode exists. Add a per-daemon
   policy (`hosts.json` `policy.no_shell` and/or a `--no-shell` flag) that
   **rejects** any `Shell` node — and, with lever 1, any `exec sh -c` — before
   prompting: "structured or nothing" for operators who want it. Folds into the
   *reject-unresolvable-stages* idea in the structured-plan section above.
3. **Catalogue the shell tail as first-class op proposals.** The two most common
   forces in the log.1 trail that still require the hatch: a `detach` op
   (backgrounding + a structured pid return, replacing `nohup … & echo $!`) and a
   read-file op (replacing `$(cat /proc/…)`). See the "Gaps Dune does NOT cover"
   list above. Each retired force converts an opaque stage into reviewable ones.

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
plan model above, which this item should be folded into once that lands. The
daemon failing open must never be the difference between safe and unsafe; the
hook failing open (misconfig, different client) likewise must not — the daemon is
the backstop. Captured follow-up, not active work.

## Partial-`seq` retry hazard and the sudo-credential-in-pipe caveat

Surfaced while reviewing the structured-plan executor (the plan model above,
first increment landed). Two interacting behaviours deserve a safer story than
"the caller must know."

**The retry hazard.** A `seq` runs its steps in order and stops at the first
non-accepted failure (`executor.rs`, `run_seq` → `SeqNode::Seq`). When a later
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

---

## Rung 6 — seL4-style end-to-end refinement (aspirational)

Long-horizon: prove the daemon's logic refines an abstract approval spec, with
trust assumptions (`/dev/tty`, `sudo`, kernel, SSH) stated explicitly as the
boundary of the proof. Value even unrealised: forces a complete enumeration of
what is trusted-by-assumption.
