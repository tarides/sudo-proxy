# Changelog

Most recent at top. See [docs/formalisation-roadmap.md](docs/formalisation-roadmap.md)
for the assurance-ladder context behind the security-formalisation entries.

## Unreleased — Each program is resolved once and pinned (#105, 1.3.0)

A request's plan was compiled, and every program in it looked up, three
times: for the `no_shell` check, for the prompt, and for the spawn. The prompt
also canonicalised each path again for `-> target`. If a file changed between
those passes, a different file could run than the one approved, `no_shell`
could be bypassed (a symlink to `true` at the check, to `sh` at the spawn),
or the `-> target` shown could be stale. No security impact today: bare names
resolve on the root-owned login `PATH`, and a `./name` the requester could
swap is one whose contents it could already rewrite. It is a prerequisite for
#101, whose `--inherit-path` makes the lookup use user-writable directories.

- `executor::prepare` compiles the plan once and pins each program: an
  `O_PATH` descriptor, its `(dev, ino)`, and the canonical target read through
  it. The `no_shell` check, the pkexec decision, the prompt (`Prompter::prompt`
  now takes the `PreparedRequest`) and `exec_*` all use that one result.
- Just before each spawn the path must still name the pinned inode; otherwise
  the stage is refused with "changed since it was approved" and nothing runs.
  A pipe runs every pre-spawn refusal for all its stages before any starts.
  **Behaviour change:** this includes a binary replaced by an earlier step of
  the same request (`cargo build && ./target/debug/app`, `apt-get upgrade &&
  systemctl restart …`), which ran before; send such steps as separate
  requests (`usage.md`). A native (ELF) binary running as the daemon's user
  is executed through its descriptor (`/proc/self/fd/N`); anything else (a
  script with or without `#!`, a binfmt_misc format) and an escalated step
  are spawned by path after the check.
- A request that queued for the terminal (behind another prompt or an
  escalated run) and whose pins no longer hold when its turn comes is
  compiled again before the prompt, and `no_shell` is applied to the new
  resolution, so the prompt never shows a stale target.
- The daemon raises its soft open-file limit to the hard limit at start (each
  pin holds a descriptor while the request waits); children get the original
  limit back.
- A program run by a wrapper (`env X=1 tool`, `nice`, `timeout`, …) is passed
  to the wrapper by its pinned absolute path (basename unchanged; applets
  excluded), so the wrapper does not search `PATH` again. **Behaviour change:**
  such a program that is not found is now refused before the spawn
  ("command not found: x (run by env)") instead of failing inside the wrapper
  with exit 127, also behind a `find` or `xargs` that might never run it. A
  resolved path containing `=` is refused behind `env`, which would read it
  as an assignment. A `find -execdir` / `-okdir` program named with a `/` is
  left as written (`find` runs it from each match's directory), and so are
  such words in opaque stages. PATH entries that are not absolute are never
  searched.
- The prompt's `⚠ invalid plan` line (bounded in #90) is gone: a
  `PreparedRequest` exists only for a plan that compiled.
- Docs: `security.md` ("resolved once" now holds), the threat model (new B4
  row, attack-tree leaf 3.7 and its residual: contents changed in place, the
  check-to-exec window for scripts and escalated steps), the assurance case
  (Sn4.2, Sn4.3, Sn5.4), `architecture.md`.
- Tests: `tests/pinning.rs` changes files from inside the scripted prompt
  (rename over, symlink retargeted to a shell under `no_shell`, wrapped
  program swapped, in-place rewrite residual, a script without `#!`, a pipe
  refused before any stage starts, a queued request re-prepared or refused by
  `no_shell`); executor unit tests for the pin, the descriptor exec and the
  wrapped-argv rewrite (`-execdir`, `=` only behind `env`). A live run through
  the real prompt confirmed the refusal of a symlink retargeted after
  approval.

## Unreleased — Trusted helpers under `/nix/store` are accepted (NixOS `--pkexec`, 1.3.0)

The trusted-helper check added for GHSA-gx9w-4f7x-2gcp refused any directory
that is group- or world-writable. On NixOS `/usr/bin/env` resolves into
`/nix/store` (`root:nixbld 1775`), so the `env` that `--pkexec` mode probes
for `-C` was refused, and every escalated request under `--pkexec` failed
with "pkexec mode needs an `env` that supports -C". The released 1.2.3 is not
affected: it has no such probe, and `sudo` / `pkexec` come from
`/run/wrappers/bin`. The check now accepts a root-owned sticky directory, as
the `hosts.json` check already did: others can add entries there but cannot
rename or remove root's. Since a directory on the search list can now hold
other users' entries, every symlink on the helper's path as found must be
root-owned, or it could be repointed between the check and the spawn.

## Unreleased — Unknown plan keys are rejected (#89, 1.3.0)

Every plan object accepted and silently dropped keys it does not define. A
misspelled key (`stdin_from` for `with-stdin-from`, `pth` for a redirect's
`path`) vanished, and the rest of the plan was prompted for and run: the
regression test shows such a request approved and executed on the old code.
Plans now reject unknown keys at any depth, on every node and on redirect
targets, before anything is prompted, with serde's "unknown field `x`, expected …" from the
daemon (`invalid JSON`), the MCP server (`invalid plan`) and `sudo-request
--plan` (`invalid plan JSON`). `run-as` with `as: root` and a `name`, whose
`name` used to be dropped, is now an error too. The request envelope stays
lenient, so a newer client can still talk to an older daemon.

1.3.0 is the first release to ship plans, so this fixes their wire format
before any client depends on the lenient one; it is pulled forward from #89's
Phase 1. serde cannot combine `deny_unknown_fields` with the `flatten` that
`run-as` needs, so `Plan` and `RedirTarget` now (de)serialize through a private
wire form (`protocol::wire`), converted by exhaustive matches in both
directions. The Rust types are unchanged and the bytes on the wire are
identical: `wire_form_literals` was frozen from the old serializer, in its own
commit, and passes before and after. Tests: `prop_plan_wire_roundtrip` (5 000
random plans over every variant), `plan_rejects_unknown_keys_at_every_level`,
`request_stays_lenient_but_its_plan_is_strict`, and
`plan_unknown_key_rejected_without_prompt` (raw socket, no prompt).

## Unreleased — Bound the `⚠ invalid plan` prompt line (#90)

The prompt printed a `compile_plan` error unclipped on its `⚠ invalid plan`
line, and that error can quote request data: `environment variable not
allowed: {key}` carries a setenv key of any length. The daemon rejects a plan
that does not compile before prompting, so the line was unreachable, but it
sat outside the "every prompt line is bounded" property of #85 (G4.3).
The plan part of the prompt is now one function, `write_plan_section`, used by
`prompt_tty`; its error arm prints the message through `shown` (escaped, then
clipped to 160 chars with the hidden-chars marker). Valid plans render as
before: no golden changed. Tests: `invalid_plan_line_is_bounded` (a 10 000-char
key gives one bounded line under both styles), the #85 property now goes
through `write_plan_section`, and `plan_disallowed_setenv_rejected_without_prompt`
pins the server-side ordering for the one error that quotes request data.
Sn4.3 lists the line and the two tests.

## Unreleased — wrapper-aware opaque detection (#87)

**The gap.** The opaque flag and the `no_shell` policy (#67) looked only at a
stage's `argv[0]`, so `env sh -c …`, `nice bash …`, `timeout 5 sh -c …` and
`python3 -c …` rendered as tame stages and ran under `no_shell`; `env VAR=… opam
…` also hid `opam` from `Resolves:`. **The fix.** New pure module
`src/wrappers.rs` unwraps argv through known wrappers (`env`, `nice`, `nohup`,
`setsid`, `stdbuf`, `timeout`, `ionice`, `chrt`, `taskset`, `time`, `xargs`,
`busybox`/`toybox`/`coreutils`, `find -exec`) and flags shells, inline-code
interpreters and runners (`sudo`, `ssh`, …) as opaque. It fails closed on
unknown or abbreviated options, missing arguments, `env -S`/`-i`/PATH
changes, env names `setenv` hard-rejects (`LD_*`, `BASH_ENV`, `ENV`, `IFS`),
`find -exec {}`, dispatcher options, ambiguous names and chains deeper than 8.
`Resolves:` lists every program with `(run by …)`, and `looked up at run time`
(no path) for an escalated stage's inner programs. The `no_shell` message
gives the prompt's reason. **Behaviour change under `no_shell`:** these
stages are now rejected. Tests: unit tables and two properties in
`src/wrappers.rs`, executor/TUI tests, `tests/no_shell.rs`,
`tests/pty_no_shell.rs`, a `wrappers` pty golden, corpus cases 06/22 stay
transparent. Assurance case G4.7.

## Unreleased — Bound every approval-prompt line, not only Command: (#85)

**The gap.** Only the `Command:` line was length-bounded (G4.3 / F3). The
`Steps:` block capped its number of lines but wrote each line whole, so a
privileged `exec ["echo", <900 KB>]` printed the whole argument on `Steps:`
line 0 and pushed the `[y/N]` question off-screen. The `Resolves:` block and
line (a long absolute `argv[0]`, and up to 256 entries) and the metadata lines
(`From:`, `Requester:`, `Client:`, `Time:`, `ID:`, `Reason:`, `Env:`, the
session name of the `a` line) had no length bound either. **The fix**
(`src/tui.rs`, display only): each `Steps:` line is clipped to 160 visible
chars (`clip_styled`, which skips the daemon's own colour escapes and resets
the colour before the marker), each `Resolves:` name and path to 160, each
metadata field to 256, the `Env:` line to 1024, and the `Resolves:` block to 32
entries, each with an explicit `… [N more chars hidden]` marker. The full texts
the bash-oracle properties check (`steps_shell_text`, `command_summary`) are
unchanged. **Tests:** unit tests for each clip, the property
`prop_prompt_lines_are_bounded_and_prefix_faithful` (every line bounded, line
count bounded, each `Steps:` line a prefix of its unclipped text), the pty test
`huge_argument_prompt_is_bounded`, and a `long-argument` golden; the existing
goldens are byte-identical.

## Unreleased — `--pkexec` delegates only single-step privileged requests to pkexec (#88)

Under `--pkexec`, every `privileged: true` request went to pkexec, one dialog
per escalated step. A dialog shows a single argv (named `/usr/bin/env`, since
steps run as `pkexec env -C DIR -- argv`) and never the files the daemon opens
for a redirection, so no dialog showed the whole plan, and with `pkexec-cache`
the later steps ran with no dialog at all. Now only a `privileged: true`
request that compiles to one step with no redirection is delegated to pkexec
(`delegate_to_pkexec` in `src/server.rs`, reading the same views the prompt
renders). Every other privileged request (multi-step, redirected, or escalating
only through `run-as`) gets the TUI prompt and runs through sudo; a `--pkexec`
user without sudo rights now gets a sudo failure after approving such a plan,
as `run-as` plans already did, and these requests are audited as
`approved`/`denied`/`timeout` instead of `pkexec`. Unchanged: the dialog still
names `/usr/bin/env` and omits env and accepted exit codes (backlog items
"pkexec dialog names `/usr/bin/env`" and "Does a single-leaf plan's `setenv`
reach the program under `--pkexec`?"). Tests: a unit table for the predicate, `tests/plan_exec.rs`
`pkexec_mode_prompts_for_multi_leaf_privileged_plans` (run/seq/alt/pipe,
redirect, with-stdin-from; one `denied` audit record each, none `pkexec`), and
the pty test `pkexec_flag_multi_step_plan_gets_the_tui_prompt` through the real
CLI with `DISPLAY` set. G5.4 / Sn5.4 and threat-model leaf 4.5 added.

## Unreleased — Widen the prompt's forbidden-character class (#86)

`has_dangerous_chars` rejected C0 controls and three zero-width/bidi ranges
only. DEL and C1 (NEL, CSI, OSC), soft hyphen, ALM, line/paragraph
separators, word joiner and invisible operators, BOM, tag characters and
variation selectors all reached the approval prompt. The class is now one
rule, `c ≠ TAB ∧ c ∈ Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point`,
held as a table built from the Unicode 16.0.0 UCD
(`protocol::DANGEROUS_RANGES`) and reused by the audit-record and
`--log-json` escapers.

- **Resolves paths.** Paths shown on `Resolves:` (tui and zenity) are printed
  through `escape_dangerous`: a symlink's target name never goes through
  validation, so a same-UID caller could put ESC or a newline on the prompt
  that way.
- **Env-key message.** The "env key contains forbidden characters" error no
  longer echoes the key. For consistency only: the key reached only the
  response, and the audit copy was already escaped.
- **MCP.** `sudo-proxy-mcp` strips the class from `description` before it
  becomes `reason`, so an emoji with U+FE0F no longer fails the request. The
  daemon gate stays strict.
- **Newly rejected input.** Soft hyphens, emoji presentation sequences with
  U+FE0F in `reason` from non-MCP clients, Arabic/Syriac text using U+061C,
  U+0600–0605 or U+070F, a leading BOM, and tag characters now get the
  existing validation error; drop the character.
- **Tests.** An exhaustive unit test checks the table over every `char`
  against a General_Category oracle (`unicode-general-category`, a pinned
  dev-dependency) plus a verbatim copy of the DICP list; a regression table;
  integration tests over argv/reason/session/env value/plan leaves; a
  non-ASCII accept test; an audit escape test; a `Resolves:` symlink test;
  the property test with valid env keys and multibyte text; and the Kani
  harnesses over the whole `char` domain.

## Unreleased — Audit log for every request outcome (#65)

The daemon logged prompted requests and unattended runs, and only with `-v`. It
did not log replayed ids, stale or malformed `time`, validation failures, human
denials, or prompt timeouts, and its lines had no timestamps (threat-model B1,
"Repudiation"). New `src/audit.rs`: every connection outcome now produces one
record with an RFC 3339 timestamp, peer UID, id, session, self-declared
requester (#25), host, outcome, and, for validated requests, the command
summary. Request-derived strings are clipped and their control/bidi characters
escaped in every sink. Records go to stderr (always), an append-only 0600 JSONL
file at `$XDG_STATE_HOME/sudo-proxy/audit.jsonl` (on by default;
`--audit-log PATH`, `--no-audit-log`), and syslog `LOG_AUTHPRIV` (on by default; `--no-syslog`). Env
values and `reason` are never recorded. If the audit file cannot be opened, the
daemon refuses to start. The old unconditional `[id] [unattended] [session …]`
line and the peer-UID rejection line are folded into the audit line. The
`no_shell` policy (#67) and the stop-predates-daemon check (#63) record as
`rejected:no_shell` and `rejected:stop_before_start`. Tests: `tests/audit.rs`
covers each outcome and the no-leak properties; the busy test and a pty test
check the default file path.

## Unreleased — Close the `exec sh -c` loophole; strict `no_shell` policy (#67)

**The gap.** Only an explicit `shell` op was flagged *opaque* at the prompt. A
plain `exec` of `["sh","-c","…"]` (or a flat-pipeline stage) put a whole shell on
the path but rendered as a tame exec stage resolving `/usr/bin/sh`, quietly
defeating the "make `Shell` avoidable" goal. And the strict mode that
`protocol.rs` promised did not exist.

- **Opaque detection** (`src/executor.rs`, `push_leaf`). A step whose program is
  a shell interpreter (`sh`, `bash`, `dash`, `zsh`, `ksh`, `mksh`, `ash`, `fish`,
  `csh`, `tcsh`, `yash`, `posh`) is opaque. It is matched by name, by path, or by
  the canonical resolved binary, with or without `-c`. Every step goes through
  `push_leaf`, so the prompt and the policy read the same bit.
- **Strict policy.** `"policy": {"no_shell": true}` in `hosts.json`, or
  `--no-shell` / `--allow-shell` (same tri-state as `unattended_eligible`),
  rejects any request with an opaque step before prompting, ahead of the TUI,
  `--pkexec` and unattended paths. `--no-shell` is forwarded with `--host`;
  `--allow-shell` is refused there. The file is read through the same
  owner-private check as `unattended_eligible` (GHSA-xx2m-j9f7-gcmr); if it
  fails, strict mode is **on** (fail closed), so a file another user can write
  cannot switch it off.
- **Tests.** `tests/no_shell.rs` checks six opaque shapes rejected without a
  prompt, structured requests still running, and everything prompted when the
  policy is off. There are unit tests for detection (including a renamed
  symlink), the TUI render, and the serde default. Docs: `docs/usage.md`
  "Strict no-shell mode".
- **Not covered.** Shells behind wrappers (`env`, `nice`, `timeout`) and other
  interpreters. Folded into the `env`-resolution follow-up in the backlog.

Verified live by driving the real daemon through a pty (`script(1)`): the
permissive daemon flagged `sh` as opaque and ran on `y`; `--no-shell` returned
the policy error with no prompt. That probe became backlog item #1 / issue #68.

## Unreleased — a captured `stop` no longer stops a restarted daemon (#63)

Replay protection (`SeenIds`) keeps the ids it has seen in memory, one set per
daemon instance. A `stop` accepted by one instance was therefore accepted
again by a newly started instance if it was resent within the 60 s freshness
window, despite docs/protocol.md promising that a captured stop could not be
replayed. The daemon now records its start time (in Unix seconds, before
binding the socket) and rejects a `stop` whose `time` is earlier than that.
Any stop that an earlier instance accepted is dated before that instance exited,
so it predates the new one. Nothing changes on the wire and clients need no update.
Only `stop` is gated: replaying a `ping` is harmless, a replayed exec still
reaches the approval prompt, and gating either one would make legitimate
requests sent just after `start_server` depend on the client's clock. The one
remaining gap is a restart within the same wall-clock second as the original
stop. `parse_age` is now split into a pure `parse_epoch` plus a clock read.
Tests: `server::tests::check_not_before_start_boundaries`,
`parse_epoch_round_trips_epoch_to_iso`, and in `tests/stop.rs`
`stop_dated_before_daemon_start_is_rejected` and
`captured_stop_does_not_stop_restarted_daemon` (the issue's repro).

## Unreleased — `pkexec-cache` check no longer says "not installed" when it cannot read rules.d (#75)

The check mode began with `Path::exists()`, which returns `false` on any error,
including `EACCES`. On distributions that ship `/etc/polkit-1/rules.d` as
`root:polkitd 0750`, a non-root `pkexec-cache` (the documented way to check)
reported `not installed: … does not exist` even when the rule was installed. The
check now reads the file in one step (`read_rule`): only `NotFound` means
"not installed". `PermissionDenied` prints
`unknown: cannot read …: permission denied (run with sudo)` and exits 1, and any
other error is reported as before. `docs/pkexec.md` mentions the `sudo` check.
Tests: `pkexec-cache` unit tests `read_rule_missing_is_none`,
`read_rule_present_returns_content` and
`read_rule_unreadable_dir_is_permission_denied` (the issue's case).

## Unreleased — `pkexec-cache` validates the username it writes into the polkit rule (#64)

`pkexec-cache --create` took the username from `SUDO_USER`, `PKEXEC_UID` or
`LOGNAME`/`USER` without checking it and pasted it into the generated polkit
JavaScript as `subject.user == "{username}"`. A name containing `"` changed the
rule's logic: `SUDO_USER='x" || true || "'` produced a rule granting
`AUTH_ADMIN_KEEP` to every action for every subject. This needed root, but root
running the tool directly with an inherited `LOGNAME`/`USER` was a realistic path.
Every candidate name is now checked against the login-name charset
`^[a-z_][a-z0-9_-]*\$?$` (at most 32 characters) and looked up with
`getpwnam_r`; a missing or uid-0 account is refused, and a set but invalid value
is an error rather than a fall-through to the next source. The name is emitted as
a JSON string literal, and `--check` decodes it the same way and reports a rule
whose name fails validation as `corrupt`. For valid names the rule file is
byte-identical to before, so installed rules still check as `installed`.
Tests: `pkexec-cache` unit tests `validate_username_*`, `expected_content_*`,
`extract_username_*`, `injected_rule_does_not_check_as_installed` (the issue's
repro) and `resolve_user_rejects_root_and_unknown_users`.

## Unreleased — the `Resolves:` line names the binary that actually runs (#62)

The prompt resolved `argv[0]` on the daemon's own PATH, but the executor
spawned the bare name with a cleared environment, so the child searched the
default login PATH (sudo searched its `secure_path`, pkexec's `env` the login
PATH). A daemon started from a dev shell (Nix, virtualenv, `~/.local/bin`)
could show one file and run another, or show a file and then fail with ENOENT.
A relative name such as `./tool` under a `chdir` was checked against the
daemon's working directory but run from the plan's.

`executor::resolve_command` now resolves each leaf once, at plan compile time,
on the child's PATH and against the leaf's `chdir`. The TUI and GUI prompts
display that result and `build_command` spawns it (keeping the requested
`argv[0]`), including as the command after `sudo --` and `pkexec env -C DIR --`.
A name that does not resolve is refused at spawn with `command not found`
instead of being looked up a second time. The pkexec `=` check now covers the
resolved path that `env` receives. Regressions: unit tests in `executor`, and
`resolves_line_names_the_binary_that_runs` in `tests/pty_e2e.rs`, which follows
the issue's repro.

## v1.2.3 — 2026-11-25 (security release)

A patch release on top of v1.2.2 with one security fix, and nothing else:

- **GHSA-gx9w-4f7x-2gcp** (high): the daemon no longer looks up `sudo`,
  `pkexec`, its GUI dialogs, or the `env` it probes for `-C` on its own
  `PATH`, where a same-UID process could plant one (e.g. in `~/.cargo/bin`).
  It uses the first setuid-root `sudo`/`pkexec` in a root-owned directory on
  a fixed list (`/run/wrappers/bin` + the default login PATH).
  `--sudo-path PATH` names it explicitly for other layouts. On main, the pty
  harness now passes `--sudo-path tests/shims/sudo` instead of putting the
  shim first on the daemon's PATH.

**Upgrade note:** if `sudo` on your host is not in one of those directories,
start the daemon with `--sudo-path`; it warns at startup when none is found.

## v1.2.2 — 2026-11-21 (security release)

A patch release on top of v1.2.1 with one security fix and one backported
fix, and nothing else (main's 1.3 work is not included):

- **GHSA-cpmp-67wf-gwmx** (high): the daemon refuses to start in a terminal
  that other same-UID processes can type into (tmux/screen, kitty/WezTerm/
  Konsole remote control, X11, …), unless started with
  `--allow-injectable-tty`. Unprivileged children no longer share its
  controlling terminal.
- **#62** (backport of #80): the `Resolves:` line names the binary that
  actually runs.

**Upgrade note:** if you start the daemon inside tmux/screen or on X11, it now
refuses with an explanation; move it to a terminal of its own on Wayland, or
pass `--allow-injectable-tty`. With `--host`, upgrade the remote first if you
use the override, since a 1.2.1 remote rejects the forwarded flag.

### Refuse approval terminals other processes can type into (GHSA-cpmp-67wf-gwmx)

The daemon approves a request by reading one key from its terminal, and it
cannot tell a key the human typed from one injected by another process running
as the same user. The usual requester, an AI agent, also has a same-UID shell.
In tmux or screen (`send-keys`, `stuff`), in a terminal with remote control
(kitty, WezTerm, Konsole's D-Bus `sendText`), or in any X11 session
(`xdotool key y`), it could send a privileged request and answer `y` to its own
prompt, or `a` to grant itself the session.

- The daemon now checks its terminal at startup (`src/ttyguard.rs`). If it
  finds one of these, it prints each reason and refuses to start. Covered:
  multiplexer `TERM` or `$TMUX`/`$STY`/`$ZELLIJ`; kitty, WezTerm, Konsole,
  VS Code and Emacs terminals; X11 without Wayland. `--allow-injectable-tty`
  starts it anyway, with a warning line in every prompt. There is deliberately
  no `hosts.json` equivalent: an agent can write that file and restart the
  daemon through MCP. `--pkexec` skips the check, since privileged approval
  then happens in polkit's dialog.
- With `--host`, the local terminal is checked before ssh starts, and the
  override is forwarded to the remote daemon. A remote older than 1.2.2
  rejects the flag and exits, which fails closed.
- Unprivileged children now run in their own session, with no controlling
  terminal, so a command (or a background job it leaves) cannot `TIOCSTI`
  keystrokes into a later prompt. A kernel that still allows `TIOCSTI` is
  reported as a warning.
- `sudo-proxy-mcp` removes the launcher's own terminal variables (`TMUX`,
  `KITTY_*`, …) from the window it spawns, so a fresh window is not refused for
  the agent's tmux. If the daemon refuses, the window stays open until Enter,
  and the `start_server` error explains what to do.
- Docs: threat-model B3 row and attack-tree leaf 3.5 with residuals,
  assurance-case assumption A1, security/usage/install/README.

Residuals: an XWayland terminal inside a Wayland session, emulators the check
does not know, and X11 synthetic input into the polkit dialog under `--pkexec`.
The structural fix is to run the agent as a separate Unix user.

### The `Resolves:` line names the binary that actually runs (#62, backport of #80)

The prompt resolved `argv[0]` on the daemon's own PATH, but the executor
spawned the bare name with a cleared environment, so the child searched the
default login PATH (sudo searched its `secure_path`, pkexec's `sh -c` the login
PATH). A daemon started from a dev shell (Nix, virtualenv, `~/.local/bin`)
could show one file and run another, or show a file and then fail with ENOENT.

`executor::resolve_command` now resolves argv[0] on the child's PATH, and a
name containing `/` against the child's working directory `/`. The TUI and GUI
prompts display that result, and every spawn path uses it: directly (keeping
the requested `argv[0]`), as the program after `sudo` / `pkexec`, and in the
multi-stage pkexec `sh -c` string. A name that does not resolve is refused with
`command not found: <name>` instead of being looked up a second time; in a
pipeline, before any stage is spawned. The GUI dialog now also shows
`(not found in PATH)`. As in 1.2.1, the TUI shows the `Resolves:` line for the
first stage and a warning for later stages that do not resolve.

Behaviour change: a privileged command found only on sudo's `secure_path` (e.g.
`/snap/bin`) but not on the default login PATH is now refused, where it
previously ran under a mismatched prompt.

This re-applies the fix from main (#80) to the 1.2 pipeline executor; the code
differs because 1.2 predates structured plans. Regressions: unit tests in
`executor` and `exec_direct_spawns_resolved_path_keeping_argv0` in
`tests/exec.rs`.

## v1.2.1 — 2026-11-18 (security release)

A patch release on top of v1.2.0 with two security fixes and nothing else:

- **GHSA-xx2m-j9f7-gcmr** (medium): the `hosts.json` unattended-eligibility
  policy is ignored unless the file and its directories are owner-private.
- **GHSA-h6r4-gh2r-qr98** (low): a request whose `time` is more than 30 s in the
  future is rejected, which closes a replay window (a captured `stop` could be
  replayed).

### `hosts.json` policy trusted only when owner-private (GHSA-xx2m-j9f7-gcmr)

The daemon read `policy.unattended_eligible` from `hosts.json` without checking
who owned the file or its mode. So a file that someone else could write (a
foreign owner, 0666, or a group- or world-writable parent directory) could make
the daemon unattended-eligible. The threat model says attack 4.4 is "blocked by
F4", but nothing enforced that. Now `hosts::load_trusted_policy` checks the
file the way OpenSSH StrictModes does:

- The file is opened with `O_NOFOLLOW` and checked with `fstat` on the open
  descriptor, so the check and the read can't race.
- The file must be a regular file owned by the daemon's UID and not group- or
  world-writable.
- Every directory up to `$HOME` must be owned by that UID or root and not
  group- or world-writable. A root-owned sticky directory such as `/tmp` is
  allowed: others can add entries to it but can't rename or remove ours.

If the check fails, the daemon prints a warning on stderr and is not eligible
(fail closed). An explicit `--unattended-eligible` flag still wins. The host
inventory is unaffected. The pty harness (#68) confirmed the end-to-end
behaviour: an eligible 0666 file gives `[y/N]` and a warning, and a 0600 file
gives `[y/N/a]`. Rung: G7 barrier 1 (C8).

### Future-dated requests rejected; replay window closed (GHSA-h6r4-gh2r-qr98)

`parse_age` treated a `time` in the future as age 0, so a future-dated request
passed the freshness check forever. Replay protection forgets an id after
120 s, so the same bytes were then accepted again. That made a captured `stop`
replayable, and it broke REVIEWING.md C3 and the `docs/protocol.md` claim.

`parse_age` now returns a signed age. The new `check_age` rejects a `time` more
than `MAX_FUTURE_SKEW` (30 s) ahead. 30 s rather than a few seconds because
remote requests carry the client's clock. A compile-time assertion keeps
`REPLAY_RETENTION >= MAX_REQUEST_AGE + MAX_FUTURE_SKEW`, so any request that
could pass freshness again is still deduplicated.

Tests:

- The clamp test is replaced by a rejection test and a window-boundary test.
- A new property test says that any id that can pass freshness is still
  remembered. It fails when the skew check is disabled.

In the TLA+ `ReplayWindow` model, `FreshAt` bounds the future by `Skew`, and
`NoFutureReplay` moves into the checked `.cfg`, where it holds. Negative
controls show `Retention >= Freshness + Skew` is the tight bound. Rung: C3 /
extended Rung 4.

## 2026-11-17 — `cargo deny` unblocked: ignore RUSTSEC-2026-0543 (chrono unmaintained)

A new informational advisory marks every `chrono` version unmaintained, and
`deny.toml` denies unmaintained crates, so the `cargo deny` job failed on every
PR (#67, #69). `chrono` comes in only through the `mcp` feature: `rmcp`
depends on it unconditionally (and enables `schemars`' `chrono04`). Upgrading
does not help, because `rmcp` 3.11 still requires it. The advisory ID is now
ignored in `deny.toml`, with a rationale, and the `cargo audit` CI step mirrors
it. A future `chrono` vulnerability advisory has its own ID and still fails the
check. Revisit when `rmcp` moves to `jiff`/`time`. Rung: supply chain.

## 2026-11-16 — Structured composite-execution plans (PR #59): no shell on the privileged path

**The gap.** A captured approval trail (24 consecutive requests from one
`sudo-proxy-mcp` client, 2026-10-16) showed every command arriving as
`argv = ["bash", "-lc", "<script>"]`. Every `Resolves:` line was `/usr/bin/bash`,
because the real binaries were chosen inside the script by `$PATH`. And one root
approval covered several effects: one request bundled two `sysctl` writes and a
nested `sudo -u … bash -lc` under a single "y".

**The fix.** A request's flat `pipeline` is generalised into a `Plan` tree that
the daemon runs itself, with no shell on the privileged path. The structure the
human approves is the structure that runs.

- **Schema** (`src/protocol.rs`). JSON ops modelled on Dune's shell-free action
  language: `run` (`&&`), `seq` (`;`), `alt` (`||`), `pipe`, `redirect`
  (truncate/append, `2>&1`), `with-stdin-from`, `setenv` (env allowlist),
  `chdir`, `run-as` (`[ROOT]` / `[as user]`), `with-accepted-exit-codes`, and an
  explicit opaque `system` escape hatch. Validation is recursive and bounded, and
  a flat `pipeline` turns into a plan, so existing clients keep working. A plan
  containing `run-as` counts as privileged.
- **Executor** (`src/executor.rs`). Fork/exec for each step, with pipes and
  redirections. An escalated step runs as `sudo [-u user] -- argv` (or
  `pkexec env -C dir -- argv`), never `sudo sh -c`. `pipeline_to_shell` is gone.
- **Prompt** (`src/tui.rs`). A `Steps:` block and a paste-able `Command:` line,
  printed from one layout that groups like the executor runs. Each step shows
  its run-as tag and its own resolved binary; `system` steps are flagged opaque.
- **Clients.** The MCP `execute` tool takes a `plan`; `sudo-request` gained
  `--plan` / `--plan-file`; the daemon gained `--log-json`.
- **Evidence.** Rung 2 properties: the prompt texts and the executor agree (bash
  parse trees, a differential run against `sh`), and no shell appears on the
  privileged path. Also a Kani harness, `tests/plan_exec.rs`, and a manual corpus
  of real logged requests (`tests/manual/log-corpus/`).

Escalation stays per step through `sudo`, with the daemon running as the user; a
root daemon calling `setuid` itself is recorded in the backlog as an option. The
follow-ups (the `exec sh -c` loophole, strict no-shell mode, `detach` and
read-file ops, display-fidelity rungs) are in the backlog.

## 2026-11-09 — PR #59 review: the displayed plan now means what runs

A review of the structured-plan PR found plans whose prompt text meant
something other than what the executor ran, and a `--pkexec` approval gap.
Fixed in `dcd8723`:

- **`--pkexec` gate.** Only `privileged: true` requests go to pkexec. A plan
  that escalates only through `run-as` takes the TUI prompt and sudo, so its
  unescalated steps can no longer run unapproved.
- **`with-accepted-exit-codes` is shown** (was backlog Priority #1 item 8). It
  renders as `{ cmd || [ $? -eq N ]; }` (a `case` for several codes) in both
  `Steps:` and `Command:`, with an `# exit N accepted` comment in Steps, and
  both G4.5 property tests now generate it.
- **Validation rejects shapes with no faithful shell spelling:** a stream
  redirected twice along one path, `with-stdin-from` on a later pipe stage,
  relative `chdir`/redirect/stdin paths, and env keys that are not shell
  variable names.
- **`run-as` user `root`** is normalised to root; the sudo `#uid` form is refused.
- **`--log-json`** escapes control and bidi characters before printing.
- **pkexec cwd.** Escalated leaves run as `pkexec env -C <dir> -- argv`, since
  pkexec otherwise starts in the target user's home.

## 2026-10-16 — Alert the human when an approval prompt appears (bell + blink)

Usability/safety work, not an assurance-ladder rung — the change is purely
additive to `prompt_tty` and leaves the security-relevant decision path
(`classify_key`, the keypress read, the timeout) untouched.

- **The gap.** A root (or unprivileged) approval prompt was written silently to
  `/dev/tty`. When the daemon's terminal was unfocused or off-screen the request
  could go unnoticed until the 60s timeout denied it — no attention signal.

- **Two attention cues, both on by default.** `prompt_tty` now rings the
  terminal bell (`\x07` / BEL) and blinks the question line (SGR `\x1b[5m` …
  `\x1b[25m`) just before the `Execute?` question. BEL is the primary cue —
  terminals map it to an audible beep and, for an unfocused window, the WM/dock
  urgency hint; the blink is the in-window fallback we fully control. We emit the
  bytes; the terminal's own visual-bell/urgency setting decides the rendering.

- **Opt-out mirrors `NO_COLOR`.** Each cue is independently silenced by its own
  env var — `SUDO_PROXY_NO_BELL` and `SUDO_PROXY_NO_BLINK` — read with the same
  `var_os(...).is_some_and(|v| !v.is_empty())` idiom as `style()`. A new `Alert`
  struct + pure `alert_for(no_bell, no_blink)` splits the env mapping from the
  I/O, exactly as `Style`/`style_for` already do.

- **Additive by construction.** The question write was factored into a
  writer-generic `write_question_line` helper (the BEL leads; the blink wraps
  only the text, so the resting cursor does not blink). Two unit tests cover the
  env mapping and assert the escape bytes are present when on and absent when
  off, exercised against a `Vec<u8>` buffer rather than `/dev/tty`. Full suite
  green; README documents the opt-out.

## 2026-09-15 — Glama quality score: from unscored to grade A

Release/hygiene work, not an assurance-ladder rung.

- **Root-caused why Glama showed `quality: null`.** The registry's `/inspect`
  view had `repository.inspectable: false` and `toolCount: 0`: Glama scores a
  server by building it, running it, and calling `tools/list`, and it does **not**
  build a `Dockerfile` from the repo — it builds from the server's admin page
  (`.../admin/dockerfile`) as *build steps* + a *CMD*, run in Glama's
  `debian:trixie-slim` base (Node + `mcp-proxy` preinstalled, but no Rust). With
  no build configured, nothing launched, so no tools enumerated.

- **Configured the admin build; the server now grades A.** Build steps install
  the Rust toolchain and run `cargo build --release --bin sudo-proxy-mcp`; the
  CMD launches the stdio binary `/app/target/release/sudo-proxy-mcp`. Glama then
  enumerated the three tools (`execute`, `start_server`, `update_host`),
  `inspectable` flipped true, and `scores.quality` computed to **A**. The
  paste-safe recipe (JSON arrays with no embedded double quotes) is documented in
  `docs/mcp.md`.

- **PRs #45 → #46 → #47.** #45 added a repo `Dockerfile` + introspection test +
  docs; #46 removed the `Dockerfile`/`.dockerignore` once we confirmed Glama
  ignores repo Dockerfiles, keeping `tests/mcp_introspection.rs` (a Docker-free
  regression guard that drives `initialize` → `tools/list` and asserts the three
  tools) and documenting the real admin-page recipe; #47 added the Glama
  server/tools/connector terminology mapping and made the documented build
  config paste-safe.

- **Declined the inapplicable Glama nudges.** "Try in browser" / hosted usage
  and "seed usage" don't fit a `hosting:local-only` server that needs a live
  daemon and a human TUI (sandbox calls only return "sudo-proxy is not
  running"); left "related servers" as-is.

- **Listed on awesome-mcp-servers** (punkpeye/awesome-mcp-servers#13975,
  `check-submission` green).

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
