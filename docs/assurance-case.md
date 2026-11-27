# Security assurance case

[← README](../README.md) · see also [formalisation-roadmap.md](formalisation-roadmap.md) · [threat-model.md](threat-model.md) · [security.md](security.md) · [security-audit.md](security-audit.md)

> The G2–G6 sub-goals below are the assurance (defence) side of the argument.
> Their threat-side counterpart — a STRIDE-per-boundary pass and an attack tree
> rooted at ¬G1, with every leaf cross-referenced back to these G-nodes — is in
> [threat-model.md](threat-model.md) (Rung 0).

This is a **security assurance case** for sudo-proxy, written in
[Goal Structuring Notation (GSN)](https://etn-sas.eu/2020/06/26/assurance-case-notations/).
It states one top-level claim, decomposes it into sub-claims by adversary and by
control, and attaches to each leaf the *evidence* that currently discharges it —
together with the [roadmap rung](formalisation-roadmap.md#the-rigor-ladder) at
which that evidence sits. As evidence strengthens (a leaf moving from "fuzz
test" to "machine-checked proof") the argument structure is unchanged; only the
**Solution** nodes are upgraded.

## Notation

GSN node kinds used here:

- **G** — *Goal*: a claim to be established.
- **S** — *Strategy*: the reasoning step linking a goal to its sub-goals.
- **C** — *Context*: a definition or scope statement.
- **A** — *Assumption*: a statement taken as true without proof (a trust
  boundary of the argument).
- **J** — *Justification*: rationale for a strategy.
- **Sn** — *Solution*: a reference to evidence.

Solution nodes carry a status: **[discharged]** (the claim holds on today's
evidence; its residuals may name strengthening still planned), **[partial]**
(today's evidence covers only part of the claim; the rest is planned),
**[planned]** (claim asserted, evidence not yet produced).

## Top-level claim

> **G1 — Nothing privileged runs without a human deliberately approving the
> exact command shown.**

> A second, parallel top-level invariant **G7** (below) guards the *unprivileged*
> surface: no unprivileged command runs with less scrutiny than the agent's Bash
> tool. G2–G6 decompose G1; G7 stands beside it with its own sub-goals.

```
                                  ┌──────────────────────────────────────┐
   C1 TOE: daemon + MCP server    │  G1  No privileged execution without  │
   + SSH-tunnel path  ───────────▶│      deliberate human approval of     │◀── J1 Single invariant;
                                   │      the exact command shown          │      every control serves it
   A1..A4 trust assumptions ─────▶└──────────────────────────────────────┘
                                                   │
                                          ┌────────┴ S1: argue over the path
                                          │   from request to root execution
        ┌──────────────┬─────────────────┼──────────────────┬─────────────────┐
        ▼              ▼                  ▼                  ▼                 ▼
      G2             G3                 G4                 G5                G6
  Authenticity   Integrity of      Faithful display   Approval is        Adversary
  of requests    what is run       at the gate        necessary &        cannot bypass
  (no replay,    (no injection,    (TUI shows the     binding           the gate
  fresh, right   no shell line,    real command)      (privileged ⇒     (A1/A2/A3
  peer)          env sanitized)                        keypress)         coverage)
```

## Context, assumptions, justification

| Node | Kind | Statement |
|------|------|-----------|
| **C1** | Context | The Target of Evaluation is the `sudo-proxy` daemon, the `sudo-proxy-mcp` server, and the `--host` SSH-tunnel path. Out of scope: the AI model, the operator's judgement when reading the prompt. |
| **C2** | Context | Adversaries: **A1** prompt-injected MCP caller; **A2** same-UID local process (direct socket); **A3** network MITM / malicious remote. (See [security-audit.md](security-audit.md#threat-model).) |
| **A1** | Assumption | `/dev/tty` is trusted: what the daemon writes is what the human sees, and the keypress read is the human's. The second half is false on a terminal other same-UID processes can type into (GHSA-cpmp-67wf-gwmx). So the daemon refuses the terminals it can recognise as such unless started with `--allow-injectable-tty`, and its unprivileged children have no controlling terminal. Residuals: [threat-model.md](threat-model.md#coverage-and-residuals) 3.5. |
| **A2** | Assumption | `sudo` (and `pkexec`) correctly enforce escalation and `env_reset`; the kernel enforces socket permissions and `SO_PEERCRED`. |
| **A3** | Assumption | The host is effectively single-user *or* the operator accepts that any same-UID process is already inside the trust boundary for non-privileged actions (finding F2). With `--inherit-path` / `--inherit-env` (#101), the directories on the inherited `PATH` and the files that define the dev shell (`.envrc`, `flake.nix`, …) are inside that boundary too. |
| **A4** | Assumption | For the SSH path, remote hosts are in `known_hosts` before first use (or `StrictHostKeyChecking=accept-new` is configured) — this gives payload confidentiality and lets the daemon reach the genuine remote; **and** the daemon authenticates to the remote by key (the remote's `authorized_keys`), which gives command authenticity at the remote. The ProVerif model ([`proofs/proverif/`](../proofs/proverif/)) makes both halves explicit and shows which guarantee rests on which. |
| **J1** | Justification | The whole security model reduces to G1 (see [security-audit.md](security-audit.md#summary)); structuring the argument around the single invariant keeps every control traceable to it. |
| **S1** | Strategy | Argue over the causal path from an inbound request to root execution: a request must be *authentic* (G2), what executes must be *the thing that was validated* (G3), the human must *see the real command* (G4), approval must be *necessary and binding* (G5), and no adversary may *bypass* the gate (G6). |

## Sub-goals and evidence

### G2 — Authenticity of requests

*Only fresh, non-replayed requests from the authorised peer are accepted.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G2.1** | Replayed request UUIDs are rejected. `SeenIds` check-and-insert is atomic. | — | |
| **Sn2.1** | `src/server.rs` dedup set; regression test in suite. | 1–2 | [discharged] |
| **G2.2** | Stale requests are rejected; freshness is monotone (no integer-wrap bypass, regressions #11/#14). | — | |
| **Sn2.2** | `parse_age` fuzzed with 20000 random + extreme inputs (`server::tests::fuzz_parse_age_*`); `checked_*` arithmetic throughout. | 2 | [partial] → Kani bounded proof (Rung 3) |
| **G2.3** | The connecting peer is the daemon UID. | — | |
| **Sn2.3** | `SO_PEERCRED` on the accepted connection; cross-UID rejected; 0600 socket via umask-around-bind + chmod (no TOCTOU). `src/server.rs`. | 1 | [discharged] |

### G3 — Integrity of what is run

*The command that executes is exactly the validated argv, with no injection and
a sanitized environment.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G3.1** | The daemon never builds a shell command line: every step execs its argv word for word, never re-parsed (each program word replaced by its pinned absolute path, #105). An escalated step is `sudo [-u user] [K=V…] -- program args` or `pkexec [--user user] env -C dir -- program args`; the daemon never wraps a step in `sh -c`, so shell metacharacters in a request cannot inject. The daemon starts a shell only where the request names one (a `shell` op, or a shell as the program, directly or behind a wrapper); such a step is flagged opaque (G4.7) and refused under `no_shell`. Programs that start a shell themselves (`make`, `awk` `system()`) are G4.7 residuals. | — | |
| **Sn3.1** | `src/executor.rs` `build_command`: the pinned program and each argv word are passed with `Command::new`/`arg`/`args`, never joined into a string. `prop_built_command_is_the_argv_word_for_word` (200 random leaves: run-as root, a named user or none; argv words full of shell metacharacters and `-c`, `--`, `-u`; random env): the built `sudo` and `pkexec` argv equal the forms above exactly, and a direct leaf passes `argv[1..]` unchanged, so no word is added, split, joined or reordered. `escalated_leaf_is_literal_argv_never_a_shell_wrapper` (one example per mode); `tests/no_shell.rs` (`no_shell_rejects_opaque_stages_without_prompting`, a `shell` op among the opaque requests). The structured-plan executor removed the old multi-stage `sh -c` and its `shell_escape`, and the round-trip property that guarded them. Residual: on a host with no trusted `sudo` or `pkexec` (a container), the property checks only the modes it can build. | 2 | [partial] → Flux boundary type (Rung 3) |
| **G3.2** | The environment is a hard-reject allowlist; `LD_PRELOAD`/`LD_*`/`IFS`/`BASH_ENV`/`SSH_AUTH_SOCK` are rejected, not stripped. The daemon's own environment reaches a step only by operator opt-in (`--inherit-path` / `--inherit-env`), only for a request with no escalated step, and never reaches the `sudo` process or a root step. | — | |
| **Sn3.2** | `src/executor.rs` env sanitization; login defaults from `getpwuid(geteuid())`, not the request. #101: the inherited layer is applied only in `build_command`'s `Direct` arm; the server decides once per request from `effective_privileged()` and `compile_plan` refuses an escalated request or leaf that would inherit; the `sudo` process gets a cleared environment (`TERM`, `LANG`, `LC_*`); wildcards never match code-loading, terminal or `SSH_AUTH_SOCK` names (`src/inherit.rs`). `tests/inherit.rs` (`escalated_request_gets_nothing_inherited`: no inherited name in any step of `gen \| run-as root cat`, nor in sudo's argv or environment), `tests/escalator_stub.rs`. Residual: a step's output can return inherited values to the requester; the dev shell's own trustworthiness (A3). | 1–2 | [discharged] |
| **G3.3** | Inputs carrying control, format, separator and default-ignorable (Cc/Cf/Zl/Zp/DICP) characters are rejected before use. | — | |
| **Sn3.3** | `has_dangerous_chars()` over every `pipeline` arg and `env` key/value; `tests/validation.rs` (widened in #86; class checked exhaustively against the UCD; Kani proves string/char agreement). | 2 | [discharged] |

### G4 — Faithful display at the gate

*The TUI shows the operator the real command and nothing that misrepresents it. G4.8 is the only claim made of the GUI dialogs.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G4.1** | No request field rendered to `/dev/tty` can inject ANSI or control, format, separator and default-ignorable (Cc/Cf/Zl/Zp/DICP) characters. | — | |
| **Sn4.1** | After **F1** fix: `has_dangerous_chars()` is applied to `reason`, `session`, `host`, `version`, `id`, `requester` in `validate_request`, covering both MCP and direct-socket paths; regression test (widened in #86; class checked exhaustively against the UCD; Kani proves string/char agreement). | 2 | [discharged] |
| **G4.2** | The resolved absolute path of argv[0] is shown, with `-> target` when it is a symlink, so redirection cannot be hidden. With an inherited `PATH` (#101), a program the daemon's user could replace is marked `(user-writable)`, and a long path is clipped in the middle so its name and target stay visible. | — | |
| **Sn4.2** | `src/tui.rs` path canonicalisation + explicit failure message. Programs run by a wrapper are listed too, with `(run by …)`: with their path for a stage running as the daemon user, `looked up at run time` for an escalated one, and no path for a multi-call applet, which the dispatcher runs built in (#87). The path shown is the path that runs (#105): `executor::prepare` compiles the plan once, resolving each program and pinning it (an `O_PATH` descriptor, its `(dev, ino)`, and the canonical target read through that descriptor). The `no_shell` check, the prompt (`Prompter` takes the `PreparedRequest`) and the spawn read that one value; the spawn is refused if a path names another inode by then, a direct binary is executed through its descriptor, and a program run by a wrapper is passed to it by its pinned absolute path. Evidence: `tests/pinning.rs`, `resolution_pins_the_inode_it_found`, `spawn_argv_names_wrapped_programs_by_path`. Residual: contents changed in place (same inode); the window between the identity check and the exec for a `#!` script or an escalated step, which is spawned by path; programs the approved program looks up itself. | 1 | [discharged] |
| **G4.3** | A large command cannot push the real command or the `[y/N]` line off-screen. | — | |
| **Sn4.3** | After **F3** fix and #85: every line written to the approval prompt is length-bounded (`Command:` 1024 chars; `Steps:` lines, `Resolves:` names and paths 160; metadata fields 256; `Env:` 1024; each with an explicit hidden-chars marker, and the `Steps:` and `Resolves:` blocks are capped at 32 entries. The prompt has no `⚠ invalid plan` line any more (#90 bounded it): it renders a `PreparedRequest`, which exists only for a plan that compiled (#105), and the daemon rejects a plan that does not compile before prompting, so `compile_plan` errors, which can quote request data, never reach the prompt. Evidence: `prop_prompt_lines_are_bounded_and_prefix_faithful`, `huge_argument_prompt_is_bounded` (pty), the `long-argument` golden, and `plan_disallowed_setenv_rejected_without_prompt` (ordering). Residual: the bound limits the prompt's size to a constant but does not guarantee it fits a small terminal (worst case about 70 lines, plus wrapping at 80 columns); and characters are counted as chars, not terminal columns: wide CJK glyphs take two columns, and tabs (allowed by `has_dangerous_chars`) can each expand to up to 8 columns, so a 160-char `Steps:` line of tabs can render about 1 280 columns (16 rows at 80 columns) (#98). The clip is applied to the whole rendered text, so a long argument can push a chain operator, a group's `(` or `)`, or a redirection (`> path`, `2>&1`, `< path`) into the hidden tail of its `Steps:` line, and of `Command:` past 1024 chars; the marker shows that text is hidden, but not which (#97). | 2 | [discharged] |
| **G4.4** | Residual: printable-range Unicode look-alikes / NBSP in `reason` (passive, cannot hide the real command). | — | |
| **Sn4.4** | Documented residual in [security-audit.md](security-audit.md) (F1). | 0 | [accepted-risk] |
| **G4.5** | The grouping shown at the gate is the grouping that runs: the `Steps:` block (what the operator reviews) and the `Command:` line (what they may paste) parse, as shell, to the same tree, and that tree means what the executor runs. | — | |
| **Sn4.5a** | Syntactic half (render ⇒ shell tree): the `Steps:` block and the `Command:` line parse to the same tree. `src/tui.rs`: both are printed from one layout tree (the rules in [testing.md](testing.md#how-the-prompt-shows-grouping)); golden layouts; `prop_steps_and_command_parse_to_the_same_tree` (bash parse trees equal, 300 random plans incl. `run-as`, redirections, quoting, `with-accepted-exit-codes`); `tests/manual_corpus.rs` (bash parse check on every manual plan). Shapes with no faithful shell spelling (a stream redirected twice, `with-stdin-from` on a later pipe stage, relative paths, env keys that are not shell names) are rejected by `ValidatedRequest::validate`. Residuals: `bash` is the oracle, not a specification; the two parse trees are compared with each other, not with the plan's structure (Phase 2 parser, Rung 3 Kani). | 2 | [discharged] |
| **Sn4.5b** | Semantic half (shell tree ⇒ executor): that tree means what the executor runs. `prop_displayed_text_runs_like_the_executor` (executor stdout = `sh` on each text, 150 random side-effect-free plans); `with-accepted-exit-codes` renders as `{ cmd \|\| [ $? -eq N ]; }` (a `case` for several codes) and is in the property. Residuals: the differential run covers only privilege-free, side-effect-free plans (no `run-as`, no file other than `/dev/null`); a pasted line runs under the operator's environment, not the executor's sanitized one; after a failed `cd` the two still diverge on what follows the scope: the executor aborts the whole plan (the spawn fails), while a shell running the pasted line skips the scope's body (`( cd DIR && ( body ) )`, so it never runs in the previous directory) but goes on with any `;`-sequenced steps after it. | 2 | [partial] → see [formalisation-roadmap.md](formalisation-roadmap.md#display-fidelity-across-the-rungs) |
| **G4.6** | Syntax is daemon-owned. Every piece of shell syntax in the command slot (the `Command:` line and the `Steps:` block) is written by the daemon from the plan: operators, parentheses, redirection arrows and fd numbers, `sudo`, `cd`/`export`, the `with-accepted-exit-codes` wrapper and its trailing `# exit N accepted` comment, quoting. A string from the request appears there only as a token quoted by `shquote` (for `setenv`, the value part of the `KEY=` assignment word). The one string printed without `shquote` is a `setenv` key, which validation restricts to a shell name, a subset of the characters `shquote` leaves unquoted, so it reads exactly as its quoted form would. A program word that `shquote` leaves bare but a shell would read as syntax (an assignment `NAME=…` or `NAME+=…`, or a reserved word such as `time`) is rejected at validation. A plan key the grammar does not define is rejected at any depth before prompting, so every wire field is one the renderer prints by these rules. No wire field reaches the slot as syntax: a `shell` op's script appears as one quoted argument to `sh -c` or `bash -c`, flagged opaque (G4.7). In the `Resolves:` block, every request word (program and wrapper names, the words an opaque reason quotes) and every filesystem path (escaped first, #86) is quoted the same way, so none can pass for a column, a `->` arrow or a marker the daemon writes. | — | |
| **Sn4.6** | `src/tui.rs` `layout`, `lay_*`, `redir_suffix` (by construction: every request string goes through `shquote`; exit codes are formatted integers; enums map to fixed text). `prop_shquote_reads_back_as_one_word`: in `sh` and in `bash`, `shquote(w)` reads back as the one word `w`, for every metacharacter, quote, blank and non-ASCII sample alone and at the start, middle and end of a word of unquoted-safe characters, for brace and glob words run where the globs match, and for 200 random words. `protocol::is_valid_env_name`; `protocol::check_command_word` and `program_word_that_reads_as_shell_syntax_is_rejected` (in a plan at any depth and in the flat `pipeline`). `deny_unknown_fields` on every plan node and redirect target (`protocol::wire`, `plan_rejects_unknown_keys_at_every_level`). `Resolves:`: `shown_path`, `write_resolve_block`, the reason texts of `wrappers.rs` and `command_string.rs`; `resolves_quotes_names_and_paths_that_could_pass_for_columns`, `describe_texts`. Residuals: the slot is rendered from a second walk of `Plan`, not from the compiled plan the executor runs (#89 step 5); no lint stops a request-derived string from reaching the TTY other than quoted by `shquote` or, for metadata, sanitized on a fixed label line (step 9); no runtime check that the text shown parses back to the compiled plan (Phase 2); `bash` decides which words are syntax, so the reserved words of other shells (zsh's `repeat`, `foreach`, `end`) are not rejected. | 1–2 | [partial] → see [formalisation-roadmap.md](formalisation-roadmap.md#display-fidelity-across-the-rungs) |
| **G4.7** | A stage that runs a program the prompt cannot show stage by stage (a shell, an inline-code interpreter, a program of the ssh family carrying a command string run remotely or through a shell, a non-unwrapped runner, or any of these behind a known wrapper) is flagged opaque and refused under `no_shell`. An `env` wrapper setting any code-loading variable is opaque; inherited code-loading variables are named on the `Env:` line and refused at startup under `no_shell` (#101). Residual: shebang interpreters and programs looked up later, on the inherited `PATH`, are not shown. | — | |
| **Sn4.7** | `src/wrappers.rs` unwrap (#87) and its fail-closed rules (unknown option, missing argument, `env -S`/`-i`/`PATH`, the env names rejected as in G3.2, `find -exec {}`, an action word inside a `find -exec` command, `xargs -I` replacement in the program word, a `find`/`xargs -I` placeholder or `xargs`-appended input reaching a nested wrapper's words, a command-string program's arguments or an interpreter's words up to its script (#92 review), `--` or any other option word where a program is expected, dispatcher options, ambiguous names, depth > 8); `flock FILE -c`/`--command` (#92); `src/command_string.rs` (#91): `ssh`, `sftp` (its batch file or stdin can run `!command`) and dashed `git-<command>` always, `git` subcommands off an allowlist always, and the `scp`/`sftp`/`rsync`/`git` options and words that carry a command string or name a program or library to load (coarse, fail-closed scans; ssh's `-o` tokenizing, git's long-option abbreviations and switch clusters included); a file named on the command line that carries commands is a trigger; a wrapper name resolving to an interpreter or command-string program (or the reverse) is ambiguous; unit tables; `scan_is_total`; `prop_wrapping_preserves_opacity` (with the ssh family among its names); `tests/no_shell.rs`, `tests/pty_no_shell.rs`, the `remote` UI golden. Residuals: `awk`/`sed`/`make` and other open-ended runners; commands set in files a program finds by convention (git hooks and config, `~/.ssh/config`, popt aliases); programs a scanned git subcommand looks up on PATH (pager, `man`, `gpg`, `ssh`); interpreters running a script file; env names only some programs interpret (`GIT_PAGER`, `GIT_EDITOR`, `SSH_ASKPASS`, …). | 2 | [partial] |
| **G4.8** | The GUI dialogs (`src/gui.rs`, zenity / kdialog) show every request field as literal text: no markup, no rich text or link, and no line break from a backslash escape. Their `Command:` line is the TUI's (`command_summary`, bounded like it). They are not otherwise G4-faithful; see the residuals. | — | |
| **Sn4.8** | `src/gui.rs` (#95): zenity is run with `--no-markup` (`gtk_label_set_text`, no `g_strcompress`); kdialog, which has no plain-text option, gets the text entity-escaped, `\` doubled for its `parseString`, inside `<qt><p style="white-space:pre-wrap">`. Unit tests `zenity_args_disable_markup`, `kdialog_text_is_literal` (round trip through kdialog's unescaping and HTML's), `format_prompt_text_carries_fields_verbatim`, `format_prompt_text_shows_plan_commands` (the `Command:` line was blank for every plan request, so for all of `sudo-proxy-mcp`'s); checked against the upstream sources (zenity 4.2.1 `msg.c`, kdialog `kdialog.cpp`/`utils.cpp`, kwidgetsaddons `kmessagebox.cpp`) and live (zenity 4.2.1; kdialog from Debian trixie under Wayland), before and after. Over-wide lines are shortened in the middle with `…` by kdialog (`KSqueezedTextLabel`, checked live: the markup survives). Residuals, for #98.1: no `Steps:` block, opaque marker (G4.7), `-> target` or `(user-writable)` marker (G4.2), `Env:` line (#101), or bound on the metadata lines and the `Resolves:` block (G4.3). `GuiPrompter` is not used by the `sudo-proxy` binary. | 2 | [discharged] |

### G5 — Approval is necessary and binding

*A privileged command executes only after an interactive keypress, and the
keypress binds to the command shown.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G5.1** | `privileged:true` always reaches the Y/N gate regardless of any policy. Exception: under the opt-in `--pkexec` flag, polkit's dialog replaces the Y/N gate for a single unredirected escalated step; see G5.4. | — | |
| **Sn5.1** | TLC-checked: the `PolicyFlipsOnlyOnKeypress` invariant of [`proofs/tla/`](../proofs/tla/) proves the policy flag flips only via an interactive `a` keypress on an unprivileged request — never a request field, replay, MCP flag, or timeout — over all attacker forgeries/replays and operator choices. `src/server.rs`. | 4 | [discharged] (model-checked) |
| **G5.2** | The prompt reads a single keypress in non-canonical mode and times out after 60 s (default **deny**). | — | |
| **Sn5.2** | `src/tui.rs` prompt; timeout test. The GUI dialogs (`src/gui.rs` `run_dialog`, #95 review) use the timeout the server passes: a dialog still open at the deadline is killed and denied as a timeout (kdialog had none; zenity's `--timeout` is not relied on alone); `run_dialog_denies_an_unanswered_dialog_at_the_deadline`, `zenity_timeout_rounds_up_to_whole_seconds`. | 1 | [discharged] |
| **G5.3** | No policy value relaxes the **privileged** gate: `privileged:true` requires a `y` keypress regardless of `unattended_eligible` or the session grant. | — | |
| **Sn5.3** | TLC-checked: `PrivilegedGateIndependentOfPolicy` ([`proofs/tla/`](../proofs/tla/)) proves the privileged gate requires a `y` keypress for *any* eligibility/grant state. The *unprivileged* side (eligibility + session grant) is the second invariant **G7** below. | 4 | [discharged] (model-checked) |
| **G5.4** | Under `--pkexec`, approval is delegated to polkit only for a request whose dialog shows one escalated argv with no redirection (`privileged: true`, one leaf, no redirection); every other privileged request reaches the TUI Y/N gate. | — | |
| **Sn5.4** | `src/server.rs` `delegate_to_pkexec` (unit table `delegate_to_pkexec_only_for_a_single_plain_leaf`; it reads the same `PreparedRequest` views the prompt renders); `tests/plan_exec.rs` `pkexec_mode_prompts_for_multi_leaf_privileged_plans`, `pkexec_mode_still_prompts_for_run_as_plans`; `tests/pty_e2e.rs` `pkexec_flag_multi_step_plan_gets_the_tui_prompt`. Residuals: the dialog names `/usr/bin/env` and shows the working directory only as `env -C DIR`; it does not show plan `setenv`, request env or `with-accepted-exit-codes` (whether `setenv` reaches the program under pkexec at all is unverified; see backlog); `pkexec-cache` makes even a single-step request run with no dialog (documented as not recommended). | 1–2 | [discharged] |

### G6 — Adversary cannot bypass the gate

*Each named adversary is covered; no path reaches root execution around G2–G5.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G6.1** | **A1** (MCP caller): all attacker-controlled fields are validated; structured argv (never a shell string); HITL gate is unconditional for privileged. | — | |
| **Sn6.1** | OWASP MCP HITL + structured-invocation controls realised; `tests/validation.rs`, F1 fix. | 0–2 | [partial] |
| **G6.2** | **A2** (same-UID direct socket): daemon-side validation does not depend on client-side `validate_host`; display fields validated at the daemon. | — | |
| **Sn6.2** | F1 fix moves sanitization into `validate_request` (daemon side); `SO_PEERCRED` + 0600. | 2 | [discharged] |
| **G6.3** | **A3** (network / remote): `validate_host` allowlist `[A-Za-z0-9._@:-]`, rejects leading `-` (ssh option injection); host is a trailing positional; remote UID digit-only + length-capped; ssh via argv. | — | |
| **Sn6.3** | `src/server.rs`, `src/bin/sudo-proxy.rs`, `src/hosts.rs`. ProVerif model ([`proofs/proverif/`](../proofs/proverif/)) makes **A4 explicit** by modelling the real host-key + client-key material: it **derives** the first-contact MITM from host-key substitution (payload secrecy `false` unpinned — leaf 4.2), and disentangles confidentiality (rides on host-key pinning) from command authenticity (rides on client auth, so it holds even on first contact); the separation theorem shows a channel compromise does not bypass the local keypress gate. Residual A4 (no `StrictHostKeyChecking`) now formally characterised, not closed. | 4 | [discharged] (residual A4 made explicit) |
| **G6.4** | Resource exhaustion cannot force-open the gate: 1 MiB request cap, 64 in-flight, 16 MiB output cap. | — | |
| **Sn6.4** | `src/server.rs`, `src/executor.rs`; cap test (flaky **S2**, control sound). | 1–2 | [partial] |

### G7 — No unprivileged command runs with less scrutiny than the Bash tool

*Every unprivileged command faces a live human gate unless an operator made its
host eligible out-of-band AND a human confirmed the session; and a self/loopback
target cannot route around that gate.*

| Node | Claim / Evidence | Rung | Status |
|------|------------------|------|--------|
| **G7.1** | No unprivileged command runs unattended except behind two barriers — `unattended_eligible` (config-only, immutable at runtime) AND an in-session `a` keypress — and the grant is never persisted. | — | |
| **Sn7.1** | `tests/approval.rs` (`every_unprivileged_request_is_prompted_when_not_eligible`, `non_eligible_approved_always_grants_nothing`, `eligible_approved_always_grants_session_but_never_persists`, `grant_is_keyed_by_session`); `src/hosts.rs` (`stale_confirm_unprivileged_key_is_inert`). TLC: `NoUnattendedUnprivilegedExec` ([`proofs/tla/`](../proofs/tla/)). Closes audit **F2**. | 2, 4 | [discharged] |
| **G7.2** | No persisted policy value enables unattended execution on load (fail-closed default; stale `confirm_unprivileged` inert). | — | |
| **Sn7.2** | `src/hosts.rs` serde tests; `Policy::default` is `unattended_eligible=false`. | 2 | [discharged] |
| **G7.3** | A self/loopback target is classified local and cannot route SSH-to-self around local policy; local unprivileged is delegated to the Bash tool. Soundness of undetected aliases rests on G7.1 holding on every daemon (C10). | — | |
| **Sn7.3** | `src/server.rs` (`is_local_host_classifies_self_and_loopback`), `src/mcp.rs` (`normalize_host_folds_loopback_to_local`). Closes audit **F5**. | 2 | [discharged] |
| **G7.4** | `--inherit-path` / `--inherit-env` are command-line only (no request field, `hosts.json` key or environment variable), never forwarded (`--host` refuses them; `sudo-proxy-mcp` builds a fixed command line), and exclude the `a` answer (`--unattended-eligible` refused, a `hosts.json` `unattended_eligible` ignored, and the server forces eligibility off). | — | |
| **Sn7.4** | `src/bin/sudo-proxy.rs` `inherit_config`; `src/server.rs` `run`; `tests/inherit.rs` (`startup_refusals`, `mcp_never_passes_the_flags`). (#101) | 1–2 | [discharged] |

## Open items tracked against the case

These are the leaves where the argument is currently weakest, drawn from
[security-audit.md](security-audit.md) and the rungs not yet climbed:

- **Sn2.2** — the freshness arithmetic is discharged by **Kani** (Rung 3);
  `Sn5.1 / Sn5.3` (the approval + policy transitions) are now discharged by the
  **TLC-checked** state machine ([`proofs/tla/`](../proofs/tla/), Rung 4).
- **Sn6.3** — the A3 channel guarantees rest on assumption **A4**; the
  **ProVerif** model ([`proofs/proverif/`](../proofs/proverif/), Rung 4) now
  makes that dependency explicit by *deriving* the first-contact MITM from
  host-key substitution (a *characterised residual*, not a closed one — see leaf
  4.2), and attributes confidentiality to host-key pinning vs command
  authenticity to client auth.
- **Sn6.4 / S2** — stabilise the flaky resource-cap test so the cap stays
  covered in CI.
- **Sn4.4** — accepted residual risk (look-alike `reason`).
- **G7.1 residual** — the bounded unattended window on an eligible daemon after an
  `a` keypress (audit **F2**, now closed but with a characterised residual);
  judged at Bash-allow-rule parity. Revisit if a command allowlist / auto-approve
  surface is ever added (see the
  [allowlisting note](architecture.md#design-note-allowlisting-when-it-lands)).

## How to use this document

1. When a control changes, update the corresponding **Solution** node and its
   status — not the goal structure.
2. When climbing a [roadmap rung](formalisation-roadmap.md), the deliverable is
   a stronger Solution node here (e.g. a Kani proof replacing a fuzz test under
   Sn2.2), with the Rung column bumped.
3. When adding a feature that introduces a new path to execution (notably any
   auto-approve / allowlist surface), add the sub-goals it must satisfy under
   G5/G6 *before* merging, so the case never silently develops a gap.
