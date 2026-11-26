# Threat model

[← README](../README.md) · see also [security-audit.md](security-audit.md) · [assurance-case.md](assurance-case.md) · [formalisation-roadmap.md](formalisation-roadmap.md)

This is the structured threat enumeration for sudo-proxy — **Rung 0** of the
[formalisation roadmap](formalisation-roadmap.md#the-rigor-ladder). It does two
things the prose audit did not: a **STRIDE pass per trust boundary**, and an
**attack tree** whose root is the negation of the security invariant. Every leaf
is cross-referenced to the sub-goal in [assurance-case.md](assurance-case.md)
that discharges it and to the relevant audit finding, so the threat side and the
assurance side stay traceable to each other.

## Scope

The invariant under attack is **G1**:

> Nothing privileged runs without a human deliberately approving the exact
> command shown.

The Target of Evaluation, the three adversaries (**A1** prompt-injected MCP
caller, **A2** same-UID local process, **A3** network MITM / malicious remote),
and the trust assumptions (**A1–A4** in the assurance case) are defined in
[security-audit.md](security-audit.md#threat-model) and
[assurance-case.md](assurance-case.md). They are not restated here; this
document classifies *how* those adversaries act at each boundary.

## Trust boundaries

The data-flow boundaries an attacker's input crosses on the way to root
execution:

| ID | Boundary | Primary adversary |
|----|----------|-------------------|
| **B1** | model → `sudo-proxy-mcp` (MCP stdio) | A1 |
| **B2** | MCP server / direct client → Unix socket → daemon | A2 |
| **B3** | daemon → `/dev/tty` → human (display + keypress) | A1 (content), A2 |
| **B4** | daemon → `sudo` / `pkexec` / exec → root | A1 |
| **B5** | local daemon → SSH tunnel → remote daemon | A3 |
| **B6** | daemon ↔ `hosts.json` / policy persistence | A2 |

## STRIDE per boundary

For each boundary, the STRIDE categories that bear on the invariant, the
concrete threat, the existing control, and the cross-reference
(G-node in [assurance-case.md](assurance-case.md); finding in
[security-audit.md](security-audit.md)). Categories that do not threaten the
invariant at a given boundary are omitted.

### B1 — MCP caller → server (A1)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | Caller identity is unauthenticated. | By design any caller is treated as adversarial; safety does not depend on caller identity — the human gate does. | G5, G6.1 |
| Tampering | Crafted `argv`/`env`/`description` misrepresents intent. | argv/env validation; `description`→`reason` sanitized at the daemon. | G3.3, G4.1 / F1 |
| Tampering | An unknown or misspelled plan key (`stdin_from` for `with-stdin-from`, `pth` for `path`) is silently dropped, so the plan shown and run is not the one the caller meant, and the rest of it still runs. | `deny_unknown_fields` on every plan node and redirect target (`protocol::wire`), at any depth: the request fails before prompting. `run-as` with `as: root` and a `name` is rejected. `Request` itself stays lenient, for forward compatibility. | #89 (1.3.0) |
| Repudiation | No per-request record of what was approved, or of rejected probes (replays, malformed / stale requests). | Audit log, on by default: one record per connection outcome (approved, denied, timeout, unattended, every rejection reason) with an RFC 3339 timestamp, peer UID, id, session, host and, for validated requests, the command — to stderr, an append-only 0600 JSONL file, and syslog (`LOG_AUTHPRIV`). Env values and `reason` are never recorded. | #65 (residual below) |
| DoS | Oversized / flooding requests block the gate. | 1 MiB request cap, 64 in-flight cap. | G6.4 |
| Elevation | Obtain root without approval. | Unconditional human gate on `privileged:true`. | G5, G6.1 |

### B2 — Unix socket → daemon (A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | A different-UID process connects. | `SO_PEERCRED` check + 0600 socket. | G2.3 |
| Tampering | Direct client sets `host`/`session`/`id`/`version`/`requester` to inject display content, bypassing client-side `validate_host`. | Display-field sanitization moved into daemon-side `validate_request`. | G4.1, G6.2 / F1 |
| Spoofing | Client misdeclares its `requester` (e.g. an AI claiming `human`, or a script claiming `ai`) to change how the approver reads the prompt. | `requester` is display-only metadata, never a trust input: the prompt labels it "self-declared, not verified" and no gate or policy reads it. `sudo-proxy-mcp` always sends `ai` / `ai:<id>` (client-side enforcement; the daemon cannot verify it). Issue #25. | G4.1 |
| DoS | Replay of a captured request; connection flooding. | UUID dedup; in-flight cap. | G2.1, G6.4 |
| Elevation | Bypass the MCP layer's `validate_host`. | Daemon-side controls do not depend on it. | G6.2 |

### B3 — daemon → TTY → human (A1 content, A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | ANSI / control / bidi sequences forge a benign-looking command in the prompt. | `has_dangerous_chars()` rejects control, format, separator and default-ignorable (Cc/Cf/Zl/Zp/DICP) characters on every displayed field; resolved absolute path of argv[0] shown with `-> target` on symlinks; filesystem-derived `Resolves:` paths escaped (#86). | G4.1, G4.2 / F1 |
| Tampering | A huge argument pushes the real command and `[y/N]` off-screen. | Every prompt line and block length-bounded (`Command:`, `Steps:`, `Resolves:`, metadata) with a hidden-chars marker. | G4.3 / F3 |
| DoS | Operator never answers, leaving the gate open. | 60 s timeout, default **deny**. | G5.2 |
| Elevation | Social-engineer the human into approving. | Covered by G4; residual printable-range look-alikes accepted. | G4.4 (residual) |
| Spoofing | A same-UID process **types the answer itself**: synthetic keystrokes into the approval terminal (`tmux send-keys`, `screen -X stuff`, kitty/wezterm remote control, Konsole D-Bus, X11 XTEST, `TIOCSTI`). The typical requester (an agent) has a same-UID shell, so A1 reaches this as A2. | The daemon refuses to start in a terminal that accepts such input (`ttyguard`: multiplexer `TERM`/`$TMUX`/`$STY`/`$ZELLIJ`, remote-control emulators, VS Code, Emacs, X11 without Wayland) unless started with `--allow-injectable-tty`, which puts a warning line in every prompt. There is deliberately no `hosts.json` equivalent, since an agent can write that file and restart the daemon through MCP. Unprivileged children run in their own session, with no controlling terminal, so they cannot `TIOCSTI` into the prompt. Legacy `TIOCSTI` is reported at startup. `sudo-proxy-mcp` scrubs the launcher's terminal variables from the window it spawns. | A1 (assumption, now checked) / GHSA-cpmp-67wf-gwmx |
| Elevation | Wrapper (`env`, `nice`, `timeout`, `coreutils`…) or inline interpreter hides a shell from the opaque flag and `no_shell`; `env LD_PRELOAD=…` injects code into a vouched program; a faithful argv carries a command string run remotely or through a shell (`ssh host 'cmd'`, `rsync -e`, `scp -o ProxyCommand=…`, `git -c core.sshCommand=…`, `ext::`, `git rebase --exec`, #91). | Wrapper-aware unwrap; unparsable wrapper, PATH change, a code-loading env name (`LD_*`, `DYLD_*`, `BASH_ENV`, `PYTHONPATH`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `RSYNC_RSH`, …; `wrappers::CODE_LOADING`), a command-string option of the ssh family (`command_string::scan`; `ssh` always) or unknown runner → opaque. The same names, inherited from the daemon's environment with `--inherit-env`, are never matched by a wildcard; named exactly, they are listed on the prompt's `Env:` line and refused at startup under `no_shell` (#101). | G4.7 |

### B4 — daemon → exec → root (A1)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Tampering | Executed command differs from the validated/shown argv (shell injection). | No shell on the privileged path; `Command::new(argv[0]).args(…)`. | G3.1 |
| Tampering | The file that runs differs from the one checked and shown: renamed over, a symlink retargeted, or the same name added to an earlier `PATH` directory between the prompt and the spawn (up to 60 s, plus time queued behind another prompt). | Each program is resolved once per request and pinned: path, `(dev, ino)` and canonical target, all from one `O_PATH` descriptor. The `no_shell` check, the prompt and the spawn read that pin. The spawn is refused if the path now names another inode; a direct binary is executed through its descriptor (`/proc/self/fd/N`); a program run by a wrapper is passed to it by its pinned absolute path, so the wrapper never searches `PATH`. **Residual:** see 3.7 below. | G4.2 / #105 |
| Elevation | Environment-based escalation (`LD_PRELOAD`, `IFS`, `BASH_ENV`); agent-socket abuse. | Hard-reject env allowlist for the request's `env` and `setenv`; `privileged + forward_agent` rejected; request `SSH_AUTH_SOCK` rejected. The daemon's own environment reaches a step only by operator opt-in (`--inherit-path` / `--inherit-env`, command line only, #101), and only for a request with no escalated step, in the executor's `Direct` arm; the `sudo` process gets a cleared environment (`TERM`, `LANG`, `LC_*`), so nothing from it reaches a root step. | G3.2 |
| Tampering | With `--inherit-path`, an inherited variable or a user-writable `PATH` directory (`.venv/bin`, `~/.cargo/bin`) substitutes the code an approved unprivileged step runs. | Startup check of every `PATH` entry (absolute, owned by root or the daemon's user, not writable by group or others except a root-owned sticky directory above the entry or the user's private group); each program pinned (#105) and wrapped programs passed by absolute path; a candidate must be executable by the daemon's user (`execvp`'s rule); `Resolves:` marks `(user-writable)` files; escalated requests resolve on the login `PATH`, and helpers never on any `PATH` (B4 row above). **Residual:** see "Inherited environment" below. | G4.2 / #101 |
| Info disclosure | Child inherits the socket fd or secrets. | Execution isolation: cwd `/`, umask 0077, stdin null, no fd inheritance. Without `--inherit-env` a child gets no variable from the daemon's environment; with it, the operator chose the names, values are never shown at the prompt nor written to the audit log, and a step's output can still carry them back to the requester (residual below). | A2 (assumption), G3.x |
| DoS | Runaway child floods output. | 16 MiB per-stream output cap. | G6.4 |
| Elevation | A same-UID process plants a `sudo` (or `pkexec`, or GUI dialog) in a user-writable directory on the daemon's own `PATH` (`~/.cargo/bin`, `~/.local/bin`, shims), which then runs on the next approved privileged request with the human's credential while the prompt shows the approved command. | Helpers are never looked up on the daemon's `PATH`. They are searched on a fixed list (`/run/wrappers/bin` + the default login PATH) and a candidate is used only if it is a root-owned file, not writable by group, others or (through an ACL) the daemon's user, whose directories (as spelled and as resolved) are all the same, except that a root-owned sticky directory may be group- or world-writable (others can add entries but not replace root's; this admits NixOS's `/nix/store`), and every symlink on the spelled path must be root-owned so no one else can repoint it; `sudo` and `pkexec` must also be setuid (`helper::check_trusted`); an untrusted candidate is skipped, never used. `--sudo-path` overrides this for unusual layouts; it is CLI-only (no `hosts.json` or environment equivalent, not forwarded by `--host`, not passed by `sudo-proxy-mcp`) and announced at startup. **Residual:** whoever can replace the installed `sudo-proxy` binary, or what launches it (the terminal emulator `sudo-proxy-mcp` finds on its `PATH`, the client-side `ssh` and `~/.ssh/config`), controls the next daemon; install it where the agent cannot write. | G1 / GHSA-gx9w-4f7x-2gcp |

### B5 — SSH tunnel → remote (A3)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Spoofing | MITM impersonates the remote host on first contact. | SSH host-key / `known_hosts` (assumption A4); **gap:** no `StrictHostKeyChecking` set. | G6.3 (residual A4) |
| Tampering | Channel tampering. | SSH transport integrity (assumption A4). | A4 |
| Elevation | SSH option injection via a crafted `host`. | `validate_host` allowlist `[A-Za-z0-9._@:-]`, rejects leading `-`; host is a trailing positional; remote UID digit-only + length-capped. | G6.3 |
| Info disclosure | Eavesdropping on the tunnel. | SSH transport confidentiality (assumption A4). | A4 |

### B6 — policy / config persistence (A2)

| STRIDE | Threat | Control | Ref |
|--------|--------|---------|-----|
| Tampering | Another user rewrites `hosts.json` to set `unattended_eligible`. | The daemon trusts the policy only if `hosts.json` is a regular file owned by its UID and not group/world-writable, and every directory up to `$HOME` is owned by it or root and not group/world-writable (StrictModes-style: `O_NOFOLLOW` + `fstat` on the open fd; `hosts::load_policy_from`). Otherwise it warns and fails closed to not eligible (GHSA-xx2m-j9f7-gcmr). `save_to` writes 0600/0700. Eligibility only *permits* the session-scoped `a` grant — it does not itself run anything unattended, and a human must still press `a`; the grant is never persisted. The **privileged** gate is never relaxed. A2 with write access to the config is already same-UID and can run unprivileged code directly, so this grants no new capability. | G7 / F4, F2 |
| Info disclosure | World-readable `hosts.json` leaks host inventory, cached UIDs, policy. | After F4 fix: 0600 file / 0700 dir, mirroring the socket-bind umask pattern. | F4 |
| Elevation | Flip the privileged gate, or run unprivileged unattended, via the persisted policy. | No persisted value enables unattended exec on load (a stale `confirm_unprivileged` is inert; `unattended_eligible` only permits, never grants). Only an interactive `a` keypress on an eligible daemon flips the in-memory grant; the **privileged** gate is never relaxed. | G7 (C4, C8) / F2 |

## Attack tree

Root is the negation of G1. Children are OR-decomposed (any one path achieves
the root). Each leaf is annotated with `[control → G-node / finding · status]`.

```
A  A root command runs that the human did NOT approve
│  (= ¬G1)
│
├─ 1  Forge an authentic-looking request that skips approval   (defeat G2 / G5)
│   ├─ 1.1 Replay a previously approved request
│   │        [UUID dedup → G2.1 · blocked]
│   ├─ 1.2 Backdate / forge a fresh timestamp
│   │        [monotone freshness, checked arith → G2.2 · blocked (regr #11/#14)]
│   ├─ 1.3 Connect as a non-owner UID
│   │        [SO_PEERCRED + 0600 → G2.3 · blocked]
│   └─ 1.4 Flip persisted policy to auto-approve a privileged command
│            [privileged gate never relaxed by policy → G5.1/G5.3 / F2
│             · blocked (residual: unprivileged auto-approve, by design)]
│
├─ 2  Make the executed command differ from what was validated  (defeat G3)
│   ├─ 2.1 Shell-metacharacter injection (;, |, &&, $(...))
│   │        [no shell; structured argv → G3.1 · blocked]
│   ├─ 2.2 Environment escalation (LD_PRELOAD / IFS / BASH_ENV)
│   │        [hard-reject env allowlist → G3.2 · blocked]
│   ├─ 2.3 Control / zero-width / bidi characters in argv
│   │        [has_dangerous_chars → G3.3 · blocked]
│   └─ 2.4 An inherited variable or PATH entry substitutes code (--inherit-*)
│            [operator opt-in, unprivileged-only, wildcard exclusions, startup
│             PATH check, cleared sudo env → G3.2 / #101 · mitigated;
│             residual: the dev shell's own trustworthiness]
│
├─ 3  Deceive the human into approving the wrong thing           (defeat G4)
│   ├─ 3.1 ANSI / control / bidi in reason/host/session/id/version/requester
│   │        [daemon-side sanitization of all display fields → G4.1 / F1 · blocked]
│   ├─ 3.2 Symlink redirection of argv[0] (/usr/local/bin/foo -> /tmp/evil)
│   │        [resolved path + "-> target" shown → G4.2 · blocked]
│   ├─ 3.3 Push the real command / [y/N] off-screen with a huge arg
│   │        [every prompt line and block length-bounded (`Command:`, `Steps:`, `Resolves:`, metadata) → G4.3 / F3 · blocked]
│   ├─ 3.4 Printable-range Unicode look-alike / NBSP in reason
│   │        [cannot hide the real command → G4.4 · residual (accepted)]
│   ├─ 3.5 Answer the prompt without the human: inject `y` into the TTY
│   │        [startup refusal of injectable terminals; children without a
│   │         controlling tty → A1 / GHSA-cpmp-67wf-gwmx
│   │         · blocked for detected terminals (residual: undetected ones)]
│   ├─ 3.6 Shell or inline code behind a wrapper (env sh -c, python3 -c)
│   │        [wrapper-aware unwrap → G4.7 · mitigated; residual: awk/sed/script interpreters]
│   ├─ 3.7 Swap the approved file between the prompt and the spawn
│   │        [resolved once and pinned by inode → G4.2 / #105 · blocked;
│   │         residual: contents changed in place, script / escalated exec window]
│   └─ 3.8 The path shown differs from the path run on an inherited PATH
│            (a decoy earlier on PATH, a wrapper's own lookup)
│            [wrapped programs pinned by absolute path; execvp access rule;
│             (user-writable) marker → G4.2 / #101 · mitigated; residual:
│             shebang interpreters and programs looked up later]
│
└─ 4  Execute around the gate entirely                      (defeat G5 / G6)
    ├─ 4.1 Direct same-UID socket client bypassing MCP validate_host
    │        [validation is daemon-side → G6.2 · blocked]
    ├─ 4.2 SSH option injection / remote impersonation
    │        [validate_host + known_hosts → G6.3
    │         · blocked (residual: first-contact MITM, assumption A4)]
    ├─ 4.3 Exhaust resources to make the gate fail open
    │        [caps + default-deny timeout → G5.2 / G6.4 · blocked]
    ├─ 4.4 Tamper hosts.json to weaken the gate
    │        [enforced owner/mode check / F4; privileged gate independent → G5.3 · blocked
    │         (residual: unprivileged auto-approve, by design)]
    └─ 4.5 Use `--pkexec` delegation to run a multi-step plan behind single-step
             dialogs (or none, under `pkexec-cache`)
             [single-leaf delegation → G5.4 / #88 · blocked (residual: dialog names
              `/usr/bin/env` and omits env / exit codes; `pkexec-cache` documented as unsafe)]
```

## Coverage and residuals

Every leaf maps to a sub-goal in [assurance-case.md](assurance-case.md); no leaf
is unaccounted for. The residuals — already on record and accepted — are:

- **2.4 / 3.8 — inherited environment (`--inherit-path` / `--inherit-env`,
  #101).** Off by default; an operator turns it on for a daemon started by
  hand in a dev shell. What remains:
  - *Where the environment comes from.* It comes from `.envrc` and what it
    pulls in (`flake.nix`, `shell.nix`, `.env`), which an agent may be able
    to edit in the repository. A request to restart the daemon after such a
    change deserves the care of a privileged command; the startup report and
    its fingerprints make a change visible.
  - *Values leave through output.* stdout and stderr go back to the
    requester, so a step that prints its environment discloses the inherited
    values, and every approved step holds the operator's ambient credentials.
    A local process running as the daemon's user can read them anyway
    (`/proc`, the dev shell's files); a remote requester could not.
  - *Contents of user-writable binaries.* Pinning fixes which file runs, not
    what is in it; `(user-writable)` is the only signal.
  - *Shebang interpreters.* `#!/usr/bin/env x` looks `x` up at run time on
    the inherited `PATH`; the prompt shows the script, not the interpreter.
  - *Programs looked up later.* `just` recipes, `sops exec-env`, scripts and
    other runners look programs up on the inherited `PATH`, which the prompt
    cannot show. This is the existing open-ended-runner residual, made the
    normal case.

- **1.4 / 4.4 — unattended unprivileged window (F2, closed; bounded residual).**
  The old persisted, global auto-approve is gone (invariant G7). What remains is
  bounded: on a daemon an operator has *deliberately* made `unattended_eligible`,
  one `a` keypress opens a session-scoped, non-persistent window in which later
  *unprivileged* commands run logged-but-unprompted. The **privileged** gate is
  never affected. Judged at Bash-allow-rule parity; see
  [security-audit.md](security-audit.md) finding F2 and REVIEWING.md C8.
- **loopback self-routing (F5, closed).** `is_local_host` normalizes self/loopback
  targets; residual undetected aliases are covered by the C10 composition (every
  remote daemon still gates unattended exec). See finding F5.
- **3.5 — keystroke injection into the approval terminal
  (GHSA-cpmp-67wf-gwmx).** Detection reads environment variables and one sysctl,
  so it is best effort. It does not see an XWayland terminal (e.g. `xterm`)
  inside a Wayland session, an emulator with remote control it does not know,
  or a process that shares the daemon's controlling terminal on a kernel that
  still allows `TIOCSTI`. Nor does it cover `--pkexec`, whose polkit dialog has
  X11's own synthetic-input exposure, or a daemon the operator started with
  `--allow-injectable-tty`. An agent can always start a daemon of its own in a
  terminal it controls; that daemon's `sudo` then has no cached credential for
  the new terminal and asks for the password. The structural fix is to run the
  agent as a separate Unix user, or in a sandbox without access to the display
  or the multiplexer's socket.
- **3.4 — look-alike `reason` (F1 residual).** Printable Unicode can mislead but
  cannot conceal the real command line, which is printed separately.
  Combining overlays (U+0334–0338), RTL letters and whitespace look-alikes
  (U+00A0, U+2000–200A, U+3000) remain accepted after #86: they are printable,
  and `shquote` single-quotes any non-ASCII token, so they cannot sit next to an
  operator.
- **3.7 — what pinning does not cover (#105).** Pinning fixes *which file*
  runs, not what is in it: a file the requester can write can be rewritten in
  place (same inode) after the prompt, and its new contents run. A `#!` script
  cannot be executed through a close-on-exec descriptor (the interpreter gets
  a path that no longer opens), and `sudo` closes inherited descriptors, so a
  script and an escalated step are spawned by path after the `(dev, ino)`
  check, leaving a short window between the check and the exec. Today bare
  names resolve on the root-owned login `PATH`, so both cases need a `./name`
  in a directory the requester can write, where rewriting the file is already
  possible. Programs the approved program looks up itself (a script's
  commands, `just` recipes, `#!/usr/bin/env x`) are not shown and not pinned,
  and neither is a `find -execdir` / `-okdir` program named with a `/`, which
  `find` runs from each match's directory.
- **4.2 — SSH first-contact MITM (assumption A4).** The ssh invocation sets no
  `StrictHostKeyChecking`; safety depends on the remote being in `known_hosts`
  first, or configuring `StrictHostKeyChecking=accept-new`.
- **B1 Repudiation (#65, narrowed).** Every outcome is now recorded, but the
  JSONL file is owned by the daemon's UID — the same UID as the agent — so it
  is append-only by convention only: a same-UID process can truncate or rewrite
  it. It is tamper-evident against other users, not against the requester. The
  syslog copy, held by the system logger, is the stronger record; ship it off
  the host for a record the requester cannot reach.
- **4.5 — `--pkexec` delegation (#88, narrowed).** Only a `privileged: true`
  request that is one step with no redirection is delegated to pkexec's dialog;
  every other privileged plan gets the TUI prompt and sudo. The dialog still
  names `/usr/bin/env`, shows the working directory only as `env -C`, and omits
  plan `setenv`, request env and accepted exit codes; `pkexec-cache` (opt-in,
  documented as unsafe) removes the dialog altogether.

These residuals were the inputs to **Rung 4**, now discharged
([roadmap](formalisation-roadmap.md#the-rigor-ladder)): the policy-transition
residual (1.4/4.4) is pinned by the TLC-checked state machine in
[`proofs/tla/`](../proofs/tla/) (`PolicyFlipsOnlyOnKeypress`,
`PrivilegedGateIndependentOfPolicy`), and the SSH residual (4.2) is made explicit
by the ProVerif model in [`proofs/proverif/`](../proofs/proverif/), which models
the real host-key and client-key material and **derives** the first-contact MITM
from the attacker substituting its own host key. The model disentangles which
assumption protects what: payload **confidentiality** rides on host-key pinning
(A4) — broken on first contact, the derived MITM trace — while **command
authenticity** at the remote rides on **client authentication** (the remote's
`authorized_keys`), so even a first-contact eavesdropper cannot forge or alter a
command the honest remote will run. The 1.4/4.4 *by-design* trade-off
(unprivileged auto-approve) and the 4.2 A4 dependency remain accepted residuals —
now formally characterised rather than only argued in prose.
