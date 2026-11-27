# Security considerations

[← README](../README.md)

For a point-in-time adversarial audit of the source tree, see
[security-audit.md](security-audit.md). For the longer-term plan to formalise
this security model — from code review up to mechanized verification — see
[formalisation-roadmap.md](formalisation-roadmap.md), the structured
[threat-model.md](threat-model.md) (STRIDE + attack tree), and the GSN
[assurance-case.md](assurance-case.md).

**Environment:** the request `env` is gated by a hard allowlist
(`LANG`, `LC_*`, `TZ`, `HOME`, `DEBIAN_FRONTEND`, `TERM`), and every key must
be a shell variable name (`[A-Za-z_][A-Za-z0-9_]*`). Anything else —
including `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, etc. — produces an
error response; nothing is silently stripped. For pkexec and direct
execution the process environment is cleared before applying the
allowlist. For sudo mode the `sudo` process gets a cleared environment
plus `TERM`, `LANG` and `LC_*` from the daemon's, and the request's
variables as `K=V` arguments; sudo's own `env_reset` policy then applies. So
nothing else from the daemon's environment reaches a root command, not even
the names sudo's `env_keep` would pass through (`DISPLAY`, …). `SSH_AUTH_SOCK` is
rejected with a specific error; agent forwarding goes through the
dedicated `forward_agent` field instead (see "SSH agent forwarding"
in [usage.md](usage.md)).

**No shell command line:** each step is executed via
`Command::new(<pinned path>).args(…)`, and an escalated step as
`sudo [-u user] [K=V…] -- program args`. The daemon never builds a shell
command line or wraps a step in `sh -c`, which prevents `;`, `|`, `&&`
injection. It starts a shell only where the request names one (a `shell` op,
or a shell as the program, directly or behind a wrapper); the prompt flags
such a step opaque and the `no_shell` policy refuses it. Programs that start
a shell themselves are not detected (see "Not detected" in
[usage.md](usage.md)).

**Program names that read as shell syntax:** a program word the approval
prompt would show as shell syntax (`FOO=bar`, read as an assignment, or a
reserved word such as `time`) is rejected; name such a program by path
(`./FOO=bar`, `/usr/bin/time`).

**Input validation:** argv and env strings are rejected if they contain control,
format, separator or default-ignorable characters (Unicode Cc, Cf, Zl, Zp and
Default_Ignorable_Code_Point, except tab: e.g. ESC, DEL, C1, soft hyphen,
zero-width, bidi controls, BOM, tag characters, variation selectors) that could
mislead the user during TUI approval.

**Replay protection:** request UUIDs are tracked in a set that is cleared every
1000 entries. Duplicate IDs are rejected. Requests must carry a non-empty
`time`; missing, unparseable, or older-than-60-seconds values are rejected.

**Socket security:** the socket file is created with mode 0600 (owner-only).
`$XDG_RUNTIME_DIR` is already restricted to the user.

**Execution isolation:** child processes run with cwd `/`, umask 0077, and
stdout/stderr piped — they do not inherit the socket file descriptor. stdin is
null. Privileged children (sudo, pkexec) stay in the daemon's session so sudo
can open the terminal for its password prompt. Unprivileged children run in a
session of their own, with **no controlling terminal**, so they cannot inject
keystrokes into the approval prompt with `TIOCSTI` (GHSA-cpmp-67wf-gwmx).

**Approval terminal (GHSA-cpmp-67wf-gwmx):** the prompt cannot tell a key the
human typed from one another process running as the same user injected, and
an AI requester typically has a same-UID shell. So the daemon refuses to start
in a terminal that accepts synthetic input from other processes:

- tmux, GNU screen, zellij (`TERM`, `$TMUX`, `$STY`, `$ZELLIJ`);
- kitty, WezTerm, Konsole (remote control), VS Code's integrated terminal,
  Emacs terminals;
- any terminal in an X11 session (XTEST, e.g. `xdotool key y`).

It prints each reason and exits. Run it in a terminal window of its own, on
Wayland (GNOME Terminal, foot, Alacritty, …). `sudo-proxy --allow-injectable-tty`
starts it anyway, and every prompt then carries a warning line. The override
has no `hosts.json` equivalent because an agent can write that file:
whoever starts the daemon decides. A kernel that still allows `TIOCSTI`
(`dev.tty.legacy_tiocsti`, or no such sysctl before 6.2) is reported as a
warning. Detection is best effort; see the residuals in
[threat-model.md](threat-model.md#coverage-and-residuals). The strongest
setup is to run the agent as a **separate Unix user**, or in a sandbox without
access to your display or your multiplexer's socket.

**TUI hardening:** the Y/N prompt reads a single keypress in non-canonical
terminal mode (no Enter required) and times out after 60 seconds (default deny).
The resolved absolute path of argv[0] is displayed alongside the requested name,
followed by `->` and the canonical target when it differs (i.e. when the
PATH-found file is itself a symlink), so a same-UID adversary who substitutes
`/usr/local/bin/foo -> /tmp/evil` cannot hide the redirection by either
relying on a PATH search or passing the absolute path directly. If
`canonicalize` fails (broken symlink, EACCES) the prompt says so explicitly
rather than silently displaying the as-found name. If argv[0] is not found in
PATH, the prompt shows `(not found in PATH)` as a warning, and the stage is
refused at spawn.

argv[0] is resolved **once**, the way the child would see it: a bare name is
searched on the child's PATH (the default login PATH, which no request can
change), never on the daemon's own PATH; a name containing `/` is taken
relative to the stage's `chdir`. The executor then spawns that resolved path —
directly, or as the command after `sudo --` / `pkexec env -C DIR --` — so
neither `Command`, sudo's `secure_path`, nor `env` performs a second lookup
that could pick a different file than the prompt showed (issue #62).

The plan is compiled once per request, and each program is pinned when it is
found (issue #105): the file is opened (`O_PATH`), and its `(dev, ino)` and
canonical target (the `-> target` the prompt shows) come from that
descriptor. The `no_shell` check, the prompt and the spawn all read this one
resolution. If the request waited for the terminal behind another prompt or
an escalated run, and a pin no longer holds when its turn comes, the plan is
compiled again before the prompt (and `no_shell` applied to the new
resolution), so the human approves what is there now. Just before each spawn
the path must still name the same inode, otherwise the stage is refused
("changed since it was approved") and nothing runs; in a pipe, no stage
starts. This includes a binary that an earlier step of the same request
replaced (`cargo build && ./target/debug/app`, `apt-get upgrade && systemctl
restart …`): the human approved the old file, so such a step must be sent as
a request of its own.

A native (ELF) binary running as the daemon's user is executed through its
descriptor (`/proc/self/fd/N`), so not even that last check leaves a window.
Anything else, a `#!` script, a script without `#!` (which libc hands to
`/bin/sh`) or a binfmt_misc format, is given to an interpreter by path, which
a close-on-exec descriptor cannot serve, so it is spawned by path after the
check; so is an escalated step, since `sudo` closes inherited descriptors.

Programs run by a wrapper (`env X=1 tool`, `nice`, `timeout`, `xargs`,
`find -exec`) are pinned too: the wrapper receives the pinned absolute path in
place of the name (basename unchanged), so it never searches PATH, and a
wrapped program that was not found is refused before the spawn, like an
unfound argv[0], even behind a `find` that might match nothing. A pinned path
containing `=` is refused behind `env`, which would read it as an assignment.
A `find -execdir` / `-okdir` program named with a `/` is left as written,
since `find` runs it from each match's directory. PATH entries that are not
absolute are never searched.

Pinning fixes which file runs, not its contents: a file the requester can
write can still be rewritten in place (see the threat model, 3.7). The
`Resolves:` lines mark such a program `(user-writable)`: the daemon's user
owns or may write the file, the directory it was found in, or its symlink
target's directory. A PATH candidate is taken only if the daemon's user may execute it
(an effective-UID access check, as `execvp` does), so a decoy without execute
permission cannot make the prompt show one file while a wrapper's own lookup
runs a later one. A long path is clipped in the middle, keeping its end.

**Inherited environment (`--inherit-path`, `--inherit-env`, #101).** A daemon
started by hand in a dev shell can hand that shell's `PATH`, and the
variables `--inherit-env=PATTERN,…` names, to requests that have **no
escalated step**. Such a request's programs are resolved, pinned and shown
on the inherited `PATH` instead of the login one, by the same rules as
above; a request with `privileged` or a `run-as` anywhere inherits nothing,
in none of its steps. Both flags are command-line only, refused with
`--host`, never passed by `sudo-proxy-mcp`, and exclude the `a` answer. At
startup every `PATH` entry must be absolute and free of characters the
prompt rejects, and every directory up to `/` must be owned by root or the
daemon's user and not writable by group or others, except a root-owned
sticky directory above the entry (`/nix/store`, but not `/tmp` as the entry
itself, where anyone could add a program) or a directory the user owns whose
group is the user's private group: named after the user, with no other
member. Wildcards (`PREFIX*`, `*`)
never match code-loading variables (`LD_*`, `PYTHONPATH`, `NODE_OPTIONS`,
…), terminal and display variables, or `SSH_AUTH_SOCK`, which is never
inherited. A request that inherits shows `Env: daemon environment (…)` and
any code-loading names it carries, never values; the audit record says it
inherited and lists the resolved programs, never names or values. The
startup report lists the `PATH` entries and the inherited names, with two
fingerprints to compare across starts. See the threat model for what
remains (the dev shell's own trustworthiness, values returned in output,
shebang interpreters).

The escalator itself is not looked up on the daemon's PATH either, since that
PATH often starts with directories the daemon's user can write
(`~/.cargo/bin`, `~/.local/bin`). `sudo`, `pkexec`, the `env` pkexec mode
runs to keep the working directory (and the `true` its `-C` probe runs), and
the `zenity` / `kdialog` dialogs are searched on a fixed list
(`/run/wrappers/bin` followed by the default login PATH), and a candidate is
used only if it and every directory above it are owned by root and not
group/world-writable, and, for `sudo` / `pkexec`, the file is setuid. A
candidate this user can write through an ACL is refused too. A root-owned
sticky directory (NixOS's `/nix/store`, `root:nixbld 1775`, where
`/usr/bin/env` resolves) passes even though it is group-writable: others can
add entries there but cannot rename or remove root's. Because others can add
entries, every symlink on the path as found must be owned by root, so no one
else can repoint it between the check and the spawn. A planted file
is skipped, never run. On Debian/Ubuntu `/usr/local/bin` is group-writable
(`root:staff 2775`), so a `sudo` installed there is skipped in favour of
`/usr/bin/sudo`; `-v` prints which one the daemon uses. `--sudo-path PATH`
(command line only, not forwarded with `--host`) names `sudo` explicitly for
layouts the list does not cover; only its form is checked (an absolute path
to an executable file), not its ownership, and the daemon says so when it
starts (GHSA-gx9w-4f7x-2gcp). This also holds with `--inherit-path`: an
inherited `PATH` decides what an unprivileged step's programs resolve to,
never which escalator runs a root step. The `env -C / -- true` probe runs with a
cleared environment and that fixed list as its `PATH`, so the `true` it runs
is never taken from the daemon's `PATH` either.

The dialogs show the request as plain text (#95). zenity gets `--no-markup`;
without it, zenity parses the text as Pango markup after expanding backslash
escapes, so a `<span size="1">` in a field could hide text and a literal `\n`
could draw a forged `Command:` line. kdialog has no plain-text option: it
always expands `\n`, and guesses rich text (with links enabled) from the first
line, which holds `session` and `host` unless the `[AI-AGENT REQUEST]` header
precedes it. Its text is therefore entity-escaped,
with every `\` doubled, inside a `<qt>` element with `white-space:pre-wrap`.
