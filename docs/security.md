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
allowlist. For sudo mode the process environment is inherited, but
sudo's own `env_reset` policy handles cleanup. `SSH_AUTH_SOCK` is
rejected with a specific error; agent forwarding goes through the
dedicated `forward_agent` field instead (see "SSH agent forwarding"
in [usage.md](usage.md)).

**No shell invocation:** commands are executed via `Command::new(argv[0]).args(…)`,
never `sh -c`. This prevents `;`, `|`, `&&` injection.

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

The escalator itself is not looked up on the daemon's PATH either, since that
PATH often starts with directories the daemon's user can write
(`~/.cargo/bin`, `~/.local/bin`). `sudo`, `pkexec`, the `env` probed for
`-C`, and the `zenity` / `kdialog` dialogs are searched on a fixed list
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
starts (GHSA-gx9w-4f7x-2gcp).
