# Security considerations

[← README](../README.md)

For a point-in-time adversarial audit of the source tree, see
[security-audit.md](security-audit.md).

**Environment:** the request `env` is gated by a hard allowlist
(`LANG`, `LC_*`, `TZ`, `HOME`, `DEBIAN_FRONTEND`, `TERM`). Anything else —
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

**Input validation:** argv and env strings are rejected if they contain control
characters (0x00–0x1F except tab), zero-width characters (U+200B–U+200F), or
bidi override characters (U+202A–U+202E, U+2066–U+2069) that could mislead
the user during TUI approval.

**Replay protection:** request UUIDs are tracked in a set that is cleared every
1000 entries. Duplicate IDs are rejected. Requests must carry a non-empty
`time`; missing, unparseable, or older-than-60-seconds values are rejected.

**Socket security:** the socket file is created with mode 0600 (owner-only).
`$XDG_RUNTIME_DIR` is already restricted to the user.

**Execution isolation:** child processes run with cwd `/`, umask 0077, and
stdout/stderr piped — they do not inherit the socket file descriptor. stdin is
null except for sudo mode, which inherits the terminal so sudo can prompt for a
password.

**TUI hardening:** the Y/N prompt reads a single keypress in non-canonical
terminal mode (no Enter required) and times out after 60 seconds (default deny).
The resolved absolute path of argv[0] is displayed alongside the requested name,
followed by `->` and the canonical target when it differs (i.e. when the
PATH-found file is itself a symlink), so a same-UID adversary who substitutes
`/usr/local/bin/foo -> /tmp/evil` cannot hide the redirection by either
relying on a PATH search or passing the absolute path directly. If
`canonicalize` fails (broken symlink, EACCES) the prompt says so explicitly
rather than silently displaying the as-found name. If argv[0] is not found in
PATH, the prompt shows `(not found in PATH)` as a warning.
