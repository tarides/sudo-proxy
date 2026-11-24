# Usage

[← README](../README.md)

## Non-privileged mode

With `privileged: false` in the request, sudo-proxy runs the command
directly as the current user, without sudo. The TUI Y/N gate fires on
**every** unprivileged command by default — same human review as the
privileged path, just no password step.

Two things narrow this surface (invariant **G7** — "no unprivileged command
runs with less scrutiny than the Bash tool"):

- **Local unprivileged commands are refused.** Over the MCP `execute` tool, an
  unprivileged command targeting the local machine (including loopback aliases
  like `127.0.0.1`, `::1`, or this host's own name) is declined with a message
  telling the agent to use its Bash tool instead — which already applies your
  permission rules. sudo-proxy is for privilege escalation and for remote hosts.
- **Unattended mode needs two deliberate acts.** On a **remote** host you may
  want a batch of unprivileged commands to run without a keypress each. That
  requires (1) an operator to set `"unattended_eligible": true` in that host's
  `~/.config/sudo-proxy/hosts.json` (an out-of-band file edit — nothing on the
  wire can set it), and (2) a human to answer `a` at a prompt. Only then do
  subsequent unprivileged commands run unattended, logged, **only for requests
  carrying the same `session` name** as the one approved (other clients of the
  same daemon are still prompted) — the grant is in-memory and never persisted,
  so it is gone when the daemon or SSH tunnel ends. `session` is chosen by the
  client, so this keeps cooperating clients apart; it is not a boundary against
  a same-user process that reuses another client's session name. On a non-eligible daemon, `a` approves just the one
  command. The **privileged** gate is never relaxed.

Pass `--unattended-eligible` when starting a daemon to make it eligible without
editing the file (the session grant still needs the `a` keypress; it is never
persisted).

## Strict no-shell mode

Every structured op exists so a shell feature need not be expressed by shelling
out. A stage that *does* run a shell — an explicit `shell` op, or an `exec`
whose program is a shell (`sh -c '…'`, `bash script.sh`, a renamed symlink to
one) — hides its inner commands from the prompt, so it is flagged
**opaque — resolves only the shell**.

An operator who wants "structured or nothing" can reject such requests outright,
before any prompt: set `"policy": {"no_shell": true}` in the host's
`~/.config/sudo-proxy/hosts.json`, or start the daemon with `--no-shell`
(`--allow-shell` overrides the file for a local daemon). `--no-shell` is
forwarded to the remote daemon with `--host`; to *loosen* a remote's own
policy, edit its hosts.json. As with `unattended_eligible`, the file's policy
is trusted only if the file and its directories are yours and not group- or
world-writable; otherwise the daemon warns and fails closed, here meaning strict
mode **on**. Wrappers (`env sh -c`, `nice bash …`) and other
interpreters (`python -c`) are not detected yet.

## Command-line

```bash
# Start the server (TUI prompt + sudo)
sudo-proxy

# Quiet by default; verbose prints startup info and logs each request
sudo-proxy -v

# Audit log (on by default): one record per request outcome, rejections
# included, to stderr, $XDG_STATE_HOME/sudo-proxy/audit.jsonl (else
# ~/.local/state/sudo-proxy/audit.jsonl) and syslog. See "Audit log" below.
sudo-proxy --audit-log /path/to/audit.jsonl
sudo-proxy --no-audit-log --no-syslog   # stderr audit lines only

# Connect to a remote host via SSH tunnel
# Resolves remote UID, sets up tunnel, execs into SSH running sudo-proxy
sudo-proxy --host remotehost
sudo-proxy --host remotehost -v     # prints the ssh command before connecting

# Allow a human to grant unattended unprivileged execution for the session
# (default is to prompt every command; with this flag the prompt offers `a`,
# which grants an in-memory, never-persisted session grant). Equivalent to
# setting "unattended_eligible": true in this host's hosts.json.
sudo-proxy --unattended-eligible

# Reject opaque stages (shell op, exec of sh/bash/…) before prompting.
# Equivalent to "policy": {"no_shell": true} in hosts.json.
sudo-proxy --no-shell

# Custom socket path
sudo-proxy --socket /tmp/my-proxy.sock

# Start even in a terminal other processes can type into (tmux, X11, …).
# Every prompt then shows a warning; see "Where to run the daemon" below.
sudo-proxy --allow-injectable-tty

# Send a request (debug client)
sudo-request id
sudo-request --reason "install web server" apt install nginx

# Run without privilege escalation
sudo-request --no-privilege ls /etc

# Tag the request with a session name (default: sudo-request-cli)
sudo-request --session my-project apt update

# Declare who is asking (shown as "Requester: … (self-declared, not verified)";
# default: human). Use e.g. "automation" from cron/CI wrappers. A value of "ai"
# or "ai:<id>" also raises the [AI-AGENT REQUEST] banner.
sudo-request --requester automation apt update

# Send a structured plan (assembled like the MCP execute tool). Drives the full
# plan surface — exec / run(&&) / seq(;) / alt(||) / pipe / redirect / run-as /
# setenv / chdir / shell.
sudo-request --no-privilege \
    --plan '{"op":"alt","steps":[{"op":"exec","argv":["false"]},{"op":"exec","argv":["echo","none"]}]}'

# ...or read the plan JSON from a file ('-' for stdin)
sudo-request --no-privilege --plan-file ./scratch/plan.json
```

To drive a new feature end-to-end through the real daemon and human gate before
merging, see [testing.md](testing.md).

## Where to run the daemon

The approval prompt trusts the keypress it reads. Since 1.2.2 the daemon
refuses to start in a terminal that other processes running as you can type
into: tmux/screen/zellij panes, kitty/WezTerm/Konsole (remote control), VS
Code's or Emacs' terminal, and any terminal in an X11 session. It prints why
and exits (GHSA-cpmp-67wf-gwmx). Run it in a terminal window of its own on
Wayland. If the MCP server's `start_server` fails for this reason, start
`sudo-proxy` (or `sudo-proxy --host HOST`) yourself in such a terminal;
`start_server` then finds it running. To accept the risk, start it yourself
with `--allow-injectable-tty`. There is no `hosts.json` setting for this.

With `--host`, the check runs on the local terminal, where the remote prompt
is answered. The remote daemon checks too, and receives
`--allow-injectable-tty` when you passed it locally. A remote older than 1.2.2
rejects that flag, so upgrade remotes first.

## Remote hosts over SSH

`sudo-proxy --host HOST` resolves the remote UID (cached in
`~/.config/sudo-proxy/hosts.json`), sets up an SSH tunnel to the remote
`sudo-proxy.sock`, and execs into `ssh -t -L <tunnel> HOST sudo-proxy`.
The remote TUI prompt and sudo password prompt appear in your terminal.
The MCP server uses this internally via `start_server(host=...)`.

The equivalent without `--host` (useful if only the remote has sudo-proxy
installed, or for understanding what happens under the hood):

```bash
ssh -t -L /tmp/sudo-proxy-HOST.sock:/run/user/$(ssh HOST id -u)/sudo-proxy.sock HOST sudo-proxy
```

This allocates a PTY (`-t`), forwards the local socket to the remote
`sudo-proxy.sock`, and runs `sudo-proxy` on the remote end. Clients then
connect to `/tmp/sudo-proxy-HOST.sock` locally.

## SSH agent forwarding for `git clone` of private repos

Cloning a private GitHub repository on the remote host requires the
remote `git` to authenticate with your local SSH key. `sudo-proxy`
supports this in a tightly scoped way:

```bash
# 1. Start the tunnel with agent forwarding (-A) enabled.
sudo-proxy --host HOST --forward-agent

# 2. Per-request opt-in. Privileged commands cannot use the agent.
sudo-request --no-privilege --forward-agent -- \
    git clone git@github.com:org/private-repo.git
```

Through the MCP server:

```jsonc
start_server({"host": "HOST", "forward_agent": true})
execute({
  "argv": ["git", "clone", "git@github.com:org/private-repo.git"],
  "privileged": false,
  "forward_agent": true
})
```

Security model:

- The `SSH_AUTH_SOCK` injected into the child process is taken from the
  daemon's *own* environment (set by `sshd` when `-A` was used). It is
  never read from the request — a local peer cannot point your `git`
  invocation at a different agent socket.
- `forward_agent: true` is honored only when `privileged: false`. The
  daemon rejects the request otherwise; sudo/pkexec children never see
  the socket.
- Without `--forward-agent` on the launcher, requests with
  `forward_agent: true` still run, but no `SSH_AUTH_SOCK` is set on the
  child (the daemon has no socket to inject).

## Audit log

The daemon records the outcome of every request: approved, approved with a
session grant (`a`), unattended, denied, timed out, and every rejection
(replayed id, stale or missing `time`, forbidden characters, disallowed env,
invalid plan, malformed JSON, busy, foreign peer UID). Recording is on by
default and does not depend on `-v`. Each record goes to three sinks:

- **stderr**: one line, every request-derived field escaped and clipped;
- **a JSON-lines file**: `$XDG_STATE_HOME/sudo-proxy/audit.jsonl`, else
  `~/.local/state/sudo-proxy/audit.jsonl`. It is created mode 0600 in a 0700
  directory and opened `O_APPEND`. Use `--audit-log PATH` to move it and
  `--no-audit-log` to turn it off;
- **syslog**: facility `authpriv`, identifier `sudo-proxy`. Use `--no-syslog`
  to turn it off. On systemd hosts: `journalctl -t sudo-proxy`.

A remote daemon (`sudo-proxy --host HOST`) writes its log on the remote host,
where the command was gated.

Example record:

```json
{"time":"2026-11-18T10:04:31Z","outcome":"rejected:duplicate_id","peer_uid":1000,"id":"6f1c…","session":"sudo-proxy-mcp","host":"","privileged":true,"detail":"duplicate request id: 6f1c…"}
```

Fields: `time` (RFC 3339 UTC), `outcome` (`approved`, `approved_session`,
`unattended`, `pkexec`, `denied`, `timeout`, `ping`, `stop`, `prompt_error`,
`rejected:<reason>`), `peer_uid`, `id`, `session`, `requester` (when the client
declared one), `host`, `privileged`,
`command` (only for requests that passed validation), `detail` (the error sent
to the client), `status` and `exit_codes` (for requests that ran). Request
`env` values, `reason`, and the raw bytes of an invalid request are never
recorded. Request-derived strings are clipped to 256 characters, and tab,
newline and every character the prompt forbids (control, format, separator and
default-ignorable) are written as `\u{…}` escapes (as on stderr), so
the file is safe to `cat` or `tail -f` in a terminal.

The file belongs to the daemon's UID, which is also the requester's UID, so a
same-UID process can rewrite it. The syslog copy is the record the requester
cannot alter; forward it off the host if that matters.
