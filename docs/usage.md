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
  subsequent unprivileged commands run unattended, logged, **for that session
  only** — the grant is in-memory and never persisted, so it is gone when the
  daemon or SSH tunnel ends. On a non-eligible daemon, `a` approves just the one
  command. The **privileged** gate is never relaxed.

Pass `--unattended-eligible` when starting a daemon to make it eligible without
editing the file (the session grant still needs the `a` keypress; it is never
persisted).

## Command-line

```bash
# Start the server (TUI prompt + sudo)
sudo-proxy

# Quiet by default; verbose prints startup info and logs each request
sudo-proxy -v

# Connect to a remote host via SSH tunnel
# Resolves remote UID, sets up tunnel, execs into SSH running sudo-proxy
sudo-proxy --host remotehost
sudo-proxy --host remotehost -v     # prints the ssh command before connecting

# Allow a human to grant unattended unprivileged execution for the session
# (default is to prompt every command; with this flag the prompt offers `a`,
# which grants an in-memory, never-persisted session grant). Equivalent to
# setting "unattended_eligible": true in this host's hosts.json.
sudo-proxy --unattended-eligible

# Custom socket path
sudo-proxy --socket /tmp/my-proxy.sock

# Send a request (debug client)
sudo-request id
sudo-request --reason "install web server" apt install nginx

# Run without privilege escalation
sudo-request --no-privilege ls /etc

# Tag the request with a session name (default: sudo-request-cli)
sudo-request --session my-project apt update
```

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
