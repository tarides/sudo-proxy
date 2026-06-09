# Usage

[← README](../README.md)

## Non-privileged mode

With `privileged: false` in the request, sudo-proxy runs the command
directly as the current user, without sudo. The TUI Y/N gate fires by
default — same human review as the privileged path, just no password
step. The prompt offers three keys: `y` to approve once, `N` (default)
to deny, `a` to approve **and** mark the host as trusted for unprivileged
commands. Picking `a` writes a `policy` block into
`~/.config/sudo-proxy/hosts.json` (`{"confirm_unprivileged": false}`)
and from that point on unprivileged commands just print a one-line
banner — privileged commands still require a Y/N. Pass
`--no-confirm-unprivileged` to skip the gate without persisting, or
`--confirm-unprivileged` to force the gate even if the file says
otherwise.

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

# Skip the confirmation prompt for unprivileged commands
# (default is to prompt for both; press `a` at a prompt to persist this
# choice in hosts.json so future runs of the daemon skip the gate too)
sudo-proxy --no-confirm-unprivileged
# Force the gate even if hosts.json says otherwise
sudo-proxy --confirm-unprivileged

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
