# pkexec mode

[← README](../README.md)

By default, sudo-proxy separates approval (TUI prompt) from privilege
escalation (sudo). The TUI shows the command for single-keypress Y/N
approval, then sudo handles password authentication — both in the same
terminal window.

The `--pkexec` flag bypasses the TUI entirely and lets pkexec handle both
authentication and approval in its own dialog. This mode exists but is not
recommended because polkit conflates authentication (proving who you are) and
authorization (approving what to do):

- **Without auth caching**: pkexec asks for a password on every single
  request. This is safe but impractical for an AI agent workflow that may
  run dozens of commands.

- **With auth caching**: pkexec skips its dialog entirely for the cache
  duration — commands run silently with no approval prompt. This is unsafe
  and defeats sudo-proxy's human-in-the-loop design.

There is no middle ground in polkit. The TUI mode solves this by always
prompting for approval (one keypress, no password) while letting the OS
handle password authentication separately.

## pkexec authentication caching

If you do use `--pkexec` mode, you can optionally configure polkit to cache
authentication for a few minutes, similar to `sudo`'s default behavior.

**This is a user decision.** The rule applies to all `pkexec` calls from your
user, not just those from sudo-proxy — polkit has no way to distinguish the
calling program. Evaluate whether this trade-off is acceptable for your setup.

The `pkexec-cache` tool manages this rule:

```bash
# Check if the rule is installed
pkexec-cache

# Install the rule (detects your username from SUDO_USER)
sudo pkexec-cache --create

# Remove the rule
sudo pkexec-cache --delete
```

The rule is written to `/etc/polkit-1/rules.d/50-pkexec-cache.rules`
and caches authentication for the calling user with these conditions:
- `subject.active` — only the foreground session (not background terminals)
- `subject.local` — only local sessions (not SSH)
- `AUTH_ADMIN_KEEP` — cache the admin password for ~5 minutes

polkitd monitors its rules directory and reloads automatically — no service
restart is needed.

There is no GUI tool to manage polkit rules on any distribution. On current
Ubuntu and Debian, polkit uses the JavaScript `.rules` format — the older
`.pkla` format is deprecated. The
[Arch Wiki polkit page](https://wiki.archlinux.org/title/Polkit) is the most
comprehensive reference.
