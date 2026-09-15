# Protocol

[← README](../README.md)

JSON lines over Unix socket. One request per connection, processed sequentially.
Maximum request size: 1 MB. Each line must terminate with `\n`; a peer that
sends a partial line and closes gets a specific "missing trailing newline"
error rather than an "invalid JSON" misdirection.

**Request:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "workstation.local",
  "session": "claude-code-project-alpha",
  "time": "2026-02-13T14:30:00Z",
  "pipeline": [["apt", "install", "nginx"]],
  "env": {"DEBIAN_FRONTEND": "noninteractive"},
  "reason": "Install nginx to set up a web server",
  "privileged": true,
  "forward_agent": false
}
```

The wire shape is always a list of stages: a single command is
`[["cmd", "arg"]]`, a pipeline is `[["a"], ["b"], ["c"]]` (equivalent
to `a | b | c`). The MCP `execute` tool accepts a convenience `argv`
field and wraps it for you.

Field defaults (every field is optional on the wire, but an `exec`
request with an empty or missing `pipeline` is rejected at validation):

- `id` — defaults to a fresh UUIDv4.
- `host`, `session`, `time`, `reason`, `env` — empty if omitted, but
  `time` must be a fresh, non-empty ISO 8601 timestamp; missing or
  unparseable values are rejected.
- `privileged` — defaults to `true` (the most-restrictive default; a
  client that forgets the field still goes through approval + sudo).
- `forward_agent` — defaults to `false`. Setting `true` is only valid
  when `privileged: false`.
- `action` — defaults to `"exec"` (and is omitted from the wire for exec
  requests, keeping them byte-identical to the pre-1.1 format). See
  *Control actions* below.

**Control actions** (since 1.1): `"action": "stop"` asks the daemon to
shut down cleanly — it prints a notice on its TTY (no approval prompt),
replies `ok`, and exits; `"action": "ping"` replies `ok` with
`"message": "pong"` without prompting. Both are sent with
`"pipeline": []` and pass every gate an exec request does (same-UID
check, field sanitization, freshness, replay protection), so a captured
stop request cannot be replayed later. Compatibility: a pre-1.1 daemon
ignores the unknown `action` key and rejects the empty pipeline at
validation — before any prompt — with `"pipeline must not be empty"`;
since every response carries the daemon's `version`, new clients use
that reply to detect peers that predate control actions.

**Response:**
```jsonc
// Success — single command:
{"id":"550e...","status":"ok",
 "stages":[{"exit_code":0,"stderr":"<base64>"}],
 "stdout":"<base64>"}

// Success — two-stage pipeline (one stages entry per command):
{"id":"550e...","status":"ok",
 "stages":[
   {"exit_code":0,"stderr":""},
   {"exit_code":0,"stderr":""}
 ],
 "stdout":"<base64>"}

// Truncation flags only appear when the daemon capped the corresponding
// stream at MAX_OUTPUT_BYTES (16 MiB):
{"id":"550e...","status":"ok",
 "stages":[{"exit_code":0,"stderr":"<base64>","stderr_truncated":true}],
 "stdout":"<base64>","stdout_truncated":true}

{"id":"550e...","status":"denied"}
{"id":"550e...","status":"timeout"}
{"id":"550e...","status":"error","message":"..."}
```

`stages` carries one entry per pipeline stage (`exit_code` and
base64-encoded `stderr`). The final stage's stdout is hoisted to the
top-level `stdout` field. Truncation flags are absent when false.

**Forward-compat:** every optional field uses `#[serde(default)]`.
Clients should ignore unknown fields and tolerate additional metadata
(e.g. truncation flags, stage subfields) added in future versions.
