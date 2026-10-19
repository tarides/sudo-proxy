# Manual testing: drive the daemon live

[← README](../README.md) · see also [usage.md](usage.md), [protocol.md](protocol.md)

The unit and integration suites (`cargo test`) cover logic and drive the daemon
through a *scripted* approval. This doc is the complement: how to exercise a new
feature **end-to-end through the real daemon and the real human gate** — the
approval prompt appears in your terminal and you approve it yourself — before
merging. It is the fastest way to see a change behave exactly as an operator (or
the MCP `execute` tool) will experience it.

The key enabler is `sudo-request --plan`, which assembles a structured `Plan`
request the same way the MCP tool does (`mcp::build_request`), so you can drive
the full plan surface (`seq`, `alt`, `pipe`, `redirect`, `run-as`, `setenv`,
`chdir`, `system`) from the command line — no MCP client and no hand-written
socket JSON required.

## Setup

Build the branch under test, then run the daemon in one terminal and send
requests from another.

**Terminal A — the daemon + approval TUI.** This is where the prompt appears and
where you press the keys. Use a dedicated test socket so you never collide with
an installed daemon's default socket:

```bash
cargo build --release
./target/release/sudo-proxy -v --socket /tmp/sp-test.sock
```

**Terminal B — send requests** with the freshly built client:

```bash
# A single command / pipeline (flat form)
./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print \
    echo hi '|' wc -c

# A structured plan — the same assembly the MCP execute tool performs
./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print \
    --reason "try alt" \
    --plan '{"op":"alt","steps":[{"op":"run","argv":["false"]},{"op":"run","argv":["echo","fallback-ran"]}]}'
```

When the request arrives, Terminal A shows the per-stage prompt — each stage with
its own resolved real binary and run-as tag — and waits for a key. Press **`y`**
to approve; the client in Terminal B then prints the result.

For a large plan, keep it in a file and use `--plan-file` (or `--plan-file -` to
read from stdin):

```bash
./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print \
    --plan-file ./scratch/plan.json
```

## Reading the result

With `--print`, the client shows the structured response:

```
exit [1, 0]
== stdout == (1 lines)
fallback-ran
```

- The `exit [...]` array is one entry **per stage, in prompt order**.
- A stage that was **not run** (short-circuited) reports the `-1` sentinel. For
  the `alt` above with a succeeding first step you would instead see
  `exit [0, -1]` — the first alternative succeeded, so the second never ran.
- `stdout` is the aggregate of every captured stage.

## Tips

- **Decline** with `n` or Enter (default is deny) → the client prints
  `Request denied.` and exits non-zero. Good for testing the deny path.
- **Mimic the MCP session label** with `--session sudo-proxy-mcp` if a feature
  keys off the session name.
- **Exercise privileged stages** by dropping `--no-privilege` (you will satisfy a
  real `sudo`/`pkexec` prompt) or by using a `run-as` node inside the plan.
- **Fidelity caveat.** `sudo-request` reproduces the MCP's *request assembly*, not
  its policy layer: the MCP additionally refuses unprivileged *local* commands
  (invariant G7 — "use the Bash tool"). That refusal lives in the MCP execute
  handler, not in the daemon, which is exactly what lets you drive unprivileged
  local plans here for testing.

## Without a human (CI / headless)

The human gate reads `/dev/tty`, so full execution needs either a person or a
pseudo-terminal harness. Two headless-friendly paths:

- **Pre-prompt rejection needs no keypress.** A structurally invalid plan (e.g. a
  `redirect` wrapping a `seq`/`alt`) is rejected *before* prompting, so a client
  call returns an `invalid plan: …` error with no interaction — handy for
  smoke-testing the client→daemon plumbing against a backgrounded daemon.
- **Scripted approval** for real execution: the integration tests drive the
  daemon through a scripted prompter — see `tests/plan_exec.rs`
  (`plan_request_end_to_end_through_daemon`) and `tests/validation.rs`. Prefer
  adding a case there over automating the live TUI.
