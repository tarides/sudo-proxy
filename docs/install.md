# Installation

[← README](../README.md)

## From crates.io (with Rust toolchain)

```bash
# Everything including the MCP server (mcp is a default feature)
cargo install sudo-proxy

# Core binaries only (sudo-proxy, sudo-request, pkexec-cache)
cargo install sudo-proxy --no-default-features
```

## From git (development version)

```bash
cargo install --git ssh://git@github.com/tarides/sudo-proxy.git
```

The MCP server depends on `rmcp`, `tokio`, and `schemars`. These are behind
the `mcp` Cargo feature, which is **on by default**. Pass
`--no-default-features` to build only the core binaries (no `rmcp`/`tokio`/
`schemars`), e.g. on a remote host that just needs the `sudo-proxy` server.

| Binary | Feature | Purpose |
|---|---|---|
| `sudo-proxy` | — | Server: socket listener, approval UI, execution |
| `sudo-request` | — | Debug client (local socket only) |
| `pkexec-cache` | — | Optional polkit rule manager |
| `sudo-proxy-mcp` | `mcp` | MCP server (stdio, for AI agents) |

## Prebuilt static binaries (no Rust needed)

Download from [GitHub Releases](https://github.com/tarides/sudo-proxy/releases).
Each release includes a tarball with statically-linked x86_64 Linux binaries
(MUSL) that run on any distribution regardless of glibc version.

## Deploying to a remote host

The remote host only needs the `sudo-proxy` binary. A single static file,
no runtime dependencies, no config:

```bash
# Download the latest release tarball, extract, and copy
scp sudo-proxy remote:/usr/local/bin/
```

When an AI agent calls `start_server(host="remote")`, the MCP server SSHs
in and runs `sudo-proxy` on the remote. The only prerequisites on the
remote side are SSH access and the `sudo-proxy` binary in `$PATH`.

## Local workstation setup

Install all binaries and optionally set up polkit auth caching:

```bash
cargo install sudo-proxy

# Optional: cache pkexec auth for ~5 minutes (like sudo)
sudo pkexec-cache --create
```

Then configure your MCP client — see [MCP server](mcp.md).

## Building locally

```bash
cargo build --release                        # all binaries (mcp is default)
cargo build --release --no-default-features   # core only
```

## Cargo dependencies

Core: `serde`, `serde_json`, `base64`, `uuid`, `libc`.
MCP feature: adds `rmcp`, `tokio`, `schemars`.
