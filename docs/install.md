# Installation

[← README](../README.md)

## From crates.io (with Rust toolchain)

```bash
# Core binaries only (sudo-proxy, sudo-request, pkexec-cache)
cargo install sudo-proxy

# Everything including the MCP server
cargo install sudo-proxy --features mcp
```

## From git (development version)

```bash
cargo install --git ssh://git@github.com/tarides/sudo-proxy.git --features mcp
```

The MCP server depends on `rmcp`, `tokio`, and `schemars`. These are
behind the `mcp` Cargo feature so the core binaries stay lean and compile
fast.

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
cargo install sudo-proxy --features mcp

# Optional: cache pkexec auth for ~5 minutes (like sudo)
sudo pkexec-cache --create
```

Then configure your MCP client — see [MCP server](mcp.md).

## Building locally

```bash
cargo build --release                 # core only
cargo build --release --features mcp  # all
```

## Cargo dependencies

Core: `serde`, `serde_json`, `base64`, `uuid`, `libc`.
MCP feature: adds `rmcp`, `tokio`, `schemars`.
