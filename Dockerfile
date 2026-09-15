# MCP introspection image — for registry crawlers, not for deployment.
#
# This image exists so registry crawlers (Glama, the MCP Inspector) can build
# the server, run it over stdio, and enumerate its tools via the standard
# `tools/list` handshake. Glama builds the Dockerfile checked into the repo in
# preference to an AI-inferred one and re-scans on every new commit
# (https://glama.ai/mcp/methodology); its quality score is computed from the
# enumerated tool definitions, so the server must be launchable to be scored.
#
# It is NOT a deployment artifact. sudo-proxy's entire purpose is a
# human-in-the-loop TUI approval gate over real privilege escalation, and this
# container has neither a TTY nor sudo — so it can list tools but cannot approve
# or execute anything. Do not present this image as a way to "run sudo-proxy in
# Docker".

# ---- build stage ----
FROM rust:1.96-slim-bookworm AS build
WORKDIR /src
COPY . .
# `mcp` is a default feature, so this builds the stdio MCP server. Build only
# that binary — the host daemon and helpers are not needed for introspection.
RUN cargo build --release --bin sudo-proxy-mcp

# ---- runtime stage ----
# All dependencies are pure Rust (no native libs), so a bare glibc base needs
# nothing extra beyond the binary.
FROM debian:bookworm-slim
COPY --from=build /src/target/release/sudo-proxy-mcp /usr/local/bin/sudo-proxy-mcp
# The MCP server speaks JSON-RPC over stdio: reads requests on stdin, writes
# responses on stdout. Entrypoint is sudo-proxy-mcp, NOT the sudo-proxy host
# daemon (which would not answer an MCP handshake).
ENTRYPOINT ["sudo-proxy-mcp"]
