# CLAUDE.md

## Build

```bash
cargo build --release --features mcp   # all binaries
cargo build --release                  # core only (no MCP server)
```

## Version bumps

The version in `Cargo.toml` must match the git tag. When bumping the version:
1. Update `version` in `Cargo.toml`
2. Tag the commit: `git tag v<VERSION>`

All binaries read the version from `Cargo.toml` at compile time via `env!("CARGO_PKG_VERSION")`.
