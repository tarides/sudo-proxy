# CLAUDE.md

## Build

```bash
cargo build --release                       # all binaries (mcp is a default feature)
cargo build --release --no-default-features  # core only (no MCP server)
```

## Version bumps

The version in `Cargo.toml` must match the git tag. When bumping the version:
1. Update `version` in `Cargo.toml`
2. Update the hardcoded version strings in the packaging metadata so they
   don't drift from `Cargo.toml`:
   - `server.json` (the `version` field and the `mcpb` package identifier URL)
   - `packaging/mcpb/manifest.json`
   - `.claude-plugin/plugin.json`
3. Tag the commit: `git tag v<VERSION>`

All binaries read the version from `Cargo.toml` at compile time via `env!("CARGO_PKG_VERSION")`.
The JSON files above carry the string separately because they are consumed by
external tooling (the MCP registry, mcpb, the Claude Code plugin loader) before
any binary runs.
