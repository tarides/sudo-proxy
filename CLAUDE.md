# CLAUDE.md

## Build

```bash
cargo build --release                       # all binaries (mcp is a default feature)
cargo build --release --no-default-features  # core only (no MCP server)
```

## Version bumps

The version in `Cargo.toml` must match the git tag; both release workflows
fail on a tag that does not name it. When bumping the version:
1. Update `version` in `Cargo.toml`
2. Update the hardcoded version strings in the packaging metadata so they
   don't drift from `Cargo.toml`:
   - `server.json` (the `version` field and the `mcpb` package identifier URL)
   - `packaging/mcpb/manifest.json`
   - `.claude-plugin/plugin.json`
3. Tag the commit: `git tag v<VERSION>`

**Pre-releases** (`1.3.0-rc.1`: any version with a `-`): the tag publishes the
crate to crates.io (cargo installs it only when asked for by version) and a
GitHub release marked pre-release, but skips the MCP Registry, which would
list it as the latest version. Leave `.claude-plugin/plugin.json` at the last
stable version: the plugin marketplace installs from `main`, and changing that
string hands every plugin user the current `main` on their next update,
whatever the tag. Bump it with the stable release.

All binaries read the version from `Cargo.toml` at compile time via `env!("CARGO_PKG_VERSION")`.
The JSON files above carry the string separately because they are consumed by
external tooling (the MCP registry, mcpb, the Claude Code plugin loader) before
any binary runs.
