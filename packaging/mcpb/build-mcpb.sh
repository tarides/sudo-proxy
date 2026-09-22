#!/usr/bin/env sh
# Build an MCPB bundle (.mcpb) for the sudo-proxy-mcp MCP server.
#
# An .mcpb file is a zip of a manifest.json (which pins `sudo-proxy-mcp` as the
# entry point) plus the binary itself. Unlike the crates.io package, this lets
# MCP clients and directory probes launch the *MCP server* binary directly —
# `cargo install sudo-proxy` installs four binaries and the registry has no way
# to say "run sudo-proxy-mcp, not sudo-proxy". See docs/mcp.md.
#
# Usage: build-mcpb.sh <version> <bin_dir> <out_dir>
#   version  release version, e.g. 1.1.0 (injected into the manifest)
#   bin_dir  directory containing the built `sudo-proxy-mcp` binary
#   out_dir  where to write the .mcpb (and its .sha256)
#
# Prints the sha256 to stdout and writes <out_dir>/<name>.mcpb.sha256.
set -eu

VERSION="${1:?version required}"
BIN_DIR="${2:?bin_dir required}"
OUT_DIR="${3:?out_dir required}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANIFEST_SRC="$HERE/manifest.json"
BIN="$BIN_DIR/sudo-proxy-mcp"
NAME="sudo-proxy-mcp-v${VERSION}-x86_64-linux.mcpb"
OUT="$OUT_DIR/$NAME"

[ -f "$BIN" ] || { echo "error: $BIN not found" >&2; exit 1; }

mkdir -p "$OUT_DIR"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# Canonical manifest content lives in manifest.json; only the version is injected
# so it always tracks the release tag (single source of truth = Cargo.toml/tag).
jq --arg v "$VERSION" '.version = $v' "$MANIFEST_SRC" > "$STAGE/manifest.json"
cp "$BIN" "$STAGE/sudo-proxy-mcp"
chmod +x "$STAGE/sudo-proxy-mcp"

rm -f "$OUT"
# -X: no extra file attributes/timestamps -> reproducible-ish archive.
( cd "$STAGE" && zip -qX "$OUT" manifest.json sudo-proxy-mcp )

SHA=$(sha256sum "$OUT" | awk '{print $1}')
printf '%s' "$SHA" > "$OUT.sha256"
echo "$SHA"
