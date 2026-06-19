//! Internal implementation library for the sudo-proxy binaries.
//!
//! This is **not** a stable public API. It exists only so the `sudo-proxy`,
//! `sudo-request`, `pkexec-cache`, and `sudo-proxy-mcp` binaries can share
//! code; items may change or be removed in any release, including patch
//! releases. The supported, versioned contract is the MCP tools, the
//! JSON-line wire protocol (docs/protocol.md), and the CLI — not these Rust
//! types. Do not depend on this crate as a library.
#![doc(hidden)]

pub mod cli;
pub mod datetime;
pub mod executor;
pub mod gui;
pub mod hosts;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod mode;
#[cfg(kani)]
mod proofs;
#[cfg(test)]
pub(crate) mod prop;
pub mod protocol;
pub mod server;
pub mod tui;
