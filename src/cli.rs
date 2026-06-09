//! Shared command-line helpers for the crate's binaries.
//!
//! The four binaries each hand-roll their own argument loop (their flag sets
//! differ enough that a single parser would obscure more than it shares), but
//! the `--version` handler and the `SUDO_*_TIMEOUT_SECS` env lookup were
//! identical copies. Those primitives live here.

use std::time::Duration;

/// Print `"<bin> <version>"` to stdout and exit successfully.
///
/// `version` is the package version (same value as `CARGO_PKG_VERSION` for
/// every binary in this crate; see [`crate::protocol::VERSION`]).
pub fn print_version(bin: &str) -> ! {
    println!("{bin} {}", crate::protocol::VERSION);
    std::process::exit(0);
}

/// Resolve a `Duration` from environment variable `var` (parsed as whole
/// seconds), falling back to `default` when the variable is unset or invalid.
pub fn env_timeout(var: &str, default: Duration) -> Duration {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}
