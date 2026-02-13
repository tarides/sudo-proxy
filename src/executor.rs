use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::protocol::{Request, Response};

/// Environment variables that are never passed through (security-sensitive).
const ENV_BLOCKLIST: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DYNAMIC_WEAK",
    "LD_ORIGIN_PATH",
];

/// Only these env var names (or prefixes) are allowed through.
fn is_env_allowed(key: &str) -> bool {
    matches!(
        key,
        "LANG" | "TZ" | "HOME" | "DEBIAN_FRONTEND" | "TERM"
    ) || key.starts_with("LC_")
}

/// Sanitize the environment from a request.
/// Returns Ok(filtered map) or Err(message) if a non-allowed var is found.
pub fn sanitize_env(env: &HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (k, v) in env {
        if ENV_BLOCKLIST.iter().any(|b| k == *b) {
            eprintln!("warning: stripped blocked env var: {k}");
            continue;
        }
        if !is_env_allowed(k) {
            return Err(format!("environment variable not allowed: {k}"));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

/// Resolve a command name to an absolute path by searching PATH.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        if p.is_file() {
            return Some(p);
        }
        return None;
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if let Ok(meta) = candidate.metadata() {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Execute a command via pkexec (local/graphical mode).
pub fn exec_pkexec(req: &Request, env: &HashMap<String, String>) -> Response {
    let mut cmd = Command::new("pkexec");
    for arg in &req.argv {
        cmd.arg(arg);
    }
    cmd.current_dir("/");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    // pkexec needs DISPLAY/WAYLAND_DISPLAY to show its dialog
    if let Ok(v) = std::env::var("DISPLAY") {
        cmd.env("DISPLAY", v);
    }
    if let Ok(v) = std::env::var("WAYLAND_DISPLAY") {
        cmd.env("WAYLAND_DISPLAY", v);
    }
    if let Ok(v) = std::env::var("XAUTHORITY") {
        cmd.env("XAUTHORITY", v);
    }

    run_command(&mut cmd, &req.id)
}

/// Execute a command via sudo (remote/TUI mode).
pub fn exec_sudo(req: &Request, env: &HashMap<String, String>) -> Response {
    let mut cmd = Command::new("sudo");
    // Pass env vars via sudo's --preserve-env or env setting
    for (k, v) in env {
        cmd.arg(format!("{k}={v}"));
    }
    for arg in &req.argv {
        cmd.arg(arg);
    }
    cmd.current_dir("/");
    // sudo needs to read password from the terminal, not stdin
    // We don't pipe stdin so it inherits the terminal
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    run_command(&mut cmd, &req.id)
}

/// Execute a command directly as the current user (no privilege escalation).
pub fn exec_direct(req: &Request, env: &HashMap<String, String>) -> Response {
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
    cmd.current_dir("/");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }

    run_command(&mut cmd, &req.id)
}

fn run_command(cmd: &mut Command, id: &str) -> Response {
    // Set umask before exec
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }

    match cmd.output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            Response::ok(id, code, &output.stdout, &output.stderr)
        }
        Err(e) => Response::error(id, &format!("failed to execute command: {e}")),
    }
}
