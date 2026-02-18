use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::protocol::{Request, Response, StageResult};

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

/// Execute a pipeline via pkexec (local/graphical mode).
/// For multi-stage pipelines, wraps in `pkexec sh -c 'cmd1 | cmd2 | ...'`.
pub fn exec_pkexec(req: &Request, env: &HashMap<String, String>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_pkexec_stage(&req.pipeline[0], env, &req.id);
    }

    // Multi-stage: wrap entire pipeline in sh -c via pkexec
    let shell_cmd = pipeline_to_shell(&req.pipeline, env);
    let mut cmd = Command::new("pkexec");
    cmd.args(["sh", "-c", &shell_cmd]);
    cmd.current_dir("/");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
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

    run_single_command(&mut cmd, &req.id)
}

/// Execute a pipeline via sudo (remote/TUI mode).
pub fn exec_sudo(req: &Request, env: &HashMap<String, String>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_sudo_stage(&req.pipeline[0], env, &req.id);
    }

    exec_pipeline(req, env, EscalationMode::Sudo)
}

/// Execute a pipeline directly as the current user (no privilege escalation).
pub fn exec_direct(req: &Request, env: &HashMap<String, String>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_direct_stage(&req.pipeline[0], env, &req.id);
    }

    exec_pipeline(req, env, EscalationMode::Direct)
}

// ---------------------------------------------------------------------------
// Single-stage helpers
// ---------------------------------------------------------------------------

fn exec_pkexec_stage(
    argv: &[String],
    env: &HashMap<String, String>,
    id: &str,
) -> Response {
    let mut cmd = Command::new("pkexec");
    for arg in argv {
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
    if let Ok(v) = std::env::var("DISPLAY") {
        cmd.env("DISPLAY", v);
    }
    if let Ok(v) = std::env::var("WAYLAND_DISPLAY") {
        cmd.env("WAYLAND_DISPLAY", v);
    }
    if let Ok(v) = std::env::var("XAUTHORITY") {
        cmd.env("XAUTHORITY", v);
    }

    run_single_command(&mut cmd, id)
}

fn exec_sudo_stage(
    argv: &[String],
    env: &HashMap<String, String>,
    id: &str,
) -> Response {
    let mut cmd = Command::new("sudo");
    for (k, v) in env {
        cmd.arg(format!("{k}={v}"));
    }
    for arg in argv {
        cmd.arg(arg);
    }
    cmd.current_dir("/");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    run_single_command(&mut cmd, id)
}

fn exec_direct_stage(
    argv: &[String],
    env: &HashMap<String, String>,
    id: &str,
) -> Response {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.current_dir("/");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }

    run_single_command(&mut cmd, id)
}

fn run_single_command(cmd: &mut Command, id: &str) -> Response {
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
            let stage = StageResult {
                exit_code: code,
                stderr: B64.encode(&output.stderr),
            };
            Response::ok(id, vec![stage], &output.stdout)
        }
        Err(e) => Response::error(id, &format!("failed to execute command: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Pipeline execution
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum EscalationMode {
    Sudo,
    Direct,
}

/// Execute a multi-stage pipeline by spawning N children connected by pipes.
fn exec_pipeline(
    req: &Request,
    env: &HashMap<String, String>,
    mode: EscalationMode,
) -> Response {
    let n = req.pipeline.len();
    assert!(n >= 2);

    let mut children: Vec<std::process::Child> = Vec::with_capacity(n);
    let mut prev_stdout: Option<Stdio> = None;

    for (i, argv) in req.pipeline.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == n - 1;

        let mut cmd = match mode {
            EscalationMode::Sudo => {
                let mut c = Command::new("sudo");
                for (k, v) in env {
                    c.arg(format!("{k}={v}"));
                }
                for arg in argv {
                    c.arg(arg);
                }
                c
            }
            EscalationMode::Direct => {
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c.env_clear();
                for (k, v) in env {
                    c.env(k, v);
                }
                c
            }
        };

        cmd.current_dir("/");

        // stdin: first stage gets null (direct) or inherited terminal (sudo),
        // others get previous stage's stdout
        if let Some(prev) = prev_stdout.take() {
            cmd.stdin(prev);
        } else if is_first {
            match mode {
                EscalationMode::Direct => {
                    cmd.stdin(Stdio::null());
                }
                EscalationMode::Sudo => {
                    // Inherit terminal for sudo password prompt
                }
            }
        }

        // stdout: last stage piped to parent, others piped to next stage
        cmd.stdout(Stdio::piped());

        // stderr: always piped to parent
        cmd.stderr(Stdio::piped());

        // Set umask before exec
        unsafe {
            cmd.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }

        match cmd.spawn() {
            Ok(mut child) => {
                if !is_last {
                    // Take this child's stdout to feed next stage's stdin
                    if let Some(stdout) = child.stdout.take() {
                        prev_stdout = Some(Stdio::from(stdout));
                    }
                }
                children.push(child);
            }
            Err(e) => {
                // Kill already-spawned children
                for mut c in children {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return Response::error(
                    &req.id,
                    &format!("failed to spawn pipeline stage {i}: {e}"),
                );
            }
        }
    }

    collect_pipeline_results(&req.id, children, n)
}

/// Collect results from all pipeline children.
/// Reads each stage's stderr in threads, reads last stage's stdout in main thread.
fn collect_pipeline_results(
    id: &str,
    mut children: Vec<std::process::Child>,
    n: usize,
) -> Response {
    // Spawn threads to read each stage's stderr concurrently
    let mut stderr_threads = Vec::with_capacity(n);
    for child in &mut children {
        let mut stderr_pipe = child.stderr.take();
        stderr_threads.push(std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut pipe) = stderr_pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        }));
    }

    // Read last stage's stdout in main thread
    let mut final_stdout = Vec::new();
    if let Some(ref mut last_child) = children.last_mut() {
        if let Some(ref mut stdout_pipe) = last_child.stdout {
            let _ = stdout_pipe.read_to_end(&mut final_stdout);
        }
    }

    // Wait for all children and collect exit codes
    let mut stages = Vec::with_capacity(n);
    for mut child in children {
        let exit_code = match child.wait() {
            Ok(status) => status.code().unwrap_or(-1),
            Err(_) => -1,
        };
        let stderr_buf = stderr_threads
            .remove(0)
            .join()
            .unwrap_or_default();
        stages.push(StageResult {
            exit_code,
            stderr: B64.encode(&stderr_buf),
        });
    }

    Response::ok(id, stages, &final_stdout)
}

/// Build a shell command string for a pipeline with env vars (used by pkexec multi-stage).
fn pipeline_to_shell(pipeline: &[Vec<String>], env: &HashMap<String, String>) -> String {
    let env_prefix: String = env
        .iter()
        .map(|(k, v)| format!("{}={}", shell_escape(k), shell_escape(v)))
        .collect::<Vec<_>>()
        .join(" ");

    let stages: Vec<String> = pipeline
        .iter()
        .map(|argv| {
            argv.iter()
                .map(|a| shell_escape(a))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();

    if env_prefix.is_empty() {
        stages.join(" | ")
    } else {
        format!("{} {}", env_prefix, stages.join(" | "))
    }
}

fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '/' | '.' | '=' | ':' | ','))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}
