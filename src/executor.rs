use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::protocol::{Request, Response, StageResult};

/// Hard cap on captured stdout/stderr per stream. A privileged
/// `cat /dev/zero` would otherwise OOM the daemon. When the cap is
/// reached, the drainer stops reading and the child is killed so it
/// doesn't wedge on a full pipe.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Default per-command execution timeout. Bounds how long any one
/// privileged command can hold a handler thread (D-state, infinite
/// loops, blocked on stdin). Override via SUDO_PROXY_EXEC_TIMEOUT_SECS.
pub const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// How often to poll `try_wait` while waiting for a child.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Resolve the per-command execution timeout from the environment, or
/// fall back to DEFAULT_EXEC_TIMEOUT.
pub fn exec_timeout() -> Duration {
    std::env::var("SUDO_PROXY_EXEC_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_EXEC_TIMEOUT)
}

/// Only these env var names (or prefixes) are allowed through.
fn is_env_allowed(key: &str) -> bool {
    matches!(
        key,
        "LANG" | "TZ" | "HOME" | "DEBIAN_FRONTEND" | "TERM"
    ) || key.starts_with("LC_")
}

/// Sanitize the environment from a request.
///
/// Hard rejection model: every var must be on the allowlist, otherwise
/// the whole request fails. There is no silent stripping — `LD_PRELOAD`
/// and friends fail loudly the same way any unknown var does.
pub fn sanitize_env(env: &HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (k, v) in env {
        // SSH_AUTH_SOCK is owned by the daemon's environment (set by sshd
        // when the user opened the tunnel with -A). Accepting a request-
        // supplied value would let a local peer point a child at an
        // arbitrary socket. Use `forward_agent: true` instead.
        if k == "SSH_AUTH_SOCK" {
            return Err(
                "SSH_AUTH_SOCK cannot be set in request env; use forward_agent instead"
                    .to_string(),
            );
        }
        if !is_env_allowed(k) {
            return Err(format!("environment variable not allowed: {k}"));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

/// Default PATH injected when none is set in the request. Mirrors
/// `/etc/login.defs`'s ENV_PATH on Debian/Ubuntu.
const DEFAULT_LOGIN_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Login-shell env (HOME/USER/LOGNAME/PATH) for the daemon's effective
/// uid. PAM's `session` stack would set these on an interactive SSH
/// login, but command-mode SSH (`ssh host sudo-proxy`) bypasses it —
/// so the daemon inherits a stripped env and any `env_clear()`'d child
/// sees nothing. Computed once via getpwuid; cached in `OnceLock`.
fn login_env_defaults() -> &'static HashMap<String, String> {
    static CACHE: OnceLock<HashMap<String, String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = HashMap::new();
        let pw = unsafe { libc::getpwuid(libc::geteuid()) };
        if !pw.is_null() {
            unsafe {
                if let Ok(name) = std::ffi::CStr::from_ptr((*pw).pw_name).to_str() {
                    if !name.is_empty() {
                        out.insert("USER".into(), name.to_string());
                        out.insert("LOGNAME".into(), name.to_string());
                    }
                }
                if let Ok(dir) = std::ffi::CStr::from_ptr((*pw).pw_dir).to_str() {
                    if !dir.is_empty() {
                        out.insert("HOME".into(), dir.to_string());
                    }
                }
            }
        }
        out.insert("PATH".into(), DEFAULT_LOGIN_PATH.into());
        out
    })
}

/// Fill in missing login env (HOME / USER / LOGNAME / PATH) from the
/// daemon's /etc/passwd entry. Only inserts keys that aren't already
/// set, so a caller-supplied HOME wins. Callers can't currently supply
/// USER / LOGNAME / PATH (allowlist rejects them), so those are
/// effectively always daemon-derived.
pub fn apply_login_env_defaults(env: &mut HashMap<String, String>) {
    for (k, v) in login_env_defaults() {
        env.entry(k.clone()).or_insert_with(|| v.clone());
    }
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
pub fn exec_pkexec(req: &Request, env: &HashMap<String, String>, tty_lock: &Mutex<()>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_pkexec_stage(&req.pipeline[0], env, &req.id, tty_lock);
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

    run_single_command(&mut cmd, &req.id, exec_timeout(), Some(tty_lock))
}

/// Execute a pipeline via sudo (remote/TUI mode).
pub fn exec_sudo(req: &Request, env: &HashMap<String, String>, tty_lock: &Mutex<()>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_sudo_stage(&req.pipeline[0], env, &req.id, tty_lock);
    }

    exec_pipeline(req, env, EscalationMode::Sudo)
}

/// Execute a pipeline directly as the current user (no privilege escalation).
pub fn exec_direct(req: &Request, env: &HashMap<String, String>) -> Response {
    if req.pipeline.len() == 1 {
        return exec_direct_stage(&req.pipeline[0], env, &req.id, req.forward_agent);
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
    tty_lock: &Mutex<()>,
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

    run_single_command(&mut cmd, id, exec_timeout(), Some(tty_lock))
}

fn exec_sudo_stage(
    argv: &[String],
    env: &HashMap<String, String>,
    id: &str,
    tty_lock: &Mutex<()>,
) -> Response {
    let mut cmd = Command::new("sudo");
    for (k, v) in env {
        cmd.arg(format!("{k}={v}"));
    }
    for arg in argv {
        cmd.arg(arg);
    }
    cmd.current_dir("/");
    // Close stdin so a privileged child like `sudo cat` doesn't inherit
    // the daemon's controlling tty and block reading from it. sudo opens
    // /dev/tty itself for password entry, so this doesn't break auth.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    run_single_command(&mut cmd, id, exec_timeout(), Some(tty_lock))
}

fn exec_direct_stage(
    argv: &[String],
    env: &HashMap<String, String>,
    id: &str,
    forward_agent: bool,
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
    if forward_agent {
        if let Some(sock) = crate::server::forwarded_agent_socket() {
            cmd.env("SSH_AUTH_SOCK", &sock);
        }
    }

    run_single_command(&mut cmd, id, exec_timeout(), None)
}

/// Spawn `cmd`, drain stdout/stderr concurrently with caps, and wait for
/// the child up to `timeout`. Kill the child on cap-hit or timeout so it
/// doesn't outlive the daemon.
/// `fg_lock` is `Some` for privileged children (sudo, pkexec) that need
/// the controlling tty's foreground pgrp so sudo's `/dev/tty` password
/// prompt doesn't EIO; the mutex serializes the swap against prompts
/// (held by `server::handle_connection`). `None` for unprivileged
/// children: they run with `stdin=null` and piped stdio, never read
/// /dev/tty, and would needlessly serialize with daemon prompts.
fn run_single_command(
    cmd: &mut Command,
    id: &str,
    timeout: Duration,
    fg_lock: Option<&Mutex<()>>,
) -> Response {
    unsafe {
        cmd.pre_exec(|| {
            // New process group so kill_group can SIGKILL the entire
            // group on timeout — otherwise a wrapper like `sh -c '... &'`
            // would leave grandchild processes orphaned to PID 1, holding
            // stdio pipes open and blocking our drain threads forever.
            //
            // setpgid (vs the historical setsid) keeps the child in the
            // *same session* as the daemon, so the controlling terminal
            // stays reachable. Under setsid the child had no controlling
            // tty, and `sudo` could not open /dev/tty for its password
            // prompt — see issue #19.
            libc::setpgid(0, 0);
            libc::umask(0o077);
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Response::error(id, &format!("failed to execute command: {e}")),
    };

    let cpid = child.id() as libc::pid_t;
    // Race-safe duplicate of the child's setpgid: closes the window
    // between fork() and the child reaching its pre_exec hook. A second
    // setpgid with the same args is harmless; if the child has already
    // exec'd, EACCES is returned and we fall back to whatever the child
    // managed to set itself.
    unsafe {
        let _ = libc::setpgid(cpid, cpid);
    }

    // Hand the controlling terminal's foreground to the child so reads
    // from /dev/tty (e.g. sudo's password prompt) don't raise SIGTTIN
    // and stop the child. Best-effort — no-op when the daemon has no
    // controlling tty (headless / detached run). Skipped for
    // unprivileged children: they don't read /dev/tty and the swap's
    // shared `tty_lock` would needlessly queue them behind prompts.
    let _fg = fg_lock.and_then(|m| ForegroundGuard::take(cpid, m));

    // Drain stdout/stderr in threads so a child filling its stderr pipe
    // doesn't block our read of stdout (or vice versa).
    let stdout_handle = child.stdout.take().map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));
    let stderr_handle = child.stderr.take().map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));

    let deadline = Instant::now() + timeout;
    let exit = match wait_with_deadline(&mut child, deadline) {
        Ok(s) => s,
        Err(WaitError::Timeout) => {
            kill_group(&mut child);
            return Response::error(
                id,
                &format!("command timed out after {}s", timeout.as_secs()),
            );
        }
        Err(WaitError::Io(e)) => {
            kill_group(&mut child);
            return Response::error(id, &format!("wait failed: {e}"));
        }
    };

    let (stdout_bytes, stdout_truncated) = stdout_handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    let (stderr_bytes, stderr_truncated) = stderr_handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();

    let stage = StageResult {
        exit_code: exit.code().unwrap_or(-1),
        stderr: B64.encode(&stderr_bytes),
        stderr_truncated,
    };
    Response::ok_with_truncation(id, vec![stage], &stdout_bytes, stdout_truncated)
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

    let mut children: Vec<Child> = Vec::with_capacity(n);
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
                if req.forward_agent {
                    if let Some(sock) = crate::server::forwarded_agent_socket() {
                        c.env("SSH_AUTH_SOCK", &sock);
                    }
                }
                c
            }
        };

        cmd.current_dir("/");

        // stdin: first stage gets null, later stages get the previous
        // stage's stdout. sudo's password prompt reads from /dev/tty, not
        // stdin, so closing stdin doesn't break authentication and prevents
        // the first stage from blocking on the daemon's tty.
        if let Some(prev) = prev_stdout.take() {
            cmd.stdin(prev);
        } else if is_first {
            cmd.stdin(Stdio::null());
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::umask(0o077);
                Ok(())
            });
        }

        match cmd.spawn() {
            Ok(mut child) => {
                if !is_last {
                    if let Some(stdout) = child.stdout.take() {
                        prev_stdout = Some(Stdio::from(stdout));
                    }
                }
                children.push(child);
            }
            Err(e) => {
                // Already-spawned children get killed via KillOnDrop below.
                let _guard = KillOnDrop::new(children);
                return Response::error(
                    &req.id,
                    &format!("failed to spawn pipeline stage {i}: {e}"),
                );
            }
        }
    }

    collect_pipeline_results(&req.id, children, n, exec_timeout())
}

/// Collect results from all pipeline children with caps and a timeout.
/// On panic in any of the spawned drain/wait threads, the KillOnDrop guard
/// terminates every still-running child so we never orphan a process to PID 1.
fn collect_pipeline_results(
    id: &str,
    children: Vec<Child>,
    n: usize,
    timeout: Duration,
) -> Response {
    let mut guard = KillOnDrop::new(children);

    // Spawn one drainer per stderr (capped). The last stage's stdout is
    // also drained in a thread for symmetry — we don't want to block on
    // it while a sibling stage's stderr fills up.
    let mut stderr_handles = Vec::with_capacity(n);
    for child in guard.children.iter_mut() {
        let stderr_pipe = child.stderr.take();
        stderr_handles.push(stderr_pipe.map(|s| spawn_drain(s, MAX_OUTPUT_BYTES)));
    }
    let stdout_handle = guard
        .children
        .last_mut()
        .and_then(|c| c.stdout.take())
        .map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));

    let deadline = Instant::now() + timeout;
    let mut exits: Vec<Option<ExitStatus>> = vec![None; n];

    // Wait for each child up to the deadline. We poll in parallel by
    // round-robining try_wait across all not-yet-exited children.
    loop {
        let mut all_done = true;
        for (i, child) in guard.children.iter_mut().enumerate() {
            if exits[i].is_some() {
                continue;
            }
            match child.try_wait() {
                Ok(Some(s)) => exits[i] = Some(s),
                Ok(None) => all_done = false,
                Err(_) => exits[i] = Some(synthetic_failure_status()),
            }
        }
        if all_done {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }

    // Anything not exited gets killed; record a synthetic failure status
    // for those stages.
    let mut timed_out = false;
    for (i, child) in guard.children.iter_mut().enumerate() {
        if exits[i].is_none() {
            timed_out = true;
            kill_group(child);
            exits[i] = Some(synthetic_failure_status());
        }
    }

    let (stdout_bytes, stdout_truncated) = stdout_handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();

    // All children have exited (or been killed); join their stderr drainers.
    let mut stages = Vec::with_capacity(n);
    for (i, h) in stderr_handles.into_iter().enumerate() {
        let (bytes, truncated) = h.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        stages.push(StageResult {
            exit_code: exits[i].as_ref().and_then(|s| s.code()).unwrap_or(-1),
            stderr: B64.encode(&bytes),
            stderr_truncated: truncated,
        });
    }

    // All children have been waited on already; defuse the guard.
    let _ = guard.into_inner();

    if timed_out {
        return Response::error(
            id,
            &format!("pipeline timed out after {}s", timeout.as_secs()),
        );
    }
    Response::ok_with_truncation(id, stages, &stdout_bytes, stdout_truncated)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// RAII handoff of the controlling tty's foreground process group.
///
/// On `take`, opens /dev/tty, saves the current foreground pgid, and
/// installs `child_pgid` as the new foreground (with SIGTTOU blocked
/// across the syscall — without that the daemon would self-suspend if
/// it itself were in a background pgrp). On drop, the previous
/// foreground is restored and the saved signal mask reinstated.
///
/// Holds `tty_lock` (a per-server `Mutex<()>` owned by `server::run`) for
/// its lifetime. The same lock is taken by the prompt path in `server`,
/// so prompts and exec foreground-swaps are mutually exclusive — without
/// that, an in-flight swap would leave the daemon in a background pgrp
/// on /dev/tty and any concurrent prompt would EIO (PR #22 turned the
/// prior SIGTTIN-stop into EIO).
///
/// Best-effort: returns `None` if the daemon has no controlling tty,
/// or if `tcgetpgrp`/`tcsetpgrp` fails. In those cases the caller
/// proceeds without the swap; kill-group reaping (via the `setpgid` in
/// `pre_exec`) is independent and unaffected.
struct ForegroundGuard<'a> {
    _lock: MutexGuard<'a, ()>,
    tty_fd: libc::c_int,
    prev_pgrp: libc::pid_t,
    saved_mask: libc::sigset_t,
}

impl<'a> ForegroundGuard<'a> {
    fn take(child_pgid: libc::pid_t, tty_lock: &'a Mutex<()>) -> Option<Self> {
        let lock = tty_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        unsafe {
            let tty_fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            if tty_fd < 0 {
                return None;
            }

            let mut to_block: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut to_block);
            libc::sigaddset(&mut to_block, libc::SIGTTOU);
            let mut saved_mask: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &to_block, &mut saved_mask);

            let prev_pgrp = libc::tcgetpgrp(tty_fd);
            if prev_pgrp < 0 {
                libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
                libc::close(tty_fd);
                return None;
            }

            if libc::tcsetpgrp(tty_fd, child_pgid) != 0 {
                libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
                libc::close(tty_fd);
                return None;
            }

            Some(Self {
                _lock: lock,
                tty_fd,
                prev_pgrp,
                saved_mask,
            })
        }
    }
}

impl Drop for ForegroundGuard<'_> {
    fn drop(&mut self) {
        // Best-effort restore. Failures are silently ignored: the
        // daemon may have already lost the controlling tty (e.g. ssh
        // tunnel collapsed) or the prior pgid may have died.
        unsafe {
            libc::tcsetpgrp(self.tty_fd, self.prev_pgrp);
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved_mask, std::ptr::null_mut());
            libc::close(self.tty_fd);
        }
    }
}

#[derive(Debug)]
enum WaitError {
    Timeout,
    Io(std::io::Error),
}

fn wait_with_deadline(child: &mut Child, deadline: Instant) -> Result<ExitStatus, WaitError> {
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => {}
            Err(e) => return Err(WaitError::Io(e)),
        }
        if Instant::now() >= deadline {
            return Err(WaitError::Timeout);
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
}

/// Drain `reader` into a Vec, capping at `max` bytes. Reading stops as
/// soon as the cap is exceeded; the caller must arrange for the producer
/// to be killed so it doesn't wedge on a full pipe.
fn spawn_drain<R: Read + Send + 'static>(
    mut reader: R,
    max: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if buf.len() + n > max {
                let take = max.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..take]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if truncated {
            // Drain any remaining bytes from the pipe to unblock the
            // child, but don't keep them. Bounded by best-effort: if
            // the child writes forever, the eventual kill will close it.
            let mut sink = [0u8; 65536];
            while let Ok(n) = reader.read(&mut sink) {
                if n == 0 {
                    break;
                }
            }
        }
        (buf, truncated)
    })
}

/// Send SIGKILL to the child's entire process group (it's a group leader
/// because of `setsid` in `pre_exec`), then reap. Falls back to a single
/// `kill()` + `wait()` if the killpg syscall fails for any reason.
fn kill_group(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    unsafe {
        if libc::killpg(pid, libc::SIGKILL) != 0 {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

fn synthetic_failure_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    // 137 is the conventional "killed by SIGKILL" exit (128 + 9).
    ExitStatus::from_raw(137 << 8)
}

/// Kill every child that hasn't been claimed by the success path. Used to
/// avoid orphaning processes when a panic unwinds out of the pipeline
/// collection logic — `Vec<Child>::drop` does NOT kill its members.
struct KillOnDrop {
    children: Vec<Child>,
}

impl KillOnDrop {
    fn new(children: Vec<Child>) -> Self {
        Self { children }
    }
    fn into_inner(mut self) -> Vec<Child> {
        std::mem::take(&mut self.children)
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        for child in &mut self.children {
            kill_group(child);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    #[test]
    fn sanitize_env_rejects_ld_preload() {
        // Issue #16: LD_PRELOAD must not be silently stripped. It now
        // takes the same hard-reject path as any other non-allowlisted
        // var.
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let err = sanitize_env(&env).expect_err("LD_PRELOAD must be rejected");
        assert!(
            err.contains("LD_PRELOAD"),
            "expected error to mention LD_PRELOAD, got: {err:?}"
        );
    }

    #[test]
    fn sanitize_env_rejects_path_override() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/tmp/evil".to_string());
        let err = sanitize_env(&env).expect_err("PATH must be rejected");
        assert!(err.contains("PATH"), "got: {err:?}");
    }

    #[test]
    fn sanitize_env_allows_lang() {
        let mut env = HashMap::new();
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        let out = sanitize_env(&env).expect("LANG is on the allowlist");
        assert_eq!(out.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    }

    #[test]
    fn kill_on_drop_terminates_running_child() {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        // Sanity: the child is alive.
        std::thread::sleep(Duration::from_millis(20));
        assert!(pid_alive(pid));

        {
            let _guard = KillOnDrop::new(vec![child]);
        } // drop: kill+wait

        // SIGKILL is delivered synchronously inside Drop and we waited,
        // so the child must already be reaped.
        assert!(!pid_alive(pid), "child {pid} survived KillOnDrop");
    }

    #[test]
    fn into_inner_defuses_the_guard() {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        let guard = KillOnDrop::new(vec![child]);
        let mut released = guard.into_inner();
        assert!(pid_alive(pid), "into_inner must not kill");

        // Test cleanup: actually kill the released child so we don't
        // leak an orphan from the test process.
        for c in &mut released {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    // --- Security audit: randomized fuzz of shell_escape -----------------
    //
    // Invariant: for any input `s`, the string produced by shell_escape(s),
    // when evaluated by /bin/sh as a single word, must reproduce `s`
    // byte-for-byte. A break here is a pipeline command-injection (multi-
    // stage requests are assembled into `sh -c '<stage> | <stage>'`).
    //
    // We feed a metacharacter-heavy alphabet (quotes, $, backticks,
    // backslash, |, ;, &, spaces, parens, braces) — exactly the bytes that
    // could break out of single-quoting. Newline/NUL/control chars are
    // excluded because validate_request rejects them before shell_escape is
    // ever reached, so they are not part of this function's input domain.
    #[test]
    fn fuzz_shell_escape_roundtrips_through_sh() {
        use std::process::Command;

        // Deterministic xorshift64* PRNG — reproducible, no external dep.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545F4914F6CDD1D);
            state
        };

        // Alphabet of shell-significant characters plus a few benign ones.
        let alphabet: &[u8] = b"abc01 '\"\\$`|;&()<>*?{}[]=:,.-_/!#%^~@ \t";
        let mut failures = Vec::new();

        for _ in 0..5000 {
            let len = (next() % 24) as usize;
            let mut s = String::new();
            for _ in 0..len {
                let c = alphabet[(next() as usize) % alphabet.len()] as char;
                s.push(c);
            }
            let esc = shell_escape(&s);
            // Use printf %s so the escaped word is the sole argument.
            let script = format!("printf %s {esc}");
            let out = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                // Empty PATH: even if escaping failed, an injected word
                // resolves to nothing executable rather than a real command.
                .env("PATH", "")
                .current_dir("/")
                .output()
                .expect("spawn /bin/sh");
            if out.stdout != s.as_bytes() {
                failures.push((s.clone(), esc.clone(), out.stdout.clone()));
            }
        }
        assert!(
            failures.is_empty(),
            "shell_escape round-trip failures (input, escaped, sh-output): {:?}",
            &failures[..failures.len().min(5)]
        );
    }

    // Targeted regression cases alongside the random sweep.
    #[test]
    fn shell_escape_known_injection_vectors_are_inert() {
        use std::process::Command;
        let vectors = [
            "'; touch /tmp/sudo_proxy_pwned; '",
            "$(touch /tmp/sudo_proxy_pwned)",
            "`touch /tmp/sudo_proxy_pwned`",
            "a'b\"c\\d",
            "'\''",
            "",
            "$IFS",
            "x|y",
        ];
        for v in vectors {
            let esc = shell_escape(v);
            let out = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {esc}"))
                .env("PATH", "")
                .current_dir("/")
                .output()
                .expect("spawn /bin/sh");
            assert_eq!(
                out.stdout,
                v.as_bytes(),
                "shell_escape failed to neutralize {v:?} -> {esc:?}"
            );
        }
    }
}
