use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::executor::{exec_direct, exec_pkexec, exec_sudo, sanitize_env};
use crate::mode::Mode;
use crate::protocol::{Request, Response};
use crate::tui::{self, Prompter, ResultSink};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUEST_AGE: Duration = Duration::from_secs(60);
/// How long replay-protection ids are remembered. Twice MAX_REQUEST_AGE so that
/// any id that could still pass the freshness check is also still in the set.
const REPLAY_RETENTION: Duration = Duration::from_secs(120);
/// Per-syscall read/write timeout. Bounds any single I/O operation.
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Wall-clock deadline for completing the request handshake (read+parse).
/// CONNECTION_IO_TIMEOUT bounds each syscall, but a slow-loris client
/// could trickle bytes within each window indefinitely. This deadline
/// puts an upper bound on the whole handshake regardless of pacing.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Hard cap on the size of one JSON request line, including the trailing
/// newline. Bounds the per-connection read buffer.
const MAX_REQUEST_BYTES: usize = 1_048_576;
/// Default ceiling on concurrent handler threads. A buggy or hostile
/// same-UID process that opens N connections must not be able to spawn N
/// threads; once the cap is reached, new connections receive a `busy`
/// error and are closed without spawning. Soft cap — chosen high enough
/// that legitimate burst usage is unaffected.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Returns the SSH_AUTH_SOCK forwarded to the daemon, if any.
///
/// Read from the daemon's *own* environment (set by sshd when the user
/// opened the tunnel with `-A`), never from a request — the request env
/// is controlled by the local peer. Used by the executor to inject the
/// socket into unprivileged children that requested `forward_agent`.
///
/// The daemon never mutates its own environment, so live-reading gives a
/// stable value across the daemon's lifetime; we don't bother caching.
pub fn forwarded_agent_socket() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK").ok()
}

/// Characters forbidden in argv strings (control chars, bidi overrides, zero-width).
fn has_dangerous_chars(s: &str) -> bool {
    for c in s.chars() {
        // Control chars 0x00-0x1F except tab (0x09)
        if c != '\t' && (c as u32) < 0x20 {
            return true;
        }
        // Zero-width and bidi override characters
        match c as u32 {
            0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => return true,
            _ => {}
        }
    }
    false
}

fn validate_request(req: &Request) -> Result<(), String> {
    if req.pipeline.is_empty() {
        return Err("pipeline must not be empty".to_string());
    }
    for (stage_idx, argv) in req.pipeline.iter().enumerate() {
        if argv.is_empty() {
            return Err(format!("pipeline stage {stage_idx} must not be empty"));
        }
        for (i, arg) in argv.iter().enumerate() {
            if has_dangerous_chars(arg) {
                return Err(format!(
                    "pipeline[{stage_idx}][{i}] contains forbidden control/bidi characters"
                ));
            }
        }
    }
    // Validate env keys too
    for key in req.env.keys() {
        if has_dangerous_chars(key) {
            return Err(format!("env key '{key}' contains forbidden characters"));
        }
    }
    for val in req.env.values() {
        if has_dangerous_chars(val) {
            return Err("env value contains forbidden characters".to_string());
        }
    }
    Ok(())
}

/// Reject requests whose `time` is missing, malformed, or older than
/// MAX_REQUEST_AGE. Performed at connection-handler entry, before any
/// TTY contention, so a request's freshness is judged at acceptance
/// rather than after waiting in line.
fn check_freshness(req: &Request) -> Result<(), String> {
    if req.time.is_empty() {
        return Err("missing time field".to_string());
    }
    let age = parse_age(&req.time).ok_or_else(|| "malformed time field".to_string())?;
    if age > MAX_REQUEST_AGE {
        return Err(format!(
            "request too old: {}s (max {}s)",
            age.as_secs(),
            MAX_REQUEST_AGE.as_secs()
        ));
    }
    Ok(())
}

/// Recover poisoned mutex guards. The two mutexes in this module guard
/// `SeenIds` (whose only mutation is insert / evict — no broken
/// invariant after a panic) and `()` (the TTY serializer — no state).
/// A panicking prompter must not poison the daemon for every subsequent
/// request.
fn lock_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Log the underlying `io::Error` from a failed `Prompter::prompt`.
///
/// Verbose-only because a healthy daemon never hits this branch; when
/// it does, the kind + raw_os_error is what distinguishes a benign
/// `BrokenPipe` (peer hung up mid-prompt) from a residual
/// background-pgrp `EIO` (the fix from PR #22 turned the daemon-stop
/// hang into this errno; if it ever recurs, it shows up here).
fn log_prompt_io_error(verbose: bool, id: &str, e: &io::Error) {
    if !verbose {
        return;
    }
    eprintln!(
        "[{id}] prompt io error: kind={:?} raw_os_error={:?}: {e}",
        e.kind(),
        e.raw_os_error()
    );
}

/// RAII decrement of `in_flight` on drop. Plain `fetch_sub` after
/// `handle_connection` would be skipped on panic, leaking the counter.
struct InFlightGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Parse an ISO 8601 UTC timestamp and return its age relative to now.
fn parse_age(timestamp: &str) -> Option<Duration> {
    // Expect format: 2026-02-13T14:30:00Z or similar
    // Minimal parser for YYYY-MM-DDTHH:MM:SSZ
    let ts = timestamp.trim().trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?;

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|s| s.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);
    let (hour, min, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    // Reject out-of-range components up front. Defence in depth: without
    // these guards, year < 1970 underflows `(year - 1970)`, day == 0
    // underflows `(day - 1)`, and an out-of-range month would index
    // `days_before_month` out of bounds. A wrapped value cascades into
    // `ts_secs` and a stale request can appear fresh (issue #11).
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Allow sec == 60 for ISO 8601 leap-second tolerance.
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    // Days in each month (non-leap). Good enough for age checking.
    let days_before_month: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = year.checked_sub(1970)?.checked_mul(365)?
        .checked_add(year.checked_sub(1969)? / 4)?;
    days = days
        .checked_add(days_before_month[(month - 1) as usize])?
        .checked_add(day - 1)?;
    // Leap year correction for current year
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days = days.checked_add(1)?;
    }
    let ts_secs = days
        .checked_mul(86400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)?;

    let now_secs = now.as_secs();
    if ts_secs > now_secs {
        Some(Duration::from_secs(0))
    } else {
        Some(Duration::from_secs(now_secs - ts_secs))
    }
}

fn runtime_dir() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
    PathBuf::from(dir)
}

pub fn default_socket_path() -> PathBuf {
    runtime_dir().join("sudo-proxy.sock")
}

/// Local tunnel endpoint path for a remote host's sudo-proxy socket.
/// Caller must validate `host` with [`validate_host`] first.
pub fn remote_socket_path(host: &str) -> PathBuf {
    runtime_dir().join(format!("sudo-proxy-{host}.sock"))
}

/// Reject host strings that would escape the socket directory, be passed
/// as an option flag to ssh, or carry shell metacharacters into a downstream
/// `sh -c` style call site. Strict allowlist: ASCII alphanumerics plus
/// `.`, `-`, `_`, `@`, `:`. Everything else (including the shell
/// metacharacters `;`, `|`, `&`, `$`, backtick, `(`, `)`, `<`, `>`, `*`, `?`,
/// braces, brackets, quotes, `=`, `,`, etc.) is rejected. Bare-form IPv6
/// (`::1`, `user@::1`) works because `:` is allowed; bracketed `[::1]` is
/// not.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    if host.starts_with('-') {
        return Err("host must not start with '-'".into());
    }
    for c in host.chars() {
        let ok = c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':');
        if !ok {
            return Err(format!("host contains forbidden character: {c:?}"));
        }
    }
    Ok(())
}

/// Bounded set of recently-seen request ids, evicted by age.
pub(crate) struct SeenIds {
    set: HashSet<String>,
    queue: VecDeque<(String, Instant)>,
    now: Box<dyn Fn() -> Instant + Send>,
}

impl SeenIds {
    pub(crate) fn new<F: Fn() -> Instant + Send + 'static>(now: F) -> Self {
        Self {
            set: HashSet::new(),
            queue: VecDeque::new(),
            now: Box::new(now),
        }
    }

    /// Atomic check-and-insert: returns `true` if `id` was new (and is now
    /// remembered), `false` if it was already in the set. Combining the two
    /// steps into one critical section closes the TOCTOU window between
    /// concurrent connection threads.
    pub(crate) fn try_insert(&mut self, id: String) -> bool {
        self.evict_stale();
        if self.set.contains(&id) {
            return false;
        }
        self.set.insert(id.clone());
        self.queue.push_back((id, (self.now)()));
        true
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    fn evict_stale(&mut self) {
        let now = (self.now)();
        while let Some((_, t)) = self.queue.front() {
            if now.duration_since(*t) > REPLAY_RETENTION {
                let (old, _) = self.queue.pop_front().unwrap();
                self.set.remove(&old);
            } else {
                break;
            }
        }
    }
}

/// Read SO_PEERCRED for a connected Unix socket and return the peer UID.
/// Linux-specific. Used to refuse cross-UID connections as defense-in-depth
/// — the socket file is already 0600 in a 0700 runtime dir.
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Bind the listener, refusing to clobber an active server. If the socket
/// path is already bound and accepts connections, error out. If the file
/// exists but no peer accepts, treat it as stale and replace it.
fn bind_listener(socket_path: &Path) -> io::Result<UnixListener> {
    // Tighten umask so the socket is created 0600 even before the explicit
    // chmod below — closes the bind→chmod TOCTOU window.
    let prev_umask = unsafe { libc::umask(0o077) };
    let first = UnixListener::bind(socket_path);
    unsafe { libc::umask(prev_umask) };

    let listener = match first {
        Ok(l) => l,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            if UnixStream::connect(socket_path).is_ok() {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "sudo-proxy is already running on {}",
                        socket_path.display()
                    ),
                ));
            }
            fs::remove_file(socket_path)?;
            let prev = unsafe { libc::umask(0o077) };
            let l = UnixListener::bind(socket_path);
            unsafe { libc::umask(prev) };
            l?
        }
        Err(e) => return Err(e),
    };

    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Tunable knobs for `run`. Holds the static configuration that doesn't
/// change over the daemon's lifetime; runtime objects (prompter, sink,
/// shutdown, counter) stay separate so tests can inject fakes.
pub struct ServerConfig {
    pub mode: Mode,
    pub pkexec_only: bool,
    pub verbose: bool,
    pub confirm_unprivileged: bool,
    pub max_in_flight: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Local,
            pkexec_only: false,
            verbose: false,
            // Human-in-the-loop is the marketed value of sudo-proxy.
            // Unprivileged commands now go through the same Y/N gate as
            // privileged ones by default; opt out via
            // `--no-confirm-unprivileged` for batch/automation flows.
            confirm_unprivileged: true,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }
}

pub fn run(
    socket_path: &Path,
    config: ServerConfig,
    prompter: Arc<dyn Prompter>,
    result_sink: Arc<dyn ResultSink>,
    shutdown: &AtomicBool,
    in_flight: Arc<AtomicUsize>,
    tty_lock: Arc<Mutex<()>>,
) -> std::io::Result<()> {
    let listener = bind_listener(socket_path)?;
    listener.set_nonblocking(true)?;

    if config.verbose {
        eprintln!("sudo-proxy listening on {}", socket_path.display());
        eprintln!("mode: {}", config.mode.label());
        if forwarded_agent_socket().is_some() {
            eprintln!("ssh agent forwarding: available");
        }
    }

    let our_uid = unsafe { libc::getuid() };
    let seen_ids = Arc::new(Mutex::new(SeenIds::new(Instant::now)));

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        let (mut stream, _addr) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE) | Some(libc::ENFILE)
                ) =>
            {
                eprintln!("accept: file-descriptor pressure ({e}); backing off");
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        // Backpressure: if the cap is reached, reject inline rather than
        // spawn another handler thread. We don't read anything from the
        // peer here — just write a fixed busy response and close. The
        // socket file is 0600 in a 0700 dir so only same-UID peers reach
        // this path; no need to verify SO_PEERCRED before declining.
        if in_flight.load(Ordering::Relaxed) >= config.max_in_flight {
            let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));
            let resp = Response::error("", "server busy: too many in-flight requests");
            let _ = write_response(&mut stream, &resp);
            continue;
        }

        in_flight.fetch_add(1, Ordering::Relaxed);
        let prompter = Arc::clone(&prompter);
        let sink = Arc::clone(&result_sink);
        let seen = Arc::clone(&seen_ids);
        let tty = Arc::clone(&tty_lock);
        let guard = InFlightGuard {
            counter: Arc::clone(&in_flight),
        };

        let mode = config.mode;
        let pkexec_only = config.pkexec_only;
        let verbose = config.verbose;
        let confirm_unprivileged = config.confirm_unprivileged;
        thread::spawn(move || {
            let _guard = guard;
            handle_connection(
                stream,
                our_uid,
                mode,
                pkexec_only,
                verbose,
                confirm_unprivileged,
                prompter,
                sink,
                seen,
                tty,
            );
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_connection(
    mut stream: UnixStream,
    our_uid: u32,
    mode: Mode,
    pkexec_only: bool,
    verbose: bool,
    confirm_unprivileged: bool,
    prompter: Arc<dyn Prompter>,
    result_sink: Arc<dyn ResultSink>,
    seen_ids: Arc<Mutex<SeenIds>>,
    tty_lock: Arc<Mutex<()>>,
) {
    // Defense-in-depth: refuse connections from other UIDs even though the
    // socket file is 0600 inside a 0700 runtime dir.
    match peer_uid(&stream) {
        Ok(uid) if uid == our_uid => {}
        Ok(uid) => {
            eprintln!("rejecting connection from uid {uid} (expected {our_uid})");
            return;
        }
        Err(e) => {
            eprintln!("peer credential check failed: {e}");
            return;
        }
    }

    let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));

    let line = match read_request_line(&mut stream, Instant::now() + HANDSHAKE_DEADLINE) {
        Ok(b) if b.is_empty() => return,
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            let resp = Response::error("", "handshake deadline exceeded");
            let _ = write_response(&mut stream, &resp);
            return;
        }
        Err(e) => {
            let resp = Response::error("", &format!("read error: {e}"));
            let _ = write_response(&mut stream, &resp);
            return;
        }
    };

    let req: Request = match serde_json::from_slice(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::error("", &format!("invalid JSON: {e}"));
            let _ = write_response(&mut stream, &resp);
            return;
        }
    };

    if let Err(msg) = validate_request(&req) {
        let resp = Response::error(&req.id, &msg);
        let _ = write_response(&mut stream, &resp);
        return;
    }

    // Agent forwarding is unprivileged-only. A privileged child runs under
    // sudo (which env_resets) or pkexec (which we env_clear), so the socket
    // would be silently dropped — but we reject explicitly so a misconfigured
    // caller fails loudly instead of being puzzled by a missing key.
    if req.forward_agent && req.privileged {
        let resp = Response::error(
            &req.id,
            "forward_agent is only allowed for unprivileged commands",
        );
        let _ = write_response(&mut stream, &resp);
        return;
    }

    // Freshness is checked at handler entry, NOT after the TTY lock — a
    // request must not age past MAX_REQUEST_AGE just because it queued
    // behind another user's prompt.
    if let Err(msg) = check_freshness(&req) {
        let resp = Response::error(&req.id, &msg);
        let _ = write_response(&mut stream, &resp);
        return;
    }

    let env = match sanitize_env(&req.env) {
        Ok(e) => e,
        Err(msg) => {
            let resp = Response::error(&req.id, &msg);
            let _ = write_response(&mut stream, &resp);
            return;
        }
    };

    // Atomic check-and-insert: closes the TOCTOU window between
    // contains() and insert() that exists when two threads race the
    // same request id.
    {
        let mut ids = lock_recover(&seen_ids);
        if !ids.try_insert(req.id.clone()) {
            drop(ids);
            let resp = Response::error(&req.id, &format!("duplicate request id: {}", req.id));
            let _ = write_response(&mut stream, &resp);
            return;
        }
    }

    if verbose {
        let priv_label = if req.privileged { "privileged" } else { "unprivileged" };
        let pipeline_display = crate::tui::pipeline_join(&req.pipeline);
        let client_ver = if req.version.is_empty() { "unknown" } else { req.version.as_str() };
        eprintln!("[{}] [{}] [client {}] {}", req.id, priv_label, client_ver, pipeline_display);
    }

    let resp = if req.privileged {
        if pkexec_only && mode == Mode::Local {
            // --pkexec: pkexec itself handles auth and approval; no TTY lock.
            exec_pkexec(&req, &env, &tty_lock)
        } else {
            // The TTY lock is shared with `executor::ForegroundGuard`, so a
            // prompt blocks until any in-flight exec has released the
            // foreground pgrp. Without that, the daemon would be in a
            // background pgrp on /dev/tty during the prompt and reads /
            // writes would EIO (PR #22 turned the prior SIGTTIN stop into
            // EIO). Released before exec so the same lock can be re-taken
            // by ForegroundGuard for the swap.
            let prompt_result = {
                let _g = lock_recover(&tty_lock);
                prompter.prompt(&req, PROMPT_TIMEOUT)
            };
            match prompt_result {
                Ok(tui::PromptResult::Approved) => exec_sudo(&req, &env, &tty_lock),
                Ok(tui::PromptResult::Denied) => Response::denied(&req.id),
                Ok(tui::PromptResult::Timeout) => Response::timeout(&req.id),
                Err(e) => {
                    log_prompt_io_error(verbose, &req.id, &e);
                    Response::error(&req.id, &format!("prompt error: {e}"))
                }
            }
        }
    } else if confirm_unprivileged {
        let prompt_result = {
            let _g = lock_recover(&tty_lock);
            prompter.prompt(&req, PROMPT_TIMEOUT)
        };
        match prompt_result {
            Ok(tui::PromptResult::Approved) => exec_direct(&req, &env),
            Ok(tui::PromptResult::Denied) => Response::denied(&req.id),
            Ok(tui::PromptResult::Timeout) => Response::timeout(&req.id),
            Err(e) => {
                log_prompt_io_error(verbose, &req.id, &e);
                Response::error(&req.id, &format!("prompt error: {e}"))
            }
        }
    } else {
        // Non-privileged, no confirmation: print a one-line banner so the
        // user can see what the proxy is running on their behalf, then exec.
        // Best-effort: try_lock so the banner never queues behind a
        // long-running privileged prompt. Skipping the banner under
        // contention is preferred to making `ls` wait on a human Y/N.
        if let Ok(_g) = tty_lock.try_lock() {
            let _ = tui::display_banner(&req);
        }
        exec_direct(&req, &env)
    };

    // Echo result on the TTY. The privileged path takes the lock blocking
    // because it is already serialized with the prompt anyway. The
    // unprivileged path uses try_lock so a still-pending privileged prompt
    // never delays an unprivileged command's completion. Skip pkexec
    // because pkexec has its own dialog.
    let used_pkexec = req.privileged && pkexec_only && mode == Mode::Local;
    if !used_pkexec {
        if req.privileged {
            let _g = lock_recover(&tty_lock);
            let _ = result_sink.display(&resp);
        } else if let Ok(_g) = tty_lock.try_lock() {
            let _ = result_sink.display(&resp);
        }
    }

    let _ = write_response(&mut stream, &resp);
}

fn write_response(stream: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    let json = serde_json::to_string(resp).unwrap_or_else(|_| {
        r#"{"id":"","status":"error","message":"serialization failed"}"#.to_string()
    });
    writeln!(stream, "{json}")?;
    stream.flush()
}

/// Read up to one newline-terminated request line from `stream`, bounded by
/// both a wall-clock `deadline` and a max byte count. Returns the line
/// *without* the trailing newline. An empty Vec means the client closed
/// before sending any data.
fn read_request_line(stream: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "handshake deadline exceeded",
            ));
        }
        let remaining = deadline - now;
        // Cap each syscall at CONNECTION_IO_TIMEOUT so a kernel-stuck
        // read can't outlive the deadline by more than that amount.
        let to = remaining.min(CONNECTION_IO_TIMEOUT);
        stream.set_read_timeout(Some(to))?;

        let n = match stream.read(&mut chunk) {
            Ok(0) => {
                // EOF. An empty buffer is the canonical "client closed
                // before sending data" signal — handle_connection uses
                // is_empty() to drop these silently. A non-empty buffer
                // without a terminating newline is a protocol violation:
                // surfacing a specific error keeps the size-cap and
                // missing-newline cases from masquerading as "invalid
                // JSON" downstream.
                if buf.is_empty() {
                    return Ok(buf);
                }
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "request missing trailing newline",
                ));
            }
            Ok(n) => n,
            // Per-syscall timeout: loop back so the deadline check at the
            // top of the loop converts a true deadline expiry into the
            // canonical "handshake deadline exceeded" error.
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };

        let want = (MAX_REQUEST_BYTES.saturating_sub(buf.len())).min(n);
        buf.extend_from_slice(&chunk[..want]);
        if let Some(idx) = buf.iter().position(|&b| b == b'\n') {
            buf.truncate(idx);
            return Ok(buf);
        }
        if want < n {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "request exceeds maximum size",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn fake_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + 'static) {
        let cell = Arc::new(Mutex::new(Instant::now()));
        let cloned = Arc::clone(&cell);
        (cell, move || *cloned.lock().unwrap())
    }

    fn advance(clock: &Mutex<Instant>, by: Duration) {
        let mut g = clock.lock().unwrap();
        *g += by;
    }

    #[test]
    fn seen_ids_remembers_insertion() {
        let (_clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        assert!(ids.contains("alpha"));
        assert!(!ids.contains("beta"));
    }

    #[test]
    fn seen_ids_evicts_after_retention() {
        let (clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        advance(&clock, REPLAY_RETENTION + Duration::from_secs(1));
        assert!(ids.try_insert("beta".into()));
        assert!(!ids.contains("alpha"));
        assert!(ids.contains("beta"));
    }

    #[test]
    fn seen_ids_keeps_within_retention() {
        let (clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        advance(&clock, Duration::from_secs(60));
        assert!(ids.try_insert("beta".into()));
        assert!(ids.contains("alpha"));
        assert!(ids.contains("beta"));
    }

    #[test]
    fn seen_ids_partial_eviction() {
        let (clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("a".into()));
        advance(&clock, Duration::from_secs(60));
        assert!(ids.try_insert("b".into()));
        advance(&clock, Duration::from_secs(70));
        assert!(ids.try_insert("c".into()));
        assert!(!ids.contains("a"));
        assert!(ids.contains("b"));
        assert!(ids.contains("c"));
    }

    #[test]
    fn try_insert_returns_true_on_new_id() {
        let (_clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        assert!(ids.contains("alpha"));
    }

    #[test]
    fn try_insert_returns_false_on_duplicate() {
        let (_clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        assert!(!ids.try_insert("alpha".into()));
    }

    #[test]
    fn try_insert_accepts_id_again_after_eviction() {
        let (clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("alpha".into()));
        advance(&clock, REPLAY_RETENTION + Duration::from_secs(1));
        // The next try_insert must evict "alpha" before its own check, so a
        // re-use of the same id after retention is treated as new.
        assert!(ids.try_insert("alpha".into()));
    }

    #[test]
    fn validate_host_rejects_dash_prefix() {
        assert!(validate_host("-oProxyCommand=evil").is_err());
    }

    #[test]
    fn validate_host_rejects_slashes_and_control() {
        assert!(validate_host("foo/bar").is_err());
        assert!(validate_host("foo\nbar").is_err());
        assert!(validate_host("").is_err());
    }

    #[test]
    fn validate_host_accepts_typical_targets() {
        assert!(validate_host("localhost").is_ok());
        assert!(validate_host("user@host.example.com").is_ok());
        assert!(validate_host("root@10.0.0.1").is_ok());
    }

    #[test]
    fn validate_host_rejects_shell_metacharacters() {
        // Each of these would, if `host` were ever interpolated into an
        // `sh -c` string, allow the caller to break out of the intended
        // command. The strict allowlist must reject every one.
        for bad in [
            "a;b", "a|b", "a&b", "a$b", "a`b", "a(b", "a)b", "a<b", "a>b",
            "a*b", "a?b", "a{b", "a}b", "a[b", "a]b", "a'b", "a\"b", "a\\b",
            "a=b", "a,b", "a~b", "a!b", "a#b", "a%b", "a^b", "a+b", "a/b",
        ] {
            assert!(
                validate_host(bad).is_err(),
                "validate_host must reject {bad:?}"
            );
        }
    }

    #[test]
    fn parse_age_rejects_malformed_strings() {
        assert!(parse_age("").is_none());
        assert!(parse_age("not-a-timestamp").is_none());
        assert!(parse_age("2026-04-30").is_none(), "missing T-separated time");
        assert!(parse_age("2026-04-30T12:00").is_none(), "incomplete time");
        assert!(parse_age("2026-13-01T00:00:00Z").is_none(), "month out of range");
    }

    /// Issue #11 regression: out-of-range components used to underflow
    /// or wrap, letting a stale timestamp appear age-zero.
    #[test]
    fn parse_age_rejects_out_of_range_components() {
        assert!(parse_age("1969-12-31T23:59:59Z").is_none(), "year < 1970");
        assert!(parse_age("0001-01-01T00:00:00Z").is_none(), "ancient year");
        assert!(parse_age("2026-00-15T00:00:00Z").is_none(), "month == 0");
        assert!(parse_age("2026-01-00T00:00:00Z").is_none(), "day == 0");
        assert!(parse_age("2026-01-32T00:00:00Z").is_none(), "day > 31");
        assert!(parse_age("2026-02-30T25:00:00Z").is_none(), "hour > 23");
        assert!(parse_age("2026-02-15T12:60:00Z").is_none(), "minute > 59");
        assert!(parse_age("2026-02-15T12:00:61Z").is_none(), "sec > 60");
    }

    #[test]
    fn parse_age_accepts_valid_iso8601() {
        // Any well-formed past timestamp returns Some(_). We can't know the
        // exact age without freezing wall-clock time; just assert it parses.
        assert!(parse_age("2024-01-01T00:00:00Z").is_some());
        assert!(parse_age("2024-01-01T00:00:00").is_some(), "trailing Z optional");
    }

    #[test]
    fn parse_age_clamps_future_timestamp_to_zero() {
        // A timestamp far enough in the future should not panic on subtract;
        // the parser caps the age at zero.
        let age = parse_age("3000-01-01T00:00:00Z");
        assert_eq!(age, Some(Duration::from_secs(0)));
    }
}
