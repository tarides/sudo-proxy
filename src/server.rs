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

use crate::audit::{AuditConfig, AuditLog, Event, Outcome, Reject};
use crate::executor::{exec_direct, exec_pkexec, exec_sudo, sanitize_env, LeafPrivilege, LeafView};
use crate::mode::Mode;
use crate::protocol::{is_dangerous_char, Request, Response, ValidatedRequest};
use crate::tui::{self, Prompter, ResultSink};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUEST_AGE: Duration = Duration::from_secs(60);
/// How far in the future a request's `time` may be. A request to a remote
/// daemon carries the *client's* clock, so a little skew is tolerated; beyond
/// it the request is rejected. Without this bound a future-dated request
/// stayed fresh forever and became replayable once its id was evicted
/// (GHSA-h6r4-gh2r-qr98).
const MAX_FUTURE_SKEW: Duration = Duration::from_secs(30);
/// How long replay-protection ids are remembered. A request accepted at `t`
/// has `time <= t + MAX_FUTURE_SKEW`, so it can pass the freshness check
/// again only until `t + MAX_FUTURE_SKEW + MAX_REQUEST_AGE`. Retention must
/// cover that span so any id that could still pass freshness is still in the
/// set; the assertion below enforces it at compile time.
const REPLAY_RETENTION: Duration = Duration::from_secs(120);
const _: () = assert!(
    REPLAY_RETENTION.as_secs() >= MAX_REQUEST_AGE.as_secs() + MAX_FUTURE_SKEW.as_secs(),
    "REPLAY_RETENTION must cover MAX_REQUEST_AGE + MAX_FUTURE_SKEW"
);
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

/// Reject requests whose `time` is missing, malformed, older than
/// MAX_REQUEST_AGE, or more than MAX_FUTURE_SKEW in the future. Performed at
/// connection-handler entry, before any TTY contention, so a request's
/// freshness is judged at acceptance rather than after waiting in line.
fn check_freshness(req: &Request) -> Result<(), String> {
    if req.time.is_empty() {
        return Err("missing time field".to_string());
    }
    let age = parse_age(&req.time).ok_or_else(|| "malformed time field".to_string())?;
    check_age(age)
}

/// The freshness window on a signed age (seconds; negative = future-dated).
/// Split from `check_freshness` so the window can be tested without a clock.
fn check_age(age: i64) -> Result<(), String> {
    if age < 0 && age.unsigned_abs() > MAX_FUTURE_SKEW.as_secs() {
        return Err(format!(
            "request time is {}s in the future (max skew {}s)",
            age.unsigned_abs(),
            MAX_FUTURE_SKEW.as_secs()
        ));
    }
    if age > 0 && age.unsigned_abs() > MAX_REQUEST_AGE.as_secs() {
        return Err(format!(
            "request too old: {age}s (max {}s)",
            MAX_REQUEST_AGE.as_secs()
        ));
    }
    Ok(())
}

/// Reject a `stop` dated before this daemon instance started (issue #63).
///
/// Replay protection (`SeenIds`) is in memory, per instance, so on its own it
/// would let a stop captured from a previous instance stop a freshly restarted
/// one while still inside the freshness window. Any stop accepted by an
/// earlier instance is dated before that instance exited, hence before this
/// one started. The comparison is strict: `time` has one-second resolution and
/// a legitimate request satisfies `floor(sent) >= floor(started)`, so `<` never
/// rejects one (barring clock skew between client and daemon). The residual
/// gap is a restart within the same wall-clock second as the original stop.
fn check_not_before_start(req_epoch: u64, started_epoch: u64) -> Result<(), String> {
    if req_epoch < started_epoch {
        return Err(format!(
            "stop request predates this daemon instance (request {}s before start)",
            started_epoch - req_epoch
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

/// ` [req <requester>]` for the daemon's stderr log lines, or empty when the
/// peer declared none — so "approved, requested by an AI" is greppable until
/// the append-only audit log (#6) persists the field. Self-declared, unverified.
fn requester_tag(req: &Request) -> String {
    if req.requester.is_empty() {
        String::new()
    } else {
        format!(" [req {}]", req.requester)
    }
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

/// Parse an ISO 8601 UTC timestamp and return its signed age relative to
/// now, in seconds: positive for the past, negative for the future. A future
/// timestamp is no longer clamped to 0 — `check_age` bounds it.
fn parse_age(timestamp: &str) -> Option<i64> {
    let ts_secs = parse_epoch(timestamp)?;
    let now_secs = i64::try_from(now_epoch()?).ok()?;
    let ts_secs = i64::try_from(ts_secs).ok()?;
    now_secs.checked_sub(ts_secs)
}

/// Current wall-clock time in whole seconds since the Unix epoch.
fn now_epoch() -> Option<u64> {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Parse an ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) into seconds
/// since the Unix epoch. Pure: no clock read.
fn parse_epoch(timestamp: &str) -> Option<u64> {
    // Expect format: 2026-02-13T14:30:00Z or similar
    // Minimal parser for YYYY-MM-DDTHH:MM:SSZ
    let ts = timestamp.trim().trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|s| s.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    // The pure date-arithmetic core lives in `datetime::ymd_hms_to_epoch`
    // (the reverse of `epoch_to_iso`), where Kani proves it panic/overflow/
    // wrap-free over the whole u64 domain — see docs/formalisation-roadmap.md.
    crate::datetime::ymd_hms_to_epoch(
        date_parts[0],
        date_parts[1],
        date_parts[2],
        time_parts[0],
        time_parts[1],
        time_parts[2],
    )
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

/// This machine's hostname (from `/etc/hostname`), used by [`is_local_host`] to
/// recognise a request that names the local box. Falls back to an empty string
/// (which matches nothing) if the file is unreadable, keeping the classifier
/// fail-closed toward "remote".
pub fn own_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// True if `host` denotes the machine this proxy runs on, so a request naming
/// it must route to the *local* path rather than an SSH tunnel. This is the C9
/// normaliser (invariant G7): it folds loopback literals and the machine's own
/// hostname to "local" so a self-target cannot masquerade as remote — e.g.
/// `execute(host="127.0.0.1")` must not open an SSH-to-self tunnel that routes
/// around local policy.
///
/// Best-effort by construction: ssh-config aliases and NAT hairpin can hide a
/// self-target it cannot see. G7 does not rest on catching every alias (see
/// C10) — local unprivileged is delegated to the Bash tool and every remote
/// daemon still gates unattended execution, so an undetected self-alias routed
/// SSH-to-self still lands on a gated daemon.
///
/// `own_hostname` is injected rather than read here, so the classification is a
/// pure function of its inputs and the property test stays hermetic.
pub fn is_local_host(host: &str, own_hostname: &str) -> bool {
    // Drop an optional `user@` prefix and a single trailing FQDN dot; compare
    // case-insensitively.
    let h = host.rsplit('@').next().unwrap_or(host);
    let h = h.strip_suffix('.').unwrap_or(h);
    let h_lower = h.to_ascii_lowercase();

    if h_lower == "localhost" {
        return true;
    }
    // The whole 127.0.0.0/8 block is loopback — parse it, don't string-match,
    // so `127.0.0.1.evil.com` is NOT treated as local.
    if let Ok(v4) = h.parse::<std::net::Ipv4Addr>() {
        return v4.octets()[0] == 127;
    }
    if let Ok(v6) = h.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    // The machine's own name — full FQDN, or a bare label matching our first
    // label (so `box` matches a hostname of `box.local`). A dotted FQDN must
    // match in full, so an unrelated `box.example.com` is not caught. An empty
    // `own_hostname` (unreadable /etc/hostname) matches nothing.
    if !own_hostname.is_empty() {
        let own_lower = own_hostname.to_ascii_lowercase();
        if h_lower == own_lower {
            return true;
        }
        if !h_lower.contains('.') {
            let own_label = own_lower.split('.').next().unwrap_or(&own_lower);
            if !own_label.is_empty() && h_lower == own_label {
                return true;
            }
        }
    }
    false
}

/// Sessions a human has granted unattended unprivileged execution, by pressing
/// `a` on an eligible daemon (barrier 2 of G7). Keyed by the request's
/// `session`, so a grant made for one client does not open the gate for the
/// others sharing the daemon (issue #8). `session` is self-declared, so this
/// separates well-behaved clients; it is not a boundary against a same-UID
/// client that claims another's session name (which could already run
/// unprivileged code directly). In memory only, never persisted.
#[derive(Default)]
pub(crate) struct UnattendedGrants(Mutex<HashSet<String>>);

impl UnattendedGrants {
    pub(crate) fn is_granted(&self, session: &str) -> bool {
        lock_recover(&self.0).contains(session)
    }

    pub(crate) fn grant(&self, session: &str) {
        lock_recover(&self.0).insert(session.to_string());
    }
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
                    format!("sudo-proxy is already running on {}", socket_path.display()),
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
    /// Log each request's command as pretty-printed JSON (just the `plan`, or a
    /// legacy `pipeline`) to stderr, before validation — a debug aid for
    /// inspecting what a client (e.g. the MCP server) actually sent. Independent
    /// of `verbose`.
    pub log_json: bool,
    /// Whether this daemon *may* offer the session-scoped `a` answer at an
    /// unprivileged prompt (invariant G7, first barrier). Read from the
    /// `unattended_eligible` policy in `hosts.json` at startup and immutable
    /// thereafter — no wire field, MCP flag, or keypress changes it. Default
    /// `false` (fail-closed): every unprivileged command is prompted.
    pub unattended_eligible: bool,
    /// Strict "structured or nothing" mode: reject, before prompting, any
    /// request with an opaque stage (a `Shell` node, or an `Exec` of a shell,
    /// inline-code interpreter or runner, directly or behind a wrapper).
    /// Read from `policy.no_shell` in `hosts.json` or `--no-shell` /
    /// `--allow-shell` at startup; immutable thereafter. Default `false`.
    pub no_shell: bool,
    pub max_in_flight: usize,
    /// Persistent audit sinks (issue #65). The stderr audit line is always
    /// written; `Default` turns the file and syslog sinks off.
    pub audit: AuditConfig,
    /// `--inherit-path` / `--inherit-env` (#101): the daemon environment that
    /// requests with no escalated step run with. Built at startup from the
    /// command line only; immutable thereafter. `None` by default.
    pub inherit: Option<Arc<crate::inherit::Inherited>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Local,
            pkexec_only: false,
            verbose: false,
            log_json: false,
            unattended_eligible: false,
            no_shell: false,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            audit: AuditConfig::default(),
            inherit: None,
        }
    }
}

pub fn run(
    socket_path: &Path,
    config: ServerConfig,
    prompter: Arc<dyn Prompter>,
    result_sink: Arc<dyn ResultSink>,
    shutdown: Arc<AtomicBool>,
    in_flight: Arc<AtomicUsize>,
    tty_lock: Arc<Mutex<()>>,
) -> std::io::Result<()> {
    // Taken before the socket exists, so no request this instance can
    // receive is dated earlier than a legitimate sender could have stamped it.
    let started_epoch =
        now_epoch().ok_or_else(|| io::Error::other("system clock is before the Unix epoch"))?;
    // Open the audit sinks before binding: an operator who expects an audit
    // trail must not get a running daemon that silently records nothing.
    let audit = Arc::new(
        AuditLog::open(&config.audit)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot open audit log: {e}")))?,
    );
    // `--inherit-path` / `--inherit-env` (#101): a startup record, with the
    // names-and-PATH fingerprint only (the values one stays on the terminal).
    // No variable name is recorded: the patterns stay on the terminal.
    if let Some(inh) = &config.inherit {
        audit.record(&Event {
            outcome: Some(Outcome::Startup),
            detail: Some(format!(
                "{} path_entries={} variables={} fingerprint={}",
                inh.mode.flag(),
                inh.path_entries.len(),
                inh.vars.len(),
                inh.names_fingerprint()
            )),
            ..Default::default()
        });
    }
    let listener = bind_listener(socket_path)?;
    listener.set_nonblocking(true)?;
    crate::executor::raise_fd_limit();

    if config.verbose {
        eprintln!("sudo-proxy listening on {}", socket_path.display());
        eprintln!("mode: {}", config.mode.label());
        if forwarded_agent_socket().is_some() {
            eprintln!("ssh agent forwarding: available");
        }
    }

    let our_uid = unsafe { libc::getuid() };
    let seen_ids = Arc::new(Mutex::new(SeenIds::new(Instant::now)));
    // Eligibility is a runtime-immutable config input (barrier 1). The session
    // grants (barrier 2) start EMPTY and only an interactive `a` can add one —
    // for the requesting `session` only, in memory only, never persisted. They
    // die with the daemon, i.e. with the SSH tunnel for a remote host, so no
    // grant can outlive the daemon (invariant G7).
    // `--inherit-path` / `--inherit-env` exclude `a` (#101): every request
    // on such a daemon with no escalated step inherits, so the startup
    // refuses `--unattended-eligible` with them; this holds it here too.
    let unattended_eligible = config.unattended_eligible && config.inherit.is_none();
    let unattended_grants = Arc::new(UnattendedGrants::default());

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
            Err(e) if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) => {
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
            audit.record(&Event {
                outcome: Some(Outcome::Rejected(Reject::Busy)),
                detail: resp.message.clone(),
                ..Default::default()
            });
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
        let log_json = config.log_json;
        let no_shell = config.no_shell;
        let inherit = config.inherit.clone();
        let unattended_grants = Arc::clone(&unattended_grants);
        let shutdown = Arc::clone(&shutdown);
        let audit = Arc::clone(&audit);
        thread::spawn(move || {
            let _guard = guard;
            handle_connection(
                stream,
                our_uid,
                mode,
                pkexec_only,
                verbose,
                log_json,
                unattended_eligible,
                no_shell,
                inherit,
                unattended_grants,
                prompter,
                sink,
                seen,
                tty,
                shutdown,
                started_epoch,
                &audit,
            );
        });
    }
}

/// For `--log-json`: print just the command portion of a received request — the
/// `plan` (or, for a legacy flat request, the `pipeline`) — pretty-printed
/// (2-space indent, one element per line) to stderr. Serializing the *typed*
/// `Plan` keeps serde's on-wire key order (`op` first, then fields in
/// declaration order) rather than the alphabetical order a `Value` round-trip
/// would impose. Falls back to the whole raw line if the body is not valid JSON.
///
/// This runs *before* validation and writes to the approval terminal, so every
/// byte is passed through [`escape_for_terminal`]: a request must not be able
/// to redraw the prompt with raw escape or bidi sequences.
fn log_plan_json(line: &[u8]) {
    let raw = || escape_for_terminal(String::from_utf8_lossy(line).trim_end());
    let Ok(req) = serde_json::from_slice::<Request>(line) else {
        eprintln!("[json] {}", raw());
        return;
    };
    let (label, pretty) = if let Some(plan) = &req.plan {
        ("plan", serde_json::to_string_pretty(plan))
    } else if !req.pipeline.is_empty() {
        ("pipeline", serde_json::to_string_pretty(&req.pipeline))
    } else {
        eprintln!("[json] (control request — no plan)");
        return;
    };
    match pretty {
        Ok(s) => eprintln!("[json] {label}:\n{}", escape_for_terminal(&s)),
        Err(_) => eprintln!("[json] {}", raw()),
    }
}

/// Make untrusted text safe to print on the approval terminal: every
/// character `protocol::is_dangerous_char` forbids (control, format,
/// separator, default-ignorable; tab is not one) except newline is written as
/// a `\u{…}` escape.
fn escape_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let u = c as u32;
        if c != '\n' && is_dangerous_char(c) {
            out.push_str(&format!("\\u{{{u:x}}}"));
        } else {
            out.push(c);
        }
    }
    out
}

/// `--pkexec` delegates approval to pkexec's dialog only when that dialog
/// shows one escalated argv with no redirection: privileged as a whole, one
/// leaf, no redirects. Everything else takes the TUI prompt and sudo.
///
/// `req_privileged` is the request's raw `privileged` flag, not
/// `effective_privileged()`: a plan escalating only through `run-as` may carry
/// unescalated leaves that pkexec never shows, so it must not delegate.
fn delegate_to_pkexec(
    pkexec_only: bool,
    mode: Mode,
    req_privileged: bool,
    views: &[LeafView],
) -> bool {
    pkexec_only
        && mode == Mode::Local
        && req_privileged
        && matches!(views, [v] if v.redirects.is_empty() && v.privilege != LeafPrivilege::Direct)
}

#[allow(clippy::too_many_arguments)]
fn handle_connection(
    mut stream: UnixStream,
    our_uid: u32,
    mode: Mode,
    pkexec_only: bool,
    verbose: bool,
    log_json: bool,
    unattended_eligible: bool,
    no_shell: bool,
    inherit: Option<Arc<crate::inherit::Inherited>>,
    unattended_grants: Arc<UnattendedGrants>,
    prompter: Arc<dyn Prompter>,
    result_sink: Arc<dyn ResultSink>,
    seen_ids: Arc<Mutex<SeenIds>>,
    tty_lock: Arc<Mutex<()>>,
    shutdown: Arc<AtomicBool>,
    started_epoch: u64,
    audit: &AuditLog,
) {
    // Audit context, filled in as the connection progresses. Every return
    // below goes through `reject` or the final `record`, so each request
    // leaves exactly one audit event (issue #65). The one exception is a peer
    // that closes before sending a byte (e.g. a liveness probe): no request,
    // nothing to record.
    let mut ev = Event::default();
    // The record is written *before* the reply, so the log never lags what a
    // client has been told.
    let reject = |stream: &mut UnixStream, ev: &Event, why: Reject, resp: Response| {
        audit.record(&Event {
            outcome: Some(Outcome::Rejected(why)),
            detail: resp.message.clone(),
            ..ev.clone()
        });
        let _ = write_response(stream, &resp);
    };

    // Defense-in-depth: refuse connections from other UIDs even though the
    // socket file is 0600 inside a 0700 runtime dir.
    // Nothing is written back to a rejected peer.
    match peer_uid(&stream) {
        Ok(uid) if uid == our_uid => ev.peer_uid = Some(uid),
        Ok(uid) => {
            audit.record(&Event {
                peer_uid: Some(uid),
                outcome: Some(Outcome::Rejected(Reject::PeerUid)),
                detail: Some(format!("expected uid {our_uid}")),
                ..Default::default()
            });
            return;
        }
        Err(e) => {
            audit.record(&Event {
                outcome: Some(Outcome::Rejected(Reject::PeerCred)),
                detail: Some(e.to_string()),
                ..Default::default()
            });
            return;
        }
    }

    let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));

    let line = match read_request_line(&mut stream, Instant::now() + HANDSHAKE_DEADLINE) {
        Ok(b) if b.is_empty() => return,
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            let resp = Response::error("", "handshake deadline exceeded");
            reject(&mut stream, &ev, Reject::Handshake, resp);
            return;
        }
        Err(e) => {
            let resp = Response::error("", &format!("read error: {e}"));
            reject(&mut stream, &ev, Reject::Read, resp);
            return;
        }
    };

    // JSON logging (debug aid): pretty-print just the command portion of the
    // request, before validation. Gated on its own flag.
    if log_json {
        log_plan_json(&line);
    }

    let req: Request = match serde_json::from_slice(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::error("", &format!("invalid JSON: {e}"));
            reject(&mut stream, &ev, Reject::InvalidJson, resp);
            return;
        }
    };
    // Unvalidated until `validate` succeeds; `audit` escapes and clips them.
    ev.id = req.id.clone();
    ev.session = req.session.clone();
    ev.host = req.host.clone();
    ev.requester = req.requester.clone();

    // Validate before anything privileged can touch the request. `exec_*` and
    // `prompter.prompt` accept only a `PreparedRequest`, which is built only
    // from a `&ValidatedRequest`, so this conversion is the single,
    // type-enforced gate between the wire and dispatch. `req` is
    // shadowed by the validated value; field reads below go through its `Deref`.
    let req_id = req.id.clone();
    let req = match ValidatedRequest::validate(req) {
        Ok(v) => v,
        Err(msg) => {
            let resp = Response::error(&req_id, &msg);
            reject(&mut stream, &ev, Reject::Invalid, resp);
            return;
        }
    };
    ev.privileged = Some(req.effective_privileged());

    // Agent forwarding is unprivileged-only. A privileged child runs under
    // sudo (which env_resets) or pkexec (which we env_clear), so the socket
    // would be silently dropped — but we reject explicitly so a misconfigured
    // caller fails loudly instead of being puzzled by a missing key. A plan
    // that escalates via a `run-as` node counts as privileged here too.
    if req.forward_agent && req.effective_privileged() {
        let resp = Response::error(
            &req.id,
            "forward_agent is only allowed for unprivileged commands",
        );
        reject(&mut stream, &ev, Reject::ForwardAgent, resp);
        return;
    }

    // Freshness is checked at handler entry, NOT after the TTY lock — a
    // request must not age past MAX_REQUEST_AGE just because it queued
    // behind another user's prompt.
    if let Err(msg) = check_freshness(&req) {
        let resp = Response::error(&req.id, &msg);
        reject(&mut stream, &ev, Reject::Time, resp);
        return;
    }

    let mut env = match sanitize_env(&req.env) {
        Ok(e) => e,
        Err(msg) => {
            let resp = Response::error(&req.id, &msg);
            reject(&mut stream, &ev, Reject::Env, resp);
            return;
        }
    };
    // Whether this request runs with the daemon environment (#101), decided
    // once, here, from the same predicate as every other "has an escalated
    // step" decision: a request any of whose steps runs as root or as another
    // user (`privileged`, or a `run-as` anywhere) never does, none of its
    // steps included. The one decision is passed to the compilation and so
    // to the prompt.
    let inherit = inherit.filter(|_| !req.effective_privileged());

    // Command-mode SSH skips PAM session, so the daemon (and every
    // env_clear()'d child) starts with no HOME/USER/LOGNAME/PATH.
    // Inject defaults from /etc/passwd so opam/git/ssh stop silently
    // misbehaving — see issue #23. An inheriting request gets them at spawn
    // instead, under the inherited layer.
    if inherit.is_none() {
        crate::executor::apply_login_env_defaults(&mut env);
    }

    // Atomic check-and-insert: closes the TOCTOU window between
    // contains() and insert() that exists when two threads race the
    // same request id.
    {
        let mut ids = lock_recover(&seen_ids);
        if !ids.try_insert(req.id.clone()) {
            drop(ids);
            let resp = Response::error(&req.id, &format!("duplicate request id: {}", req.id));
            reject(&mut stream, &ev, Reject::DuplicateId, resp);
            return;
        }
    }

    // Control actions, dispatched only after every gate above (peer uid,
    // validation, freshness, replay). Replay protection is per instance; a
    // stop additionally must not predate this instance (issue #63), so a
    // captured stop can be replayed neither here nor against a restart.
    match req.action {
        crate::protocol::Action::Ping => {
            if verbose {
                let client_ver = if req.version.is_empty() {
                    "unknown"
                } else {
                    req.version.as_str()
                };
                eprintln!(
                    "[{}] ping from {} (client {client_ver})",
                    req.id, req.session
                );
            }
            let mut resp = Response::ok(&req.id, vec![], b"");
            resp.message = Some("pong".to_string());
            ev.outcome = Some(Outcome::Ping);
            audit.record(&ev);
            let _ = write_response(&mut stream, &resp);
            return;
        }
        crate::protocol::Action::Stop => {
            // `time` already parsed in `check_freshness`; re-parse is total.
            let gate = parse_epoch(&req.time)
                .ok_or_else(|| "malformed time field".to_string())
                .and_then(|t| check_not_before_start(t, started_epoch));
            if let Err(msg) = gate {
                let resp = Response::error(&req.id, &msg);
                reject(&mut stream, &ev, Reject::StopBeforeStart, resp);
                return;
            }
            // No approval prompt (by design): a same-UID peer can already
            // SIGTERM the daemon, so the gate would add friction without
            // adding a security boundary. The TTY notice keeps the human
            // informed; try_lock so a pending prompt can't delay shutdown.
            if let Ok(_g) = tty_lock.try_lock() {
                let _ = tui::display_notice(&format!("sudo-proxy stopped by {}", req.session));
            }
            // Reply before flipping the flag so the client reliably reads
            // the Ok response before the process exits.
            let resp = Response::ok(&req.id, vec![], b"");
            ev.outcome = Some(Outcome::Stop);
            audit.record(&ev);
            let _ = write_response(&mut stream, &resp);
            shutdown.store(true, Ordering::Relaxed);
            return;
        }
        crate::protocol::Action::Exec => {}
    }

    // Compile the plan once, resolving and pinning every program it runs
    // (issue #105). The `no_shell` check, the pkexec decision, the prompt and
    // the executor all read this one value; nothing below compiles the plan
    // or looks a program up again. A structurally-invalid plan (e.g. redirect
    // of a composite, a disallowed setenv) is rejected here, before
    // prompting: the human should never be asked to approve something the
    // executor cannot run.
    let mut prepared = match crate::executor::prepare_with(&req, &env, inherit) {
        Ok(p) => p,
        Err(msg) => {
            let resp = Response::error(&req.id, &format!("invalid plan: {msg}"));
            reject(&mut stream, &ev, Reject::InvalidPlan, resp);
            return;
        }
    };
    let views = prepared.views();
    if prepared.inherit().is_some() {
        ev.inherited = true;
        ev.programs = audit_programs(views);
    }

    // Strict no-shell policy: reject any opaque stage (a `Shell` node, or a
    // shell, inline-code interpreter or runner, directly or behind a wrapper)
    // before prompting and before the unattended grant or `--pkexec` paths. It
    // reads the same opacity, and the same reason text, the prompt renders, so
    // what the prompt would flag is exactly what is refused.
    if let Some(msg) = no_shell_violation(no_shell, views) {
        reject(
            &mut stream,
            &ev,
            Reject::NoShell,
            Response::error(&req.id, &msg),
        );
        return;
    }

    let effective_privileged = req.effective_privileged();
    ev.command = Some(crate::tui::command_summary(&req));

    if verbose {
        let priv_label = if effective_privileged {
            "privileged"
        } else {
            "unprivileged"
        };
        let cmd_display = crate::tui::command_summary(&req);
        let client_ver = if req.version.is_empty() {
            "unknown"
        } else {
            req.version.as_str()
        };
        eprintln!(
            "[{}] [{}] [client {}]{} {}",
            req.id,
            priv_label,
            client_ver,
            requester_tag(&req),
            cmd_display
        );
    }

    // --pkexec hands approval to pkexec's own dialog, which shows a single
    // escalated argv (as `env -C DIR -- BIN args`) and no redirection. So it
    // delegates only a request that is `privileged: true`, compiles to exactly
    // one leaf, and has no redirection on it (the daemon opens redirected
    // files itself; the dialog never names them). Everything else — a
    // multi-step plan, a redirected step, or a plan privileged only through
    // `run-as` — takes the TUI prompt and runs through sudo. The predicate
    // reads the same `views` the prompt renders.
    let use_pkexec = delegate_to_pkexec(pkexec_only, mode, req.privileged, views);

    let (resp, outcome) = if effective_privileged {
        if use_pkexec {
            // --pkexec: pkexec itself handles auth and approval; no TTY lock.
            (exec_pkexec(&prepared, &tty_lock), Outcome::Pkexec)
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
                fresh_prompt(
                    &mut prepared,
                    &env,
                    no_shell,
                    &*prompter,
                    unattended_eligible,
                )
            };
            let prompt_result = match prompt_result {
                Ok(r) => r,
                Err((why, msg)) => {
                    reject(&mut stream, &ev, why, Response::error(&req.id, &msg));
                    return;
                }
            };
            match prompt_result {
                Ok(tui::PromptResult::Approved) => {
                    (exec_sudo(&prepared, &tty_lock), Outcome::Approved)
                }
                // The TUI never emits ApprovedAlways for privileged
                // requests; treat defensively as denial if it ever
                // appears here so no policy can pre-grant root.
                Ok(tui::PromptResult::ApprovedAlways) | Ok(tui::PromptResult::Denied) => {
                    (Response::denied(&req.id), Outcome::Denied)
                }
                Ok(tui::PromptResult::Timeout) => (Response::timeout(&req.id), Outcome::Timeout),
                Err(e) => {
                    log_prompt_io_error(verbose, &req.id, &e);
                    (
                        Response::error(&req.id, &format!("prompt error: {e}")),
                        Outcome::PromptError,
                    )
                }
            }
        }
    } else if unattended_grants.is_granted(&req.session) {
        // This request's session holds a grant: this daemon is eligible AND a
        // human pressed `a` on an earlier request from the same `session`. Run
        // unattended. Other sessions are unaffected (issue #8). The audit
        // record (written below, unconditionally, with session and requester)
        // is the reliable record of what ran in this no-prompt window, and
        // unlike the TTY banner it never depends on the tty_lock, so an
        // unprivileged command is never blocked behind an in-flight privileged
        // prompt. The TTY banner stays best-effort (try_lock) for on-screen
        // visibility. The grant lives only in memory and dies with the
        // daemon/tunnel; it is never persisted.
        if let Ok(_g) = tty_lock.try_lock() {
            let _ = tui::display_banner(&req);
        }
        (exec_direct(&prepared), Outcome::Unattended)
    } else {
        // Default unprivileged path: prompt every command. `a` is offered only
        // when eligible; on an eligible daemon an `a` press approves this
        // command AND grants this request's `session` in memory. When not eligible,
        // `a` degrades to approve-once and grants nothing.
        let prompt_result = {
            let _g = lock_recover(&tty_lock);
            fresh_prompt(
                &mut prepared,
                &env,
                no_shell,
                &*prompter,
                unattended_eligible,
            )
        };
        let prompt_result = match prompt_result {
            Ok(r) => r,
            Err((why, msg)) => {
                reject(&mut stream, &ev, why, Response::error(&req.id, &msg));
                return;
            }
        };
        match prompt_result {
            Ok(tui::PromptResult::Approved) => (exec_direct(&prepared), Outcome::Approved),
            Ok(tui::PromptResult::ApprovedAlways) => {
                // Grant the session only when eligible — never persisted, no
                // hosts.json write. Barrier 1 (eligibility) gates barrier 2.
                // When not eligible, `a` degrades to approve-once.
                let outcome = if unattended_eligible {
                    unattended_grants.grant(&req.session);
                    Outcome::ApprovedSession
                } else {
                    Outcome::Approved
                };
                (exec_direct(&prepared), outcome)
            }
            Ok(tui::PromptResult::Denied) => (Response::denied(&req.id), Outcome::Denied),
            Ok(tui::PromptResult::Timeout) => (Response::timeout(&req.id), Outcome::Timeout),
            Err(e) => {
                log_prompt_io_error(verbose, &req.id, &e);
                (
                    Response::error(&req.id, &format!("prompt error: {e}")),
                    Outcome::PromptError,
                )
            }
        }
    };

    // Echo result on the TTY. The privileged path takes the lock blocking
    // because it is already serialized with the prompt anyway. The
    // unprivileged path uses try_lock so a still-pending privileged prompt
    // never delays an unprivileged command's completion. Skip pkexec
    // because pkexec has its own dialog.
    if !use_pkexec {
        if effective_privileged {
            let _g = lock_recover(&tty_lock);
            let _ = result_sink.display(&resp);
        } else if let Ok(_g) = tty_lock.try_lock() {
            let _ = result_sink.display(&resp);
        }
    }

    ev.outcome = Some(outcome);
    audit.record(&ev.with_response(&resp));

    let _ = write_response(&mut stream, &resp);
}

/// Each step's programs as resolved and pinned, for the audit record of a
/// request that runs with the daemon environment (#101): `path`, or
/// `path -> canonical` when they differ, plus ` (user-writable)`.
fn audit_programs(views: &[LeafView]) -> Vec<String> {
    views
        .iter()
        .flat_map(|v| v.programs.iter())
        .filter_map(|p| p.resolved.as_ref())
        .map(|r| {
            let path = clip_middle(&r.path.display().to_string(), AUDIT_PATH_CHARS);
            let mut s = match r.canonical() {
                Some(c) if c != r.path => {
                    format!(
                        "{path} -> {}",
                        clip_middle(&c.display().to_string(), AUDIT_PATH_CHARS)
                    )
                }
                _ => path,
            };
            if r.user_writable {
                s.push_str(" (user-writable)");
            }
            s
        })
        .collect()
}

/// Each path in an audit `programs` entry is kept to this many chars (plus
/// the clip marker), so `path -> target (user-writable)` fits the audit log's
/// 256-char field bound and the marker is never the part cut.
const AUDIT_PATH_CHARS: usize = 90;

/// Clip `s` to `max` chars in the middle, keeping its start and its end (the
/// program's name), with an explicit marker between them.
fn clip_middle(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let tail = max / 2;
    let head = max - tail;
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(n - tail).collect();
    format!("{start}…[{} more chars hidden]…{end}", n - head - tail)
}

/// The strict `no_shell` policy's refusal, if any stage is opaque (a `Shell`
/// node, or a shell, inline-code interpreter or runner, directly or behind a
/// wrapper). It reads the same opacity, and the same reason text, the prompt
/// renders, so what the prompt would flag is exactly what is refused.
fn no_shell_violation(no_shell: bool, views: &[LeafView]) -> Option<String> {
    if !no_shell {
        return None;
    }
    let (v, o) = views
        .iter()
        .find_map(|v| v.opaque_reason.as_ref().map(|o| (v, o)))?;
    let prog = v.programs.get(o.at);
    let name = prog.map(|p| p.name.as_str()).unwrap_or("");
    let via = prog
        .and_then(|p| p.via.as_deref())
        .map(|w| format!(" via {w}"))
        .unwrap_or_default();
    Some(format!(
        "shell escape hatch rejected by policy (no_shell): stage {} runs {name}{via}: \
         opaque — {}; express it with structured ops \
         (run/seq/alt/pipe/redirect/setenv/chdir/run-as)",
        v.stage_id, o.reason
    ))
}

/// Prompt for `prepared`, called with the TTY lock held. A request may have
/// queued for that lock behind another prompt or an escalated run that
/// replaced one of its programs (an upgrade). If a pin no longer holds, the
/// plan is compiled again first, so the prompt shows the files there now
/// rather than an approval that would only be refused at spawn (issue
/// #105), and the `no_shell` policy is applied to the new resolution.
fn fresh_prompt(
    prepared: &mut crate::executor::PreparedRequest<'_>,
    env: &std::collections::HashMap<String, String>,
    no_shell: bool,
    prompter: &dyn Prompter,
    eligible: bool,
) -> Result<io::Result<tui::PromptResult>, (Reject, String)> {
    if !prepared.pins_current() {
        let inherit = prepared.inherit().cloned();
        *prepared = crate::executor::prepare_with(prepared.request(), env, inherit)
            .map_err(|e| (Reject::InvalidPlan, format!("invalid plan: {e}")))?;
        if let Some(msg) = no_shell_violation(no_shell, prepared.views()) {
            return Err((Reject::NoShell, msg));
        }
    }
    Ok(prompter.prompt(prepared, eligible, PROMPT_TIMEOUT))
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
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
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

    /// A long path in an audit `programs` entry is clipped in the middle, so
    /// the program's name and the `(user-writable)` marker survive (#101).
    #[test]
    fn audit_program_paths_are_clipped_in_the_middle() {
        let long = format!("/tmp/{}/bin/devtool", "d".repeat(300));
        let out = clip_middle(&long, AUDIT_PATH_CHARS);
        assert!(
            out.starts_with("/tmp/ddd") && out.ends_with("/bin/devtool"),
            "{out}"
        );
        assert!(out.contains("more chars hidden"), "{out}");
        // The worst case: paths of PATH_MAX (4095 bytes, so a 4-digit hidden
        // count) on both sides of `->`, plus the marker.
        let max = format!("/{}", "d".repeat(4094));
        let out = clip_middle(&max, AUDIT_PATH_CHARS);
        assert!(out.contains("[4005 more chars hidden]"), "{out}");
        let entry = format!("{out} -> {out} (user-writable)");
        assert!(entry.chars().count() <= 256, "{}", entry.chars().count());
        assert_eq!(clip_middle("/usr/bin/x", AUDIT_PATH_CHARS), "/usr/bin/x");
    }
    use crate::prop::Rng;
    use std::sync::{Arc, Mutex};

    fn leaf_view(privilege: LeafPrivilege, redirects: &str) -> LeafView {
        LeafView {
            stage_id: 0,
            argv: vec!["id".into()],
            privilege,
            resolved_bin: None,
            opaque: false,
            opaque_reason: None,
            programs: vec![],
            redirects: redirects.into(),
            in_pipe: false,
        }
    }

    #[test]
    fn delegate_to_pkexec_only_for_a_single_plain_leaf() {
        let root = || leaf_view(LeafPrivilege::Root, "");
        let nobody = || leaf_view(LeafPrivilege::User("nobody".into()), "");
        let d = |views: &[LeafView]| delegate_to_pkexec(true, Mode::Local, true, views);

        // The only shape that delegates: one escalated leaf, no redirection.
        assert!(d(&[root()]));
        assert!(d(&[nobody()]));

        // More or fewer than one leaf.
        assert!(!d(&[root(), root()]));
        assert!(!d(&[root(), nobody()]));
        assert!(!d(&[]));

        // A redirected single leaf: the dialog would not show the file.
        assert!(!d(&[leaf_view(LeafPrivilege::Root, "> /tmp/x")]));
        assert!(!d(&[leaf_view(LeafPrivilege::Root, "< /etc/hosts")]));
        assert!(!d(&[leaf_view(LeafPrivilege::Root, "2>&1")]));

        // Defensive: an unescalated leaf never delegates.
        assert!(!d(&[leaf_view(LeafPrivilege::Direct, "")]));

        // The other conjuncts.
        assert!(!delegate_to_pkexec(false, Mode::Local, true, &[root()]));
        assert!(!delegate_to_pkexec(true, Mode::Remote, true, &[root()]));
        // privileged: false (e.g. a run-as-only plan) never delegates.
        assert!(!delegate_to_pkexec(true, Mode::Local, false, &[nobody()]));
    }

    /// `--log-json` prints request bytes before validation, on the approval
    /// terminal: escape, C1, DEL and bidi characters must come out inert.
    #[test]
    fn escape_for_terminal_neutralises_control_and_bidi() {
        let s = "a\x1b[2J\u{9b}31m\u{7f}\u{202e}b\rc\n\td";
        let e = escape_for_terminal(s);
        assert_eq!(e, "a\\u{1b}[2J\\u{9b}31m\\u{7f}\\u{202e}b\\u{d}c\n\td");
        assert!(!e
            .chars()
            .any(|c| crate::protocol::has_dangerous_chars(&c.to_string()) && c != '\n'));
    }

    /// Issue #63: a stop dated before the daemon started is rejected; one
    /// dated at or after the start second is accepted.
    #[test]
    fn check_not_before_start_boundaries() {
        let start = 1_800_000_000;
        assert!(check_not_before_start(start, start).is_ok(), "same second");
        assert!(check_not_before_start(start + 1, start).is_ok(), "after");
        let err = check_not_before_start(start - 1, start).unwrap_err();
        assert!(err.contains("predates"), "{err}");
        assert!(check_not_before_start(0, start).is_err(), "far past");
    }

    #[test]
    fn parse_epoch_round_trips_epoch_to_iso() {
        for secs in [0u64, 951_782_400, 1_800_000_000, 4_102_444_799] {
            let iso = crate::datetime::epoch_to_iso(secs);
            assert_eq!(parse_epoch(&iso), Some(secs), "{iso}");
        }
        assert_eq!(parse_epoch("not-a-time"), None);
    }

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
    fn is_local_host_classifies_self_and_loopback() {
        // Hermetic: own hostname is injected, never read from /etc/hostname.
        let own = "box.local";
        // Local: canonical name, whole 127/8, IPv6 loopback, user@ and trailing
        // dot forms, case-insensitivity, own hostname (full + bare first label).
        for local in [
            "localhost",
            "LOCALHOST",
            "LocalHost",
            "localhost.",
            "127.0.0.1",
            "127.0.0.5",
            "127.1.2.3",
            "user@127.0.0.1",
            "::1",
            "user@::1",
            "box.local",
            "BOX.LOCAL",
            "box",
        ] {
            assert!(
                is_local_host(local, own),
                "is_local_host({local:?}) should be local"
            );
        }
        // Remote: suffix/prefix/substring dodges must NOT match, and genuine
        // remotes stay remote. An unrelated FQDN sharing our first label is
        // remote (only a bare label or the full FQDN counts as self).
        for remote in [
            "127.0.0.1.evil.com",
            "notlocalhost",
            "localhost.evil.com",
            "example.com",
            "10.0.0.4",
            "128.0.0.1",
            "::2",
            "box.example.com",
            "buildbox",
        ] {
            assert!(
                !is_local_host(remote, own),
                "is_local_host({remote:?}) should be remote"
            );
        }
        // An unreadable /etc/hostname (empty own) matches nothing by name, but
        // loopback literals still resolve local.
        assert!(is_local_host("127.0.0.1", ""));
        assert!(!is_local_host("box", ""));
    }

    #[test]
    fn validate_host_rejects_shell_metacharacters() {
        // Each of these would, if `host` were ever interpolated into an
        // `sh -c` string, allow the caller to break out of the intended
        // command. The strict allowlist must reject every one.
        for bad in [
            "a;b", "a|b", "a&b", "a$b", "a`b", "a(b", "a)b", "a<b", "a>b", "a*b", "a?b", "a{b",
            "a}b", "a[b", "a]b", "a'b", "a\"b", "a\\b", "a=b", "a,b", "a~b", "a!b", "a#b", "a%b",
            "a^b", "a+b", "a/b",
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
        assert!(
            parse_age("2026-04-30").is_none(),
            "missing T-separated time"
        );
        assert!(parse_age("2026-04-30T12:00").is_none(), "incomplete time");
        assert!(
            parse_age("2026-13-01T00:00:00Z").is_none(),
            "month out of range"
        );
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
        assert!(
            parse_age("2024-01-01T00:00:00").is_some(),
            "trailing Z optional"
        );
    }

    #[test]
    fn far_future_timestamp_is_rejected_not_clamped() {
        // GHSA-h6r4-gh2r-qr98: a far-future timestamp used to clamp to age 0
        // and pass freshness forever. It now parses to a negative age, and
        // the freshness window rejects it.
        let age = parse_age("3000-01-01T00:00:00Z").expect("valid ts");
        assert!(
            age < 0,
            "future timestamp must have a negative age, got {age}"
        );
        let err = check_age(age).unwrap_err();
        assert!(err.contains("in the future"), "{err}");
    }

    #[test]
    fn check_age_window_boundaries() {
        let skew = MAX_FUTURE_SKEW.as_secs() as i64;
        let max = MAX_REQUEST_AGE.as_secs() as i64;
        assert!(check_age(0).is_ok());
        assert!(check_age(-skew).is_ok(), "exactly at the skew bound");
        assert!(check_age(-skew - 1).is_err(), "just past the skew bound");
        assert!(check_age(max).is_ok(), "exactly at the age bound");
        assert!(check_age(max + 1).is_err(), "just past the age bound");
        assert!(check_age(i64::MIN).is_err());
        assert!(check_age(i64::MAX).is_err());
    }

    // === Property: any id that can pass freshness is still remembered ======
    //
    // Spec clause (C3, GHSA-h6r4-gh2r-qr98): if a request with a fixed `time`
    // is accepted at instant `t0` (its id inserted into `SeenIds`), then at
    // every later instant `t0 + d` at which the *same bytes* would pass the
    // freshness check again, the id is still in the set, so the replay is
    // rejected as a duplicate. Before the fix this failed for any request
    // dated more than REPLAY_RETENTION into the future.

    /// The predicate, for a request whose signed age at acceptance was
    /// `age0` (seconds) and a replay `d` seconds later.
    fn fresh_replay_is_still_remembered(age0: i64, d: u64) -> bool {
        if check_age(age0).is_err() {
            return true; // never accepted: vacuous
        }
        let Some(age_then) = age0.checked_add(d as i64) else {
            return true;
        };
        if check_age(age_then).is_err() {
            return true; // replay rejected by freshness: fine
        }
        let (clock, now) = fake_clock();
        let mut ids = SeenIds::new(now);
        assert!(ids.try_insert("r".into()));
        advance(&clock, Duration::from_secs(d));
        // A concurrent insert triggers eviction exactly as a replay would.
        let _ = ids.try_insert("other".into());
        ids.contains("r")
    }

    #[test]
    fn prop_fresh_replay_is_still_remembered() {
        let mut rng = Rng::new(0x5EE1D5_C0FFEE);
        let span = (MAX_REQUEST_AGE + MAX_FUTURE_SKEW + REPLAY_RETENTION).as_secs() as i64;
        for _ in 0..20000 {
            // Acceptance ages from far future to just past stale, replay
            // delays over the whole retention horizon and beyond.
            let age0 = (rng.next_u64() % (4 * span as u64)) as i64 - 3 * span;
            let d = rng.next_u64() % (2 * span as u64);
            assert!(
                fresh_replay_is_still_remembered(age0, d),
                "replay of a request accepted at age {age0}s passes freshness \
                 {d}s later but its id was evicted"
            );
        }
        // The advisory's witness: dated one hour ahead, replayed after 125 s.
        assert!(fresh_replay_is_still_remembered(-3600, 125));
        // Worst case the window allows: accepted at the skew bound, replayed
        // at the age bound.
        let worst = (MAX_FUTURE_SKEW + MAX_REQUEST_AGE).as_secs();
        assert!(fresh_replay_is_still_remembered(
            -(MAX_FUTURE_SKEW.as_secs() as i64),
            worst
        ));
    }

    // === Property: parse_age is total and panic-free ====================
    //
    // Spec clause (Rung 2; proof obligation for Rung 3 Kani over the
    // attacker-controlled parsers): `parse_age` handles attacker-controlled
    // `time` strings (the freshness / anti-replay gate). It must return for
    // every input — never panic — and never wrap into a bogus age (issues
    // #11/#14 were exactly an integer underflow on out-of-range components).
    // The `checked_*` arithmetic enforces no-wrap by yielding `None`.

    /// The predicate: `parse_age(s)` returns without panicking for any input.
    /// (No-wrap is structural — every arithmetic step is `checked_*`.)
    fn parse_age_total_and_panic_free(s: &str) {
        let _ = parse_age(s);
    }

    // Driver: garbage and near-valid timestamps from the same alphabet the
    // freshness gate sees on the wire, plus structured extreme components.
    #[test]
    fn prop_parse_age_total_and_panic_free() {
        let alphabet: &[u8] = b"0123456789-:TZ +.eE/\\\0\tx";
        let mut rng = Rng::new(0xDEADBEEFCAFEF00D);
        for _ in 0..20000 {
            parse_age_total_and_panic_free(&rng.string(alphabet, 39));
        }

        // Structured near-valid timestamps with extreme components.
        for &(y, mo, d, h, mi, se) in &[
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
            (1969, 12, 31, 23, 59, 59),
            (u64::MAX, 12, 31, 23, 59, 60),
            (1970, 13, 32, 24, 60, 61),
            (1970, 1, 1, 0, 0, 0),
            (9_999_999_999, 1, 1, 0, 0, 0),
        ] {
            let ts = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z");
            parse_age_total_and_panic_free(&ts);
        }
    }

    // === Property: freshness is monotone ================================
    //
    // Spec clause (Rung 2; proof obligation for Rung 3 Kani): making a
    // request's timestamp *earlier* must never make it look *fresher*. An
    // integer-wrap bug violates this by mapping an ancient timestamp to a tiny
    // age; monotonicity is the general invariant the targeted stale-not-fresh
    // case (year 2000) is one witness of.

    /// The predicate, given `earlier <= later` (epoch seconds): the age of the
    /// earlier timestamp is never below the age of the later one. Both call
    /// `parse_age` micro-seconds apart, so the wall-clock `now` they read
    /// differs by at most one whole second; a `gap >= 1s` between the two
    /// timestamps dominates that drift, keeping the comparison exact.
    fn freshness_is_monotone(earlier: u64, later: u64) -> bool {
        debug_assert!(earlier <= later);
        match (
            parse_age(&crate::datetime::epoch_to_iso(earlier)),
            parse_age(&crate::datetime::epoch_to_iso(later)),
        ) {
            // epoch_to_iso emits well-formed timestamps, so both must parse.
            (Some(age_earlier), Some(age_later)) => age_earlier >= age_later,
            _ => false,
        }
    }

    #[test]
    fn prop_freshness_is_monotone() {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rng = Rng::new(0xF00DF00DF00DF00D);
        for _ in 0..5000 {
            // Span stale (deep past) through future (negative age); the
            // earlier endpoint ranges from 2001 up to ~now, the gap is always
            // at least one second so the now-drift between the two reads of
            // the clock cannot invert the ordering.
            let earlier = 1_000_000_000 + (rng.next_u64() % (now - 1_000_000_000 + 50_000_000));
            let gap = 1 + (rng.next_u64() % 50_000_000);
            assert!(
                freshness_is_monotone(earlier, earlier + gap),
                "freshness non-monotone: earlier={earlier} later={}",
                earlier + gap
            );
        }

        // Witness of the clause: a clearly-stale timestamp is outside the
        // freshness window — integer-wrap must not make it look fresh.
        let stale = parse_age("2000-01-01T00:00:00Z").expect("valid ts");
        assert!(
            stale > MAX_REQUEST_AGE.as_secs() as i64,
            "a year-2000 timestamp must be classified stale, got {stale:?}"
        );
    }

    // === Property: an accepted request has no dangerous displayed field ==
    //
    // Spec clause (Rung 2): if `ValidatedRequest::validate` accepts a request,
    // then every request-derived string later rendered on the approval prompt —
    // each argv element, every env key and value, and reason/session/host/
    // version/id — is free of the control/bidi characters `has_dangerous_chars`
    // forbids. A field carrying raw ANSI/escape/newline bytes could redraw the
    // terminal and misrepresent the command being approved.
    //
    // Rung 3 strengthens this from a sampled property into a structural one:
    // `validate` is now the *only* constructor of `ValidatedRequest`, and
    // `exec_*`/`prompt` accept only that type, so "a request reaching dispatch
    // skipped validation" is a compile error.
    //
    // Residual (proven vs tested). The end-to-end guarantee decomposes into:
    //   (1) the typestate proves `validate` is *invoked* before dispatch
    //       [compile-time];
    //   (2) Kani proves `has_dangerous_chars` is panic-free and matches its
    //       range spec [`src/proofs.rs`];
    //   (3) that `validate` applies (2) to *every* displayed field (argv, env
    //       keys/values, reason/session/host/version/id) and rejects empty
    //       pipelines — covered ONLY by this property test, not by proof.
    // So if a future edit drops a field from `validate`'s loop, neither the
    // typestate nor Kani catches it — only this test does (drop one field's
    // check and it turns red). Discharging (3) formally is a Rung 5 Creusot
    // target (a contract on `validate` enumerating the fields).

    /// The predicate. Vacuously true for rejected requests — the clause
    /// constrains only those that pass the gate.
    fn accepted_request_has_no_dangerous_displayed_field(req: &Request) -> bool {
        use crate::protocol::has_dangerous_chars;
        if ValidatedRequest::validate(req.clone()).is_err() {
            return true;
        }
        let argv_clean = req
            .pipeline
            .iter()
            .flatten()
            .all(|a| !has_dangerous_chars(a));
        let env_clean = req
            .env
            .iter()
            .all(|(k, v)| !has_dangerous_chars(k) && !has_dangerous_chars(v));
        let fields_clean = [
            &req.reason,
            &req.session,
            &req.host,
            &req.version,
            &req.id,
            &req.requester,
        ]
        .iter()
        .all(|f| !has_dangerous_chars(f));
        argv_clean && env_clean && fields_clean
    }

    /// Build a string of length `0..=max_len` from a benign `char` alphabet —
    /// every one of these passes `has_dangerous_chars`. It includes printable
    /// non-ASCII (issue #86), so the accept direction covers multibyte text.
    /// Used for argv, reason, host, session, version, id, requester and env
    /// *values*; env keys come from `rand_env_key`.
    fn rand_chars(rng: &mut Rng, max_len: usize) -> String {
        const BENIGN: &[char] = &[
            'a', 'b', 'c', '0', '1', ' ', '/', '-', '.', '_', '=', ':', ',', 'é', '漢', '→',
        ];
        let len = rng.below(max_len + 1);
        (0..len).map(|_| BENIGN[rng.below(BENIGN.len())]).collect()
    }

    /// A valid env key (`[a-z_][a-z0-9_]{0,4}`), so `is_valid_env_name` never
    /// rejects the request before the property under test is reached.
    fn rand_env_key(rng: &mut Rng) -> String {
        const FIRST: &[char] = &['a', 'b', 'c', '_'];
        const REST: &[char] = &['a', 'b', 'c', '0', '1', '_'];
        let mut key = String::from(FIRST[rng.below(FIRST.len())]);
        for _ in 0..rng.below(5) {
            key.push(REST[rng.below(REST.len())]);
        }
        key
    }

    // A sample of every danger class `has_dangerous_chars` forbids: C0
    // controls (NUL, ESC, newline, CR), DEL and C1 (NEL, CSI), format
    // characters (soft hyphen, ALM, zero-width, bidi override/isolate, word
    // joiner, BOM, tag), line/paragraph separators, and reserved
    // default-ignorable U+2065 (issue #86).
    const DANGEROUS: &[char] = &[
        '\u{0}',
        '\u{1b}',
        '\n',
        '\r',
        '\u{200b}',
        '\u{202e}',
        '\u{2066}',
        '\u{7f}',
        '\u{85}',
        '\u{9b}',
        '\u{ad}',
        '\u{61c}',
        '\u{2028}',
        '\u{2029}',
        '\u{2060}',
        '\u{2065}',
        '\u{feff}',
        '\u{e0041}',
    ];

    /// Generate a request whose fields are all benign, then with probability
    /// 1/2 splice one dangerous char into one randomly-chosen displayed field.
    /// This guarantees the generator yields both accepted and rejected
    /// requests — so the implication is exercised in both directions, not
    /// vacuously satisfied — while covering every field `validate_request`
    /// guards (argv, env key, env value, and reason/host/session/version/id).
    fn random_request(rng: &mut Rng) -> Request {
        let stages = 1 + rng.below(3);
        let mut pipeline: Vec<Vec<String>> = (0..stages)
            .map(|_| {
                let args = 1 + rng.below(3);
                (0..args).map(|_| rand_chars(rng, 6)).collect()
            })
            .collect();
        let mut env = std::collections::HashMap::new();
        // Always at least one entry so the env branch is reachable.
        for _ in 0..(1 + rng.below(2)) {
            env.insert(rand_env_key(rng), rand_chars(rng, 5));
        }
        let mut req = Request {
            id: rand_chars(rng, 6),
            host: rand_chars(rng, 6),
            session: rand_chars(rng, 6),
            time: crate::datetime::now_iso8601(),
            pipeline: std::mem::take(&mut pipeline),
            plan: None,
            action: crate::protocol::Action::Exec,
            env,
            reason: rand_chars(rng, 8),
            privileged: rng.next_u64() & 1 == 0,
            forward_agent: false,
            version: rand_chars(rng, 5),
            requester: rand_chars(rng, 6),
        };

        if rng.next_u64() & 1 == 0 {
            let danger = DANGEROUS[rng.below(DANGEROUS.len())];
            match rng.below(8) {
                0 => req.reason.push(danger),
                1 => req.host.push(danger),
                2 => req.session.push(danger),
                3 => req.version.push(danger),
                4 => req.id.push(danger),
                5 => req.requester.push(danger),
                6 => req.pipeline[0][0].push(danger),
                _ => {
                    // Corrupt an env value (rebuild the one entry we know exists).
                    let key = req.env.keys().next().cloned().unwrap();
                    let mut val = req.env.remove(&key).unwrap();
                    val.push(danger);
                    req.env.insert(key, val);
                }
            }
        }
        req
    }

    #[test]
    fn prop_accepted_request_has_no_dangerous_displayed_field() {
        let mut rng = Rng::new(0x51ED5EEDC0FFEE11);
        let (mut accepted, mut rejected) = (0u32, 0u32);
        for _ in 0..5000 {
            let req = random_request(&mut rng);
            assert!(
                accepted_request_has_no_dangerous_displayed_field(&req),
                "validate_request accepted a request with a dangerous displayed field: {req:?}"
            );
            if ValidatedRequest::validate(req.clone()).is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        // Both directions exercised: the implication is not vacuous.
        assert!(accepted > 0, "generator never produced an accepted request");
        assert!(rejected > 0, "generator never produced a rejected request");
        // About half the requests are clean by construction; demand a solid
        // share so the accept direction (multibyte text included) is not
        // vacuous.
        assert!(
            accepted >= 2000,
            "too few accepted requests: {accepted} of 5000"
        );
    }
}
