//! Security audit log (issue #65, threat-model B1 "Repudiation").
//!
//! Every terminal outcome of every daemon connection is recorded: approvals,
//! denials, timeouts, unattended runs, and every rejection path (peer UID,
//! malformed or invalid requests, stale `time`, replayed id, …). A record goes
//! to up to three sinks:
//!
//! - **stderr**, always, independent of `-v`: one human-readable line;
//! - an **append-only JSONL file** (`O_APPEND`, mode 0600), on by default;
//! - **syslog** (`LOG_AUTHPRIV`), on by default.
//!
//! What is never recorded: request `env` values, `reason`, and the raw bytes of
//! a request that failed validation. [`Event`] has no field for any of them, so
//! no call site can leak them by accident. The `command` summary is attached
//! only to requests that passed validation.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde::Serialize;

use crate::protocol::{is_dangerous_char, Response, Status};

/// Longest a single untrusted field may be in a record. A request that fails
/// validation can carry up to 1 MiB in `id`/`session`/`host`; the log must not
/// grow by that much per probe.
const MAX_FIELD_CHARS: usize = 256;

/// Where audit records go. `Default` disables both persistent sinks (stderr is
/// always written) — the daemon binary turns them on; tests opt in.
#[derive(Clone, Debug, Default)]
pub struct AuditConfig {
    pub file: Option<PathBuf>,
    pub syslog: bool,
}

/// Default audit file: `$XDG_STATE_HOME/sudo-proxy/audit.jsonl`, falling back
/// to `$HOME/.local/state/sudo-proxy/audit.jsonl`. `None` if neither variable
/// is set to an absolute path.
pub fn default_audit_path() -> Option<PathBuf> {
    let abs = |v: String| {
        let p = PathBuf::from(v);
        p.is_absolute().then_some(p)
    };
    let base = std::env::var("XDG_STATE_HOME")
        .ok()
        .and_then(abs)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .and_then(abs)
                .map(|h| h.join(".local/state"))
        })?;
    Some(base.join("sudo-proxy").join("audit.jsonl"))
}

/// Why a request was turned away before any prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    PeerUid,
    PeerCred,
    Busy,
    Handshake,
    Read,
    InvalidJson,
    Invalid,
    ForwardAgent,
    /// Missing, malformed, too old, or too far in the future.
    Time,
    Env,
    DuplicateId,
    InvalidPlan,
    /// A `stop` dated before this daemon instance started (#63).
    StopBeforeStart,
    /// An opaque stage refused by the `no_shell` policy.
    NoShell,
}

impl Reject {
    fn as_str(self) -> &'static str {
        match self {
            Reject::PeerUid => "peer_uid",
            Reject::PeerCred => "peer_cred",
            Reject::Busy => "busy",
            Reject::Handshake => "handshake_timeout",
            Reject::Read => "read_error",
            Reject::InvalidJson => "invalid_json",
            Reject::Invalid => "invalid_request",
            Reject::ForwardAgent => "forward_agent",
            Reject::Time => "time",
            Reject::Env => "env",
            Reject::DuplicateId => "duplicate_id",
            Reject::InvalidPlan => "invalid_plan",
            Reject::StopBeforeStart => "stop_before_start",
            Reject::NoShell => "no_shell",
        }
    }
}

/// Terminal outcome of one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A human approved this request once.
    Approved,
    /// A human pressed `a`: approved, and the session grant was flipped on.
    ApprovedSession,
    /// Ran without a prompt under an existing session grant.
    Unattended,
    /// Approval delegated to pkexec's own dialog (`--pkexec`).
    Pkexec,
    Denied,
    Timeout,
    Ping,
    Stop,
    /// The daemon started with `--inherit-path` / `--inherit-env` (#101);
    /// `detail` names the flag, counts, and the names-and-`PATH`
    /// fingerprint; never a variable name or value.
    Startup,
    /// The prompt itself failed (I/O error on the terminal).
    PromptError,
    Rejected(Reject),
}

impl Outcome {
    pub fn label(self) -> String {
        match self {
            Outcome::Approved => "approved".into(),
            Outcome::ApprovedSession => "approved_session".into(),
            Outcome::Unattended => "unattended".into(),
            Outcome::Pkexec => "pkexec".into(),
            Outcome::Denied => "denied".into(),
            Outcome::Timeout => "timeout".into(),
            Outcome::Ping => "ping".into(),
            Outcome::Stop => "stop".into(),
            Outcome::Startup => "startup".into(),
            Outcome::PromptError => "prompt_error".into(),
            Outcome::Rejected(r) => format!("rejected:{}", r.as_str()),
        }
    }

    fn is_warning(self) -> bool {
        matches!(self, Outcome::Rejected(_) | Outcome::PromptError)
    }
}

/// One audit event. Fields are filled as far as the connection got: a
/// peer-UID rejection has no id, a validation failure has no command.
#[derive(Clone, Debug, Default)]
pub struct Event {
    pub peer_uid: Option<u32>,
    pub id: String,
    pub session: String,
    /// Self-declared requester ("human", "ai", …); empty when not sent.
    pub requester: String,
    pub host: String,
    pub privileged: Option<bool>,
    /// One-line command summary; set only for validated requests.
    pub command: Option<String>,
    pub outcome: Option<Outcome>,
    /// Rejection / error message (the one already sent to the client).
    pub detail: Option<String>,
    pub status: Option<Status>,
    pub exit_codes: Vec<i32>,
    /// The request ran with the daemon environment (#101). Its variable
    /// names and values are never recorded.
    pub inherited: bool,
    /// For an inheriting request, each step's programs as resolved and
    /// pinned: `path` or `path -> canonical target`.
    pub programs: Vec<String>,
}

impl Event {
    /// Attach the executed response's status and per-stage exit codes.
    pub fn with_response(mut self, resp: &Response) -> Self {
        self.status = Some(resp.status);
        self.exit_codes = resp.stages.iter().map(|s| s.exit_code).collect();
        if self.detail.is_none() && resp.status == Status::Error {
            self.detail = resp.message.clone();
        }
        self
    }
}

#[derive(Serialize)]
struct Record<'a> {
    time: &'a str,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_uid: Option<u32>,
    id: String,
    session: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    requester: String,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(skip_serializing_if = "<[i32]>::is_empty")]
    exit_codes: &'a [i32],
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    inherited: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    programs: Vec<String>,
}

pub struct AuditLog {
    file: Option<Mutex<File>>,
    syslog: bool,
    write_failed: AtomicBool,
}

impl AuditLog {
    /// Open the configured sinks. Creates the file's parent directory 0700 and
    /// the file itself 0600, opened `O_APPEND` so concurrent daemons sharing
    /// it never interleave inside a line.
    pub fn open(cfg: &AuditConfig) -> io::Result<Self> {
        let file = match &cfg.file {
            Some(path) => Some(Mutex::new(open_append(path)?)),
            None => None,
        };
        if cfg.syslog {
            // SAFETY: the ident is a 'static C string, as openlog requires
            // (glibc keeps the pointer).
            unsafe { libc::openlog(c"sudo-proxy".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV) };
        }
        Ok(Self {
            file,
            syslog: cfg.syslog,
            write_failed: AtomicBool::new(false),
        })
    }

    /// stderr only — for tests and callers that want no persistent sink.
    pub fn stderr_only() -> Self {
        Self {
            file: None,
            syslog: false,
            write_failed: AtomicBool::new(false),
        }
    }

    pub fn record(&self, ev: &Event) {
        let time = crate::datetime::now_iso8601();
        let outcome = ev.outcome.unwrap_or(Outcome::PromptError);
        let line = human_line(&time, ev, outcome);
        eprintln!("{line}");

        if let Some(file) = &self.file {
            let rec = Record {
                time: &time,
                outcome: outcome.label(),
                peer_uid: ev.peer_uid,
                // Escaped like the stderr line: operators read this file with
                // `cat`/`tail`, and JSON leaves bidi overrides and C1 controls
                // raw, so a rejected request could otherwise reorder or
                // restyle the terminal that displays it.
                id: safe(&ev.id),
                session: safe(&ev.session),
                requester: safe(&ev.requester),
                host: safe(&ev.host),
                privileged: ev.privileged,
                command: ev.command.as_deref().map(safe),
                detail: ev.detail.as_deref().map(safe),
                status: ev.status,
                exit_codes: &ev.exit_codes,
                inherited: ev.inherited,
                programs: ev.programs.iter().map(|p| safe(p)).collect(),
            };
            if let Ok(mut json) = serde_json::to_string(&rec) {
                json.push('\n');
                let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
                // One write_all of the whole line on an O_APPEND fd.
                if let Err(e) = f.write_all(json.as_bytes()) {
                    if !self.write_failed.swap(true, Ordering::Relaxed) {
                        eprintln!("audit log write failed: {e}");
                    }
                }
            }
        }

        if self.syslog {
            let prio = if outcome.is_warning() {
                libc::LOG_WARNING
            } else {
                libc::LOG_NOTICE
            };
            let msg = syslog_message(&line);
            // SAFETY: constant "%s" format with one valid C string argument,
            // so request-derived text can never act as a format string.
            unsafe { libc::syslog(prio, c"%s".as_ptr(), msg.as_ptr()) };
        }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
    }
    let f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    // A pre-existing file keeps its mode under `create`; tighten it.
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}

/// Truncate to [`MAX_FIELD_CHARS`] characters, marking the cut.
fn clip(s: &str) -> String {
    match s.char_indices().nth(MAX_FIELD_CHARS) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// Clip, then make terminal-safe: newline, tab (a record is one line) and
/// every character `protocol::is_dangerous_char` forbids on the prompt
/// (control, format, separator, default-ignorable) are written as `\u{…}`
/// escapes.
fn safe(s: &str) -> String {
    let mut out = String::new();
    for c in clip(s).chars() {
        let u = c as u32;
        if c == '\t' || c == '\n' || is_dangerous_char(c) {
            out.push_str(&format!("\\u{{{u:x}}}"));
        } else {
            out.push(c);
        }
    }
    out
}

fn human_line(time: &str, ev: &Event, outcome: Outcome) -> String {
    // Startup records have no request id.
    let mut line = if ev.id.is_empty() {
        time.to_string()
    } else {
        format!("{time} [{}]", safe(&ev.id))
    };
    if let Some(uid) = ev.peer_uid {
        line.push_str(&format!(" uid={uid}"));
    }
    if !ev.session.is_empty() {
        line.push_str(&format!(" session={}", safe(&ev.session)));
    }
    if !ev.requester.is_empty() {
        line.push_str(&format!(" requester={}", safe(&ev.requester)));
    }
    if !ev.host.is_empty() {
        line.push_str(&format!(" host={}", safe(&ev.host)));
    }
    if let Some(p) = ev.privileged {
        line.push_str(if p { " privileged" } else { " unprivileged" });
    }
    if ev.inherited {
        line.push_str(" inherited-env");
    }
    line.push(' ');
    line.push_str(&outcome.label());
    if !ev.exit_codes.is_empty() {
        let codes: Vec<String> = ev.exit_codes.iter().map(i32::to_string).collect();
        line.push_str(&format!(" exit={}", codes.join(",")));
    }
    if let Some(d) = &ev.detail {
        line.push_str(&format!(": {}", safe(d)));
    }
    if let Some(c) = &ev.command {
        line.push_str(&format!(" -- {}", safe(c)));
    }
    line
}

/// `human_line` is already escaped, so it has no NUL; strip defensively anyway.
fn syslog_message(line: &str) -> CString {
    CString::new(line.replace('\0', "\\u{0}")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_line_escapes_and_clips_untrusted_fields() {
        let ev = Event {
            id: "a\x1b[2J\u{202e}b\nc".into(),
            session: "s".repeat(1000),
            outcome: Some(Outcome::Rejected(Reject::Invalid)),
            ..Default::default()
        };
        let line = human_line("T", &ev, ev.outcome.unwrap());
        assert!(line.contains("a\\u{1b}[2J\\u{202e}b\\u{a}c"));
        assert!(!line.contains('\x1b') && !line.contains('\n'));
        assert!(line.contains(&format!("session={}…", "s".repeat(MAX_FIELD_CHARS))));
        assert!(line.ends_with("rejected:invalid_request"));
    }

    #[test]
    fn syslog_message_has_no_nul() {
        let m = syslog_message("a\0b");
        assert_eq!(m.to_str().unwrap(), "a\\u{0}b");
    }

    #[test]
    fn clip_is_char_boundary_safe() {
        let s = "é".repeat(MAX_FIELD_CHARS + 5);
        let c = clip(&s);
        assert_eq!(c.chars().count(), MAX_FIELD_CHARS + 1);
    }

    #[test]
    fn file_is_created_0600_in_0700_dir() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("state/sudo-proxy/audit.jsonl");
        let log = AuditLog::open(&AuditConfig {
            file: Some(path.clone()),
            syslog: false,
        })
        .unwrap();
        log.record(&Event {
            id: "x".into(),
            outcome: Some(Outcome::Denied),
            ..Default::default()
        });
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let v: serde_json::Value =
            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(v["outcome"], "denied");
        assert_eq!(v["id"], "x");
    }

    #[test]
    fn file_record_escapes_bidi_and_controls() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("audit.jsonl");
        let log = AuditLog::open(&AuditConfig {
            file: Some(path.clone()),
            syslog: false,
        })
        .unwrap();
        log.record(&Event {
            id: "i\u{9b}d".into(),
            session: "evil\u{202e}session\x1b[31m".into(),
            outcome: Some(Outcome::Rejected(Reject::Invalid)),
            ..Default::default()
        });
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains('\u{202e}') && !raw.contains('\u{9b}'),
            "{raw}"
        );
        let v: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(v["session"], "evil\\u{202e}session\\u{1b}[31m");
    }
}
