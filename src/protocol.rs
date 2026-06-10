use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;

/// Version stamped onto outgoing wire messages. All four binaries live in
/// the same crate, so this resolves to the same value everywhere.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_session")]
    pub session: String,
    #[serde(default)]
    pub time: String,
    pub pipeline: Vec<Vec<String>>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_true")]
    pub privileged: bool,
    /// Inject the daemon's snapshotted SSH_AUTH_SOCK into the child env
    /// so unprivileged commands (e.g. `git clone`) can reach the user's
    /// agent. Honored only when `privileged` is false; the daemon
    /// rejects the request otherwise.
    #[serde(default)]
    pub forward_agent: bool,
    /// Sender's `CARGO_PKG_VERSION`. Empty when peer predates this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

pub(crate) fn default_true() -> bool {
    true
}

fn default_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Request {
    /// Build an outgoing request, stamping the fields every sender fills the
    /// same way: a fresh random `id`, the current time, and this binary's
    /// `version`. Callers supply only what actually varies between sites.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: String,
        session: String,
        pipeline: Vec<Vec<String>>,
        env: HashMap<String, String>,
        reason: String,
        privileged: bool,
        forward_agent: bool,
    ) -> Self {
        Self {
            id: default_id(),
            host,
            session,
            time: crate::datetime::now_iso8601(),
            pipeline,
            env,
            reason,
            privileged,
            forward_agent,
            version: VERSION.to_string(),
        }
    }
}

fn default_session() -> String {
    "unknown".to_string()
}

/// True if `s` contains a character forbidden in any request-derived string
/// that is rendered on the approval prompt: control chars (except tab), and
/// zero-width / bidi-override characters. The prompt is the security gate, so
/// a field carrying raw ANSI/escape/newline or bidi bytes could redraw the
/// terminal and misrepresent the command being approved.
///
/// `pub(crate)` so the Rung 2 property test and the Rung 3 Kani harness can
/// drive it directly; the only *enforcement* path is `ValidatedRequest::validate`.
pub(crate) fn has_dangerous_chars(s: &str) -> bool {
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

/// A `Request` that has passed `ValidatedRequest::validate`.
///
/// The wrapped `Request` is private to this module, so the *only* way to obtain
/// a `ValidatedRequest` is through the validating constructor below. The
/// privileged execution path (`executor::exec_*`) and the approval prompt
/// (`tui::Prompter`) take `&ValidatedRequest`, which makes "a request reaching
/// dispatch skipped validation" a *compile error* rather than a runtime gap —
/// the Rung 3 closure of the F1-class finding. See docs/formalisation-roadmap.md.
#[derive(Clone, Debug)]
pub struct ValidatedRequest(Request);

impl ValidatedRequest {
    /// Validate every attacker-controlled, prompt-rendered field of `req` and,
    /// on success, consume it into a `ValidatedRequest`. The checks: a non-empty
    /// pipeline of non-empty stages, and no dangerous character in any argv
    /// element, env key/value, or in `reason`/`session`/`host`/`version`/`id`.
    ///
    /// `reason` may arrive from the MCP `description`, and `host`/`session`/
    /// `id`/`version` from a direct same-UID socket client that bypasses the
    /// client-side `validate_host`; all are held to the same sanitization as
    /// argv and env. See `tui::prompt_tty` for the render this protects.
    pub fn validate(req: Request) -> Result<Self, String> {
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
        for (field, value) in [
            ("reason", &req.reason),
            ("session", &req.session),
            ("host", &req.host),
            ("version", &req.version),
            ("id", &req.id),
        ] {
            if has_dangerous_chars(value) {
                return Err(format!("{field} contains forbidden control/bidi characters"));
            }
        }
        Ok(ValidatedRequest(req))
    }

    /// Borrow the validated request.
    pub fn inner(&self) -> &Request {
        &self.0
    }
}

impl Deref for ValidatedRequest {
    type Target = Request;
    fn deref(&self) -> &Request {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageResult {
    pub exit_code: i32,
    pub stderr: String, // base64
    /// True if the stage's stderr was capped before the child finished
    /// writing. Defaults to false; old peers without this field deserialize
    /// to false transparently.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<StageResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    /// True if the final stdout was capped at MAX_OUTPUT_BYTES before the
    /// child finished writing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stdout_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Daemon's `CARGO_PKG_VERSION`. Empty when peer predates this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Denied,
    Timeout,
    Error,
}

impl Response {
    pub fn ok(id: &str, stages: Vec<StageResult>, stdout: &[u8]) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Ok,
            stages,
            stdout: Some(B64.encode(stdout)),
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn ok_with_truncation(
        id: &str,
        stages: Vec<StageResult>,
        stdout: &[u8],
        stdout_truncated: bool,
    ) -> Self {
        let mut r = Self::ok(id, stages, stdout);
        r.stdout_truncated = stdout_truncated;
        r
    }

    pub fn denied(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Denied,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn timeout(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Timeout,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn error(id: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Error,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: Some(message.to_string()),
            version: VERSION.to_string(),
        }
    }

    /// Returns the exit code of the last stage, or 0 if no stages.
    pub fn exit_code(&self) -> i32 {
        self.stages.last().map(|s| s.exit_code).unwrap_or(0)
    }
}
