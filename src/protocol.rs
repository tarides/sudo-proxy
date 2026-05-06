use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

fn default_true() -> bool {
    true
}

fn default_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn default_session() -> String {
    "unknown".to_string()
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
        }
    }

    /// Returns the exit code of the last stage, or 0 if no stages.
    pub fn exit_code(&self) -> i32 {
        self.stages.last().map(|s| s.exit_code).unwrap_or(0)
    }
}
