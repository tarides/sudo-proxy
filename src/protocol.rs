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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<StageResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
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
            message: None,
        }
    }

    pub fn denied(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Denied,
            stages: vec![],
            stdout: None,
            message: None,
        }
    }

    pub fn timeout(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Timeout,
            stages: vec![],
            stdout: None,
            message: None,
        }
    }

    pub fn error(id: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Error,
            stages: vec![],
            stdout: None,
            message: Some(message.to_string()),
        }
    }

    /// Returns the exit code of the last stage, or 0 if no stages.
    pub fn exit_code(&self) -> i32 {
        self.stages.last().map(|s| s.exit_code).unwrap_or(0)
    }
}
