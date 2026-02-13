use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_session")]
    pub session: String,
    #[serde(default)]
    pub time: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub reason: String,
}

fn default_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn default_session() -> String {
    "unknown".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Denied,
    Error,
}

impl Response {
    pub fn ok(id: &str, exit_code: i32, stdout: &[u8], stderr: &[u8]) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Ok,
            exit_code: Some(exit_code),
            stdout: Some(B64.encode(stdout)),
            stderr: Some(B64.encode(stderr)),
            message: None,
        }
    }

    pub fn denied(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Denied,
            exit_code: None,
            stdout: None,
            stderr: None,
            message: None,
        }
    }

    pub fn error(id: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Error,
            exit_code: None,
            stdout: None,
            stderr: None,
            message: Some(message.to_string()),
        }
    }
}
