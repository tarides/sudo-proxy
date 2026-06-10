use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::executor::which;
use crate::protocol::ValidatedRequest;
use crate::tui::{self, pipeline_join, Prompter, PromptResult};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct GuiPrompter;

impl Prompter for GuiPrompter {
    fn prompt(&self, req: &ValidatedRequest, _timeout: Duration) -> io::Result<PromptResult> {
        prompt_gui(req)
    }
}

/// Show a Y/N confirmation dialog for a command request.
/// Auto-detects: zenity → kdialog → TUI (/dev/tty) fallback.
pub fn prompt_gui(req: &ValidatedRequest) -> io::Result<PromptResult> {
    let text = format_prompt_text(req);

    if which("zenity").is_some() {
        if let Ok(result) = prompt_zenity(&text) {
            return Ok(result);
        }
    }

    if which("kdialog").is_some() {
        if let Ok(result) = prompt_kdialog(&text) {
            return Ok(result);
        }
    }

    // Fall back to TUI
    tui::prompt_tty(req, PROMPT_TIMEOUT)
}

fn format_prompt_text(req: &ValidatedRequest) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "From: {} @ {}",
        req.session,
        if req.host.is_empty() { "local" } else { &req.host }
    ));
    if !req.reason.is_empty() {
        lines.push(format!("Reason: {}", req.reason));
    }
    lines.push(format!("Command: {}", pipeline_join(&req.pipeline)));
    if let Some(first_argv) = req.pipeline.first() {
        if let Some(cmd_name) = first_argv.first() {
            if let Some(resolved) = which(cmd_name) {
                let resolved_str = resolved.display().to_string();
                if resolved_str != *cmd_name {
                    lines.push(format!("Resolves: {}", resolved_str));
                }
            }
        }
    }
    lines.push(String::new());
    lines.push("Allow this command to run?".to_string());
    lines.join("\n")
}

fn prompt_zenity(text: &str) -> io::Result<PromptResult> {
    let status = Command::new("zenity")
        .args(["--question", "--title=Command Request", "--timeout=60"])
        .arg(format!("--text={text}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    map_zenity_status(status.code())
}

fn prompt_kdialog(text: &str) -> io::Result<PromptResult> {
    let status = Command::new("kdialog")
        .args(["--yesno", text, "--title", "Command Request"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    map_kdialog_status(status.code())
}

/// Map zenity's documented exit codes. Anything else (signal death, crash,
/// killed window) returns Err so the daemon surfaces a real error rather
/// than silently denying a request the user never saw.
fn map_zenity_status(code: Option<i32>) -> io::Result<PromptResult> {
    match code {
        Some(0) => Ok(PromptResult::Approved),
        Some(1) => Ok(PromptResult::Denied),
        Some(5) => Ok(PromptResult::Timeout),
        Some(other) => Err(io::Error::other(format!(
            "zenity exited with unexpected status {other}"
        ))),
        None => Err(io::Error::other(
            "zenity terminated by signal (window closed?)",
        )),
    }
}

fn map_kdialog_status(code: Option<i32>) -> io::Result<PromptResult> {
    match code {
        Some(0) => Ok(PromptResult::Approved),
        Some(1) | Some(2) => Ok(PromptResult::Denied),
        Some(other) => Err(io::Error::other(format!(
            "kdialog exited with unexpected status {other}"
        ))),
        None => Err(io::Error::other(
            "kdialog terminated by signal (window closed?)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zenity_known_statuses() {
        assert!(matches!(map_zenity_status(Some(0)), Ok(PromptResult::Approved)));
        assert!(matches!(map_zenity_status(Some(1)), Ok(PromptResult::Denied)));
        assert!(matches!(map_zenity_status(Some(5)), Ok(PromptResult::Timeout)));
    }

    #[test]
    fn zenity_unknown_status_is_error() {
        assert!(map_zenity_status(Some(127)).is_err(),
            "unexpected exit must surface as error, not silent denial");
        assert!(map_zenity_status(None).is_err(),
            "signal-death must surface as error, not silent denial");
    }

    #[test]
    fn kdialog_known_statuses() {
        assert!(matches!(map_kdialog_status(Some(0)), Ok(PromptResult::Approved)));
        assert!(matches!(map_kdialog_status(Some(1)), Ok(PromptResult::Denied)));
        assert!(matches!(map_kdialog_status(Some(2)), Ok(PromptResult::Denied)));
    }

    #[test]
    fn kdialog_unknown_status_is_error() {
        assert!(map_kdialog_status(Some(127)).is_err());
        assert!(map_kdialog_status(None).is_err());
    }
}
