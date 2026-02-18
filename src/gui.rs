use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::executor::which;
use crate::protocol::Request;
use crate::tui::{self, pipeline_join, PromptResult};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Show a Y/N confirmation dialog for a command request.
/// Auto-detects: zenity → kdialog → TUI (/dev/tty) fallback.
pub fn prompt_gui(req: &Request) -> io::Result<PromptResult> {
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

fn format_prompt_text(req: &Request) -> String {
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

    match status.code() {
        Some(0) => Ok(PromptResult::Approved),
        Some(5) => Ok(PromptResult::Timeout), // zenity timeout exit code
        _ => Ok(PromptResult::Denied),
    }
}

fn prompt_kdialog(text: &str) -> io::Result<PromptResult> {
    let status = Command::new("kdialog")
        .args(["--yesno", text, "--title", "Command Request"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    match status.code() {
        Some(0) => Ok(PromptResult::Approved),
        _ => Ok(PromptResult::Denied),
    }
}
