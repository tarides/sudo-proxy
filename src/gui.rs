use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::executor::{wait_with_deadline, PreparedRequest, WaitError};
use crate::helper::{find_trusted, HELPER_PATH};
use crate::protocol::escape_dangerous;
use crate::tui::{self, PromptResult, Prompter};

/// The timeout of [`prompt_gui`]; [`GuiPrompter`] uses the one it is given.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct GuiPrompter;

impl Prompter for GuiPrompter {
    // The GUI dialogs (zenity/kdialog) are plain yes/no — they never offer the
    // session-scoped `a` answer, so `eligible` is honored only on the TUI
    // fallback path.
    fn prompt(
        &self,
        req: &PreparedRequest,
        eligible: bool,
        timeout: Duration,
    ) -> io::Result<PromptResult> {
        prompt_gui_within(req, eligible, timeout)
    }
}

/// Show a Y/N confirmation dialog for a command request, denied as
/// [`PromptResult::Timeout`] after 60 s.
/// Auto-detects: zenity → kdialog → TUI (/dev/tty) fallback.
pub fn prompt_gui(req: &PreparedRequest, eligible: bool) -> io::Result<PromptResult> {
    prompt_gui_within(req, eligible, PROMPT_TIMEOUT)
}

fn prompt_gui_within(
    req: &PreparedRequest,
    eligible: bool,
    timeout: Duration,
) -> io::Result<PromptResult> {
    let text = format_prompt_text(req);

    // The dialog answers the approval, so it is found like an escalator:
    // never on the daemon's own PATH (GHSA-gx9w-4f7x-2gcp).
    if let Ok(zenity) = find_trusted("zenity", false, HELPER_PATH) {
        if let Ok(result) = prompt_zenity(&zenity, &text, timeout) {
            return Ok(result);
        }
    }

    if let Ok(kdialog) = find_trusted("kdialog", false, HELPER_PATH) {
        if let Ok(result) = prompt_kdialog(&kdialog, &text, timeout) {
            return Ok(result);
        }
    }

    // Fall back to TUI
    tui::prompt_tty(req, eligible, timeout)
}

/// The dialog text, as plain text: request fields go in verbatim. Each backend
/// makes it literal for its own toolkit (issue #95): zenity with
/// `--no-markup` ([`zenity_args`]), kdialog by escaping ([`kdialog_text`]).
fn format_prompt_text(req: &PreparedRequest) -> String {
    let mut lines = Vec::new();
    // Same disclosure as the TUI header (issue #25); plain text, no styling.
    if req.requester_is_ai() {
        lines.push("[AI-AGENT REQUEST]".to_string());
    }
    lines.push(format!(
        "From: {} @ {}",
        req.session,
        if req.host.is_empty() {
            "local"
        } else {
            &req.host
        }
    ));
    if !req.requester.is_empty() {
        lines.push(format!(
            "Requester: {} (self-declared, not verified)",
            req.requester
        ));
    }
    if !req.reason.is_empty() {
        lines.push(format!("Reason: {}", req.reason));
    }
    // The TUI's `Command:` text: a plan request has no `pipeline`, and an
    // escalated step shows as `sudo …`.
    lines.push(format!(
        "Command: {}",
        tui::truncate_for_display(&tui::command_summary(req.request()))
    ));
    // Each stage's resolution is the pinned one the executor spawns (issues
    // #62, #105), so the dialog names the files that will run.
    let mut seen = std::collections::HashSet::new();
    for view in req.views() {
        let Some(cmd_name) = view.argv.first() else {
            continue;
        };
        let shown = match &view.resolved_bin {
            Some(r) => r.path.display().to_string(),
            None => "(not found in PATH)".to_string(),
        };
        if shown != *cmd_name && seen.insert((cmd_name.clone(), shown.clone())) {
            // Escaped for display only (issue #86): `shown` is built from the
            // validated argv[0]/cwd and the constant login PATH, so this is
            // defence in depth; the comparison above uses the raw string.
            lines.push(format!(
                "Resolves: {cmd_name} → {}",
                escape_dangerous(&shown)
            ));
        }
    }
    lines.push(String::new());
    lines.push("Allow this command to run?".to_string());
    lines.join("\n")
}

fn prompt_zenity(zenity: &Path, text: &str, timeout: Duration) -> io::Result<PromptResult> {
    let mut cmd = Command::new(zenity);
    cmd.args(zenity_args(text, timeout));
    run_dialog(cmd, timeout, map_zenity_status)
}

/// Run a dialog and map its exit status, denying it as
/// [`PromptResult::Timeout`] once `timeout` has passed: kdialog has no timeout
/// of its own, and zenity's `--timeout` is not relied on alone. A dialog
/// still open then is killed, so an unanswered request never holds its slot
/// past the prompt timeout.
fn run_dialog(
    mut cmd: Command,
    timeout: Duration,
    map: fn(Option<i32>) -> io::Result<PromptResult>,
) -> io::Result<PromptResult> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    match wait_with_deadline(&mut child, Instant::now() + timeout) {
        Ok(status) => map(status.code()),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            match e {
                WaitError::Timeout => Ok(PromptResult::Timeout),
                WaitError::Io(e) => Err(e),
            }
        }
    }
}

/// zenity's arguments. Without `--no-markup`, zenity parses `--text` as Pango
/// markup after `g_strcompress`, so request text such as `<span size="1">`
/// could hide part of the dialog and a literal `\n` would draw a line break
/// (a fake `Command:` line). With it, zenity calls `gtk_label_set_text` on the
/// text as given (zenity `src/msg.c`).
fn zenity_args(text: &str, timeout: Duration) -> Vec<String> {
    // zenity counts whole seconds; round up so it never denies early.
    let secs = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
    vec![
        "--question".into(),
        "--title=Command Request".into(),
        format!("--timeout={}", secs.max(1)),
        "--no-markup".into(),
        format!("--text={text}"),
    ]
}

fn prompt_kdialog(kdialog: &Path, text: &str, timeout: Duration) -> io::Result<PromptResult> {
    let mut cmd = Command::new(kdialog);
    cmd.args(kdialog_args(text));
    run_dialog(cmd, timeout, map_kdialog_status)
}

fn kdialog_args(text: &str) -> Vec<String> {
    vec![
        "--yesno".into(),
        kdialog_text(text),
        "--title".into(),
        "Command Request".into(),
    ]
}

const KDIALOG_OPEN: &str = "<qt><p style=\"white-space:pre-wrap\">";
const KDIALOG_CLOSE: &str = "</p></qt>";

/// The text kdialog shows exactly as `text`. kdialog has no plain-text option:
/// it expands `\n` and `\\` in its argument (`Utils::parseString`), and its
/// label guesses rich text from the first line, with links enabled
/// (`KMessageBox::AllowLink`); that line holds `session` and `host` unless
/// the `[AI-AGENT REQUEST]` header precedes it. So the text is always rich
/// text: entity-escaped, inside a `<qt>` element Qt recognises, with
/// `white-space:pre-wrap` keeping newlines and runs of spaces; and every `\`
/// is doubled for `parseString` to undo.
fn kdialog_text(text: &str) -> String {
    let mut out = String::with_capacity(KDIALOG_OPEN.len() + text.len() + KDIALOG_CLOSE.len());
    out.push_str(KDIALOG_OPEN);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push_str(KDIALOG_CLOSE);
    out
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
        assert!(matches!(
            map_zenity_status(Some(0)),
            Ok(PromptResult::Approved)
        ));
        assert!(matches!(
            map_zenity_status(Some(1)),
            Ok(PromptResult::Denied)
        ));
        assert!(matches!(
            map_zenity_status(Some(5)),
            Ok(PromptResult::Timeout)
        ));
    }

    #[test]
    fn zenity_unknown_status_is_error() {
        assert!(
            map_zenity_status(Some(127)).is_err(),
            "unexpected exit must surface as error, not silent denial"
        );
        assert!(
            map_zenity_status(None).is_err(),
            "signal-death must surface as error, not silent denial"
        );
    }

    #[test]
    fn kdialog_known_statuses() {
        assert!(matches!(
            map_kdialog_status(Some(0)),
            Ok(PromptResult::Approved)
        ));
        assert!(matches!(
            map_kdialog_status(Some(1)),
            Ok(PromptResult::Denied)
        ));
        assert!(matches!(
            map_kdialog_status(Some(2)),
            Ok(PromptResult::Denied)
        ));
    }

    #[test]
    fn kdialog_unknown_status_is_error() {
        assert!(map_kdialog_status(Some(127)).is_err());
        assert!(map_kdialog_status(None).is_err());
    }

    /// Text that markup, rich-text guessing or backslash escapes would
    /// misrender (issue #95): a tag on the first line (where kdialog guesses
    /// the format), a span that hides text, a link, a lone `<` and `&`, an
    /// entity, quotes, and a literal `\n` forging a `Command:` line.
    const HOSTILE: &str = "From: <b>s</b> @ h&lt;\n\
        Reason: <span size=\"1\">hidden</span> <a href='https://x'>x</a> a < b && c\\nCommand: ls \\\\ \\t\n\
        Command: echo 'a  b'";

    /// kdialog's `Utils::parseString`: `\\` → `\`, `\n` → newline, any other
    /// escape kept as is.
    fn kdialog_parse_string(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => out.push('\\'),
            }
        }
        out
    }

    fn html_unescape(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&")
    }

    #[test]
    fn zenity_args_disable_markup() {
        let args = zenity_args(HOSTILE, PROMPT_TIMEOUT);
        assert!(args.iter().any(|a| a == "--no-markup"), "{args:?}");
        let texts: Vec<_> = args.iter().filter(|a| a.starts_with("--text=")).collect();
        assert_eq!(texts, [&format!("--text={HOSTILE}")]);
    }

    #[test]
    fn kdialog_text_is_literal() {
        let args = kdialog_args(HOSTILE);
        assert_eq!(args[0], "--yesno");
        let shown = &args[1];
        let body = shown
            .strip_prefix(KDIALOG_OPEN)
            .and_then(|b| b.strip_suffix(KDIALOG_CLOSE))
            .expect("wrapped in <qt>");
        assert!(!body.contains(['<', '>', '"', '\'']), "{body}");
        // What kdialog displays, after its own unescaping and Qt's.
        let rendered = html_unescape(&kdialog_parse_string(body));
        assert_eq!(rendered, HOSTILE);
        // No escape survives `parseString` as a line break.
        assert_eq!(
            kdialog_parse_string(shown).lines().count(),
            HOSTILE.lines().count()
        );
    }

    fn hostile_request() -> crate::protocol::ValidatedRequest {
        let mut req = crate::protocol::Request::new(
            "h<i>&amp;".into(),
            "<b>s</b>".into(),
            vec![vec!["echo".into(), "a<b && c\\nCommand: ls".into()]],
            std::collections::HashMap::new(),
            "<span size=\"1\">hidden</span> \\n".into(),
            false,
            false,
        );
        req.requester = "<a href='x'>me</a>".into();
        crate::protocol::ValidatedRequest::validate(req).expect("valid")
    }

    fn hostile_text() -> String {
        let req = hostile_request();
        format_prompt_text(
            &crate::executor::prepare(&req, &std::collections::HashMap::new()).expect("compiles"),
        )
    }

    #[test]
    fn format_prompt_text_carries_fields_verbatim() {
        let text = hostile_text();
        for field in [
            "<b>s</b> @ h<i>&amp;",
            "Requester: <a href='x'>me</a>",
            "Reason: <span size=\"1\">hidden</span> \\n",
            "a<b && c\\nCommand: ls",
        ] {
            assert!(text.contains(field), "{field:?} missing from {text:?}");
        }
    }

    /// An unanswered dialog is killed and denied as `Timeout` at the deadline,
    /// not left waiting (kdialog has no timeout of its own).
    #[test]
    fn run_dialog_denies_an_unanswered_dialog_at_the_deadline() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let result = run_dialog(cmd, Duration::from_millis(200), map_kdialog_status);
        assert!(matches!(result, Ok(PromptResult::Timeout)), "{result:?}");
        assert!(start.elapsed() < Duration::from_secs(5), "child not killed");
    }

    #[test]
    fn run_dialog_maps_an_answer_before_the_deadline() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exit 1"]);
        let result = run_dialog(cmd, Duration::from_secs(30), map_kdialog_status);
        assert!(matches!(result, Ok(PromptResult::Denied)), "{result:?}");
    }

    #[test]
    fn zenity_timeout_rounds_up_to_whole_seconds() {
        let timeout_arg = |d| {
            zenity_args("t", d)
                .into_iter()
                .find(|a| a.starts_with("--timeout="))
                .expect("--timeout")
        };
        assert_eq!(timeout_arg(Duration::from_secs(60)), "--timeout=60");
        assert_eq!(timeout_arg(Duration::from_millis(1500)), "--timeout=2");
        assert_eq!(timeout_arg(Duration::from_millis(1)), "--timeout=1");
    }

    /// A plan request has an empty `pipeline`: the `Command:` line is the
    /// TUI's, escalated steps included, never blank.
    #[test]
    fn format_prompt_text_shows_plan_commands() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let exec = |argv: &[&str]| Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            Plan::Run {
                steps: vec![exec(&["id", "-un"]), exec(&["id", "-u"])],
            },
            std::collections::HashMap::new(),
            String::new(),
            true,
            false,
        ))
        .expect("valid");
        let prepared =
            crate::executor::prepare(&req, &std::collections::HashMap::new()).expect("compiles");
        let text = format_prompt_text(&prepared);
        assert!(
            text.lines()
                .any(|l| l == "Command: sudo id -un && sudo id -u"),
            "{text:?}"
        );
    }

    /// Manual check against the real zenity (issue #95): the dialog must show
    /// the request fields as typed, tags and `\n` included, on their own lines.
    /// Run with `cargo test --lib gui::tests::manual_zenity -- --ignored`.
    #[test]
    #[ignore = "opens a zenity dialog for a human"]
    fn manual_zenity() {
        let zenity = find_trusted("zenity", false, HELPER_PATH).expect("trusted zenity");
        let text = hostile_text();
        eprintln!("--- expected dialog text ---\n{text}\n---");
        eprintln!(
            "result: {:?}",
            prompt_zenity(&zenity, &text, PROMPT_TIMEOUT)
        );
    }
}
