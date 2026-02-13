use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::executor::which;
use crate::protocol::{Request, Response, Status};

/// Join argv into a shell-like display string, quoting args that contain spaces.
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('\'') || a.contains('"') || a.is_empty() {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, PartialEq)]
pub enum PromptResult {
    Approved,
    Denied,
    Timeout,
}

/// Display a privilege request on /dev/tty and ask for Y/N confirmation.
pub fn prompt_tty(req: &Request, timeout: Duration) -> io::Result<PromptResult> {
    let mut tty_w = OpenOptions::new().write(true).open("/dev/tty")?;
    let tty_r = File::open("/dev/tty")?;

    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    writeln!(tty_w, "\n{bold}━━━ Privilege Request ━━━{reset}")?;
    writeln!(
        tty_w,
        "From:    {} @ {}",
        req.session,
        if req.host.is_empty() { "local" } else { &req.host }
    )?;
    if !req.time.is_empty() {
        writeln!(tty_w, "Time:    {}", req.time)?;
    }
    writeln!(tty_w, "ID:      {}", req.id)?;
    if !req.reason.is_empty() {
        writeln!(tty_w, "Reason:  {bold}{}{reset}", req.reason)?;
    }
    writeln!(tty_w, "Command: {bold}{}{reset}", shell_join(&req.argv))?;

    // Show resolved path
    if let Some(resolved) = which(&req.argv[0]) {
        let resolved_str = resolved.display().to_string();
        if resolved_str != req.argv[0] {
            let mut full = vec![resolved_str];
            full.extend_from_slice(&req.argv[1..]);
            writeln!(tty_w, "Resolves: {}", shell_join(&full))?;
        }
    } else {
        writeln!(tty_w, "Resolves: {bold}(not found in PATH){reset}")?;
    }

    if !req.env.is_empty() {
        let env_display: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        writeln!(tty_w, "Env:     {}", env_display.join(" "))?;
    }

    write!(
        tty_w,
        "Execute as root? [y/N] ({}s timeout, default=N) ",
        timeout.as_secs()
    )?;
    tty_w.flush()?;

    // Read with timeout using poll
    let result = match read_line_timeout(&tty_r, timeout)? {
        None => {
            writeln!(tty_w, "\n→ Timeout")?;
            PromptResult::Timeout
        }
        Some(answer) if matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes") => {
            writeln!(tty_w, "→ Approved")?;
            PromptResult::Approved
        }
        Some(_) => {
            writeln!(tty_w, "→ Denied")?;
            PromptResult::Denied
        }
    };
    writeln!(tty_w, "{bold}━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")?;

    Ok(result)
}

const MAX_DISPLAY_LINES: usize = 3;

/// Display the command result on /dev/tty. Truncate stdout/stderr to 3 lines.
pub fn display_result(resp: &Response) -> io::Result<()> {
    let mut tty = OpenOptions::new().write(true).open("/dev/tty")?;
    write_result(&mut tty, resp)
}

/// Write the command result to any writer. Truncate stdout/stderr to 3 lines.
pub fn write_result(w: &mut impl Write, resp: &Response) -> io::Result<()> {
    let dim = "\x1b[2m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    match resp.status {
        Status::Ok => {
            let code = resp.exit_code.unwrap_or(0);
            if code == 0 {
                writeln!(w, "{dim}exit 0{reset}")?;
            } else {
                writeln!(w, "{bold}exit {code}{reset}")?;
            }
            if let Some(ref b64) = resp.stdout {
                if let Ok(bytes) = B64.decode(b64) {
                    print_truncated(w, &bytes, "stdout")?;
                }
            }
            if let Some(ref b64) = resp.stderr {
                if let Ok(bytes) = B64.decode(b64) {
                    print_truncated(w, &bytes, "stderr")?;
                }
            }
        }
        Status::Denied => {
            writeln!(w, "{dim}denied{reset}")?;
        }
        Status::Timeout => {
            writeln!(w, "{dim}timeout{reset}")?;
        }
        Status::Error => {
            let msg = resp.message.as_deref().unwrap_or("unknown error");
            writeln!(w, "{bold}error: {msg}{reset}")?;
        }
    }
    Ok(())
}

fn print_truncated(tty: &mut impl Write, bytes: &[u8], label: &str) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";
    let truncated = lines.len() > MAX_DISPLAY_LINES;
    let shown = if truncated { &lines[..MAX_DISPLAY_LINES] } else { &lines };

    let trunc_tag = if truncated { ", truncated" } else { "" };
    writeln!(
        tty,
        "{dim}== {label} == ({} lines{trunc_tag}){reset}",
        lines.len()
    )?;
    for line in shown {
        writeln!(tty, "{line}")?;
    }
    Ok(())
}

/// Read a line from a file descriptor with a timeout using poll(2).
/// Returns None on timeout, Some(line) otherwise.
fn read_line_timeout(file: &File, timeout: Duration) -> io::Result<Option<String>> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let timeout_ms = timeout.as_millis() as i32;

    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret == 0 {
        return Ok(None);
    }

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(Some(line))
}
