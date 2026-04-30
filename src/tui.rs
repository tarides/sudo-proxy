use std::fs::{File, OpenOptions};
use std::io::{self, Write};
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

/// Join a pipeline of stages into a shell-like display string with ` | ` separators.
pub fn pipeline_join(pipeline: &[Vec<String>]) -> String {
    pipeline
        .iter()
        .map(|argv| shell_join(argv))
        .collect::<Vec<_>>()
        .join(" | ")
}

#[derive(Debug, PartialEq)]
pub enum PromptResult {
    Approved,
    Denied,
    Timeout,
}

/// Asks the user to approve or deny a privilege request.
pub trait Prompter: Send + Sync {
    fn prompt(&self, req: &Request, timeout: Duration) -> io::Result<PromptResult>;
}

/// Echoes the result of a completed command back to the user.
pub trait ResultSink: Send + Sync {
    fn display(&self, resp: &Response) -> io::Result<()>;
}

pub struct TtyPrompter;

impl Prompter for TtyPrompter {
    fn prompt(&self, req: &Request, timeout: Duration) -> io::Result<PromptResult> {
        prompt_tty(req, timeout)
    }
}

pub struct TtyResultSink;

impl ResultSink for TtyResultSink {
    fn display(&self, resp: &Response) -> io::Result<()> {
        display_result(resp)
    }
}

pub struct NoopResultSink;

impl ResultSink for NoopResultSink {
    fn display(&self, _resp: &Response) -> io::Result<()> {
        Ok(())
    }
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
    writeln!(
        tty_w,
        "Command: {bold}{}{reset}",
        pipeline_join(&req.pipeline)
    )?;

    // Show resolved path for the first stage's command
    if let Some(first_argv) = req.pipeline.first() {
        if let Some(cmd_name) = first_argv.first() {
            if let Some(resolved) = which(cmd_name) {
                let resolved_str = resolved.display().to_string();
                if resolved_str != *cmd_name {
                    writeln!(tty_w, "Resolves: {}", resolved_str)?;
                }
            } else {
                writeln!(tty_w, "Resolves: {bold}(not found in PATH){reset}")?;
            }
        }

        // Warn if later stages have commands not in PATH
        for argv in req.pipeline.iter().skip(1) {
            if let Some(cmd_name) = argv.first() {
                if which(cmd_name).is_none() {
                    writeln!(
                        tty_w,
                        "Warning:  {bold}{cmd_name}{reset} not found in PATH"
                    )?;
                }
            }
        }
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

    // Read single keypress with timeout (no Enter needed)
    let result = match read_key_timeout(&tty_r, timeout)? {
        None => {
            writeln!(tty_w, "\n→ Timeout")?;
            PromptResult::Timeout
        }
        Some(b'y' | b'Y') => {
            writeln!(tty_w, "\n→ Approved")?;
            PromptResult::Approved
        }
        Some(_) => {
            writeln!(tty_w, "\n→ Denied")?;
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
            let exit_code = resp.exit_code();
            let multi_stage = resp.stages.len() > 1;

            if multi_stage {
                // Show all exit codes for multi-stage
                let codes: Vec<String> =
                    resp.stages.iter().map(|s| s.exit_code.to_string()).collect();
                let label = format!("exit [{}]", codes.join(", "));
                if exit_code == 0 {
                    writeln!(w, "{dim}{label}{reset}")?;
                } else {
                    writeln!(w, "{bold}{label}{reset}")?;
                }
            } else if exit_code == 0 {
                writeln!(w, "{dim}exit 0{reset}")?;
            } else {
                writeln!(w, "{bold}exit {exit_code}{reset}")?;
            }

            if let Some(ref b64) = resp.stdout {
                if let Ok(bytes) = B64.decode(b64) {
                    print_truncated(w, &bytes, "stdout")?;
                }
            }

            for (i, stage) in resp.stages.iter().enumerate() {
                if let Ok(bytes) = B64.decode(&stage.stderr) {
                    if !bytes.is_empty() {
                        let label = if multi_stage {
                            format!("stderr[{i}]")
                        } else {
                            "stderr".to_string()
                        };
                        print_truncated(w, &bytes, &label)?;
                    }
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

/// Read a single keypress from a file descriptor with a timeout using poll(2).
/// Switches the terminal to non-canonical mode so Enter is not required.
/// Returns None on timeout, Some(char) otherwise.
fn read_key_timeout(file: &File, timeout: Duration) -> io::Result<Option<u8>> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();

    // Save terminal state and switch to non-canonical mode
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut raw = orig;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
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

        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(buf[0]))
    })();

    // Restore terminal state
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };

    result
}
