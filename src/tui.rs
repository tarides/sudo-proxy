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

/// Upper bound on the command string shown at the approval prompt. A caller
/// could otherwise submit a multi-kilobyte argument that wraps over dozens of
/// lines and pushes the `[y/N]` question off-screen, so the human approves
/// without it in view. Bounded display keeps the prompt anchored; the marker
/// makes truncation explicit so an over-long command reads as suspicious
/// rather than benign.
const MAX_DISPLAY_CMD_CHARS: usize = 1024;

/// Truncate an approval-prompt command string to a bounded number of
/// characters, appending an explicit marker when it was shortened.
pub fn truncate_for_display(s: &str) -> String {
    let count = s.chars().count();
    if count <= MAX_DISPLAY_CMD_CHARS {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX_DISPLAY_CMD_CHARS).collect();
    let hidden = count - MAX_DISPLAY_CMD_CHARS;
    format!("{head}… [{hidden} more chars hidden — full command not shown]")
}

#[derive(Debug, PartialEq)]
pub enum PromptResult {
    Approved,
    /// Approve this request *and* grant log-only mode for unprivileged
    /// commands going forward (until reverted). Only emitted for
    /// unprivileged requests; privileged prompts never offer this.
    ApprovedAlways,
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
    let client_ver = if req.version.is_empty() { "(unknown)" } else { req.version.as_str() };
    writeln!(tty_w, "Client:  sudo-proxy {client_ver}")?;
    if !req.time.is_empty() {
        writeln!(tty_w, "Time:    {}", req.time)?;
    }
    writeln!(tty_w, "ID:      {}", req.id)?;
    if !req.reason.is_empty() {
        writeln!(tty_w, "Reason:  {bold}{}{reset}", req.reason)?;
    }
    let dim = "\x1b[2m";
    let agent_tag = if req.forward_agent {
        format!(" {dim}(agent forwarded){reset}")
    } else {
        String::new()
    };
    writeln!(
        tty_w,
        "Command: {bold}{}{reset}{agent_tag}",
        truncate_for_display(&pipeline_join(&req.pipeline))
    )?;

    // Show resolved path for the first stage's command. Symlinks are
    // followed via canonicalize so a same-UID adversary who substitutes
    // /usr/local/bin/foo -> /tmp/evil cannot hide the redirection from
    // the prompt.
    if let Some(first_argv) = req.pipeline.first() {
        if let Some(cmd_name) = first_argv.first() {
            write_resolves_line(&mut tty_w, cmd_name, bold, dim, reset)?;
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

    let (question, choices) = if req.privileged {
        ("Execute as root?", "[y/N]")
    } else {
        writeln!(
            tty_w,
            "{dim}a = always allow unprivileged on this host (saved to hosts.json){reset}"
        )?;
        ("Execute?", "[y/N/a]")
    };
    write!(
        tty_w,
        "{question} {choices} ({}s timeout, default=N) ",
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
        Some(b'a' | b'A') if !req.privileged => {
            writeln!(tty_w, "\n→ Approved (always for this host)")?;
            PromptResult::ApprovedAlways
        }
        Some(_) => {
            writeln!(tty_w, "\n→ Denied")?;
            PromptResult::Denied
        }
    };
    writeln!(tty_w, "{bold}━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")?;

    Ok(result)
}

/// Write the `Resolves:` line for a command name. PATH-searches the
/// name (or accepts an absolute path), then `canonicalize`s the result
/// so symlink redirection — including `/usr/local/bin/foo -> /tmp/evil`
/// when the absolute path was supplied directly — is visible.
///
/// Display rules:
/// - request matches resolved matches canonical: nothing printed.
/// - request differs from resolved (PATH search): show resolved path,
///   appending `-> canonical` if canonical also differs.
/// - request matches resolved but canonical differs (absolute symlink):
///   show `request -> canonical` in bold.
/// - canonicalize fails (broken symlink, EACCES): show what we know and
///   flag `(canonicalize failed)` so the prompt is honest about not
///   having verified the target.
fn write_resolves_line<W: Write>(
    w: &mut W,
    cmd_name: &str,
    bold: &str,
    dim: &str,
    reset: &str,
) -> io::Result<()> {
    let resolved = match which(cmd_name) {
        Some(p) => p,
        None => {
            return writeln!(w, "Resolves: {bold}(not found in PATH){reset}");
        }
    };
    let resolved_str = resolved.display().to_string();
    let resolved_differs = resolved_str != *cmd_name;

    match std::fs::canonicalize(&resolved) {
        Ok(canonical) => {
            let canonical_str = canonical.display().to_string();
            let canonical_differs = canonical_str != resolved_str;
            match (resolved_differs, canonical_differs) {
                (false, false) => Ok(()),
                (true, false) => writeln!(w, "Resolves: {resolved_str}"),
                (false, true) => writeln!(
                    w,
                    "Resolves: {bold}{resolved_str} -> {canonical_str}{reset}"
                ),
                (true, true) => writeln!(
                    w,
                    "Resolves: {resolved_str} {bold}->{reset} {canonical_str}"
                ),
            }
        }
        Err(_) => writeln!(
            w,
            "Resolves: {resolved_str} {dim}(canonicalize failed){reset}"
        ),
    }
}

const MAX_DISPLAY_LINES: usize = 3;

/// Print a one-line non-interactive banner on /dev/tty announcing an
/// unprivileged command that is about to run. Best-effort: silently
/// returns Ok if /dev/tty cannot be opened (headless daemon).
pub fn display_banner(req: &Request) -> io::Result<()> {
    let mut tty = match OpenOptions::new().write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";
    let cmd = pipeline_join(&req.pipeline);
    if req.forward_agent {
        writeln!(tty, "{dim}\u{25b6}{reset} {cmd} {dim}(agent forwarded){reset}")?;
    } else {
        writeln!(tty, "{dim}\u{25b6}{reset} {cmd}")?;
    }
    Ok(())
}

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

/// Restores `tcsetattr` to a saved termios on drop. Manual restore would be
/// skipped on panic, leaving the user's TTY in raw (no-echo, non-canonical)
/// mode for subsequent shells.
struct TermiosGuard {
    fd: std::os::unix::io::RawFd,
    orig: libc::termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Read a single keypress from a file descriptor with a timeout using poll(2).
/// Switches the terminal to non-canonical mode so Enter is not required.
/// Returns None on timeout, Some(char) otherwise.
fn read_key_timeout(file: &File, timeout: Duration) -> io::Result<Option<u8>> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut raw = orig;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    // TCSAFLUSH (vs TCSANOW): atomically discard any input that has been
    // received but not yet read. Without this, a stray byte buffered in
    // canonical mode before the prompt arrived (a leftover Enter, a
    // mistyped keystroke, paste residue) is delivered immediately by
    // poll/read in the new raw mode; anything other than y/Y resolves as
    // Denied without the user touching the keyboard.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = TermiosGuard { fd, orig };

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_resolves(cmd_name: &str) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_resolves_line(&mut buf, cmd_name, "B", "D", "R").expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn truncate_for_display_bounds_long_commands() {
        let short = "ls -l /tmp";
        assert_eq!(truncate_for_display(short), short);

        let long: String = std::iter::repeat('x').take(MAX_DISPLAY_CMD_CHARS + 500).collect();
        let out = truncate_for_display(&long);
        assert!(out.chars().count() < long.chars().count());
        assert!(out.contains("more chars hidden"));
        // Exactly at the boundary is not truncated.
        let exact: String = std::iter::repeat('y').take(MAX_DISPLAY_CMD_CHARS).collect();
        assert_eq!(truncate_for_display(&exact), exact);
    }

    #[test]
    fn resolves_line_path_search_no_symlink() {
        // `true` resolves via PATH and is unlikely to be symlinked.
        // The line should mention the resolved path; arrow only if canonical differs.
        let out = render_resolves("true");
        assert!(out.starts_with("Resolves: "), "got: {out:?}");
        assert!(out.trim().ends_with('e') || out.contains("->"));
    }

    #[test]
    fn resolves_line_absolute_symlink_shows_arrow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target.sh");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();

        let link = tmp.path().join("foo");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let out = render_resolves(link.to_str().unwrap());
        assert!(
            out.contains("->"),
            "absolute path that is a symlink must show '->': {out:?}"
        );
        // Bold marker B should wrap the symlink redirect for visibility.
        assert!(out.contains('B'), "expected bold marker in: {out:?}");
        assert!(
            out.contains(target.to_str().unwrap()),
            "must show canonical target {target:?} in: {out:?}"
        );
    }

    #[test]
    fn resolves_line_not_in_path() {
        let out = render_resolves("definitely-no-such-binary-9f2a");
        assert!(out.contains("not found in PATH"), "got: {out:?}");
    }

    /// If a panic unwinds out of the raw-mode block, the TermiosGuard must
    /// still call tcsetattr to restore the saved flags. Without the guard,
    /// the user's tty would be left with ICANON/ECHO cleared.
    #[test]
    fn termios_guard_restores_on_panic() {
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", io::Error::last_os_error());

        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut orig) }, 0);

        // Pre-condition: the freshly-opened pty has ICANON and ECHO set.
        assert!(orig.c_lflag & libc::ICANON != 0);
        assert!(orig.c_lflag & libc::ECHO != 0);

        let result = std::panic::catch_unwind(|| {
            let _g = TermiosGuard { fd: slave, orig };
            let mut raw = orig;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            unsafe { libc::tcsetattr(slave, libc::TCSANOW, &raw) };
            panic!("synthetic panic mid-prompt");
        });
        assert!(result.is_err());

        let mut after: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut after) }, 0);
        assert_ne!(
            after.c_lflag & libc::ICANON,
            0,
            "ICANON must be restored after panic"
        );
        assert_ne!(
            after.c_lflag & libc::ECHO,
            0,
            "ECHO must be restored after panic"
        );

        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// Regression: input pending in the line-discipline buffer at the
    /// moment the prompt switches to raw mode must be discarded, not
    /// returned by the next read. Without TCSAFLUSH, a stray byte queued
    /// before the prompt was rendered would be delivered immediately and
    /// — unless it happens to be y/Y — resolve as Denied with the user
    /// having pressed nothing.
    #[test]
    fn read_key_timeout_discards_pre_prompt_input() {
        use std::os::unix::io::FromRawFd;
        use std::time::Duration;

        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", io::Error::last_os_error());

        // Stuff the input queue with a stray byte plus a newline so the
        // line discipline (still ICANON at this point) commits it.
        let stray = b"q\n";
        let n = unsafe {
            libc::write(master, stray.as_ptr() as *const libc::c_void, stray.len())
        };
        assert_eq!(n as usize, stray.len(), "write to pty master failed");
        // Give the kernel a moment to enqueue.
        std::thread::sleep(Duration::from_millis(50));

        let slave_file = unsafe { File::from_raw_fd(slave) };
        let result =
            read_key_timeout(&slave_file, Duration::from_millis(200)).expect("read_key_timeout");
        assert_eq!(
            result, None,
            "buffered input must be flushed by TCSAFLUSH (got {result:?})"
        );

        // slave_file's Drop closes slave.
        unsafe {
            libc::close(master);
        }
    }
}
