use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::executor::{exec_direct, exec_pkexec, exec_sudo, sanitize_env};
use crate::mode::Mode;
use crate::protocol::{Request, Response};
use crate::tui;

const MAX_SEEN_IDS: usize = 1000;
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUEST_AGE: Duration = Duration::from_secs(60);

/// Characters forbidden in argv strings (control chars, bidi overrides, zero-width).
fn has_dangerous_chars(s: &str) -> bool {
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

fn validate_request(req: &Request) -> Result<(), String> {
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
    // Validate env keys too
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
    Ok(())
}

fn check_replay(req: &Request, seen_ids: &HashSet<String>) -> Result<(), String> {
    if seen_ids.contains(&req.id) {
        return Err(format!("duplicate request id: {}", req.id));
    }
    if !req.time.is_empty() {
        // Parse ISO 8601 timestamp manually (avoid chrono dependency)
        if let Some(age) = parse_age(&req.time) {
            if age > MAX_REQUEST_AGE {
                return Err(format!(
                    "request too old: {}s (max {}s)",
                    age.as_secs(),
                    MAX_REQUEST_AGE.as_secs()
                ));
            }
        }
        // If we can't parse the time, we allow it (be lenient)
    }
    Ok(())
}

/// Parse an ISO 8601 UTC timestamp and return its age relative to now.
fn parse_age(timestamp: &str) -> Option<Duration> {
    // Expect format: 2026-02-13T14:30:00Z or similar
    // Minimal parser for YYYY-MM-DDTHH:MM:SSZ
    let ts = timestamp.trim().trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?;

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|s| s.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);
    let (hour, min, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    // Days in each month (non-leap). Good enough for age checking.
    let days_before_month: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    if month < 1 || month > 12 {
        return None;
    }
    let mut days = (year - 1970) * 365 + (year - 1969) / 4;
    days += days_before_month[(month - 1) as usize] + (day - 1);
    // Leap year correction for current year
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days += 1;
    }
    let ts_secs = days * 86400 + hour * 3600 + min * 60 + sec;

    let now_secs = now.as_secs();
    if ts_secs > now_secs {
        Some(Duration::from_secs(0))
    } else {
        Some(Duration::from_secs(now_secs - ts_secs))
    }
}

pub fn default_socket_path() -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
    PathBuf::from(runtime_dir).join("sudo-proxy.sock")
}

/// Local tunnel endpoint path for a remote host's sudo-proxy socket.
pub fn remote_socket_path(host: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/sudo-proxy-{host}.sock"))
}

pub fn run(
    socket_path: &Path,
    mode: Mode,
    pkexec_only: bool,
    verbose: bool,
    confirm_unprivileged: bool,
) -> std::io::Result<()> {
    // Remove stale socket
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set socket permissions to 0600
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;

    if verbose {
        eprintln!("sudo-proxy listening on {}", socket_path.display());
        eprintln!("mode: {}", mode.label());
    }

    let mut seen_ids: HashSet<String> = HashSet::new();

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        let reader = BufReader::new(&stream);
        let mut line = String::new();
        match reader.take(1_048_576).read_line(&mut line) {
            Ok(0) => continue, // empty connection
            Ok(_) => {}
            Err(e) => {
                let resp = Response::error("", &format!("read error: {e}"));
                let _ = write_response(&mut stream, &resp);
                continue;
            }
        }

        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::error("", &format!("invalid JSON: {e}"));
                let _ = write_response(&mut stream, &resp);
                continue;
            }
        };

        // Validate request
        if let Err(msg) = validate_request(&req) {
            let resp = Response::error(&req.id, &msg);
            let _ = write_response(&mut stream, &resp);
            continue;
        }

        // Replay protection
        if let Err(msg) = check_replay(&req, &seen_ids) {
            let resp = Response::error(&req.id, &msg);
            let _ = write_response(&mut stream, &resp);
            continue;
        }

        // Sanitize environment
        let env = match sanitize_env(&req.env) {
            Ok(e) => e,
            Err(msg) => {
                let resp = Response::error(&req.id, &msg);
                let _ = write_response(&mut stream, &resp);
                continue;
            }
        };

        // Track this ID
        if seen_ids.len() >= MAX_SEEN_IDS {
            seen_ids.clear();
        }
        seen_ids.insert(req.id.clone());

        if verbose {
            let priv_label = if req.privileged { "privileged" } else { "unprivileged" };
            let pipeline_display = crate::tui::pipeline_join(&req.pipeline);
            eprintln!("[{}] [{}] {}", req.id, priv_label, pipeline_display);
        }

        let resp = if req.privileged {
            if pkexec_only && mode == Mode::Local {
                // --pkexec: old behavior — pkexec handles both auth and approval
                exec_pkexec(&req, &env)
            } else {
                // Default: TUI prompt first, then sudo for escalation
                match tui::prompt_tty(&req, PROMPT_TIMEOUT) {
                    Ok(tui::PromptResult::Approved) => exec_sudo(&req, &env),
                    Ok(tui::PromptResult::Denied) => Response::denied(&req.id),
                    Ok(tui::PromptResult::Timeout) => Response::timeout(&req.id),
                    Err(e) => Response::error(&req.id, &format!("TUI error: {e}")),
                }
            }
        } else if confirm_unprivileged {
            // Non-privileged with confirmation: always TUI
            match tui::prompt_tty(&req, PROMPT_TIMEOUT) {
                Ok(tui::PromptResult::Approved) => exec_direct(&req, &env),
                Ok(tui::PromptResult::Denied) => Response::denied(&req.id),
                Ok(tui::PromptResult::Timeout) => Response::timeout(&req.id),
                Err(e) => Response::error(&req.id, &format!("prompt error: {e}")),
            }
        } else {
            // Non-privileged, no confirmation: run directly
            exec_direct(&req, &env)
        };

        // Echo result on /dev/tty for all privileged commands
        if req.privileged && !pkexec_only {
            let _ = tui::display_result(&resp);
        }

        let _ = write_response(&mut stream, &resp);
    }

    Ok(())
}

fn write_response(stream: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    let json = serde_json::to_string(resp).unwrap_or_else(|_| {
        r#"{"id":"","status":"error","message":"serialization failed"}"#.to_string()
    });
    writeln!(stream, "{json}")?;
    stream.flush()
}
