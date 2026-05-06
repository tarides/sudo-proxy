use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sudo_proxy::protocol::{Request, Response, Status};
use sudo_proxy::server::default_socket_path;

/// Default read timeout for waiting on the daemon's response. Must exceed
/// the daemon's PROMPT_TIMEOUT (60s) and EXEC_TIMEOUT (5min default) plus
/// some slack — beyond that the daemon is wedged. Override via env var
/// `SUDO_REQUEST_TIMEOUT_SECS`.
const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 600;

fn client_timeout() -> Duration {
    std::env::var("SUDO_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(DEFAULT_CLIENT_TIMEOUT_SECS))
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...] ['|' COMMAND [ARGS...] ...]");
            process::exit(1);
        }
    };

    if opts.pipeline.is_empty() || opts.pipeline.iter().all(|s| s.is_empty()) {
        eprintln!("error: no command specified");
        eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...] ['|' COMMAND [ARGS...] ...]");
        process::exit(1);
    }

    let socket_path = opts.socket.unwrap_or_else(default_socket_path);

    let req = Request {
        id: uuid::Uuid::new_v4().to_string(),
        host: hostname(),
        session: opts.session,
        time: now_iso8601(),
        pipeline: opts.pipeline,
        env: std::collections::HashMap::new(),
        reason: opts.reason.unwrap_or_default(),
        privileged: opts.privileged,
        forward_agent: opts.forward_agent,
        version: sudo_proxy::protocol::VERSION.to_string(),
    };

    // Connect and send
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not connect to {}: {e}", socket_path.display());
            process::exit(1);
        }
    };
    let timeout = client_timeout();
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let json = serde_json::to_string(&req).expect("serialize request");
    if let Err(e) = writeln!(stream, "{json}") {
        eprintln!("error: write failed: {e}");
        process::exit(1);
    }
    let _ = stream.flush();

    // Read response
    let reader = BufReader::new(&stream);
    let mut line = String::new();
    match reader.take(10_485_760).read_line(&mut line) {
        Ok(0) => {
            eprintln!("error: server closed connection without response");
            process::exit(1);
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!(
                "error: no response from daemon after {}s — it may be wedged or waiting on a prompt",
                timeout.as_secs()
            );
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: read failed: {e}");
            process::exit(1);
        }
    }

    let resp: Response = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: invalid response JSON: {e}");
            eprintln!("raw: {}", line.trim());
            process::exit(1);
        }
    };

    // Display response
    if opts.print {
        let mut out = std::io::stdout();
        let _ = sudo_proxy::tui::write_result(&mut out, &resp);
    } else {
        match resp.status {
            Status::Ok => {
                // Write last stage's stdout to stdout
                if let Some(ref stdout_b64) = resp.stdout {
                    if let Ok(bytes) = B64.decode(stdout_b64) {
                        let _ = std::io::stdout().write_all(&bytes);
                    }
                }
                // Write each stage's stderr to stderr
                for stage in &resp.stages {
                    if let Ok(bytes) = B64.decode(&stage.stderr) {
                        if !bytes.is_empty() {
                            let _ = std::io::stderr().write_all(&bytes);
                        }
                    }
                }
                let code = resp.exit_code();
                if code != 0 {
                    eprintln!("(exit code: {code})");
                }
                process::exit(code);
            }
            Status::Denied => {
                eprintln!("Request denied.");
                process::exit(1);
            }
            Status::Timeout => {
                eprintln!("Request timed out.");
                process::exit(1);
            }
            Status::Error => {
                eprintln!(
                    "Error: {}",
                    resp.message.as_deref().unwrap_or("unknown error")
                );
                process::exit(1);
            }
        }
    }
}

struct Opts {
    socket: Option<PathBuf>,
    reason: Option<String>,
    session: String,
    print: bool,
    privileged: bool,
    forward_agent: bool,
    pipeline: Vec<Vec<String>>,
}

fn parse_args() -> Result<Opts, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = None;
    let mut reason = None;
    let mut session = String::from("sudo-request-cli");
    let mut print = false;
    let mut privileged = true;
    let mut forward_agent = false;
    let mut argv = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("sudo-request {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...] ['|' COMMAND [ARGS...] ...]");
                eprintln!();
                eprintln!("Debug client for sudo-proxy. Supports pipelines via '|' separator.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH    Unix socket path (default: $XDG_RUNTIME_DIR/sudo-proxy.sock)");
                eprintln!("  --reason TEXT    Reason for the request");
                eprintln!("  --session NAME   Session identifier (default: sudo-request-cli)");
                eprintln!("  --print          Print all output to stdout (exit code, stdout, stderr)");
                eprintln!("  --no-privilege   Run command without privilege escalation");
                eprintln!("  --forward-agent  Forward the local SSH agent to the command (unprivileged only)");
                eprintln!();
                eprintln!("Pipeline example:");
                eprintln!("  sudo-request --no-privilege ls /tmp '|' wc -l");
                std::process::exit(0);
            }
            "--socket" => {
                i += 1;
                socket = Some(PathBuf::from(
                    args.get(i).ok_or("--socket requires a value")?,
                ));
            }
            "--reason" => {
                i += 1;
                reason = Some(
                    args.get(i)
                        .ok_or("--reason requires a value")?
                        .clone(),
                );
            }
            "--session" => {
                i += 1;
                session = args
                    .get(i)
                    .ok_or("--session requires a value")?
                    .clone();
            }
            "--print" => {
                print = true;
            }
            "--no-privilege" => {
                privileged = false;
            }
            "--forward-agent" => {
                forward_agent = true;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option: {other}"));
            }
            _ => {
                // Everything from here on is the command (with | as pipeline separator)
                argv = args[i..].to_vec();
                break;
            }
        }
        i += 1;
    }

    // Split argv on '|' to build pipeline stages
    let pipeline = split_pipeline(argv);

    if forward_agent && privileged {
        return Err(
            "--forward-agent is only allowed with --no-privilege (privileged commands cannot use the agent)"
                .to_string(),
        );
    }

    Ok(Opts {
        socket,
        reason,
        session,
        print,
        privileged,
        forward_agent,
        pipeline,
    })
}

/// Split a flat argv on literal `|` tokens into pipeline stages.
fn split_pipeline(argv: Vec<String>) -> Vec<Vec<String>> {
    if argv.is_empty() {
        return vec![];
    }
    let mut pipeline = Vec::new();
    let mut current_stage = Vec::new();
    for arg in argv {
        if arg == "|" {
            if !current_stage.is_empty() {
                pipeline.push(current_stage);
                current_stage = Vec::new();
            }
        } else {
            current_stage.push(arg);
        }
    }
    if !current_stage.is_empty() {
        pipeline.push(current_stage);
    }
    pipeline
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Convert to UTC date/time
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Date from days since epoch (simplified)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let month_days: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i as u64 + 1;
            break;
        }
        days -= md;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
