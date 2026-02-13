use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sudo_proxy::protocol::{Request, Response, Status};
use sudo_proxy::server::default_socket_path;

const SSH_TUNNEL_TIMEOUT: Duration = Duration::from_secs(30);
fn resolve_remote_socket(host: &str) -> String {
    let output = Command::new("ssh")
        .args([host, "id", "-u"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let uid = String::from_utf8_lossy(&o.stdout).trim().to_string();
            format!("/run/user/{uid}/sudo-proxy.sock")
        }
        _ => {
            eprintln!("warning: could not resolve remote UID, assuming 1000");
            "/run/user/1000/sudo-proxy.sock".to_string()
        }
    }
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...]");
            process::exit(1);
        }
    };

    if opts.argv.is_empty() {
        eprintln!("error: no command specified");
        eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...]");
        process::exit(1);
    }

    let mut ssh_child: Option<Child> = None;
    let mut local_sock_cleanup: Option<String> = None;

    let socket_path = if let Some(ref host) = opts.host {
        let local_sock = format!("/tmp/sudo-request-{}.sock", process::id());
        let remote_sock = opts
            .socket
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| resolve_remote_socket(host));

        // Start SSH: allocate PTY, set up tunnel, run sudo-proxy on remote
        let tunnel_spec = format!("{local_sock}:{remote_sock}");
        let ssh_args = vec!["-t", "-L", &tunnel_spec, host, "sudo-proxy"];

        if opts.verbose {
            eprintln!("+ ssh {}", ssh_args.join(" "));
        }

        let child = match Command::new("ssh")
            .args(&ssh_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: failed to start ssh: {e}");
                process::exit(1);
            }
        };

        ssh_child = Some(child);
        local_sock_cleanup = Some(local_sock.clone());

        // Wait for the tunnel socket to appear
        if !wait_for_socket(&local_sock, SSH_TUNNEL_TIMEOUT, ssh_child.as_mut().unwrap()) {
            cleanup(&mut ssh_child, &local_sock_cleanup);
            process::exit(1);
        }

        PathBuf::from(local_sock)
    } else {
        opts.socket.unwrap_or_else(default_socket_path)
    };

    let req = Request {
        id: uuid::Uuid::new_v4().to_string(),
        host: hostname(),
        session: opts.session,
        time: now_iso8601(),
        argv: opts.argv,
        env: std::collections::HashMap::new(),
        reason: opts.reason.unwrap_or_default(),
        privileged: opts.privileged,
    };

    // Connect and send
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not connect to {}: {e}", socket_path.display());
            cleanup(&mut ssh_child, &local_sock_cleanup);
            process::exit(1);
        }
    };

    let json = serde_json::to_string(&req).expect("serialize request");
    if let Err(e) = writeln!(stream, "{json}") {
        eprintln!("error: write failed: {e}");
        cleanup(&mut ssh_child, &local_sock_cleanup);
        process::exit(1);
    }
    let _ = stream.flush();

    // Read response
    let reader = BufReader::new(&stream);
    let mut line = String::new();
    match reader.take(10_485_760).read_line(&mut line) {
        Ok(0) => {
            eprintln!("error: server closed connection without response");
            cleanup(&mut ssh_child, &local_sock_cleanup);
            process::exit(1);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: read failed: {e}");
            cleanup(&mut ssh_child, &local_sock_cleanup);
            process::exit(1);
        }
    }

    cleanup(&mut ssh_child, &local_sock_cleanup);

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
                if let Some(ref stdout_b64) = resp.stdout {
                    if let Ok(bytes) = B64.decode(stdout_b64) {
                        let _ = std::io::stdout().write_all(&bytes);
                    }
                }
                if let Some(ref stderr_b64) = resp.stderr {
                    if let Ok(bytes) = B64.decode(stderr_b64) {
                        let _ = std::io::stderr().write_all(&bytes);
                    }
                }
                let code = resp.exit_code.unwrap_or(0);
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

/// Wait for a Unix socket file to appear, polling every 100ms.
/// Returns false if timeout expires or SSH exits early.
fn wait_for_socket(path: &str, timeout: Duration, child: &mut Child) -> bool {
    let deadline = Instant::now() + timeout;
    while !Path::new(path).exists() {
        if Instant::now() > deadline {
            eprintln!("error: timeout waiting for SSH tunnel socket");
            return false;
        }
        // Check if SSH exited unexpectedly
        if let Ok(Some(status)) = child.try_wait() {
            eprintln!("error: ssh exited early with {status}");
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

fn cleanup(ssh_child: &mut Option<Child>, local_sock: &Option<String>) {
    if let Some(ref mut child) = ssh_child {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(ref path) = local_sock {
        let _ = std::fs::remove_file(path);
    }
}

struct Opts {
    socket: Option<PathBuf>,
    host: Option<String>,
    reason: Option<String>,
    session: String,
    print: bool,
    verbose: bool,
    privileged: bool,
    argv: Vec<String>,
}

fn parse_args() -> Result<Opts, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = None;
    let mut host = None;
    let mut reason = None;
    let mut session = String::from("sudo-request-cli");
    let mut print = false;
    let mut verbose = false;
    let mut privileged = true;
    let mut argv = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...]");
                eprintln!();
                eprintln!("Debug client for sudo-proxy.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH    Unix socket path");
                eprintln!("  --host HOST      Remote host (sets up SSH tunnel)");
                eprintln!("  --reason TEXT    Reason for the request");
                eprintln!("  --session NAME   Session identifier (default: sudo-request-cli)");
                eprintln!("  --print          Print all output to stdout (exit code, stdout, stderr)");
                eprintln!("  --verbose        Echo the ssh command when using --host");
                eprintln!("  --no-privilege   Run command without privilege escalation");
                std::process::exit(0);
            }
            "--socket" => {
                i += 1;
                socket = Some(PathBuf::from(
                    args.get(i).ok_or("--socket requires a value")?,
                ));
            }
            "--host" => {
                i += 1;
                host = Some(
                    args.get(i)
                        .ok_or("--host requires a value")?
                        .clone(),
                );
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
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--no-privilege" => {
                privileged = false;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option: {other}"));
            }
            _ => {
                // Everything from here on is the command
                argv = args[i..].to_vec();
                break;
            }
        }
        i += 1;
    }

    Ok(Opts {
        socket,
        host,
        reason,
        session,
        print,
        verbose,
        privileged,
        argv,
    })
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

