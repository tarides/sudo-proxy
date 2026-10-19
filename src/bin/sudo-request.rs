use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sudo_proxy::protocol::{Plan, Request, Response, Status};
use sudo_proxy::server::default_socket_path;

/// Default read timeout for waiting on the daemon's response. Must exceed
/// the daemon's PROMPT_TIMEOUT (60s) and EXEC_TIMEOUT (5min default) plus
/// some slack — beyond that the daemon is wedged. Override via env var
/// `SUDO_REQUEST_TIMEOUT_SECS`.
const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 600;

fn client_timeout() -> Duration {
    sudo_proxy::cli::env_timeout(
        "SUDO_REQUEST_TIMEOUT_SECS",
        Duration::from_secs(DEFAULT_CLIENT_TIMEOUT_SECS),
    )
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

    if opts.plan.is_none()
        && (opts.pipeline.is_empty() || opts.pipeline.iter().all(|s| s.is_empty()))
    {
        eprintln!("error: no command specified");
        eprintln!("Usage: sudo-request [OPTIONS] COMMAND [ARGS...] ['|' COMMAND [ARGS...] ...]");
        process::exit(1);
    }

    let socket_path = opts.socket.clone().unwrap_or_else(default_socket_path);

    let req = match build_request(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
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

/// Assemble the outgoing `Request` from parsed options. A `--plan` / `--plan-file`
/// JSON builds a structured plan request exactly as the MCP `execute` tool does
/// (`mcp::build_request`): parse the JSON into a `Plan` and call `new_plan`.
/// Otherwise the legacy flat `pipeline` is sent. The daemon re-validates either
/// way; this is only client-side assembly.
fn build_request(opts: &Opts) -> Result<Request, String> {
    let reason = opts.reason.clone().unwrap_or_default();
    if let Some(plan_json) = &opts.plan {
        let plan: Plan =
            serde_json::from_str(plan_json).map_err(|e| format!("invalid plan JSON: {e}"))?;
        Ok(Request::new_plan(
            hostname(),
            opts.session.clone(),
            plan,
            HashMap::new(),
            reason,
            opts.privileged,
            opts.forward_agent,
        ))
    } else {
        Ok(Request::new(
            hostname(),
            opts.session.clone(),
            opts.pipeline.clone(),
            HashMap::new(),
            reason,
            opts.privileged,
            opts.forward_agent,
        ))
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
    /// Raw plan JSON from `--plan` or `--plan-file`; mutually exclusive with a
    /// trailing command / pipeline.
    plan: Option<String>,
}

fn parse_args() -> Result<Opts, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = None;
    let mut reason = None;
    let mut session = String::from("sudo-request-cli");
    let mut print = false;
    let mut privileged = true;
    let mut forward_agent = false;
    let mut plan: Option<String> = None;
    let mut plan_file: Option<PathBuf> = None;
    let mut argv = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => sudo_proxy::cli::print_version("sudo-request"),
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
                eprintln!("  --plan JSON      Send a structured plan request (as the MCP does). The");
                eprintln!("                   JSON is an op-tagged Plan, e.g.");
                eprintln!(r#"                   '{{"op":"alt","steps":[{{"op":"exec","argv":["false"]}},{{"op":"exec","argv":["echo","fallback"]}}]}}'"#);
                eprintln!("  --plan-file PATH Read the plan JSON from a file ('-' for stdin)");
                eprintln!();
                eprintln!("Pipeline example:");
                eprintln!("  sudo-request --no-privilege ls /tmp '|' wc -l");
                eprintln!();
                eprintln!("Plan example (drives the full structured surface like the MCP):");
                eprintln!(r#"  sudo-request --no-privilege --plan '{{"op":"exec","argv":["id"]}}'"#);
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
            "--plan" => {
                i += 1;
                plan = Some(args.get(i).ok_or("--plan requires a JSON value")?.clone());
            }
            "--plan-file" => {
                i += 1;
                plan_file = Some(PathBuf::from(
                    args.get(i).ok_or("--plan-file requires a path")?,
                ));
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

    // Resolve the plan source: --plan (inline) or --plan-file (path, '-' = stdin).
    let plan = match (plan, plan_file) {
        (Some(_), Some(_)) => return Err("--plan and --plan-file are mutually exclusive".to_string()),
        (Some(json), None) => Some(json),
        (None, Some(path)) => Some(read_plan_file(&path)?),
        (None, None) => None,
    };

    if plan.is_some() && !pipeline.is_empty() {
        return Err(
            "provide either a plan (--plan/--plan-file) or a command/pipeline, not both".to_string(),
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
        plan,
    })
}

/// Read plan JSON from a file, or from stdin when the path is `-`.
fn read_plan_file(path: &std::path::Path) -> Result<String, String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("could not read plan from stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| format!("could not read plan file {}: {e}", path.display()))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sudo_proxy::protocol::ValidatedRequest;

    fn opts_with_plan(json: Option<&str>) -> Opts {
        Opts {
            socket: None,
            reason: None,
            session: "sudo-request-cli".to_string(),
            print: false,
            privileged: false,
            forward_agent: false,
            pipeline: vec![],
            plan: json.map(|s| s.to_string()),
        }
    }

    /// A `--plan` JSON is assembled into a plan-bearing request that the daemon's
    /// validator accepts — the same path the MCP `execute` tool takes.
    #[test]
    fn plan_json_builds_a_valid_plan_request() {
        let json = r#"{"op":"alt","steps":[{"op":"exec","argv":["false"]},{"op":"exec","argv":["true"]}]}"#;
        let req = build_request(&opts_with_plan(Some(json))).expect("build");
        assert!(req.plan.is_some(), "request must carry a plan");
        assert!(req.pipeline.is_empty(), "plan request must not carry a pipeline");
        ValidatedRequest::validate(req).expect("daemon-side validation should accept it");
    }

    /// Malformed plan JSON is rejected at assembly, before anything is sent.
    #[test]
    fn invalid_plan_json_is_rejected() {
        assert!(build_request(&opts_with_plan(Some("{not json"))).is_err());
    }

    /// With no plan, the legacy flat pipeline is sent unchanged.
    #[test]
    fn no_plan_sends_flat_pipeline() {
        let mut opts = opts_with_plan(None);
        opts.pipeline = vec![vec!["id".to_string()]];
        let req = build_request(&opts).expect("build");
        assert!(req.plan.is_none());
        assert_eq!(req.pipeline, vec![vec!["id".to_string()]]);
    }
}

