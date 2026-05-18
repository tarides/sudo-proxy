use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};

use sudo_proxy::mode::Mode;
use sudo_proxy::server;
use sudo_proxy::tui::{Prompter, ResultSink, TtyPrompter, TtyResultSink};

struct Opts {
    socket: PathBuf,
    host: Option<String>,
    login: Option<String>,
    pkexec: bool,
    verbose: bool,
    confirm_unprivileged: bool,
    forward_agent: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = parse_args(&args);

    if let Some(ref host) = opts.host {
        if let Err(e) = server::validate_host(host) {
            eprintln!("error: {e}");
            process::exit(1);
        }
        if let Some(ref login) = opts.login {
            if let Err(e) = server::validate_host(login) {
                eprintln!("error: invalid --login: {e}");
                process::exit(1);
            }
        }
        let target = sudo_proxy::hosts::ssh_target(host, opts.login.as_deref());
        run_remote(&target, opts.verbose, opts.forward_agent);
        // run_remote execs into ssh, so we only get here on error
        return;
    }

    if opts.forward_agent {
        eprintln!("error: --forward-agent requires --host (no SSH session in local mode)");
        process::exit(1);
    }

    let mode = Mode::detect();
    let socket_path = opts.socket;

    // Install Ctrl+C handler to clean up socket
    let cleanup_path = socket_path.clone();
    if let Err(e) = ctrlc_cleanup(cleanup_path) {
        eprintln!("warning: could not set signal handler: {e}");
    }

    // The TUI prompt reads /dev/tty. While a previously-approved
    // privileged child holds the foreground process group (handed off in
    // executor::run_single_command so sudo can read its password), the
    // daemon itself is in a *background* pgrp on its own controlling
    // terminal. A read from /dev/tty in that state delivers SIGTTIN to
    // the daemon's process group; the default action is to *stop* the
    // process — and nothing in this codebase ever sends SIGCONT, so the
    // daemon hangs until the user kills it. The user-visible symptom is
    // a TUI window that appears but never renders the next prompt while
    // Claude Code keeps retrying. Ignoring SIGTTIN/SIGTTOU turns those
    // background-tty races into EIO at the read site, where the prompt
    // simply errors out and the next request can proceed.
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    let prompter: Arc<dyn Prompter> = Arc::new(TtyPrompter);
    let sink: Arc<dyn ResultSink> = Arc::new(TtyResultSink);
    let shutdown = AtomicBool::new(false);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    let config = server::ServerConfig {
        mode,
        pkexec_only: opts.pkexec,
        verbose: opts.verbose,
        confirm_unprivileged: opts.confirm_unprivileged,
        ..Default::default()
    };

    if let Err(e) = server::run(
        &socket_path,
        config,
        prompter,
        sink,
        &shutdown,
        in_flight,
        tty_lock,
    ) {
        eprintln!("error: {e}");
        // Only remove the socket file if it is ours. AddrInUse means
        // another sudo-proxy is already bound there — deleting that
        // file would silently break the live daemon's reachability for
        // every subsequent client without taking it down, leaving a
        // running-but-unreachable process behind.
        if e.kind() != std::io::ErrorKind::AddrInUse {
            let _ = std::fs::remove_file(&socket_path);
        }
        process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Opts {
    let mut socket = None;
    let mut host = None;
    let mut login = None;
    let mut pkexec = false;
    let mut verbose = false;
    // Confirmation for unprivileged commands is on by default. The
    // `--confirm-unprivileged` flag is now a no-op kept for backwards
    // compatibility; pass `--no-confirm-unprivileged` to skip the gate.
    let mut confirm_unprivileged = true;
    let mut forward_agent = false;
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--socket" => socket = iter.next().map(PathBuf::from),
            s if s.starts_with("--socket=") => {
                socket = s.strip_prefix("--socket=").map(PathBuf::from);
            }
            "--host" => host = iter.next().map(|s| s.to_string()),
            s if s.starts_with("--host=") => {
                host = s.strip_prefix("--host=").map(|s| s.to_string());
            }
            "--login" => login = iter.next().map(|s| s.to_string()),
            s if s.starts_with("--login=") => {
                login = s.strip_prefix("--login=").map(|s| s.to_string());
            }
            "--pkexec" => pkexec = true,
            "--verbose" | "-v" => verbose = true,
            // Accepted for backwards compat — confirmation is now on by default.
            "--confirm-unprivileged" => confirm_unprivileged = true,
            "--no-confirm-unprivileged" => confirm_unprivileged = false,
            "--forward-agent" => forward_agent = true,
            "--version" | "-V" => {
                println!("sudo-proxy {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                eprintln!("Usage: sudo-proxy [--socket PATH] [--host HOST] [--pkexec] [-v] [--no-confirm-unprivileged] [--forward-agent]");
                eprintln!();
                eprintln!("Privileged command execution proxy.");
                eprintln!("Listens on a Unix socket for JSON requests and executes them via pkexec or sudo.");
                eprintln!("Every command (privileged or not) goes through the TUI Y/N gate by default.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH               Socket path (default: $XDG_RUNTIME_DIR/sudo-proxy.sock)");
                eprintln!("  --host HOST                 Connect to remote host via SSH tunnel");
                eprintln!("  --pkexec                    Use pkexec directly (no TUI prompt, pkexec handles both auth and approval)");
                eprintln!("  --verbose, -v               Print startup info and log each request to stderr");
                eprintln!("  --no-confirm-unprivileged   Skip the Y/N gate for unprivileged commands (batch/automation)");
                eprintln!("  --confirm-unprivileged      No-op (kept for backwards compat — this is now the default)");
                eprintln!("  --forward-agent             With --host: enable SSH agent forwarding (-A) so unprivileged");
                eprintln!("                              commands that opt in via forward_agent can use the local agent");
                std::process::exit(0);
            }
            _ => {
                eprintln!("unknown option: {arg}");
                std::process::exit(1);
            }
        }
    }
    Opts {
        socket: socket.unwrap_or_else(server::default_socket_path),
        host,
        login,
        pkexec,
        verbose,
        confirm_unprivileged,
        forward_agent,
    }
}

fn ctrlc_cleanup(socket_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    // Use a simple SIGINT handler that removes the socket and re-raises
    let path = socket_path.clone();
    unsafe {
        signal_hook_cleanup(path);
    }
    Ok(())
}

/// Register a signal handler that cleans up the socket file on
/// SIGINT/SIGTERM/SIGHUP. Uses raw libc since we want minimal dependencies.
unsafe fn signal_hook_cleanup(path: PathBuf) {
    use std::sync::OnceLock;

    static SOCKET_PATH: OnceLock<PathBuf> = OnceLock::new();
    SOCKET_PATH.get_or_init(|| path);

    unsafe extern "C" fn handler(sig: libc::c_int) {
        // Only async-signal-safe operations here
        if let Some(path) = SOCKET_PATH.get() {
            // Best-effort removal using libc::unlink
            let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes().to_vec());
            if let Ok(c_path) = c_path {
                libc::unlink(c_path.as_ptr());
            }
        }
        // Re-raise with default handler so wait status reflects the real signal
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }

    libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
    libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
    libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
}

/// Connect to a remote host: resolve UID, set up SSH tunnel, exec into SSH.
fn run_remote(host: &str, verbose: bool, forward_agent: bool) {
    use std::os::unix::process::CommandExt;
    use sudo_proxy::hosts::HostsConfig;

    // Resolve remote UID (cached or via SSH)
    let mut config = HostsConfig::load();
    let uid = match config.resolve_uid(host) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let local_sock = server::remote_socket_path(host);
    let remote_sock = format!("/run/user/{uid}/sudo-proxy.sock");
    let tunnel = format!("{}:{remote_sock}", local_sock.display());

    // Remove stale local socket if present
    if local_sock.exists() {
        let _ = std::fs::remove_file(&local_sock);
    }

    // Install signal handler to clean up local socket
    if let Err(e) = ctrlc_cleanup(local_sock.clone()) {
        eprintln!("warning: could not set signal handler: {e}");
    }

    // Touch host record
    config.touch(host);
    config.save();

    let mut ssh_args: Vec<&str> = vec![
        "-t",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        // Silence the "channel N: open failed: connect failed: open
        // failed" lines that ssh prints to the terminal each time the
        // MCP readiness probe connects to the local end of -L before
        // the remote sudo-proxy has bound its socket. Channel-open
        // failures log at INFO; LogLevel=ERROR drops them while keeping
        // auth failures, host-key mismatches, and other real errors
        // visible.
        "-o", "LogLevel=ERROR",
        "-L", &tunnel,
    ];
    if forward_agent {
        ssh_args.push("-A");
    }
    ssh_args.push(host);
    ssh_args.push("sudo-proxy");

    if verbose {
        eprintln!("+ ssh {}", ssh_args.join(" "));
    }

    // exec replaces this process with SSH — no child to manage
    let err = std::process::Command::new("ssh")
        .args(&ssh_args)
        .exec();

    // exec() only returns on error
    eprintln!("error: failed to exec ssh: {err}");
    let _ = std::fs::remove_file(&local_sock);
    process::exit(1);
}
