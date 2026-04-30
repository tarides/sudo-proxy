use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;

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
        run_remote(&target, opts.verbose);
        // run_remote execs into ssh, so we only get here on error
        return;
    }

    let mode = Mode::detect();
    let socket_path = opts.socket;

    // Install Ctrl+C handler to clean up socket
    let cleanup_path = socket_path.clone();
    if let Err(e) = ctrlc_cleanup(cleanup_path) {
        eprintln!("warning: could not set signal handler: {e}");
    }

    let prompter: Arc<dyn Prompter> = Arc::new(TtyPrompter);
    let sink: Arc<dyn ResultSink> = Arc::new(TtyResultSink);
    let shutdown = AtomicBool::new(false);
    let in_flight = Arc::new(AtomicUsize::new(0));

    if let Err(e) = server::run(
        &socket_path,
        mode,
        opts.pkexec,
        opts.verbose,
        opts.confirm_unprivileged,
        prompter,
        sink,
        &shutdown,
        in_flight,
    ) {
        eprintln!("error: {e}");
        let _ = std::fs::remove_file(&socket_path);
        process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Opts {
    let mut socket = None;
    let mut host = None;
    let mut login = None;
    let mut pkexec = false;
    let mut verbose = false;
    let mut confirm_unprivileged = false;
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
            "--confirm-unprivileged" => confirm_unprivileged = true,
            "--version" | "-V" => {
                println!("sudo-proxy {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                eprintln!("Usage: sudo-proxy [--socket PATH] [--host HOST] [--pkexec] [-v] [--confirm-unprivileged]");
                eprintln!();
                eprintln!("Privileged command execution proxy.");
                eprintln!("Listens on a Unix socket for JSON requests and executes them via pkexec or sudo.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH            Socket path (default: $XDG_RUNTIME_DIR/sudo-proxy.sock)");
                eprintln!("  --host HOST              Connect to remote host via SSH tunnel");
                eprintln!("  --pkexec                 Use pkexec directly (no TUI prompt, pkexec handles both auth and approval)");
                eprintln!("  --verbose, -v            Print startup info and log each request to stderr");
                eprintln!("  --confirm-unprivileged   Prompt for confirmation before running non-privileged commands");
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
fn run_remote(host: &str, verbose: bool) {
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

    let ssh_args = [
        "-t",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-L", &tunnel,
        host, "sudo-proxy",
    ];

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
