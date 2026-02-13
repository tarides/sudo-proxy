use std::path::PathBuf;
use std::process;

use sudo_proxy::mode::Mode;
use sudo_proxy::server;

struct Opts {
    socket: PathBuf,
    pkexec: bool,
    verbose: bool,
    confirm_unprivileged: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = parse_args(&args);

    let mode = Mode::detect();
    let socket_path = opts.socket;

    // Install Ctrl+C handler to clean up socket
    let cleanup_path = socket_path.clone();
    if let Err(e) = ctrlc_cleanup(cleanup_path) {
        eprintln!("warning: could not set signal handler: {e}");
    }

    if let Err(e) = server::run(&socket_path, mode, opts.pkexec, opts.verbose, opts.confirm_unprivileged) {
        eprintln!("error: {e}");
        let _ = std::fs::remove_file(&socket_path);
        process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Opts {
    let mut socket = None;
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
            "--pkexec" => pkexec = true,
            "--verbose" | "-v" => verbose = true,
            "--confirm-unprivileged" => confirm_unprivileged = true,
            "--help" | "-h" => {
                eprintln!("Usage: sudo-proxy [--socket PATH] [--pkexec] [-v] [--confirm-unprivileged]");
                eprintln!();
                eprintln!("Privileged command execution proxy.");
                eprintln!("Listens on a Unix socket for JSON requests and executes them via pkexec or sudo.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH            Socket path (default: $XDG_RUNTIME_DIR/sudo-proxy.sock)");
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

/// Register a signal handler that cleans up the socket file on SIGINT/SIGTERM.
/// Uses raw libc since we want minimal dependencies.
unsafe fn signal_hook_cleanup(path: PathBuf) {
    use std::sync::OnceLock;

    static SOCKET_PATH: OnceLock<PathBuf> = OnceLock::new();
    SOCKET_PATH.get_or_init(|| path);

    unsafe extern "C" fn handler(_sig: libc::c_int) {
        // Only async-signal-safe operations here
        if let Some(path) = SOCKET_PATH.get() {
            // Best-effort removal using libc::unlink
            let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes().to_vec());
            if let Ok(c_path) = c_path {
                libc::unlink(c_path.as_ptr());
            }
        }
        // Re-raise with default handler
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::raise(libc::SIGINT);
    }

    libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
    libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
}
