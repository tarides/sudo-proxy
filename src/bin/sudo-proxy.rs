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
    /// Log each request's command (the `plan`) as pretty-printed JSON to stderr.
    log_json: bool,
    /// `None` = take the default from `hosts.json` (`policy.unattended_eligible`).
    /// `Some(_)` = an explicit CLI flag was passed and overrides the file.
    unattended_eligible: Option<bool>,
    /// `None` = take the default from `hosts.json` (`policy.no_shell`).
    /// `Some(_)` = `--no-shell` / `--allow-shell` was passed and overrides it.
    no_shell: Option<bool>,
    forward_agent: bool,
    /// `--audit-log PATH`: overrides the default audit file location.
    audit_log: Option<PathBuf>,
    /// `--no-audit-log`: disable the audit file (the stderr line stays).
    no_audit_log: bool,
    /// `--no-syslog`: disable the syslog audit sink.
    no_syslog: bool,
    /// `--allow-injectable-tty` (GHSA-cpmp-67wf-gwmx). Deliberately a CLI
    /// flag only, with no `hosts.json` equivalent: an agent can write that
    /// file, then restart the daemon through `sudo-proxy-mcp`, which never
    /// passes this flag.
    allow_injectable_tty: bool,
    /// `--sudo-path` (GHSA-gx9w-4f7x-2gcp): the `sudo` to run instead of the
    /// trusted one found on the fixed helper path. CLI only, like
    /// `--allow-injectable-tty`: no `hosts.json` or environment equivalent,
    /// never forwarded by `--host`, never passed by `sudo-proxy-mcp`.
    sudo_path: Option<PathBuf>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = parse_args(&args);

    if let Some(ref host) = opts.host {
        if opts.sudo_path.is_some() {
            eprintln!("error: --sudo-path applies to the daemon; pass it on the remote host, not with --host");
            process::exit(1);
        }
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
        // `--no-shell` only tightens, so it is forwarded to the remote daemon
        // (an older remote rejects the unknown flag and fails closed).
        // Loosening a remote's own `policy.no_shell` from here is refused.
        if opts.no_shell == Some(false) {
            eprintln!("error: --allow-shell is not forwarded with --host; edit policy.no_shell in the remote hosts.json");
            process::exit(1);
        }
        // The remote prompt is answered through *this* terminal, so it is
        // this terminal that must not accept injected keystrokes.
        let overridden = !tty_gate(opts.allow_injectable_tty).is_empty();
        run_remote(
            &target,
            opts.verbose,
            opts.forward_agent,
            opts.no_shell == Some(true),
            overridden,
        );
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
    let shutdown = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    // Resolve both hosts.json policy settings: an explicit CLI flag wins;
    // otherwise the file's `policy`; otherwise the built-in default. The file
    // is read only if a flag is missing, and trusted only if no other
    // principal could have written it (StrictModes-style check,
    // GHSA-xx2m-j9f7-gcmr). An untrusted file fails closed for each setting:
    // not unattended-eligible (barrier 1 of G7, an out-of-band operator
    // opt-in that nothing on the wire can change), and strict no-shell mode
    // on, so a writable file cannot quietly switch it off.
    let policy = (opts.unattended_eligible.is_none() || opts.no_shell.is_none())
        .then(sudo_proxy::hosts::load_trusted_policy);
    if let Some(Err(why)) = &policy {
        let mut effects = Vec::new();
        if opts.unattended_eligible.is_none() {
            effects.push("not unattended-eligible");
        }
        if opts.no_shell.is_none() {
            effects.push("no_shell on");
        }
        eprintln!("sudo-proxy: ignoring hosts.json policy ({}): {why}", effects.join(", "));
    }
    let policy = policy.and_then(Result::ok);
    let unattended_eligible = opts
        .unattended_eligible
        .unwrap_or_else(|| policy.as_ref().is_some_and(|p| p.unattended_eligible));
    let no_shell = opts
        .no_shell
        .unwrap_or_else(|| policy.as_ref().is_none_or(|p| p.no_shell));

    // GHSA-cpmp-67wf-gwmx: refuse a terminal other same-UID processes can
    // type into, unless overridden. Under --pkexec, privileged requests are
    // approved in polkit's dialog, not here, and an injected key at the TTY
    // prompt yields only unprivileged execution, which such a process
    // already has — so the check is skipped.
    if !opts.pkexec {
        let reasons = tty_gate(opts.allow_injectable_tty);
        sudo_proxy::tui::set_injectable_tty_warning(reasons);
    }

    // GHSA-gx9w-4f7x-2gcp: resolve the escalators now, never on our own PATH,
    // and say which files they are. Under --pkexec, plans pkexec cannot take
    // still go through sudo, so both are reported.
    if let Some(ref p) = opts.sudo_path {
        if let Err(e) = sudo_proxy::helper::set_sudo_override(p) {
            eprintln!("error: {e}");
            process::exit(1);
        }
        eprintln!(
            "sudo-proxy: WARNING: running {} as sudo (--sudo-path; not checked for root ownership)",
            p.display()
        );
    }
    let mut escalators = vec![("sudo", sudo_proxy::helper::sudo())];
    if opts.pkexec {
        escalators.push(("pkexec", sudo_proxy::helper::pkexec()));
    }
    for (name, found) in escalators {
        match found {
            Ok(p) if opts.verbose => eprintln!("sudo-proxy: {name}: {}", p.display()),
            Ok(_) => {}
            Err(e) => eprintln!("sudo-proxy: warning: {e}; requests that need {name} will fail"),
        }
    }

    let config = server::ServerConfig {
        mode,
        pkexec_only: opts.pkexec,
        verbose: opts.verbose,
        log_json: opts.log_json,
        unattended_eligible,
        no_shell,
        audit: audit_config(opts.audit_log, opts.no_audit_log, opts.no_syslog),
        ..Default::default()
    };

    match server::run(
        &socket_path,
        config,
        prompter,
        sink,
        Arc::clone(&shutdown),
        in_flight,
        tty_lock,
    ) {
        // Clean return: only reachable via a stop request. Remove our
        // socket so the next start doesn't find a stale file, then exit 0
        // — the terminal window closes with us, and for a remote daemon
        // the command-mode SSH session (and its tunnel) ends too.
        Ok(()) => {
            let _ = std::fs::remove_file(&socket_path);
        }
        Err(e) => {
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
}

/// Audit sinks (issue #65): the JSONL file and syslog are on by default.
fn audit_config(
    audit_log: Option<PathBuf>,
    no_audit_log: bool,
    no_syslog: bool,
) -> sudo_proxy::audit::AuditConfig {
    let file = if no_audit_log {
        None
    } else {
        match audit_log.or_else(sudo_proxy::audit::default_audit_path) {
            Some(p) => Some(p),
            None => {
                eprintln!(
                    "error: cannot locate the audit log (neither XDG_STATE_HOME nor HOME is \
                     an absolute path); pass --audit-log PATH or --no-audit-log"
                );
                process::exit(1);
            }
        }
    };
    sudo_proxy::audit::AuditConfig {
        file,
        syslog: !no_syslog,
    }
}

/// GHSA-cpmp-67wf-gwmx: check that this terminal does not accept keystrokes
/// injected by other same-UID processes. Prints any warnings. When injectors
/// are found and `allow` is false, prints the refusal and exits 1 (holding
/// the window open first if `sudo-proxy-mcp` spawned it). Returns the
/// injector reasons when overridden (empty when the terminal is clean).
fn tty_gate(allow: bool) -> Vec<String> {
    use sudo_proxy::ttyguard;
    let a = ttyguard::assess(&ttyguard::probe());
    for w in &a.warnings {
        eprintln!("sudo-proxy: warning: {w}");
    }
    if a.injectors.is_empty() {
        return Vec::new();
    }
    if !allow {
        eprintln!("{}", ttyguard::refusal_message(&a));
        if std::env::var_os(ttyguard::HOLD_ENV).is_some_and(|v| !v.is_empty()) {
            // Spawned in a window of its own: keep it open so the reason
            // can be read before it closes.
            eprintln!("\nPress Enter to close this window.");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
        }
        process::exit(1);
    }
    eprintln!(
        "sudo-proxy: WARNING: other processes running as you can type into this terminal; \
         starting anyway (--allow-injectable-tty):"
    );
    for i in &a.injectors {
        eprintln!("  - {i}");
    }
    a.injectors
}

fn parse_args(args: &[String]) -> Opts {
    let mut socket = None;
    let mut host = None;
    let mut login = None;
    let mut pkexec = false;
    let mut verbose = false;
    let mut log_json = false;
    // Tri-state: None means "no CLI flag passed, use hosts.json policy",
    // Some(_) means an explicit flag overrides the file.
    let mut unattended_eligible: Option<bool> = None;
    let mut no_shell: Option<bool> = None;
    let mut forward_agent = false;
    let mut audit_log = None;
    let mut no_audit_log = false;
    let mut no_syslog = false;
    let mut allow_injectable_tty = false;
    let mut sudo_path = None;
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
            "--log-json" => log_json = true,
            "--unattended-eligible" => unattended_eligible = Some(true),
            "--no-unattended-eligible" => unattended_eligible = Some(false),
            "--no-shell" => no_shell = Some(true),
            "--allow-shell" => no_shell = Some(false),
            "--forward-agent" => forward_agent = true,
            "--audit-log" => match iter.next() {
                Some(p) => audit_log = Some(PathBuf::from(p)),
                None => {
                    eprintln!("--audit-log requires a PATH");
                    std::process::exit(1);
                }
            },
            s if s.starts_with("--audit-log=") => {
                audit_log = s.strip_prefix("--audit-log=").map(PathBuf::from);
            }
            "--no-audit-log" => no_audit_log = true,
            "--no-syslog" => no_syslog = true,
            "--allow-injectable-tty" => allow_injectable_tty = true,
            "--sudo-path" => match iter.next() {
                Some(v) => sudo_path = Some(PathBuf::from(v)),
                None => {
                    eprintln!("error: --sudo-path requires a value");
                    std::process::exit(1);
                }
            },
            s if s.starts_with("--sudo-path=") => {
                sudo_path = s.strip_prefix("--sudo-path=").map(PathBuf::from);
            }
            "--version" | "-V" => sudo_proxy::cli::print_version("sudo-proxy"),
            "--help" | "-h" => {
                eprintln!("Usage: sudo-proxy [--socket PATH] [--host HOST] [--pkexec] [-v] [--log-json] [--unattended-eligible] [--no-shell] [--forward-agent] [--audit-log PATH | --no-audit-log] [--no-syslog] [--allow-injectable-tty] [--sudo-path PATH]");
                eprintln!();
                eprintln!("Privileged command execution proxy.");
                eprintln!("Listens on a Unix socket for JSON requests and executes them via pkexec or sudo.");
                eprintln!("Every command (privileged or not) goes through the TUI Y/N gate.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --socket PATH               Socket path (default: $XDG_RUNTIME_DIR/sudo-proxy.sock)");
                eprintln!("  --host HOST                 Connect to remote host via SSH tunnel");
                eprintln!("  --pkexec                    Delegate approval of single-step, unredirected privileged requests to pkexec's dialog (no TUI prompt); other privileged plans still get the TUI prompt and sudo");
                eprintln!("  --verbose, -v               Print startup info and log each request to stderr");
                eprintln!("  --log-json                  Log each request's plan as pretty-printed JSON to stderr");
                eprintln!("  --unattended-eligible       Allow a human to grant unattended unprivileged execution");
                eprintln!("                              for this session via the prompt's `a` answer (overrides hosts.json;");
                eprintln!("                              the grant is in-memory only and never persisted)");
                eprintln!("                              Without the flag, hosts.json's policy is used only if the file");
                eprintln!("                              and its directories are yours and not group/world-writable");
                eprintln!("  --no-shell                  Reject, before prompting, any request with an opaque stage:");
                eprintln!("                              a `shell` op or an `exec` of a shell (sh -c, bash script.sh)");
                eprintln!("                              (overrides hosts.json policy.no_shell; forwarded with --host)");
                eprintln!("  --allow-shell               Allow opaque stages (flagged at the prompt) even if hosts.json");
                eprintln!("                              sets policy.no_shell (local daemon only)");
                eprintln!("  --forward-agent             With --host: enable SSH agent forwarding (-A) so unprivileged");
                eprintln!("                              commands that opt in via forward_agent can use the local agent");
                eprintln!("  --audit-log PATH            Audit log file (JSON lines, mode 0600, append-only)");
                eprintln!("                              (default: $XDG_STATE_HOME/sudo-proxy/audit.jsonl,");
                eprintln!("                              else ~/.local/state/sudo-proxy/audit.jsonl)");
                eprintln!("  --no-audit-log              Do not write the audit file (stderr audit lines remain)");
                eprintln!("  --no-syslog                 Do not send audit records to syslog (LOG_AUTHPRIV)");
                eprintln!("  --allow-injectable-tty      Start even if other processes running as you can type into this");
                eprintln!("                              terminal (tmux/screen, kitty/wezterm remote control, X11, …) and");
                eprintln!("                              so answer the prompt; every prompt then shows a warning");
                eprintln!("                              (no hosts.json equivalent: whoever starts the daemon decides)");
                eprintln!("  --sudo-path PATH            Run PATH as sudo. Without it, sudo is the first setuid-root sudo");
                eprintln!("                              in a root-owned directory on a fixed list (never this process's");
                eprintln!("                              PATH); PATH given here is not checked for ownership");
                eprintln!("                              (no hosts.json equivalent; not forwarded with --host)");
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
        log_json,
        unattended_eligible,
        no_shell,
        forward_agent,
        audit_log,
        no_audit_log,
        no_syslog,
        allow_injectable_tty,
        sudo_path,
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
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;

    // Store the NUL-terminated path built ONCE, at registration time. The
    // handler must do no allocation: CString::new / to_string_lossy call
    // malloc, which is not async-signal-safe and can deadlock if a signal
    // interrupts an in-progress allocation.
    static SOCKET_PATH: OnceLock<CString> = OnceLock::new();
    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        SOCKET_PATH.get_or_init(|| c_path);
    }

    unsafe extern "C" fn handler(sig: libc::c_int) {
        // Only async-signal-safe operations here: a pointer read and unlink().
        if let Some(c_path) = SOCKET_PATH.get() {
            libc::unlink(c_path.as_ptr());
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
fn run_remote(
    host: &str,
    verbose: bool,
    forward_agent: bool,
    no_shell: bool,
    allow_injectable_tty: bool,
) {
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
    if no_shell {
        ssh_args.push("--no-shell");
    }
    // The override was accepted for the terminal the remote prompt shows in;
    // pass it on so the remote daemon (whose TERM comes from here) agrees.
    // A remote older than 1.2.2 rejects the flag and exits: fail closed.
    if allow_injectable_tty {
        ssh_args.push("--allow-injectable-tty");
    }

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
