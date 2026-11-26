#![cfg(unix)]

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// C1: against a daemon that accepts but never replies, sudo-request must
/// give up within CLIENT_TIMEOUT instead of hanging forever. Drive the test
/// with SUDO_REQUEST_TIMEOUT_SECS=1 so it doesn't take 10 minutes.
#[test]
fn sudo_request_times_out_against_silent_daemon() {
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let socket = dir.path().join("p.sock");

    let listener = UnixListener::bind(&socket).expect("bind");
    let socket_for_thread = socket.clone();
    let _ = socket_for_thread; // moved into thread below

    // Fake daemon: accept the connection, drain the request, then sleep
    // forever. The client must NOT wait for us to reply.
    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut sink = [0u8; 4096];
            let _ = stream.read(&mut sink);
            // Hold the connection open without responding.
            thread::sleep(Duration::from_secs(30));
        }
    });

    let bin = env!("CARGO_BIN_EXE_sudo-request");
    let start = Instant::now();
    let output = Command::new(bin)
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--no-privilege",
            "--reason",
            "client-timeout-test",
            "true",
        ])
        .env("SUDO_REQUEST_TIMEOUT_SECS", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn sudo-request");
    let elapsed = start.elapsed();

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        elapsed < Duration::from_secs(5),
        "sudo-request took {:?} against a silent daemon — read timeout is missing",
        elapsed
    );
    assert!(
        !output.status.success(),
        "expected non-zero exit, got status={:?} stdout={} stderr={}",
        output.status,
        stdout,
        stderr
    );
    assert!(
        stderr.contains("no response from daemon") || stderr.contains("timed out"),
        "expected timeout message, got stderr: {}",
        stderr
    );

    drop(server_handle); // detach the fake daemon thread; tempdir cleans up the socket
}

// === GHSA-cpmp-67wf-gwmx: the daemon refuses a terminal other same-UID
// processes can type into, unless started with --allow-injectable-tty.

/// A `sudo-proxy` command with a controlled environment: only the variables
/// given, plus a throwaway HOME/config dir so no real hosts.json is read.
fn daemon(home: &std::path::Path, vars: &[(&str, &str)], args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sudo-proxy"));
    c.env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("cfg"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in vars {
        c.env(k, v);
    }
    c
}

#[test]
fn daemon_refuses_injectable_terminal() {
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let sock = dir.path().join("d.sock");
    for vars in [
        vec![("TERM", "tmux-256color")],
        vec![
            ("TERM", "xterm-256color"),
            ("TMUX", "/tmp/tmux-1000/default,1,0"),
        ],
        vec![("TERM", "xterm-256color"), ("DISPLAY", ":0")],
        vec![("TERM", "xterm-kitty"), ("KITTY_WINDOW_ID", "1")],
    ] {
        let out = daemon(dir.path(), &vars, &["--socket", sock.to_str().unwrap()])
            .output()
            .expect("spawn sudo-proxy");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{vars:?}: {err}");
        assert!(err.contains("refusing to start"), "{vars:?}: {err}");
        assert!(err.contains("--allow-injectable-tty"), "{vars:?}: {err}");
        assert!(
            !sock.exists(),
            "{vars:?}: must refuse before binding the socket"
        );
    }
}

#[test]
fn daemon_refuses_injectable_terminal_before_ssh_in_host_mode() {
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let out = daemon(
        dir.path(),
        &[("TERM", "screen")],
        &["--host", "example.invalid"],
    )
    .output()
    .expect("spawn sudo-proxy");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("refusing to start"), "{err}");
    // Refused before resolving the remote UID, so no hosts.json was written.
    assert!(!dir.path().join("cfg/sudo-proxy/hosts.json").exists());
}

#[test]
fn daemon_starts_on_injectable_terminal_with_override() {
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let sock = dir.path().join("d.sock");
    let mut child = daemon(
        dir.path(),
        &[("TERM", "tmux-256color")],
        &["--socket", sock.to_str().unwrap(), "--allow-injectable-tty"],
    )
    .spawn()
    .expect("spawn sudo-proxy");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let bound = sock.exists();
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        bound,
        "daemon did not bind with --allow-injectable-tty: {err}"
    );
    assert!(err.contains("WARNING"), "override must be announced: {err}");
    assert!(err.contains("TERM=tmux-256color"), "{err}");
}

#[test]
fn daemon_starts_on_clean_terminal() {
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let sock = dir.path().join("d.sock");
    let mut child = daemon(
        dir.path(),
        &[
            ("TERM", "xterm-256color"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("DISPLAY", ":0"),
        ],
        &["--socket", sock.to_str().unwrap()],
    )
    .spawn()
    .expect("spawn sudo-proxy");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let bound = sock.exists();
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(bound, "daemon refused a clean Wayland terminal: {err}");
    assert!(!err.contains("refusing"), "{err}");
}
