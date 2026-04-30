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
        stderr.contains("no response from daemon")
            || stderr.contains("timed out"),
        "expected timeout message, got stderr: {}",
        stderr
    );

    drop(server_handle); // detach the fake daemon thread; tempdir cleans up the socket
}
