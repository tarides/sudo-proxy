#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use sudo_proxy::protocol::Status;
use sudo_proxy::tui::PromptResult;

mod common;
use common::*;

/// Failure mode #3 (FIXED): under the old serial daemon, a 65s prompt
/// for A wedged the accept loop, so B sat in the kernel backlog. By the
/// time the daemon read B, B's `time` had aged past MAX_REQUEST_AGE and
/// B was rejected as `request too old`. With thread-per-connection,
/// B's connection thread starts immediately on accept; freshness is
/// checked while B is still fresh, and B succeeds.
///
/// Setup: confirm_unprivileged=false, so B (privileged=false) skips the
/// prompter entirely and runs `exec_direct` while A (privileged=true)
/// is still in its 65s prompt. A's prompter returns Denied so we don't
/// drag a real `sudo` into the test.
///
/// Runs ~65s; gated behind --ignored. Real time-passage on A's prompt
/// is what proves the freshness check is decoupled from prompt
/// serialization — under the old code, B would have been rejected.
#[test]
#[ignore]
fn request_queued_behind_slow_prompt_completes_normally() {
    let opts = TestServerOpts {
        confirm_unprivileged: false,
        ..Default::default()
    };
    let s = start_test_server(opts);

    s.prompter
        .set_response(|_| (Duration::from_secs(65), PromptResult::Denied));

    let path_a = s.socket_path.clone();
    let path_b = s.socket_path.clone();

    let t_a = thread::spawn(move || {
        let mut req = make_req("queue-A", vec![vec!["true"]]);
        req.privileged = true;
        send_request(&path_a, &req)
    });

    // Wait until A has actually entered the prompter (so the TTY lock is
    // taken and we're in the wedge window).
    assert!(wait_until(Duration::from_secs(5), || s.prompter.call_count() == 1));

    let t_b = thread::spawn(move || {
        // privileged=false + confirm_unprivileged=false → no prompter,
        // no TTY lock. With the fix, this thread runs to completion
        // while A's 65s prompt is still active.
        let req = make_req("queue-B", vec![vec!["true"]]);
        let start = Instant::now();
        let resp = send_request(&path_b, &req);
        (start.elapsed(), resp)
    });

    let (elapsed_b, resp_b) = t_b.join().unwrap();
    assert_eq!(
        resp_b.status,
        Status::Ok,
        "B should succeed; under the old code it would have been rejected as 'too old' after 65s in the backlog. message: {:?}",
        resp_b.message
    );
    assert!(
        elapsed_b < Duration::from_secs(2),
        "B finished in {:?}; should run immediately, not behind A's 65s prompt",
        elapsed_b
    );

    // Drain A so the test cleanup is deterministic.
    let resp_a = t_a.join().unwrap();
    assert_eq!(resp_a.status, Status::Denied);
}

/// HANDSHAKE_DEADLINE (10s): a client that connects and writes nothing
/// must not be allowed to wedge the loop. Server should write an error
/// response and close once the deadline expires.
#[test]
#[ignore]
fn handshake_deadline_drops_silent_client() {
    let s = start_test_server(TestServerOpts::default());

    let stream = UnixStream::connect(&s.socket_path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();

    let start = Instant::now();
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(13),
        "server took too long to drop a silent client: {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_secs(9),
        "server dropped client too eagerly (before HANDSHAKE_DEADLINE): {:?}",
        elapsed
    );
    assert!(n > 0, "expected an error response from the server");
    let parsed: serde_json::Value = serde_json::from_str(buf.trim()).unwrap();
    assert_eq!(parsed["status"], "error");
}

/// Slow-loris: a client that drips one byte every ~800ms keeps each read
/// syscall under CONNECTION_IO_TIMEOUT and would, before HANDSHAKE_DEADLINE,
/// hold a handler thread for arbitrarily long. The wall-clock deadline must
/// fire and close the connection within ~10s regardless of pacing.
#[test]
fn trickle_feed_client_disconnected_within_handshake_deadline() {
    let s = start_test_server(TestServerOpts::default());

    let stream = UnixStream::connect(&s.socket_path).expect("connect");
    let mut writer = stream.try_clone().expect("clone");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();

    let start = Instant::now();
    let writer_handle = thread::spawn(move || {
        // Drip up to 18 bytes (≈ 14s of writes) — far beyond the deadline.
        // Each byte alone never produces a newline, so read_request_line
        // keeps looping. write_all will eventually fail when the daemon
        // closes the connection.
        for _ in 0..18 {
            if writer.write_all(b"x").is_err() {
                break;
            }
            let _ = writer.flush();
            thread::sleep(Duration::from_millis(800));
        }
    });

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    let _ = writer_handle.join();

    assert!(
        elapsed <= Duration::from_secs(13),
        "daemon should close by HANDSHAKE_DEADLINE (~10s); took {:?}",
        elapsed
    );
    assert!(n > 0, "expected an error response from the server");
    let parsed: serde_json::Value = serde_json::from_str(buf.trim()).unwrap();
    assert_eq!(parsed["status"], "error");
    assert!(
        parsed["message"].as_str().unwrap_or("").contains("handshake")
            || parsed["message"]
                .as_str()
                .unwrap_or("")
                .contains("deadline"),
        "expected handshake-deadline error, got {:?}",
        parsed["message"]
    );

    assert!(wait_until(Duration::from_secs(2), || s.in_flight.load(Ordering::Relaxed) == 0));
}
