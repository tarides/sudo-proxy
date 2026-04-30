#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
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
    let mut opts = TestServerOpts::default();
    opts.confirm_unprivileged = false;
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

/// CONNECTION_IO_TIMEOUT (5s): a client that connects and writes nothing
/// must not be allowed to wedge the loop. Server should eventually write
/// an error response and close. We allow up to 8s for the round trip.
#[test]
#[ignore]
fn connection_io_timeout_drops_silent_client() {
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
        elapsed < Duration::from_secs(8),
        "server took too long to drop a silent client: {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_secs(4),
        "server dropped client too eagerly (before CONNECTION_IO_TIMEOUT): {:?}",
        elapsed
    );
    assert!(n > 0, "expected an error response from the server");
    let parsed: serde_json::Value = serde_json::from_str(buf.trim()).unwrap();
    assert_eq!(parsed["status"], "error");
}
