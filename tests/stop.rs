#![cfg(unix)]

//! Control actions (`stop` / `ping`): a stop request shuts the daemon down
//! cleanly without a prompt; a ping answers without a prompt and without
//! disturbing normal service; both stay behind the freshness gate.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sudo_proxy::protocol::{Action, Status};
use sudo_proxy::server;

mod common;
use common::{
    iso_offset, make_control_req, make_req, send_request, start_test_server, ScriptedPrompter,
    RecordingSink, TestServerOpts,
};

/// A stop request gets an Ok response, never reaches the prompter, and makes
/// `server::run` return cleanly.
#[test]
fn stop_request_shuts_down_run_without_prompt() {
    let tempdir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let path = tempdir.path().join("stop.sock");

    let prompter = Arc::new(ScriptedPrompter::new());
    let sink = Arc::new(RecordingSink::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    let p = Arc::clone(&prompter);
    let s = Arc::clone(&sink);
    let sh = Arc::clone(&shutdown);
    let inf = Arc::clone(&in_flight);
    let tty = Arc::clone(&tty_lock);
    let path_thread = path.clone();
    let handle = thread::spawn(move || {
        server::run(
            &path_thread,
            server::ServerConfig::default(),
            p,
            s,
            sh,
            inf,
            tty,
        )
    });

    // Wait for the listener.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let resp = send_request(&path, &make_control_req("stop-1", Action::Stop));
    assert_eq!(resp.status, Status::Ok, "stop must be acknowledged: {resp:?}");

    // The accept loop polls the flag every 50ms; run must return Ok soon.
    let start = Instant::now();
    let result = handle.join().expect("run thread must not panic");
    assert!(result.is_ok(), "run must return cleanly after stop: {result:?}");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "run took too long to notice the stop flag"
    );
    assert_eq!(
        prompter.call_count(),
        0,
        "stop must not go through the approval prompt"
    );
    assert!(shutdown.load(Ordering::Relaxed), "stop must set the flag");
}

/// A ping answers Ok("pong") without a prompt, and the daemon keeps serving
/// exec requests afterwards.
#[test]
fn ping_answers_without_prompt_and_daemon_survives() {
    let s = start_test_server(TestServerOpts::default());

    let resp = s.send(&make_control_req("ping-1", Action::Ping));
    assert_eq!(resp.status, Status::Ok, "ping must succeed: {resp:?}");
    assert_eq!(resp.message.as_deref(), Some("pong"));
    assert_eq!(
        resp.version,
        sudo_proxy::protocol::VERSION,
        "ping response must carry the daemon version"
    );
    assert_eq!(s.prompter.call_count(), 0, "ping must not prompt");

    let resp = s.send(&make_req("ping-then-exec", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok, "daemon must survive a ping");
}

/// Control actions sit behind the freshness gate: a stale stop request is
/// rejected and the daemon keeps running.
#[test]
fn stale_stop_is_rejected_and_daemon_survives() {
    let s = start_test_server(TestServerOpts::default());

    let mut req = make_control_req("stale-stop", Action::Stop);
    req.time = iso_offset(-300);
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message.as_deref().unwrap_or("").contains("too old"),
        "expected freshness rejection, got: {resp:?}"
    );

    let resp = s.send(&make_req("still-alive", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok, "daemon must survive a stale stop");
}
