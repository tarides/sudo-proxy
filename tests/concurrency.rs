#![cfg(unix)]

use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sudo_proxy::protocol::Status;
use sudo_proxy::tui::PromptResult;

mod common;
use common::*;

/// The TTY is single-user: even with thread-per-connection, two prompts
/// must serialize on the TTY mutex. This documents inherent serialization
/// of the prompt path, not a bug.
#[test]
fn prompt_serializes_clients() {
    let s = start_test_server(TestServerOpts::default());

    let prompt_delay = Duration::from_millis(800);
    s.prompter
        .set_response(move |_| (prompt_delay, PromptResult::Approved));

    let path_a = s.socket_path.clone();
    let path_b = s.socket_path.clone();

    let t_a = thread::spawn(move || {
        let req = make_req("blk-A", vec![vec!["true"]]);
        let start = Instant::now();
        let resp = send_request(&path_a, &req);
        (start.elapsed(), resp)
    });

    thread::sleep(Duration::from_millis(100));

    let t_b = thread::spawn(move || {
        let req = make_req("blk-B", vec![vec!["true"]]);
        let start = Instant::now();
        let resp = send_request(&path_b, &req);
        (start.elapsed(), resp)
    });

    let (_, resp_a) = t_a.join().unwrap();
    let (elapsed_b, resp_b) = t_b.join().unwrap();

    assert_eq!(resp_a.status, Status::Ok);
    assert_eq!(resp_b.status, Status::Ok);
    assert!(
        elapsed_b >= prompt_delay,
        "B finished in {:?}; expected >= {:?} due to serial TTY prompt",
        elapsed_b,
        prompt_delay
    );
    assert!(
        elapsed_b < Duration::from_secs(5),
        "B took unreasonably long: {:?}",
        elapsed_b
    );
}

/// Failure mode #2 (FIXED): a long exec must NOT wedge the accept loop.
/// A is unprivileged-no-confirm `sleep 1`; B is unprivileged-no-confirm
/// `true` arriving immediately after. With thread-per-connection, B
/// finishes well before A.
#[test]
fn long_exec_does_not_wedge_loop() {
    if skip_if_no_sleep_binary() {
        eprintln!("skipping: /bin/sleep not in PATH");
        return;
    }
    let mut opts = TestServerOpts::default();
    opts.confirm_unprivileged = false;
    let s = start_test_server(opts);

    let path_a = s.socket_path.clone();
    let path_b = s.socket_path.clone();

    let t_a = thread::spawn(move || {
        let req = make_req("wedge-A", vec![vec!["sleep", "1"]]);
        let start = Instant::now();
        let resp = send_request(&path_a, &req);
        (start.elapsed(), resp)
    });

    thread::sleep(Duration::from_millis(150));

    let t_b = thread::spawn(move || {
        let req = make_req("wedge-B", vec![vec!["true"]]);
        let start = Instant::now();
        let resp = send_request(&path_b, &req);
        (start.elapsed(), resp)
    });

    let (elapsed_a, resp_a) = t_a.join().unwrap();
    let (elapsed_b, resp_b) = t_b.join().unwrap();

    assert_eq!(resp_a.status, Status::Ok);
    assert_eq!(resp_b.status, Status::Ok);
    assert!(
        elapsed_b < Duration::from_millis(400),
        "B finished in {:?} but should have run concurrently with A's `sleep 1`",
        elapsed_b
    );
    assert!(
        elapsed_a >= Duration::from_millis(900),
        "A's `sleep 1` returned suspiciously fast: {:?}",
        elapsed_a
    );
}

/// Failure-mode-3 evidence in fast form: an unprivileged request that
/// doesn't take the prompt path runs to completion while a privileged
/// request is still in its (slow) prompt. Direct proof that the daemon
/// no longer serializes ALL traffic behind the TTY.
#[test]
fn unprivileged_runs_during_privileged_prompt() {
    let mut opts = TestServerOpts::default();
    opts.confirm_unprivileged = false;
    let s = start_test_server(opts);

    // Returning Denied avoids triggering exec_sudo for A (which would
    // need a real sudo configuration). The slow delay holds the TTY
    // lock for 1s — long enough for B to demonstrably overtake A.
    s.prompter
        .set_response(|_| (Duration::from_millis(1000), PromptResult::Denied));

    let path_a = s.socket_path.clone();
    let path_b = s.socket_path.clone();

    let t_a = thread::spawn(move || {
        let mut req = make_req("priv-A", vec![vec!["true"]]);
        req.privileged = true;
        send_request(&path_a, &req)
    });

    assert!(wait_until(Duration::from_secs(2), || s.prompter.call_count() >= 1));

    let t_b = thread::spawn(move || {
        // Unprivileged + confirm_unprivileged=false → skips prompter entirely.
        let req = make_req("unpriv-B", vec![vec!["true"]]);
        let start = Instant::now();
        let resp = send_request(&path_b, &req);
        (start.elapsed(), resp)
    });

    let (elapsed_b, resp_b) = t_b.join().unwrap();
    assert_eq!(resp_b.status, Status::Ok);
    assert!(
        elapsed_b < Duration::from_millis(400),
        "B finished in {:?}; should run during A's 1s prompt",
        elapsed_b
    );

    let resp_a = t_a.join().unwrap();
    assert_eq!(resp_a.status, Status::Denied);
}

#[test]
fn prompter_returns_timeout_propagates_to_client() {
    let s = start_test_server(TestServerOpts::default());
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Timeout));
    let resp = s.send(&make_req("to-1", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Timeout);
}

#[test]
fn prompter_returns_denied_propagates_to_client() {
    let s = start_test_server(TestServerOpts::default());
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Denied));
    let resp = s.send(&make_req("dn-1", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Denied);
}

#[test]
fn unprivileged_no_confirm_skips_prompter() {
    let mut opts = TestServerOpts::default();
    opts.confirm_unprivileged = false;
    let s = start_test_server(opts);

    let resp = s.send(&make_req("noprompt-1", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok);
    assert_eq!(
        s.prompter.call_count(),
        0,
        "prompter must not be called when confirm_unprivileged=false"
    );
}

#[test]
fn prompter_called_once_per_request() {
    let s = start_test_server(TestServerOpts::default());

    s.send(&make_req("c-1", vec![vec!["true"]]));
    s.send(&make_req("c-2", vec![vec!["true"]]));
    s.send(&make_req("c-3", vec![vec!["true"]]));

    assert_eq!(s.prompter.call_count(), 3);
    let ids: Vec<_> = s
        .prompter
        .calls()
        .into_iter()
        .map(|c| c.req.id)
        .collect();
    assert_eq!(ids, vec!["c-1", "c-2", "c-3"]);
}

/// N clients with a slow prompt finish in roughly N × prompt_delay because
/// the TTY mutex serializes prompts. Stays green under the fix — the TTY
/// is inherently serial.
#[test]
fn prompt_path_serializes_n_clients() {
    let s = start_test_server(TestServerOpts::default());
    let prompt_delay = Duration::from_millis(300);
    s.prompter
        .set_response(move |_| (prompt_delay, PromptResult::Approved));

    let n = 4;
    let mut handles = Vec::new();
    let start = Instant::now();
    for i in 0..n {
        let path = s.socket_path.clone();
        let id = format!("ser-{i}");
        handles.push(thread::spawn(move || {
            let req = make_req(&id, vec![vec!["true"]]);
            let resp = send_request(&path, &req);
            (i, Instant::now(), resp.status)
        }));
        thread::sleep(Duration::from_millis(20));
    }

    let mut results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let total = start.elapsed();
    results.sort_by_key(|(_, t, _)| *t);

    for (_, _, status) in &results {
        assert_eq!(*status, Status::Ok);
    }
    assert!(
        total >= prompt_delay * (n as u32 - 1),
        "{} clients with {:?} prompt finished in {:?}; expected serial pacing",
        n,
        prompt_delay,
        total
    );
}

/// 8 clients with distinct ids on a no-confirm server should all complete
/// in roughly the time of one request, not 8x. Direct evidence that the
/// daemon is concurrent for the non-prompt path.
#[test]
fn concurrent_distinct_ids_succeed() {
    if skip_if_no_sleep_binary() {
        eprintln!("skipping: /bin/sleep not in PATH");
        return;
    }
    let mut opts = TestServerOpts::default();
    opts.confirm_unprivileged = false;
    let s = start_test_server(opts);

    let n = 8;
    let mut handles = Vec::new();
    let start = Instant::now();
    for i in 0..n {
        let path = s.socket_path.clone();
        let id = format!("par-{i}");
        handles.push(thread::spawn(move || {
            // Each request takes ~300ms; serial would be ~2.4s total.
            let req = make_req(&id, vec![vec!["sleep", "0.3"]]);
            send_request(&path, &req)
        }));
    }
    let responses: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let total = start.elapsed();

    for r in &responses {
        assert_eq!(r.status, Status::Ok);
    }
    assert!(
        total < Duration::from_millis(1500),
        "8 concurrent 300ms requests took {:?} — should run in parallel",
        total
    );
}

/// Cap on concurrent handler threads: when in_flight reaches max_in_flight,
/// new connections must receive an inline busy response and close, rather
/// than spawning yet another thread. The cap is what prevents a same-UID
/// process from spawning thousands of threads by opening connections.
#[test]
fn burst_connections_above_cap_get_busy_response() {
    let mut opts = TestServerOpts::default();
    opts.max_in_flight = 4;
    opts.confirm_unprivileged = false;
    let s = start_test_server(opts);

    // Hold-until-released prompter so the test isn't racing the prompt
    // delay. As long as `release` is false, every prompter call blocks;
    // when it flips, all queued prompts wake.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let release = Arc::clone(&release);
        s.prompter.set_response(move |_| {
            let (lock, cvar) = &*release;
            let mut g = lock.lock().unwrap();
            while !*g {
                g = cvar.wait(g).unwrap();
            }
            (Duration::ZERO, PromptResult::Denied)
        });
    }

    // Saturate the cap: 4 privileged requests, all parked in the prompter.
    let mut occupiers = Vec::new();
    for i in 0..4 {
        let path = s.socket_path.clone();
        occupiers.push(thread::spawn(move || {
            let mut req = make_req(&format!("hold-{i}"), vec![vec!["true"]]);
            req.privileged = true;
            send_request(&path, &req)
        }));
    }

    let reached = wait_until(Duration::from_secs(10), || {
        s.in_flight.load(Ordering::Relaxed) >= 4
    });
    assert!(
        reached,
        "in_flight reached {}, expected ≥4",
        s.in_flight.load(Ordering::Relaxed)
    );

    // While the cap is saturated, every new connection must be rejected
    // inline with a busy response. No thread spawn means no further
    // increment of in_flight.
    let mut overflow = Vec::new();
    for i in 0..3 {
        let path = s.socket_path.clone();
        overflow.push(thread::spawn(move || {
            let mut req = make_req(&format!("over-{i}"), vec![vec!["true"]]);
            req.privileged = true;
            send_request(&path, &req)
        }));
    }

    let overflow_results: Vec<_> = overflow.into_iter().map(|h| h.join().unwrap()).collect();
    for r in &overflow_results {
        assert_eq!(r.status, Status::Error, "overflow request should be rejected");
        assert!(
            r.message.as_deref().unwrap_or("").contains("busy"),
            "expected busy message, got {:?}",
            r.message
        );
    }
    assert_eq!(
        s.in_flight.load(Ordering::Relaxed),
        4,
        "rejections must not have inflated in_flight"
    );

    // Release the prompter so the held requests finish.
    {
        let (lock, cvar) = &*release;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    for h in occupiers {
        let r = h.join().unwrap();
        assert_eq!(r.status, Status::Denied);
    }

    assert!(wait_until(Duration::from_secs(2), || {
        s.in_flight.load(Ordering::Relaxed) == 0
    }));
    let mut req = make_req("after-drain", vec![vec!["true"]]);
    req.privileged = true;
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Denied));
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Denied);
}

/// A panicking prompter must not leak the `in_flight` slot. Without the
/// `InFlightGuard`, the `fetch_sub` after `handle_connection` was skipped
/// during unwind, so each panic permanently inflated the counter.
#[test]
fn in_flight_decremented_after_handler_panic() {
    let s = start_test_server(TestServerOpts::default());
    s.prompter.set_response(|_| panic!("synthetic prompter panic"));

    let mut req = make_req("panic-1", vec![vec!["true"]]);
    req.privileged = true;

    let line = serde_json::to_string(&req).unwrap() + "\n";
    let _ = s.send_raw(line.as_bytes());

    let ok = wait_until(Duration::from_secs(2), || {
        s.in_flight.load(Ordering::Relaxed) == 0
    });
    assert!(
        ok,
        "in_flight remained {} after panicking handler",
        s.in_flight.load(Ordering::Relaxed)
    );
}

/// Locks in the atomicity of `try_insert`: two threads racing the same id
/// must result in exactly one Ok and one duplicate-rejection. The slow
/// prompter ensures the first request is still being processed when the
/// second arrives.
#[test]
fn concurrent_same_id_one_wins() {
    let s = start_test_server(TestServerOpts::default());

    s.prompter
        .set_response(|_| (Duration::from_millis(300), PromptResult::Approved));

    let path1 = s.socket_path.clone();
    let path2 = s.socket_path.clone();

    let t1 = thread::spawn(move || {
        send_request(&path1, &make_req("race-id", vec![vec!["true"]]))
    });
    // Tiny stagger so we test the post-try_insert state: t1's thread has
    // already consumed the id; t2 must observe it.
    thread::sleep(Duration::from_millis(50));
    let t2 = thread::spawn(move || {
        send_request(&path2, &make_req("race-id", vec![vec!["true"]]))
    });

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();

    let (oks, errs): (Vec<_>, Vec<_>) = [r1, r2]
        .into_iter()
        .partition(|r| r.status == Status::Ok);
    assert_eq!(oks.len(), 1, "exactly one request should succeed");
    assert_eq!(errs.len(), 1, "exactly one should be rejected as duplicate");
    assert!(
        errs[0].message.as_deref().unwrap().contains("duplicate"),
        "got: {:?}",
        errs[0].message
    );
}
