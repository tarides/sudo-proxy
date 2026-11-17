#![cfg(target_os = "linux")]

//! End-to-end tests against the real `sudo-proxy` binary and its real
//! `/dev/tty` prompt, driven through a pseudo-terminal (`common::pty`).
//! These cover what `ScriptedPrompter` tests cannot: the prompt as drawn,
//! single-key reads in raw mode, termios restoration, and the escalation spawn
//! (`sudo` resolved on the daemon's PATH, here a logging shim).

use sudo_proxy::protocol::{Plan, Request, RunAs, Status};

mod common;

use common::pty::{PtyDaemon, PtyOpts};

fn req(id: &str, argv: &[&str], reason: &str) -> Request {
    let mut r = common::make_req(id, vec![argv.to_vec()]);
    r.reason = reason.to_string();
    r
}

/// Split a shim argv `[-u USER] K=V... -- argv` into (`-u` target, argv).
fn split_sudo(argv: &[String]) -> (Option<&str>, &[String]) {
    let user = (argv.first().map(String::as_str) == Some("-u")).then(|| argv[1].as_str());
    let dd = argv.iter().position(|a| a == "--").expect("sudo argv has `--`");
    (user, &argv[dd + 1..])
}

#[test]
fn approve_unprivileged_runs_and_shows_result() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());
    let h = d.request_async(&req("pty-approve-1", &["echo", "pty-ok"], "pty harness approve"));

    let prompt = d.answer(b'y');
    assert!(prompt.contains("ID:      pty-approve-1"), "prompt: {prompt}");
    assert!(prompt.contains("Reason:  pty harness approve"), "prompt: {prompt}");
    assert!(prompt.contains("Command: echo pty-ok"), "prompt: {prompt}");

    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "pty-ok\n");

    // The result block is drawn before the response is written, so it is
    // already in the capture.
    d.expect("→ Approved");
    d.expect("exit 0");
    assert!(d.is_cooked(), "termios not restored after the prompt");
    assert!(d.shim_log().is_empty(), "unprivileged run must not go through sudo");
}

#[test]
fn deny_with_n_and_with_enter() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    for (id, key) in [("pty-deny-n", b'n'), ("pty-deny-enter", b'\r')] {
        // In the harness dir, so it is cleaned up even when the test fails.
        let marker = d.dir().join(format!("{id}.ran"));
        let h = d.request_async(&req(id, &["touch", marker.to_str().unwrap()], "pty harness deny"));
        let prompt = d.answer(key);
        assert!(prompt.contains(id), "prompt: {prompt}");
        let resp = h.join().unwrap();
        assert_eq!(resp.status, Status::Denied, "{id}: {resp:?}");
        d.expect("→ Denied");
        assert!(!marker.exists(), "{id}: denied command ran");
        assert!(d.is_cooked(), "{id}: termios not restored");
    }
    assert!(d.shim_log().is_empty());
}

#[test]
fn privileged_goes_through_sudo_with_literal_argv() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    // Whole-command privilege: run as root, so no `-u`. The empty argument
    // and the shell metacharacters must reach sudo untouched.
    let mut root = req("pty-priv-root", &["echo", "as root", "", "$HOME;x"], "pty harness root");
    root.privileged = true;
    let h = d.request_async(&root);
    let prompt = d.answer(b'y');
    assert!(prompt.contains("Execute as root?"), "prompt: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "as root  $HOME;x\n");

    // A plan step run as a named user: `-u nobody`.
    let mut user = common::make_req("pty-priv-user", vec![]);
    user.plan = Some(Plan::RunAs {
        who: RunAs::User { name: "nobody".into() },
        body: Box::new(Plan::Exec { argv: vec!["echo".into(), "as-nobody".into()] }),
    });
    let h = d.request_async(&user);
    let prompt = d.answer(b'y');
    assert!(prompt.contains("Execute with elevated privileges?"), "prompt: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "as-nobody\n");

    // Assert only on the `-u` target and the argv after `--`: the `K=V`
    // part carries the runner's HOME/USER.
    let log = d.shim_log();
    assert_eq!(log.len(), 2, "one sudo spawn per privileged step: {log:?}");
    let (u, argv) = split_sudo(&log[0]);
    assert_eq!(u, None);
    assert_eq!(argv, ["echo", "as root", "", "$HOME;x"]);
    let (u, argv) = split_sudo(&log[1]);
    assert_eq!(u, Some("nobody"));
    assert_eq!(argv, ["echo", "as-nobody"]);
}
