#![cfg(target_os = "linux")]

//! The `a` answer and the prompt timeout, end to end through a pty
//! (`common::pty`): what `a` offers and grants with and without
//! `--unattended-eligible`, that a grant is keyed by `session`, that `a`
//! never approves a privileged request, and that an unanswered prompt times
//! out with the tty restored.

use std::time::Duration;

use sudo_proxy::protocol::{Request, Status};

mod common;

use common::pty::{PtyDaemon, PtyOpts};

fn req(id: &str, session: &str, argv: &[&str]) -> Request {
    let mut r = common::make_req(id, vec![argv.to_vec()]);
    r.session = session.to_string();
    r.reason = "pty unattended".to_string();
    r
}

fn eligible() -> PtyDaemon {
    PtyDaemon::spawn(PtyOpts { args: vec!["--unattended-eligible".into()], ..Default::default() })
}

#[test]
fn a_without_eligibility_approves_once() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    let h = d.request_async(&req("ua-once-1", "sess-a", &["echo", "once"]));
    let prompt = d.answer(b'a');
    assert_eq!(d.expect("]"), "]", "`a` must not be offered: {prompt}");
    assert!(!prompt.contains("a = approve"), "no grant hint when not eligible: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    let shown = d.expect("━━━━━━━━━━━━━━━━━━━━━━━━━");
    assert!(shown.contains("→ Approved\n"), "plain approve-once label: {shown}");
    assert!(!shown.contains("unattended"), "{shown}");

    // Nothing was granted: the same session is prompted again.
    let h = d.request_async(&req("ua-once-2", "sess-a", &["true"]));
    let prompt = d.answer(b'n');
    assert!(prompt.contains("ua-once-2"), "{prompt}");
    assert_eq!(h.join().unwrap().status, Status::Denied);

    let log = d.daemon_log();
    assert!(!log.lines().any(|l| l.contains(" unprivileged unattended ")), "{log}");
}

#[test]
fn a_grant_is_keyed_by_session() {
    let mut d = eligible();

    // 1. Offered, with a hint naming the session it would grant.
    let h = d.request_async(&req("ua-grant-1", "sess-a", &["true"]));
    let prompt = d.answer(b'a');
    assert_eq!(d.expect("]"), "/a]", "`a` must be offered: {prompt}");
    assert!(prompt.contains("from session 'sess-a'"), "{prompt}");
    assert_eq!(h.join().unwrap().status, Status::Ok);
    d.expect("→ Approved (unattended for this session name)");

    // 2. Same session: runs without a prompt. Sent synchronously — a prompt
    //    nobody answers would block this call until the test fails.
    let resp = common::send_request(&d.socket, &req("ua-grant-2", "sess-a", &["echo", "unattended-ok"]));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "unattended-ok\n");
    d.expect("▶ echo unattended-ok");

    // 3. Another session is still prompted. By ordering: the next prompt
    //    block after the grant is this request's, so request 2 drew none.
    let h = d.request_async(&req("ua-grant-3", "sess-b", &["true"]));
    let prompt = d.answer(b'n');
    assert!(prompt.contains("ID:      ua-grant-3"), "{prompt}");
    assert!(!prompt.contains("ua-grant-2"), "{prompt}");
    assert!(prompt.contains("from session 'sess-b'"), "{prompt}");
    assert_eq!(h.join().unwrap().status, Status::Denied);

    // 4. The grant never covers a privileged request, even from sess-a.
    let mut root = req("ua-grant-4", "sess-a", &["true"]);
    root.privileged = true;
    let h = d.request_async(&root);
    let prompt = d.answer(b'n');
    assert!(prompt.contains("ua-grant-4"), "{prompt}");
    assert!(prompt.ends_with("Execute as root? [y/N"), "{prompt}");
    assert_eq!(d.expect("]"), "]", "`a` offered on a privileged request: {prompt}");
    assert!(!prompt.contains("a = approve"), "{prompt}");
    assert_eq!(h.join().unwrap().status, Status::Denied);

    // Exactly one audit record ran unattended: request 2, from sess-a.
    let log = d.daemon_log();
    let unattended: Vec<&str> = log.lines().filter(|l| l.contains(" unprivileged unattended ")).collect();
    assert_eq!(unattended.len(), 1, "{log}");
    assert!(unattended[0].contains("[ua-grant-2]"), "{log}");
    assert!(unattended[0].contains(" session=sess-a "), "{log}");
    assert!(d.shim_log().is_empty(), "nothing was escalated: {:?}", d.shim_log());
}

#[test]
fn a_on_privileged_request_denies() {
    let mut d = eligible();
    let marker = d.dir().join("priv-a.ran");
    let mut r = req("ua-priv-a", "sess-a", &["touch", marker.to_str().unwrap()]);
    r.privileged = true;
    let h = d.request_async(&r);
    let prompt = d.answer(b'a');
    assert_eq!(d.expect("]"), "]", "`a` offered on a privileged request: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Denied, "{resp:?}");
    d.expect("→ Denied");
    assert!(!marker.exists(), "denied command ran");
    assert!(d.shim_log().is_empty(), "{:?}", d.shim_log());
    assert!(d.is_cooked(), "termios not restored");
}

#[test]
#[ignore = "waits the 60 s prompt timeout"]
fn unanswered_prompt_times_out() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());
    let marker = d.dir().join("timeout.ran");
    let h = d.request_async(&req("ua-timeout", "sess-a", &["touch", marker.to_str().unwrap()]));
    d.expect("Privilege Request");
    d.expect("[y/N");
    d.expect_within("→ Timeout", Duration::from_secs(75));
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Timeout, "{resp:?}");
    assert!(!marker.exists(), "timed-out command ran");
    assert!(d.is_cooked(), "termios not restored after a timeout");
}
