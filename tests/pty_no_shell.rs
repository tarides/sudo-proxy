#![cfg(target_os = "linux")]

//! Strict `no_shell` mode, end to end through a pty (`common::pty`): an opaque
//! request is rejected before it reaches the prompt. Checked by ordering rather
//! than by "no prompt seen": after the rejection, a structured request is sent,
//! and the first prompt block on the tty must be that request's.

use sudo_proxy::protocol::{Plan, Status};

mod common;

use common::pty::{PtyDaemon, PtyOpts};

fn check(mut d: PtyDaemon) {
    let mut opaque = common::make_req("ns-opaque", vec![]);
    opaque.plan = Some(Plan::Exec { argv: vec!["sh".into(), "-c".into(), "true".into()] });
    let r = common::send_request(&d.socket, &opaque);
    assert_eq!(r.status, Status::Error, "{r:?}");
    assert!(r.message.as_deref().unwrap_or("").contains("no_shell"), "{r:?}");

    let h = d.request_async(&common::make_req("ns-structured", vec![vec!["echo", "structured-ok"]]));
    let prompt = d.answer(b'y');
    assert!(prompt.contains("ID:      ns-structured"), "{prompt}");
    let r = h.join().unwrap();
    assert_eq!(r.status, Status::Ok, "{r:?}");
    assert_eq!(common::decode_stdout(&r), "structured-ok\n");
    assert!(!d.capture().contains("ns-opaque"), "the opaque request reached the tty");
}

#[test]
fn no_shell_flag_rejects_before_prompt() {
    check(PtyDaemon::spawn(PtyOpts { args: vec!["--no-shell".into()], ..Default::default() }));
}

#[test]
fn no_shell_policy_rejects_before_prompt() {
    let json = r#"{"policy":{"no_shell":true}}"#;
    check(PtyDaemon::spawn(PtyOpts { hosts_json: Some((json.into(), 0o600)), ..Default::default() }));
}
