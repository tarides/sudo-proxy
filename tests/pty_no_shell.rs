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
    // A shell behind a wrapper is rejected the same way (#87).
    for (id, argv) in [("ns-env", &["env", "sh", "-c", "true"][..]), ("ns-timeout", &["timeout", "5", "sh", "-c", "true"])] {
        let mut req = common::make_req(id, vec![]);
        req.plan = Some(Plan::Exec { argv: argv.iter().map(|s| s.to_string()).collect() });
        let r = common::send_request(&d.socket, &req);
        assert_eq!(r.status, Status::Error, "{id}: {r:?}");
        assert!(r.message.as_deref().unwrap_or("").contains("no_shell"), "{id}: {r:?}");
    }

    let h = d.request_async(&common::make_req("ns-structured", vec![vec!["echo", "structured-ok"]]));
    let prompt = d.answer(b'y');
    assert!(prompt.contains("ID:      ns-structured"), "{prompt}");
    let r = h.join().unwrap();
    assert_eq!(r.status, Status::Ok, "{r:?}");
    assert_eq!(common::decode_stdout(&r), "structured-ok\n");
    let tty = d.capture();
    for id in ["ns-opaque", "ns-env", "ns-timeout"] {
        assert!(!tty.contains(id), "the opaque request {id} reached the tty");
    }
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

/// A `hosts.json` another user could write is not trusted, and for `no_shell`
/// failing closed means strict mode on: even a file that says
/// `"no_shell": false` cannot switch it off.
#[test]
fn untrusted_policy_turns_no_shell_on() {
    let json = r#"{"policy":{"no_shell":false}}"#;
    let d = PtyDaemon::spawn(PtyOpts { hosts_json: Some((json.into(), 0o666)), ..Default::default() });
    let log = std::fs::read_to_string(d.dir().join("daemon.log")).unwrap_or_default();
    assert!(log.contains("ignoring hosts.json policy (not unattended-eligible, no_shell on)"), "{log}");
    check(d);
}
