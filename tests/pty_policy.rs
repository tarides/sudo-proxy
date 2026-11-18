#![cfg(target_os = "linux")]
//! GHSA-xx2m-j9f7-gcmr: drive the real daemon through a pty with an eligible
//! hosts.json at various modes; check the prompt offers `a` only when trusted.
mod common;
use common::pty::{PtyDaemon, PtyOpts};
use sudo_proxy::protocol::Status;

const ELIGIBLE: &str = r#"{"policy":{"unattended_eligible":true}}"#;

fn run(mode: u32) -> (String, String) {
    let mut d = PtyDaemon::spawn(PtyOpts { hosts_json: Some((ELIGIBLE.into(), mode)), ..Default::default() });
    let mut r = common::make_req(&format!("pol-{mode:o}"), vec![vec!["true"]]);
    r.reason = "policy check".into();
    let h = d.request_async(&r);
    d.expect("Privilege Request");
    let q = d.expect("]");
    // Deny so nothing is granted; we only care what was offered.
    d.answer_raw(b'n');
    assert_eq!(h.join().unwrap().status, Status::Denied);
    let log = std::fs::read_to_string(d.dir().join("daemon.log")).unwrap_or_default();
    (q, log)
}

#[test]
fn world_writable_policy_is_ignored() {
    let (q, log) = run(0o666);
    eprintln!("--- 0666 prompt tail: {:?}\n--- daemon.log:\n{log}", q.lines().last());
    assert!(q.ends_with("[y/N]"), "{q}");
    assert!(log.contains("ignoring hosts.json policy"), "{log}");
}

#[test]
fn owner_private_policy_is_honoured() {
    let (q, log) = run(0o600);
    eprintln!("--- 0600 prompt tail: {:?}\n--- daemon.log:\n{log}", q.lines().last());
    assert!(q.ends_with("[y/N/a]"), "{q}");
    assert!(!log.contains("ignoring"), "{log}");
}
