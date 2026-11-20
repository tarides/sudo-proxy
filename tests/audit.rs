//! Audit log (issue #65): every terminal outcome of a connection leaves one
//! JSONL record, rejections included, and env values never appear in it.
#![cfg(unix)]

use std::time::Duration;

use sudo_proxy::protocol::{Action, Plan, Request, Status};
use sudo_proxy::tui::PromptResult;

mod common;
use common::*;

fn our_uid() -> u64 {
    unsafe { libc::getuid() as u64 }
}

fn server() -> TestServer {
    start_test_server(TestServerOpts::default())
}

/// Common shape of every record that got as far as a parsed request.
fn check_common(r: &serde_json::Value, outcome: &str) {
    assert_eq!(r["outcome"], outcome, "{r}");
    assert_eq!(r["peer_uid"].as_u64(), Some(our_uid()), "{r}");
    let time = r["time"].as_str().expect("time");
    assert!(
        time.len() == 20 && time.ends_with('Z') && time.as_bytes()[10] == b'T',
        "RFC 3339 UTC timestamp, got {time}"
    );
}

#[test]
fn approved_is_recorded_with_command_and_exit_code() {
    let s = server();
    let resp = s.send(&make_req("a-ok", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok);
    let r = s.audit_for("a-ok");
    check_common(&r, "approved");
    assert_eq!(r["session"], "test");
    assert_eq!(r["privileged"], false);
    assert_eq!(r["status"], "ok");
    assert_eq!(r["exit_codes"], serde_json::json!([0]));
    assert!(r["command"].as_str().unwrap().contains("true"), "{r}");
}

#[test]
fn denied_and_timeout_are_recorded() {
    let s = server();
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Denied));
    let mut req = make_req("a-deny", vec![vec!["true"]]);
    req.privileged = true;
    assert_eq!(s.send(&req).status, Status::Denied);
    let r = s.audit_for("a-deny");
    check_common(&r, "denied");
    assert_eq!(r["privileged"], true);

    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Timeout));
    let mut req = make_req("a-timeout", vec![vec!["true"]]);
    req.privileged = true;
    assert_eq!(s.send(&req).status, Status::Timeout);
    check_common(&s.audit_for("a-timeout"), "timeout");
}

#[test]
fn session_grant_and_unattended_runs_are_recorded() {
    let s = start_test_server(TestServerOpts {
        unattended_eligible: true,
        ..Default::default()
    });
    s.grant_unattended_session();
    check_common(&s.audit_for("grant-warmup"), "approved_session");
    assert_eq!(
        s.send(&make_req("a-unatt", vec![vec!["true"]])).status,
        Status::Ok
    );
    check_common(&s.audit_for("a-unatt"), "unattended");
}

#[test]
fn replayed_id_is_recorded() {
    let s = server();
    let req = make_req("a-dup", vec![vec!["true"]]);
    assert_eq!(s.send(&req).status, Status::Ok);
    let mut again = req.clone();
    again.time = iso_now();
    assert_eq!(s.send(&again).status, Status::Error);
    let recs: Vec<_> = s
        .audit_records()
        .into_iter()
        .filter(|r| r["id"] == "a-dup")
        .collect();
    assert_eq!(recs.len(), 2);
    check_common(&recs[0], "approved");
    check_common(&recs[1], "rejected:duplicate_id");
    assert!(recs[1]["detail"].as_str().unwrap().contains("duplicate"));
}

#[test]
fn stale_and_missing_time_are_recorded() {
    let s = server();
    let mut req = make_req("a-stale", vec![vec!["true"]]);
    req.time = iso_offset(-70);
    assert_eq!(s.send(&req).status, Status::Error);
    check_common(&s.audit_for("a-stale"), "rejected:time");

    let mut req = make_req("a-notime", vec![vec!["true"]]);
    req.time = String::new();
    assert_eq!(s.send(&req).status, Status::Error);
    let r = s.audit_for("a-notime");
    assert!(
        r["outcome"].as_str().unwrap().starts_with("rejected:"),
        "{r}"
    );
}

#[test]
fn validation_failure_is_recorded_without_command() {
    let s = server();
    let mut req = make_req("a-bidi", vec![vec!["true"]]);
    req.session = "evil\u{202E}session".into();
    assert_eq!(s.send(&req).status, Status::Error);
    let r = s.audit_for("a-bidi");
    check_common(&r, "rejected:invalid_request");
    // Recorded, but escaped: the file must be safe to `cat` on a terminal.
    assert_eq!(r["session"], "evil\\u{202e}session");
    assert!(
        r.get("command").is_none(),
        "no command for unvalidated: {r}"
    );
    assert!(r.get("privileged").is_none(), "{r}");
    assert_eq!(s.prompter.call_count(), 0);
}

#[test]
fn disallowed_env_is_recorded_without_its_value() {
    let s = server();
    let mut req = make_req("a-env", vec![vec!["true"]]);
    req.env
        .insert("LD_PRELOAD".into(), "hunter2-preload".into());
    assert_eq!(s.send(&req).status, Status::Error);
    check_common(&s.audit_for("a-env"), "rejected:env");

    // An allowed key runs; its value must not be logged either.
    let mut req = make_req("a-env-ok", vec![vec!["true"]]);
    req.env.insert("LANG".into(), "hunter2-lang".into());
    req.reason = "hunter2-reason".into();
    assert_eq!(s.send(&req).status, Status::Ok);
    check_common(&s.audit_for("a-env-ok"), "approved");

    let raw = std::fs::read_to_string(&s.audit_path).unwrap();
    assert!(
        !raw.contains("hunter2"),
        "secret leaked into audit log:\n{raw}"
    );
}

#[test]
fn invalid_plan_is_recorded() {
    let s = server();
    let plan = Plan::Redirect {
        stream: sudo_proxy::protocol::Stream::Stdout,
        target: sudo_proxy::protocol::RedirTarget::DevNull,
        body: Box::new(Plan::Run {
            steps: vec![
                Plan::Exec {
                    argv: vec!["true".into()],
                },
                Plan::Exec {
                    argv: vec!["true".into()],
                },
            ],
        }),
    };
    let mut req = Request::new_plan(
        String::new(),
        "test".into(),
        plan,
        Default::default(),
        String::new(),
        false,
        false,
    );
    req.id = "a-plan".into();
    req.time = iso_now();
    assert_eq!(s.send(&req).status, Status::Error);
    check_common(&s.audit_for("a-plan"), "rejected:invalid_plan");
}

#[test]
fn invalid_json_is_recorded_without_raw_bytes() {
    let s = server();
    s.send_raw(b"{not json hunter2\n");
    let recs = s.audit_records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    check_common(&recs[0], "rejected:invalid_json");
    let raw = std::fs::read_to_string(&s.audit_path).unwrap();
    assert!(!raw.contains("hunter2"), "raw request bytes leaked:\n{raw}");
}

#[test]
fn ping_is_recorded() {
    let s = server();
    assert_eq!(
        s.send(&make_control_req("a-ping", Action::Ping)).status,
        Status::Ok
    );
    check_common(&s.audit_for("a-ping"), "ping");
}

#[test]
fn records_are_one_per_line_and_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let s = server();
    for i in 0..5 {
        let mut req = make_req(&format!("a-many-{i}"), vec![vec!["true"]]);
        req.session = "multi\nline".into(); // rejected; must stay one line
        s.send(&req);
    }
    assert_eq!(s.audit_records().len(), 5);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&s.audit_path), 0o600);
    assert_eq!(mode(s.audit_path.parent().unwrap()), 0o700);
}
