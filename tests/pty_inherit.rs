#![cfg(target_os = "linux")]

//! `--inherit-env` through the real daemon and its real prompt (#101): the
//! startup report, the fixed `Env:` line, a program found on the inherited
//! `PATH` marked `(user-writable)`, and the variable reaching the step.

use std::os::unix::fs::PermissionsExt;

use sudo_proxy::protocol::Status;

mod common;

use common::pty::{PtyDaemon, PtyOpts};

#[test]
fn inherited_env_is_reported_shown_and_applied() {
    // A dev shell's bin directory: owned by the test user, 0755, under /tmp
    // (root-owned and sticky), so it passes the startup PATH check.
    let dev = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(dev.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let tool = dev.path().join("devtool");
    std::fs::write(
        &tool,
        "#!/bin/sh\necho \"root=$REPO_ROOT other=${OTHER-unset}\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut d = PtyDaemon::spawn(PtyOpts {
        args: vec!["--inherit-env=REPO_ROOT".into()],
        env: vec![
            // Replaces the harness PATH: only directories that pass the check.
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", dev.path().display()),
            ),
            ("REPO_ROOT".into(), "/repo".into()),
            ("OTHER".into(), "x".into()),
        ],
        ..Default::default()
    });

    let log = d.daemon_log();
    assert!(log.contains("patterns: REPO_ROOT"), "startup report: {log}");
    assert!(
        log.contains("variables: REPO_ROOT"),
        "startup report: {log}"
    );
    assert!(
        log.contains("fingerprint: names+PATH"),
        "startup report: {log}"
    );
    assert!(!log.contains("/repo"), "values never in the report: {log}");

    let h = d.request_async(&common::make_req("pty-inherit-1", vec![vec!["devtool"]]));
    let prompt = d.answer(b'y');
    assert!(
        prompt.contains("Env:     daemon environment (--inherit-env)"),
        "prompt: {prompt}"
    );
    assert!(
        prompt.contains("devtool (user-writable)"),
        "prompt: {prompt}"
    );
    assert!(!prompt.contains("/repo"), "values never shown: {prompt}");

    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "root=/repo other=unset\n");

    // The audit file: a startup record, and the request marked inherited
    // with its resolved program, never a variable name or value.
    let recs = common::read_audit(&d.dir().join("home/.local/state/sudo-proxy/audit.jsonl"));
    let startup = recs
        .iter()
        .find(|r| r["outcome"] == "startup")
        .expect("startup record");
    let detail = startup["detail"].as_str().unwrap();
    assert!(
        detail.contains("--inherit-env") && detail.contains("fingerprint="),
        "{detail}"
    );
    let rec = recs
        .iter()
        .find(|r| r["id"] == "pty-inherit-1")
        .expect("request record");
    assert_eq!(rec["inherited"], true, "{rec}");
    let progs = rec["programs"].to_string();
    assert!(progs.contains("devtool"), "{rec}");
    let all = serde_json::to_string(&recs).unwrap();
    assert!(
        !all.contains("/repo"),
        "a value reached the audit log: {all}"
    );
    assert!(
        !all.contains("REPO_ROOT"),
        "a variable name reached the audit log: {all}"
    );
}
