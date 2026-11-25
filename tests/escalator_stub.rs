//! GHSA-gx9w-4f7x-2gcp, executor level: every sudo spawn site runs the
//! escalator chosen by `helper::sudo()`, never a `sudo` on the daemon's PATH.
//! The shim set with `--sudo-path`'s override records each call; a planted
//! `sudo` first on PATH records that it ran. No real sudo is involved.
//! Its own test binary: it rewrites this process's PATH and the escalator is
//! cached process-wide.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

use sudo_proxy::executor::{apply_login_env_defaults, exec_sudo};
use sudo_proxy::protocol::{Request, Status, ValidatedRequest};

mod common;

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn privileged(pipeline: Vec<Vec<&str>>) -> ValidatedRequest {
    let req = Request {
        id: format!("gx9w-{}", uuid::Uuid::new_v4()),
        host: String::new(),
        session: "test".into(),
        time: String::new(),
        pipeline: pipeline
            .into_iter()
            .map(|v| v.into_iter().map(String::from).collect())
            .collect(),
        plan: None,
        action: sudo_proxy::protocol::Action::Exec,
        env: HashMap::new(),
        reason: String::new(),
        privileged: true,
        forward_agent: false,
        version: sudo_proxy::protocol::VERSION.to_string(),
        requester: String::new(),
    };
    ValidatedRequest::validate(req).unwrap()
}

#[test]
fn every_sudo_spawn_uses_the_resolved_escalator_not_path() {
    let d = tempfile::tempdir().unwrap();
    let stub_log = d.path().join("stub.log");
    let plant_log = d.path().join("plant.log");

    // The pty harness's sudo stand-in: logs each argv to SUDO_SHIM_LOG (one
    // line per call), then runs the command as the invoking user.
    let stub = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/shims/sudo");
    std::env::set_var("SUDO_SHIM_LOG", &stub_log);
    let plant_dir = d.path().join("plant");
    std::fs::create_dir(&plant_dir).unwrap();
    script(&plant_dir.join("sudo"), &format!("echo planted >> '{}'\nexit 97", plant_log.display()));

    let old = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{old}", plant_dir.display()));
    sudo_proxy::helper::set_sudo_override(&stub).unwrap();

    let mut env = HashMap::new();
    apply_login_env_defaults(&mut env);
    let lock = Mutex::new(());

    // Single stage (exec_sudo_stage).
    let resp = exec_sudo(&privileged(vec![vec!["echo", "one"]]), &env, &lock);
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::b64_decode(resp.stdout.as_deref().unwrap_or("")), b"one\n");

    // Multi-stage (exec_pipeline, one sudo per stage).
    let resp = exec_sudo(&privileged(vec![vec!["echo", "two"], vec!["cat"]]), &env, &lock);
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::b64_decode(resp.stdout.as_deref().unwrap_or("")), b"two\n");

    assert!(!plant_log.exists(), "planted sudo on PATH ran");
    let calls = std::fs::read_to_string(&stub_log).unwrap();
    assert_eq!(calls.lines().count(), 3, "expected one stand-in call per stage: {calls}");
}
