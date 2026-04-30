#![cfg(unix)]

use sudo_proxy::protocol::Status;

mod common;
use common::*;

fn server() -> TestServer {
    start_test_server(TestServerOpts::default())
}

#[test]
fn empty_pipeline_rejected() {
    let s = server();
    let mut req = make_req("v-empty-pipe", vec![]);
    req.pipeline = vec![];
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message.as_deref().unwrap().contains("must not be empty"),
        "got: {:?}",
        resp.message
    );
}

#[test]
fn empty_pipeline_stage_rejected() {
    let s = server();
    let mut req = make_req("v-empty-stage", vec![vec!["true"]]);
    req.pipeline = vec![vec![]];
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(resp.message.as_deref().unwrap().contains("stage 0"));
}

#[test]
fn dangerous_argv_chars_rejected() {
    let s = server();
    let req = make_req("v-bidi", vec![vec!["echo", "hello\u{202E}world"]]);
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(resp.message.as_deref().unwrap().contains("forbidden"));
}

#[test]
fn dangerous_env_key_rejected() {
    let s = server();
    let mut req = make_req("v-envkey", vec![vec!["true"]]);
    req.env.insert("BAD\u{0001}KEY".into(), "v".into());
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(resp.message.as_deref().unwrap().contains("env key"));
}

#[test]
fn dangerous_env_value_rejected() {
    let s = server();
    let mut req = make_req("v-envval", vec![vec!["true"]]);
    req.env.insert("OK".into(), "bad\nvalue".into());
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(resp.message.as_deref().unwrap().contains("env value"));
}

#[test]
fn invalid_json_returns_error_with_empty_id() {
    let s = server();
    let bytes = s.send_raw(b"this is not json\n");
    let text = String::from_utf8(bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["id"], "");
    assert!(parsed["message"]
        .as_str()
        .unwrap()
        .contains("invalid JSON"));
}

#[test]
fn oversize_request_rejected() {
    let s = server();
    // The server caps the read at 1 MiB. Send a 2 MiB line of garbage with a
    // newline — the read truncates, the truncated content fails JSON parsing.
    let mut payload = vec![b'x'; 2 * 1024 * 1024];
    payload.push(b'\n');
    let bytes = s.send_raw(&payload);
    let text = String::from_utf8_lossy(&bytes);
    let parsed: serde_json::Value =
        serde_json::from_str(text.trim()).expect("server must respond with JSON");
    assert_eq!(parsed["status"], "error");
}

#[test]
fn request_with_empty_time_accepted() {
    // Server is lenient when `time` is empty.
    let s = server();
    let mut req = make_req("v-notime", vec![vec!["true"]]);
    req.time = String::new();
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Ok, "got: {:?}", resp);
}

#[test]
fn stale_time_rejected() {
    // 70 seconds older than now: above MAX_REQUEST_AGE (60s).
    let s = server();
    let mut req = make_req("v-stale", vec![vec!["true"]]);
    req.time = iso_offset(-70);
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message.as_deref().unwrap().contains("too old"),
        "got: {:?}",
        resp.message
    );
}

#[test]
fn fresh_time_accepted() {
    let s = server();
    let req = make_req("v-fresh", vec![vec!["true"]]);
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Ok, "got: {:?}", resp);
}

/// Protocol default for `privileged` is `true` — most-restrictive default
/// so a client that omits the field doesn't accidentally bypass the
/// approval prompt. The wire-level test sends raw JSON without the
/// `privileged` field and verifies the prompter was invoked.
#[test]
fn missing_privileged_field_defaults_to_privileged() {
    let s = server();

    let line = br#"{"id":"defprivd","pipeline":[["true"]],"session":"t"}"#.to_vec();
    let mut payload = line;
    payload.push(b'\n');

    let bytes = s.send_raw(&payload);
    let text = String::from_utf8(bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();

    // The default scripted prompter approves; with privileged=true the
    // server uses exec_sudo, which will fail in CI (no real sudo). We
    // don't care about the exact status — only that the prompter was
    // called, which proves the request took the privileged path.
    assert_eq!(s.prompter.call_count(), 1);
    assert_eq!(parsed["id"], "defprivd");
}
