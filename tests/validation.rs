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

// Fields rendered on the approval prompt (reason/host/session/id/version)
// must be held to the same control-char/bidi sanitization as argv — an
// attacker-controlled `reason` (the MCP `description`) carrying raw ANSI or
// newlines could otherwise redraw the prompt and misrepresent the command.
#[test]
fn dangerous_reason_chars_rejected() {
    let s = server();
    let mut req = make_req("v-reason-ansi", vec![vec!["true"]]);
    // ESC (0x1B) would let an attacker emit ANSI sequences on the prompt.
    req.reason = "install updates\u{1b}[8mhidden".into();
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    assert!(resp.message.as_deref().unwrap().contains("reason"));
    assert!(resp.message.as_deref().unwrap().contains("forbidden"));
}

#[test]
fn dangerous_host_and_session_chars_rejected() {
    let s = server();
    // A direct socket client bypasses client-side validate_host, so the
    // daemon must reject control/bidi in host and session itself.
    let mut req = make_req("v-host-ctrl", vec![vec!["true"]]);
    req.host = "evil\rhost".into();
    assert_eq!(s.send(&req).status, Status::Error);

    let mut req = make_req("v-session-bidi", vec![vec!["true"]]);
    req.session = "ses\u{202e}sion".into();
    assert_eq!(s.send(&req).status, Status::Error);
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
fn unprivileged_request_prompts_by_default() {
    // Regression for issue #17: unprivileged requests must hit the TUI
    // prompter by default. Pre-fix, only privileged requests did.
    let s = start_test_server(TestServerOpts::default());
    let req = make_req("v-unpriv-default", vec![vec!["true"]]);
    // Default ScriptedPrompter approves immediately, so the request
    // succeeds; we only need to assert the prompter saw it.
    let resp = s.send(&req);
    assert_eq!(resp.status, sudo_proxy::protocol::Status::Ok);
    assert_eq!(
        s.prompter.call_count(),
        1,
        "unprivileged request must go through the prompter under default config"
    );
}

#[test]
fn ld_preload_rejected_with_specific_error() {
    // Regression for issue #16: LD_PRELOAD used to be silently stripped
    // (along with the rest of the blocklist), softening the response for
    // the most security-sensitive names. It must now hit the same hard
    // rejection path as any other non-allowlisted var.
    let s = server();
    let mut req = make_req("v-ld-preload", vec![vec!["true"]]);
    req.env.insert("LD_PRELOAD".into(), "/tmp/evil.so".into());
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("LD_PRELOAD"),
        "expected error to mention LD_PRELOAD, got: {msg:?}"
    );
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
fn request_with_empty_time_rejected() {
    // Issue #14: empty `time` used to bypass the freshness check
    // entirely. Now it is rejected with a `time`-related error.
    let s = server();
    let mut req = make_req("v-notime", vec![vec!["true"]]);
    req.time = String::new();
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(msg.contains("time"), "got: {msg:?}");
}

#[test]
fn request_with_malformed_time_rejected() {
    // Defence in depth: a parser failure used to be silently lenient.
    let s = server();
    let mut req = make_req("v-badtime", vec![vec!["true"]]);
    req.time = "not-a-timestamp".to_string();
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(msg.contains("time"), "got: {msg:?}");
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

    // Build the wire payload by hand so we can omit `privileged` while
    // still satisfying every other validation check (incl. fresh `time`,
    // which is now mandatory after issue #14).
    let line = format!(
        r#"{{"id":"defprivd","pipeline":[["true"]],"session":"t","time":"{}"}}"#,
        iso_now()
    );
    let mut payload = line.into_bytes();
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
