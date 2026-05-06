#![cfg(unix)]

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sudo_proxy::executor::{exec_direct, sanitize_env};
use sudo_proxy::protocol::{Request, Status};

mod common;
use common::*;

/// Tests that mutate the process-wide `SSH_AUTH_SOCK` env var must not
/// run concurrently with each other. They CAN run alongside tests in
/// other test binaries (those are separate processes), but cargo runs
/// tests inside one binary in parallel by default.
static ENV_MUTATION_LOCK: Mutex<()> = Mutex::new(());

fn server() -> TestServer {
    start_test_server(TestServerOpts {
        confirm_unprivileged: false,
        ..TestServerOpts::default()
    })
}

fn unpriv_req(id: &str, pipeline: Vec<Vec<&str>>) -> Request {
    let mut r = make_req(id, pipeline);
    r.privileged = false;
    r
}

fn decode_stdout(resp: &sudo_proxy::protocol::Response) -> String {
    let b64 = resp.stdout.as_deref().unwrap_or("");
    let bytes = B64.decode(b64).unwrap_or_default();
    String::from_utf8(bytes).unwrap_or_default()
}

#[test]
fn privileged_plus_forward_agent_rejected() {
    let s = server();
    let mut req = make_req("fa-priv", vec![vec!["true"]]);
    req.privileged = true;
    req.forward_agent = true;
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("forward_agent is only allowed for unprivileged"),
        "got: {msg:?}"
    );
}

#[test]
fn ssh_auth_sock_in_request_env_rejected() {
    let s = server();
    let mut req = unpriv_req("fa-env-sock", vec![vec!["true"]]);
    req.env
        .insert("SSH_AUTH_SOCK".into(), "/tmp/x.sock".into());
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error);
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("SSH_AUTH_SOCK cannot be set in request env"),
        "got: {msg:?}"
    );
}

#[test]
fn sanitize_env_rejects_ssh_auth_sock() {
    let mut env = HashMap::new();
    env.insert("SSH_AUTH_SOCK".to_string(), "/tmp/x.sock".to_string());
    let err = sanitize_env(&env).expect_err("should be rejected");
    assert!(
        err.contains("SSH_AUTH_SOCK"),
        "expected specific error mentioning SSH_AUTH_SOCK, got: {err:?}"
    );
    assert!(
        err.contains("forward_agent"),
        "expected error to mention forward_agent, got: {err:?}"
    );
}

/// Daemon has SSH_AUTH_SOCK set; an unprivileged request with
/// `forward_agent: true` should get it injected into the child env.
#[test]
fn forward_agent_injects_sock_when_daemon_has_one() {
    let _g = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if which_or_skip("printenv").is_none() {
        eprintln!("skipping: printenv not in PATH");
        return;
    }

    let sentinel = "/tmp/sudo-proxy-test-agent.sock";
    // SAFETY: serialized by ENV_MUTATION_LOCK; no other thread reads/writes
    // SSH_AUTH_SOCK while we mutate it.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", sentinel) };
    let mut req = unpriv_req("fa-inject", vec![vec!["printenv", "SSH_AUTH_SOCK"]]);
    req.forward_agent = true;
    let resp = exec_direct(&req, &HashMap::new());
    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };

    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.exit_code(), 0);
    let stdout = decode_stdout(&resp);
    assert_eq!(stdout.trim(), sentinel, "child stdout: {stdout:?}");
}

/// Daemon has SSH_AUTH_SOCK set, but the request did NOT opt in: child
/// must not see it. Guards against accidental forwarding.
#[test]
fn no_forward_agent_does_not_inject() {
    let _g = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if which_or_skip("printenv").is_none() {
        eprintln!("skipping: printenv not in PATH");
        return;
    }

    let sentinel = "/tmp/sudo-proxy-test-agent.sock";
    unsafe { std::env::set_var("SSH_AUTH_SOCK", sentinel) };
    let mut req = unpriv_req("fa-no-inject", vec![vec!["printenv", "SSH_AUTH_SOCK"]]);
    req.forward_agent = false; // explicit
    let resp = exec_direct(&req, &HashMap::new());
    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };

    // printenv exits 1 with no output when the var is unset.
    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.exit_code(), 1, "printenv should not find the var");
    assert_eq!(decode_stdout(&resp).trim(), "");
}

/// `forward_agent: true` but daemon has no SSH_AUTH_SOCK: child does
/// not get the var (graceful degradation, no error).
#[test]
fn forward_agent_without_daemon_socket_is_noop() {
    let _g = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if which_or_skip("printenv").is_none() {
        eprintln!("skipping: printenv not in PATH");
        return;
    }

    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };
    let mut req = unpriv_req("fa-noop", vec![vec!["printenv", "SSH_AUTH_SOCK"]]);
    req.forward_agent = true;
    let resp = exec_direct(&req, &HashMap::new());

    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.exit_code(), 1, "no SSH_AUTH_SOCK should be set");
}

/// Pipeline form (multi-stage Direct): the socket reaches every stage.
#[test]
fn forward_agent_injects_into_pipeline_stages() {
    let _g = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if which_or_skip("printenv").is_none() || which_or_skip("cat").is_none() {
        eprintln!("skipping: printenv or cat not in PATH");
        return;
    }

    let sentinel = "/tmp/sudo-proxy-test-agent.sock";
    unsafe { std::env::set_var("SSH_AUTH_SOCK", sentinel) };
    let mut req = unpriv_req(
        "fa-pipe",
        vec![vec!["printenv", "SSH_AUTH_SOCK"], vec!["cat"]],
    );
    req.forward_agent = true;
    let resp = exec_direct(&req, &HashMap::new());
    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };

    assert_eq!(resp.status, Status::Ok);
    assert_eq!(decode_stdout(&resp).trim(), sentinel);
}

fn which_or_skip(name: &str) -> Option<std::path::PathBuf> {
    sudo_proxy::executor::which(name)
}
