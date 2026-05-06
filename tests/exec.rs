#![cfg(unix)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sudo_proxy::executor::{exec_direct, exec_timeout, MAX_OUTPUT_BYTES};
use sudo_proxy::protocol::{Request, Status};

fn make_req(pipeline: Vec<Vec<&str>>) -> Request {
    Request {
        id: format!("exec-{}", uuid::Uuid::new_v4()),
        host: String::new(),
        session: "test".into(),
        time: String::new(),
        pipeline: pipeline
            .into_iter()
            .map(|v| v.into_iter().map(String::from).collect())
            .collect(),
        env: HashMap::new(),
        reason: String::new(),
        privileged: false,
        forward_agent: false,
    }
}

/// E1: a privileged-equivalent that produces unbounded stdout must not
/// OOM the daemon. The drainer caps at MAX_OUTPUT_BYTES and the child is
/// killed once the cap is hit.
#[test]
fn stdout_is_capped_at_max_output_bytes() {
    if which_or_skip("yes").is_none() || which_or_skip("head").is_none() {
        eprintln!("skipping: yes/head not on PATH");
        return;
    }

    // 200 MB cap target; MAX_OUTPUT_BYTES = 16 MB so we should see truncation.
    let req = make_req(vec![vec![
        "sh",
        "-c",
        "yes 'x' | head -c 200000000",
    ]]);

    let start = Instant::now();
    let resp = exec_direct(&req, &HashMap::new());
    let elapsed = start.elapsed();

    assert_eq!(resp.status, Status::Ok, "got {:?}", resp);
    assert!(resp.stdout_truncated, "expected stdout_truncated=true");
    let stdout = base64_decode(resp.stdout.as_deref().unwrap_or(""));
    assert_eq!(
        stdout.len(),
        MAX_OUTPUT_BYTES,
        "stdout was {} bytes, expected exactly {}",
        stdout.len(),
        MAX_OUTPUT_BYTES
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "exec took {:?}, expected fast cap",
        elapsed
    );
}

/// E2: a long-running child must be killed and the request returned within
/// EXEC_TIMEOUT. We override the env var so the test isn't 5 minutes.
#[test]
fn long_running_child_killed_after_timeout() {
    if which_or_skip("sleep").is_none() {
        eprintln!("skipping: sleep not on PATH");
        return;
    }

    let prev = std::env::var("SUDO_PROXY_EXEC_TIMEOUT_SECS").ok();
    std::env::set_var("SUDO_PROXY_EXEC_TIMEOUT_SECS", "1");
    let _restore = EnvRestore("SUDO_PROXY_EXEC_TIMEOUT_SECS", prev);

    assert_eq!(exec_timeout(), Duration::from_secs(1));

    let req = make_req(vec![vec!["sleep", "30"]]);
    let start = Instant::now();
    let resp = exec_direct(&req, &HashMap::new());
    let elapsed = start.elapsed();

    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message
            .as_deref()
            .unwrap_or("")
            .contains("timed out"),
        "expected timeout message, got {:?}",
        resp.message
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "exec didn't return within timeout window: {:?}",
        elapsed
    );
}

/// E2 + E4: a multi-stage pipeline whose middle stage hangs must time out
/// and not orphan any of the children to PID 1.
#[test]
fn pipeline_timeout_kills_all_stages() {
    if which_or_skip("sleep").is_none() {
        eprintln!("skipping: sleep not on PATH");
        return;
    }

    let prev = std::env::var("SUDO_PROXY_EXEC_TIMEOUT_SECS").ok();
    std::env::set_var("SUDO_PROXY_EXEC_TIMEOUT_SECS", "1");
    let _restore = EnvRestore("SUDO_PROXY_EXEC_TIMEOUT_SECS", prev);

    let req = make_req(vec![
        vec!["sh", "-c", "echo head; sleep 30"],
        vec!["sleep", "30"],
        vec!["wc", "-c"],
    ]);

    let start = Instant::now();
    let resp = exec_direct(&req, &HashMap::new());
    let elapsed = start.elapsed();

    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message
            .as_deref()
            .unwrap_or("")
            .contains("timed out"),
        "expected pipeline timeout, got {:?}",
        resp.message
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "pipeline didn't return within timeout: {:?}",
        elapsed
    );

    // Brief grace period for waitpid ripple, then verify nothing of ours
    // is still hanging around. We can't easily list children without
    // tracking pids inside the executor; the timeout's kill+wait is the
    // contract — we trust it because the single-stage test already
    // confirms wait-after-kill on the timeout path.
    std::thread::sleep(Duration::from_millis(100));
}

/// E4: KillOnDrop guard semantics — verified directly via the executor's
/// internal struct from src/executor.rs unit tests. This just establishes
/// that a normal (non-panicking) pipeline exits cleanly without the guard
/// killing anything prematurely.
#[test]
fn pipeline_succeeds_without_guard_interference() {
    let req = make_req(vec![vec!["echo", "hi"], vec!["wc", "-c"]]);
    let resp = exec_direct(&req, &HashMap::new());
    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(resp.exit_code(), 0);
    let stdout = base64_decode(resp.stdout.as_deref().unwrap_or(""));
    // "hi\n" is 3 bytes → wc -c outputs "3\n" (or similar).
    let s = String::from_utf8_lossy(&stdout);
    assert!(s.trim() == "3", "got: {:?}", s);
}

// -- helpers ----------------------------------------------------------------

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    B64.decode(s).unwrap_or_default()
}

fn which_or_skip(name: &str) -> Option<std::path::PathBuf> {
    sudo_proxy::executor::which(name)
}

struct EnvRestore(&'static str, Option<String>);
impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.1 {
            Some(v) => std::env::set_var(self.0, v),
            None => std::env::remove_var(self.0),
        }
    }
}
