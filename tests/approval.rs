//! Dispatch-level approval invariants (Rung 2 of the assurance ladder).
//!
//! Two spec clauses, checked against the real `server::run` dispatch via the
//! `ScriptedPrompter` harness:
//!
//!  * **Property 4 — `privileged:true` ⇒ a keypress occurred.** A privileged
//!    request is always routed through the prompter, and root is executed only
//!    on `Approved`. Every non-`Approved` outcome (`Denied`, `Timeout`, and the
//!    defensively-rejected `ApprovedAlways`) ends in no execution.
//!  * **Property 5 (dispatch side) — `confirm_unprivileged` flips only on an
//!    interactive keypress.** The policy flag turns off only when the prompter
//!    returns `ApprovedAlways` (which `tui::classify_key` emits solely for the
//!    `'a'` key on an unprivileged request — see the exhaustive unit property
//!    in `src/tui.rs`). A plain `Approved` leaves the flag set.

#![cfg(unix)]

use std::time::Duration;

use sudo_proxy::protocol::Status;
use sudo_proxy::tui::PromptResult;

mod common;
use common::*;

fn server() -> TestServer {
    start_test_server(TestServerOpts::default())
}

fn privileged_req(id: &str) -> sudo_proxy::protocol::Request {
    // A command with an observable side effect would still never run on these
    // paths; `true` keeps the test hermetic if a regression ever did execute.
    let mut req = make_req(id, vec![vec!["true"]]);
    req.privileged = true;
    req
}

// --- Property 4: privileged ⇒ keypress, root execs only on Approved ------

#[test]
fn privileged_denied_is_not_executed() {
    let s = server();
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Denied));
    let resp = s.send(&privileged_req("p-denied"));

    assert_eq!(resp.status, Status::Denied);
    assert!(resp.stdout.is_none(), "denied request must not produce output");
    // The prompter was consulted: the keypress gate was not bypassed.
    assert_eq!(s.prompter.call_count(), 1);
}

#[test]
fn privileged_timeout_is_not_executed() {
    let s = server();
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::Timeout));
    let resp = s.send(&privileged_req("p-timeout"));

    assert_eq!(resp.status, Status::Timeout);
    assert!(resp.stdout.is_none());
    assert_eq!(s.prompter.call_count(), 1);
}

#[test]
fn privileged_approved_always_is_rejected_not_granted() {
    // The TUI never emits ApprovedAlways for a privileged request, but the
    // dispatch must defensively treat it as a denial so no policy can
    // pre-grant root. (server.rs maps ApprovedAlways|Denied -> Denied here.)
    let s = server();
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::ApprovedAlways));
    let resp = s.send(&privileged_req("p-always"));

    assert_eq!(resp.status, Status::Denied);
    assert!(resp.stdout.is_none());
    assert_eq!(s.prompter.call_count(), 1);
}

// --- Property 5 (dispatch side): confirm_unprivileged flips only on 'a' ---

#[test]
fn plain_approve_keeps_confirm_unprivileged_set() {
    // confirm_unprivileged starts true; a plain Approved on an unprivileged
    // request must leave it set, so the *next* unprivileged request is still
    // prompted.
    let s = start_test_server(TestServerOpts {
        confirm_unprivileged: true,
        ..Default::default()
    });
    // Default ScriptedPrompter approves (plain) immediately.
    let r1 = s.send(&make_req("u-approve-1", vec![vec!["true"]]));
    let r2 = s.send(&make_req("u-approve-2", vec![vec!["true"]]));

    assert_eq!(r1.status, Status::Ok);
    assert_eq!(r2.status, Status::Ok);
    // Both requests were prompted: the flag never flipped.
    assert_eq!(s.prompter.call_count(), 2);
}

#[test]
fn approved_always_flips_confirm_unprivileged_off() {
    // Isolate the config directory: the ApprovedAlways dispatch path persists
    // the flipped policy via HostsConfig::save(), which writes
    // $XDG_CONFIG_HOME/sudo-proxy/hosts.json. Point it at a temp dir so the
    // test never touches the real user config. (set_var is process-global;
    // only this test in the binary writes config, so there is no race.)
    let cfg_dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    std::env::set_var("XDG_CONFIG_HOME", cfg_dir.path());

    let s = start_test_server(TestServerOpts {
        confirm_unprivileged: true,
        ..Default::default()
    });
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::ApprovedAlways));

    // First unprivileged request: prompted, answered ApprovedAlways -> runs
    // and flips the flag off.
    let r1 = s.send(&make_req("u-always-1", vec![vec!["true"]]));
    assert_eq!(r1.status, Status::Ok);
    assert_eq!(s.prompter.call_count(), 1);

    // Second unprivileged request: the flag is now off, so dispatch runs the
    // command without prompting. call_count must NOT increase.
    let r2 = s.send(&make_req("u-always-2", vec![vec!["true"]]));
    assert_eq!(r2.status, Status::Ok);
    assert_eq!(
        s.prompter.call_count(),
        1,
        "after ApprovedAlways the flag is off, so no further prompt should occur"
    );

    // The flipped policy was persisted to the isolated config, not the real
    // user config.
    let saved = std::fs::read_to_string(cfg_dir.path().join("sudo-proxy").join("hosts.json"))
        .expect("policy was persisted to the isolated config dir");
    assert!(
        saved.contains("\"confirm_unprivileged\""),
        "persisted config should record the policy flag: {saved}"
    );
}
