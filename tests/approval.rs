//! Dispatch-level approval invariants (Rung 2 of the assurance ladder).
//!
//! Two spec clauses, checked against the real `server::run` dispatch via the
//! `ScriptedPrompter` harness:
//!
//!  * **Property 4 — `privileged:true` ⇒ a keypress occurred.** A privileged
//!    request is always routed through the prompter, and root is executed only
//!    on `Approved`. Every non-`Approved` outcome (`Denied`, `Timeout`, and the
//!    defensively-rejected `ApprovedAlways`) ends in no execution.
//!  * **Property 5 (dispatch side) — unattended runs only behind two barriers
//!    (G7/C8).** No unprivileged command runs unattended unless the daemon is
//!    `unattended_eligible` (barrier 1, config-only — an out-of-band operator
//!    opt-in) AND a human answered `ApprovedAlways` (barrier 2, the `'a'` key,
//!    which `tui::classify_key` emits solely for an unprivileged request). The
//!    resulting grant is session-scoped and **never persisted**. On a
//!    non-eligible daemon `ApprovedAlways` approves the one command and grants
//!    nothing.

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

// --- Property 5 (dispatch side): two barriers, grant never persisted --------

#[test]
fn every_unprivileged_request_is_prompted_when_not_eligible() {
    // The default daemon is not eligible: every unprivileged request is
    // prompted, so a plain Approved on one leaves the next still prompted.
    let s = start_test_server(TestServerOpts::default());
    let r1 = s.send(&make_req("u-approve-1", vec![vec!["true"]]));
    let r2 = s.send(&make_req("u-approve-2", vec![vec!["true"]]));

    assert_eq!(r1.status, Status::Ok);
    assert_eq!(r2.status, Status::Ok);
    assert_eq!(s.prompter.call_count(), 2, "both must be prompted");
}

#[test]
fn non_eligible_approved_always_grants_nothing() {
    // Barrier 1: on a non-eligible daemon, even an ApprovedAlways answer
    // approves the single command but grants no session — the next request is
    // still prompted. This is the clause that makes `a` un-self-grantable
    // without the out-of-band config opt-in.
    let s = start_test_server(TestServerOpts::default());
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::ApprovedAlways));

    let r1 = s.send(&make_req("u-a-1", vec![vec!["true"]]));
    let r2 = s.send(&make_req("u-a-2", vec![vec!["true"]]));

    assert_eq!(r1.status, Status::Ok);
    assert_eq!(r2.status, Status::Ok);
    assert_eq!(
        s.prompter.call_count(),
        2,
        "ApprovedAlways must not grant a session when the daemon is not eligible"
    );
}

#[test]
fn eligible_approved_always_grants_session_but_never_persists() {
    // Isolate the config dir so we can assert the grant is NOT written to
    // hosts.json. (set_var is process-global; only this test in the binary
    // touches XDG_CONFIG_HOME.)
    let cfg_dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    std::env::set_var("XDG_CONFIG_HOME", cfg_dir.path());

    let s = start_test_server(TestServerOpts {
        unattended_eligible: true,
        ..Default::default()
    });
    s.prompter
        .set_response(|_| (Duration::ZERO, PromptResult::ApprovedAlways));

    // First unprivileged request: prompted, answered ApprovedAlways -> runs and
    // flips the in-memory session grant.
    let r1 = s.send(&make_req("u-always-1", vec![vec!["true"]]));
    assert_eq!(r1.status, Status::Ok);
    assert_eq!(s.prompter.call_count(), 1);

    // Second unprivileged request: granted, so dispatch runs it without
    // prompting. call_count must NOT increase.
    let r2 = s.send(&make_req("u-always-2", vec![vec!["true"]]));
    assert_eq!(r2.status, Status::Ok);
    assert_eq!(
        s.prompter.call_count(),
        1,
        "after the session grant, no further prompt should occur"
    );

    // The grant lives only in memory: nothing was persisted to hosts.json.
    let cfg = cfg_dir.path().join("sudo-proxy").join("hosts.json");
    if let Ok(saved) = std::fs::read_to_string(&cfg) {
        assert!(
            !saved.contains("unattended_eligible"),
            "the session grant must never be persisted: {saved}"
        );
    }
}
