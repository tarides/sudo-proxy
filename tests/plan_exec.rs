#![cfg(unix)]

//! Structured-plan execution: the daemon runs a `Plan` tree directly (pipes,
//! redirections, env, sequencing) with no shell on the privileged path. These
//! drive `exec_direct` (unprivileged, so every stage runs as the test user) and
//! one end-to-end case through the real daemon.

use std::collections::HashMap;

use sudo_proxy::executor::exec_direct;
use sudo_proxy::protocol::{
    Plan, RedirTarget, Request, Status, Stream, ValidatedRequest, WriteMode,
};

mod common;

fn run(argv: &[&str]) -> Plan {
    Plan::Run {
        argv: argv.iter().map(|s| s.to_string()).collect(),
    }
}

fn make_plan_req(plan: Plan) -> ValidatedRequest {
    let req = Request::new_plan(
        String::new(),
        "test".into(),
        plan,
        HashMap::new(),
        String::new(),
        false, // unprivileged: all stages run directly as the test user
        false,
    );
    ValidatedRequest::validate(req).expect("valid plan request")
}

fn decode_stdout(resp: &sudo_proxy::protocol::Response) -> String {
    String::from_utf8_lossy(&common::b64_decode(resp.stdout.as_deref().unwrap_or(""))).into_owned()
}

/// A pipe nested inside a seq: three leaves, and the response's stage list and
/// aggregate stdout match the pre-order leaf layout.
#[test]
fn pipe_inside_seq_runs_and_aggregates() {
    let plan = Plan::Seq {
        steps: vec![
            run(&["echo", "alpha"]),
            Plan::Pipe {
                stages: vec![run(&["echo", "hi"]), run(&["wc", "-c"])],
            },
        ],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    // Three Run leaves → three stages, in pre-order.
    assert_eq!(resp.stages.len(), 3, "stages: {:?}", resp.stages);
    let out = decode_stdout(&resp);
    // echo alpha (captured, standalone) + wc -c of "hi\n" == 3 (pipe tail).
    assert!(out.contains("alpha"), "stdout missing echo output: {out:?}");
    assert!(out.contains('3'), "stdout missing wc result: {out:?}");
}

/// `>` redirects a stage's stdout to a file; the aggregate stdout is then empty.
#[test]
fn redirect_stdout_to_file_truncate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("out.txt");
    let plan = Plan::Redirect {
        stream: Stream::Stdout,
        target: RedirTarget::File {
            path: path.to_string_lossy().into_owned(),
            mode: WriteMode::Truncate,
        },
        body: Box::new(run(&["printf", "hello-file"])),
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    let written = std::fs::read_to_string(&path).expect("read redirect file");
    assert_eq!(written, "hello-file");
    assert!(decode_stdout(&resp).is_empty(), "redirected stdout must not be captured");
}

/// `>>` appends rather than truncating.
#[test]
fn redirect_stdout_append() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("acc.txt");
    std::fs::write(&path, "seed-").unwrap();
    let plan = Plan::Redirect {
        stream: Stream::Stdout,
        target: RedirTarget::File {
            path: path.to_string_lossy().into_owned(),
            mode: WriteMode::Append,
        },
        body: Box::new(run(&["printf", "more"])),
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "seed-more");
}

/// `setenv` scopes a variable to its subtree, and the allowlist still applies.
#[test]
fn setenv_is_visible_to_the_stage() {
    let plan = Plan::Setenv {
        key: "LANG".into(),
        value: "xyz-sentinel".into(),
        body: Box::new(run(&["sh", "-c", "printf %s \"$LANG\""])),
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(decode_stdout(&resp), "xyz-sentinel");
}

/// A seq stops at the first failing step; later stages do not run.
#[test]
fn seq_short_circuits_on_failure() {
    let plan = Plan::Seq {
        steps: vec![
            run(&["false"]),
            run(&["sh", "-c", "printf SHOULD_NOT_RUN"]),
        ],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(resp.stages[0].exit_code, 1, "false exits 1");
    assert!(
        !decode_stdout(&resp).contains("SHOULD_NOT_RUN"),
        "second stage must not run after a failure"
    );
}

/// `with-accepted-exit-codes` lets a non-zero exit count as success, so the
/// seq continues past it.
#[test]
fn accepted_exit_codes_allow_seq_to_continue() {
    let plan = Plan::Seq {
        steps: vec![
            Plan::WithAcceptedExitCodes {
                codes: vec![1],
                body: Box::new(run(&["false"])),
            },
            run(&["sh", "-c", "printf continued"]),
        ],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert!(
        decode_stdout(&resp).contains("continued"),
        "accepted exit code should not stop the seq: {resp:?}"
    );
}

/// An alt stops at the first succeeding step; later alternatives do not run.
#[test]
fn alt_short_circuits_on_success() {
    let plan = Plan::Alt {
        steps: vec![
            run(&["true"]),
            run(&["sh", "-c", "printf SHOULD_NOT_RUN"]),
        ],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(resp.stages[0].exit_code, 0, "true exits 0");
    assert_eq!(
        resp.stages[1].exit_code, -1,
        "second alternative must not run after a success"
    );
    assert!(
        !decode_stdout(&resp).contains("SHOULD_NOT_RUN"),
        "second alternative must not run after a success"
    );
}

/// An alt runs the next alternative when a step fails.
#[test]
fn alt_runs_fallback_on_failure() {
    let plan = Plan::Alt {
        steps: vec![run(&["false"]), run(&["sh", "-c", "printf fallback"])],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(resp.stages[0].exit_code, 1, "false exits 1");
    assert!(
        decode_stdout(&resp).contains("fallback"),
        "the fallback alternative should run after a failure: {resp:?}"
    );
}

/// When every alternative fails, all of them run and the last failure stands.
#[test]
fn alt_all_fail_runs_every_step() {
    let plan = Plan::Alt {
        steps: vec![run(&["false"]), run(&["false"])],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(resp.stages[0].exit_code, 1);
    assert_eq!(resp.stages[1].exit_code, 1, "both alternatives run");
}

/// `with-accepted-exit-codes` makes a non-zero exit count as success, so the
/// alt stops there and does not run the fallback.
#[test]
fn accepted_exit_code_stops_alt() {
    let plan = Plan::Alt {
        steps: vec![
            Plan::WithAcceptedExitCodes {
                codes: vec![1],
                body: Box::new(run(&["false"])),
            },
            run(&["sh", "-c", "printf SHOULD_NOT_RUN"]),
        ],
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(
        resp.stages[1].exit_code, -1,
        "an accepted exit counts as success and stops the alt"
    );
    assert!(
        !decode_stdout(&resp).contains("SHOULD_NOT_RUN"),
        "an accepted exit should stop the alt: {resp:?}"
    );
}

/// The explicit `System` escape hatch runs a shell script verbatim.
#[test]
fn system_escape_hatch_runs() {
    let plan = Plan::System {
        shell: sudo_proxy::protocol::Shell::Sh,
        script: "printf hatch-ran".into(),
    };
    let resp = exec_direct(&make_plan_req(plan), &HashMap::new());
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 1);
    assert_eq!(decode_stdout(&resp), "hatch-ran");
}

/// End-to-end through the real daemon: a `plan`-bearing request is validated,
/// prompted (scripted-approved), executed, and its structured result returned.
#[test]
fn plan_request_end_to_end_through_daemon() {
    let server = common::start_test_server(common::TestServerOpts::default());

    let plan = Plan::Pipe {
        stages: vec![run(&["printf", "a\\nb\\nc\\n"]), run(&["wc", "-l"])],
    };
    let mut req = Request::new_plan(
        String::new(),
        "test".into(),
        plan,
        HashMap::new(),
        String::new(),
        false,
        false,
    );
    // The test harness' freshness window wants a current timestamp; new_plan
    // already stamps one, but normalize via the shared helper to be safe.
    req.time = common::iso_now();

    let resp = common::send_request(&server.socket_path, &req);
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(resp.stages.len(), 2);
    assert_eq!(
        decode_stdout(&resp).trim(),
        "3",
        "wc -l over three lines; full resp {resp:?}"
    );

    // The prompter was consulted for the plan request.
    assert!(
        !server.prompter.calls().is_empty(),
        "daemon should have prompted"
    );
}
