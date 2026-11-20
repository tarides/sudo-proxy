#![cfg(unix)]

//! Strict `no_shell` policy: a daemon started with `--no-shell` (or
//! `policy.no_shell` in hosts.json) rejects, before prompting, any request with
//! an opaque stage: an explicit `shell` op, or an `exec` whose program is a
//! shell (the `exec sh -c` loophole). Structured requests are unaffected.

use sudo_proxy::protocol::{Plan, Request, ShellProc, Status};

mod common;

fn server(no_shell: bool) -> common::TestServer {
    common::start_test_server(common::TestServerOpts {
        no_shell,
        ..Default::default()
    })
}

fn exec(argv: &[&str]) -> Plan {
    Plan::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
    }
}

fn plan_req(id: &str, plan: Plan) -> Request {
    let mut req = common::make_req(id, vec![]);
    req.plan = Some(plan);
    req
}

/// Every opaque form the policy must catch: the explicit hatch, an `exec` of
/// a shell by name and by path, a shell without `-c`, a shell nested in a
/// pipe, and a legacy flat-pipeline stage.
fn opaque_requests() -> Vec<Request> {
    vec![
        plan_req(
            "shell-op",
            Plan::Shell { shell: ShellProc::Sh, script: "echo hi".into() },
        ),
        plan_req("exec-sh-c", exec(&["sh", "-c", "echo hi"])),
        plan_req("exec-abs-bash", exec(&["/bin/bash", "-lc", "echo hi"])),
        plan_req("exec-sh-no-c", exec(&["sh"])),
        plan_req(
            "pipe-stage",
            Plan::Pipe { stages: vec![exec(&["echo", "x"]), exec(&["bash", "-c", "cat"])] },
        ),
        common::make_req("flat-pipeline", vec![vec!["sh", "-c", "echo hi"]]),
    ]
}

#[test]
fn no_shell_rejects_opaque_stages_without_prompting() {
    let s = server(true);
    for req in opaque_requests() {
        let id = req.id.clone();
        let resp = s.send(&req);
        assert_eq!(resp.status, Status::Error, "{id}: got {resp:?}");
        let msg = resp.message.as_deref().unwrap_or("");
        assert!(msg.contains("no_shell"), "{id}: message names the policy: {msg}");
        assert!(resp.stdout.is_none(), "{id}: nothing ran");
    }
    assert_eq!(s.prompter.call_count(), 0, "rejected before any prompt");
}

#[test]
fn no_shell_still_runs_structured_requests() {
    let s = server(true);
    let resp = s.send(&plan_req(
        "structured",
        Plan::Pipe { stages: vec![exec(&["echo", "sh"]), exec(&["cat"])] },
    ));
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(s.prompter.call_count(), 1, "structured request is prompted");
}

#[test]
fn without_no_shell_opaque_stages_are_prompted() {
    let s = server(false);
    let n = opaque_requests().len();
    for req in opaque_requests() {
        let id = req.id.clone();
        let resp = s.send(&req);
        assert_ne!(resp.status, Status::Error, "{id}: got {resp:?}");
    }
    assert_eq!(s.prompter.call_count(), n, "every opaque request is prompted");
}
