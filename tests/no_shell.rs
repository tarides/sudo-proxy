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
/// pipe, a legacy flat-pipeline stage, and a shell behind a wrapper (#87).
/// These are harmless: `without_no_shell_opaque_stages_are_prompted` runs them.
fn opaque_requests() -> Vec<Request> {
    let mut reqs = vec![
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
        plan_req("env-sh", exec(&["env", "sh", "-c", "true"])),
        plan_req("nice-bash", exec(&["nice", "bash", "-c", "true"])),
        plan_req("timeout-sh", exec(&["timeout", "5", "sh", "-c", "true"])),
        plan_req(
            "pipe-env-bash",
            Plan::Pipe { stages: vec![exec(&["echo", "x"]), exec(&["env", "bash", "-c", "cat"])] },
        ),
        // Review C2: `-printf` absorbs the first `-exec`; find runs the second.
        plan_req(
            "find-printf-exec",
            exec(&["find", ".", "-maxdepth", "0", "-printf", "-exec", "-exec", "sh", "-c", "true", ";"]),
        ),
        // Review C3: uutils `timeout` skips the `--` and runs `sh`.
        plan_req("timeout-dashdash-sh", exec(&["timeout", "5", "--", "sh", "-c", "true"])),
        // Review C8: uutils `timeout` parses options after the duration.
        plan_req(
            "timeout-opt-after-operand",
            exec(&["timeout", "5", "-v", "sh", "-c", "true"]),
        ),
        // Review C4: xargs takes its program from its input (stdin is empty).
        plan_req("xargs-replace", exec(&["xargs", "-I{}", "{}"])),
    ];
    if sudo_proxy::executor::resolve_command("coreutils", "/").is_some() {
        reqs.push(plan_req("coreutils-env-sh", exec(&["coreutils", "env", "sh", "-c", "true"])));
    }
    reqs
}

/// Opaque forms that must not run in CI (an interpreter, a runner, an `env`
/// that changes PATH or preloads a library, a `find` running what it finds):
/// only checked as rejected.
fn opaque_rejected_only() -> Vec<Request> {
    vec![
        plan_req("python3-c", exec(&["python3", "-c", "print(1)"])),
        // Review C1: inline code attached after a switch cluster.
        plan_req("python3-Bc-attached", exec(&["python3", "-Bcprint(1)", "foo"])),
        plan_req("perl-le-attached", exec(&["perl", "-le'print 1'", "/dev/null"])),
        plan_req("sudo-true", exec(&["sudo", "true"])),
        plan_req("env-split", exec(&["env", "-S", "true"])),
        plan_req("env-path", exec(&["env", "PATH=/tmp", "true"])),
        plan_req("env-ld-preload", exec(&["env", "LD_PRELOAD=/nonexistent.so", "true"])),
        plan_req("find-exec-found", exec(&["find", ".", "-maxdepth", "0", "-exec", "{}", ";"])),
    ]
}

#[test]
fn no_shell_rejects_opaque_stages_without_prompting() {
    let s = server(true);
    for req in opaque_requests().into_iter().chain(opaque_rejected_only()) {
        let id = req.id.clone();
        let resp = s.send(&req);
        assert_eq!(resp.status, Status::Error, "{id}: got {resp:?}");
        let msg = resp.message.as_deref().unwrap_or("");
        assert!(msg.contains("no_shell"), "{id}: message names the policy: {msg}");
        assert!(msg.contains("opaque — "), "{id}: message gives the reason: {msg}");
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

    // A wrapper around a plain program stays transparent (#87).
    let wrapped = [
        exec(&["env", "FOO=1", "true"]),
        exec(&["nice", "-n", "5", "true"]),
        exec(&["timeout", "5", "true"]),
    ];
    let n = wrapped.len();
    for (i, plan) in wrapped.into_iter().enumerate() {
        let resp = s.send(&plan_req(&format!("wrapped-{i}"), plan));
        assert_eq!(resp.status, Status::Ok, "wrapped-{i}: got {resp:?}");
    }
    assert_eq!(s.prompter.call_count(), 1 + n, "wrapped requests are prompted");
}

/// The rejection names the wrapped program and the wrapper, with the same
/// reason text the prompt shows.
#[test]
fn no_shell_message_names_the_wrapped_program() {
    let s = server(true);
    let resp = s.send(&plan_req("msg", exec(&["env", "sh", "-c", "true"])));
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(msg.contains("stage 0 runs sh via env: opaque — resolves only the shell"), "{msg}");
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
