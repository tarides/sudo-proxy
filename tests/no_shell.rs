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
/// pipe, a legacy flat-pipeline stage, a shell behind a wrapper (#87), and
/// `flock FILE -c` (#92).
/// These are harmless: `without_no_shell_opaque_stages_are_prompted` runs them.
fn opaque_requests() -> Vec<Request> {
    let mut reqs = vec![
        plan_req(
            "shell-op",
            Plan::Shell {
                shell: ShellProc::Sh,
                script: "echo hi".into(),
            },
        ),
        plan_req("exec-sh-c", exec(&["sh", "-c", "echo hi"])),
        plan_req("exec-abs-bash", exec(&["/bin/bash", "-lc", "echo hi"])),
        plan_req("exec-sh-no-c", exec(&["sh"])),
        plan_req(
            "pipe-stage",
            Plan::Pipe {
                stages: vec![exec(&["echo", "x"]), exec(&["bash", "-c", "cat"])],
            },
        ),
        common::make_req("flat-pipeline", vec![vec!["sh", "-c", "echo hi"]]),
        plan_req("env-sh", exec(&["env", "sh", "-c", "true"])),
        plan_req("nice-bash", exec(&["nice", "bash", "-c", "true"])),
        plan_req("timeout-sh", exec(&["timeout", "5", "sh", "-c", "true"])),
        plan_req(
            "pipe-env-bash",
            Plan::Pipe {
                stages: vec![exec(&["echo", "x"]), exec(&["env", "bash", "-c", "cat"])],
            },
        ),
        // Review C2: `-printf` absorbs the first `-exec`; find runs the second.
        plan_req(
            "find-printf-exec",
            exec(&[
                "find",
                ".",
                "-maxdepth",
                "0",
                "-printf",
                "-exec",
                "-exec",
                "sh",
                "-c",
                "true",
                ";",
            ]),
        ),
        // Review C3: uutils `timeout` skips the `--` and runs `sh`.
        plan_req(
            "timeout-dashdash-sh",
            exec(&["timeout", "5", "--", "sh", "-c", "true"]),
        ),
        // Review C8: uutils `timeout` parses options after the duration.
        plan_req(
            "timeout-opt-after-operand",
            exec(&["timeout", "5", "-v", "sh", "-c", "true"]),
        ),
        // Review C4: xargs takes its program from its input (stdin is empty).
        plan_req("xargs-replace", exec(&["xargs", "-I{}", "{}"])),
    ];
    if sudo_proxy::executor::resolve_command("coreutils", "/").is_some() {
        reqs.push(plan_req(
            "coreutils-env-sh",
            exec(&["coreutils", "env", "sh", "-c", "true"]),
        ));
    }
    // #92: flock runs the program after the lock file, or `$SHELL -c` with
    // `-c`. The lock is taken on the temp directory, which exists, so running
    // them creates no file.
    if sudo_proxy::executor::resolve_command("flock", "/").is_some() {
        let lock = std::env::temp_dir();
        let lock = lock.to_str().unwrap();
        reqs.push(plan_req(
            "flock-sh",
            exec(&["flock", lock, "sh", "-c", "true"]),
        ));
        reqs.push(plan_req("flock-c", exec(&["flock", lock, "-c", "true"])));
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
        plan_req(
            "python3-Bc-attached",
            exec(&["python3", "-Bcprint(1)", "foo"]),
        ),
        plan_req(
            "perl-le-attached",
            exec(&["perl", "-le'print 1'", "/dev/null"]),
        ),
        plan_req("sudo-true", exec(&["sudo", "true"])),
        plan_req("env-split", exec(&["env", "-S", "true"])),
        plan_req("env-path", exec(&["env", "PATH=/tmp", "true"])),
        plan_req(
            "env-ld-preload",
            exec(&["env", "LD_PRELOAD=/nonexistent.so", "true"]),
        ),
        plan_req(
            "find-exec-found",
            exec(&["find", ".", "-maxdepth", "0", "-exec", "{}", ";"]),
        ),
        // #91: a command string run remotely or through a shell.
        plan_req("ssh-cmd", exec(&["ssh", "h", "true"])),
        plan_req("ssh-bare", exec(&["ssh", "h"])),
        plan_req("rsync-e", exec(&["rsync", "-e", "x", "a", "b"])),
        plan_req(
            "rsync-path",
            exec(&["timeout", "5", "rsync", "--rsync-path=x", "a", "h:b"]),
        ),
        plan_req("scp-S", exec(&["scp", "-S", "x", "a", "h:b"])),
        plan_req(
            "scp-proxycommand",
            exec(&["scp", "-o", "ProxyCommand=x", "a", "h:b"]),
        ),
        plan_req("git-c", exec(&["git", "-c", "core.sshCommand=x", "fetch"])),
        plan_req("git-ext", exec(&["git", "clone", "ext::x", "d"])),
        plan_req(
            "git-rebase-exec",
            exec(&["git", "rebase", "--exec", "x", "main"]),
        ),
        plan_req(
            "git-submodule-foreach",
            exec(&["git", "submodule", "foreach", "x"]),
        ),
        plan_req(
            "env-rsync-rsh",
            exec(&["env", "RSYNC_RSH=x", "rsync", "a", "h:b"]),
        ),
        // Review of PR #117.
        plan_req(
            "scp-o-blank",
            exec(&["scp", "-o", " ProxyCommand=x", "a", "h:b"]),
        ),
        plan_req("scp-legacy", exec(&["scp", "-O", "a", "h:b"])),
        plan_req(
            "scp-pkcs11",
            exec(&["scp", "-o", "PKCS11Provider=/x.so", "a", "h:b"]),
        ),
        plan_req("rsync-old-args", exec(&["rsync", "--old-args", "a", "h:b"])),
        plan_req("rsync-daemon", exec(&["rsync", "--daemon", "--config=x"])),
        plan_req("git-abbrev", exec(&["git", "fetch", "--upload=x", "o"])),
        plan_req("git-grep-O", exec(&["git", "grep", "-Ox", "p"])),
        plan_req(
            "git-template",
            exec(&["git", "clone", "--template=t", "o", "d"]),
        ),
        plan_req("git-unlisted", exec(&["git", "remote-ext", "x", "id"])),
        plan_req("git-dashed", exec(&["git-rebase", "-x", "id", "main"])),
        plan_req(
            "env-git-external-diff",
            exec(&["env", "GIT_EXTERNAL_DIFF=x", "git", "diff"]),
        ),
        plan_req("ssh-agent", exec(&["ssh-agent", "true"])),
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
        assert!(
            msg.contains("no_shell"),
            "{id}: message names the policy: {msg}"
        );
        assert!(
            msg.contains("opaque — "),
            "{id}: message gives the reason: {msg}"
        );
        assert!(resp.stdout.is_none(), "{id}: nothing ran");
    }
    assert_eq!(s.prompter.call_count(), 0, "rejected before any prompt");
}

#[test]
fn no_shell_still_runs_structured_requests() {
    let s = server(true);
    let resp = s.send(&plan_req(
        "structured",
        Plan::Pipe {
            stages: vec![exec(&["echo", "sh"]), exec(&["cat"])],
        },
    ));
    assert_eq!(resp.status, Status::Ok, "got {resp:?}");
    assert_eq!(s.prompter.call_count(), 1, "structured request is prompted");

    // A wrapper around a plain program stays transparent (#87, #92).
    let mut wrapped = vec![
        exec(&["env", "FOO=1", "true"]),
        exec(&["nice", "-n", "5", "true"]),
        exec(&["timeout", "5", "true"]),
    ];
    if sudo_proxy::executor::resolve_command("flock", "/").is_some() {
        let lock = std::env::temp_dir();
        wrapped.push(exec(&["flock", lock.to_str().unwrap(), "true"]));
    }
    let n = wrapped.len();
    for (i, plan) in wrapped.into_iter().enumerate() {
        let resp = s.send(&plan_req(&format!("wrapped-{i}"), plan));
        assert_eq!(resp.status, Status::Ok, "wrapped-{i}: got {resp:?}");
    }
    assert_eq!(
        s.prompter.call_count(),
        1 + n,
        "wrapped requests are prompted"
    );

    // git with no command-string option stays structured (#91).
    if sudo_proxy::executor::resolve_command("git", "/").is_some() {
        let resp = s.send(&plan_req("git-version", exec(&["git", "--version"])));
        assert_eq!(resp.status, Status::Ok, "git-version: got {resp:?}");
        assert_eq!(s.prompter.call_count(), 2 + n, "git --version is prompted");
    }
}

/// #91: the rejection gives the command-string reason.
#[test]
fn no_shell_message_names_the_command_string() {
    let s = server(true);
    let resp = s.send(&plan_req("rsync", exec(&["rsync", "-e", "x", "a", "b"])));
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("opaque — runs a command string remotely or through a shell (-e)"),
        "{msg}"
    );

    // #92: `flock FILE -c` names flock and its `-c`.
    if sudo_proxy::executor::resolve_command("flock", "/").is_none() {
        return;
    }
    let lock = std::env::temp_dir();
    let resp = s.send(&plan_req(
        "flock-c",
        exec(&["flock", lock.to_str().unwrap(), "-c", "true"]),
    ));
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("opaque — runs a command string remotely or through a shell (-c)"),
        "{msg}"
    );
}

/// The rejection names the wrapped program and the wrapper, with the same
/// reason text the prompt shows.
#[test]
fn no_shell_message_names_the_wrapped_program() {
    let s = server(true);
    let resp = s.send(&plan_req("msg", exec(&["env", "sh", "-c", "true"])));
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("stage 0 runs sh via env: opaque — resolves only the shell"),
        "{msg}"
    );
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
    assert_eq!(
        s.prompter.call_count(),
        n,
        "every opaque request is prompted"
    );
}
