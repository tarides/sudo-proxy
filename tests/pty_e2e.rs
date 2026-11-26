#![cfg(target_os = "linux")]

//! End-to-end tests against the real `sudo-proxy` binary and its real
//! `/dev/tty` prompt, driven through a pseudo-terminal (`common::pty`).
//! These cover what `ScriptedPrompter` tests cannot: the prompt as drawn,
//! single-key reads in raw mode, termios restoration, and the escalation spawn
//! (`sudo` resolved on the daemon's PATH, here a logging shim).

use sudo_proxy::protocol::{Plan, Request, RunAs, Status};

mod common;

use common::pty::{PtyDaemon, PtyOpts};

fn req(id: &str, argv: &[&str], reason: &str) -> Request {
    let mut r = common::make_req(id, vec![argv.to_vec()]);
    r.reason = reason.to_string();
    r
}

/// Split a shim argv `[-u USER] K=V... -- argv` into (`-u` target, argv).
fn split_sudo(argv: &[String]) -> (Option<&str>, &[String]) {
    let user = (argv.first().map(String::as_str) == Some("-u")).then(|| argv[1].as_str());
    let dd = argv
        .iter()
        .position(|a| a == "--")
        .expect("sudo argv has `--`");
    (user, &argv[dd + 1..])
}

#[test]
fn approve_unprivileged_runs_and_shows_result() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());
    let h = d.request_async(&req(
        "pty-approve-1",
        &["echo", "pty-ok"],
        "pty harness approve",
    ));

    let prompt = d.answer(b'y');
    assert!(
        prompt.contains("ID:      pty-approve-1"),
        "prompt: {prompt}"
    );
    assert!(
        prompt.contains("Reason:  pty harness approve"),
        "prompt: {prompt}"
    );
    assert!(prompt.contains("Command: echo pty-ok"), "prompt: {prompt}");

    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "pty-ok\n");

    // The result block is drawn before the response is written, so it is
    // already in the capture.
    d.expect("→ Approved");
    d.expect("exit 0");
    assert!(d.is_cooked(), "termios not restored after the prompt");
    assert!(
        d.shim_log().is_empty(),
        "unprivileged run must not go through sudo"
    );
}

/// The real binary writes its audit log by default (issue #65), under the
/// harness's `HOME` since `XDG_STATE_HOME` is unset.
#[test]
fn default_audit_log_records_the_outcome() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());
    let h = d.request_async(&req("pty-audit-1", &["true"], "pty audit"));
    d.answer(b'n');
    assert_eq!(h.join().unwrap().status, Status::Denied);

    let path = d.dir().join("home/.local/state/sudo-proxy/audit.jsonl");
    let recs = common::read_audit(&path);
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["id"], "pty-audit-1");
    assert_eq!(recs[0]["outcome"], "denied");
}

#[test]
fn deny_with_n_and_with_enter() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    for (id, key) in [("pty-deny-n", b'n'), ("pty-deny-enter", b'\r')] {
        // In the harness dir, so it is cleaned up even when the test fails.
        let marker = d.dir().join(format!("{id}.ran"));
        let h = d.request_async(&req(
            id,
            &["touch", marker.to_str().unwrap()],
            "pty harness deny",
        ));
        let prompt = d.answer(key);
        assert!(prompt.contains(id), "prompt: {prompt}");
        let resp = h.join().unwrap();
        assert_eq!(resp.status, Status::Denied, "{id}: {resp:?}");
        d.expect("→ Denied");
        assert!(!marker.exists(), "{id}: denied command ran");
        assert!(d.is_cooked(), "{id}: termios not restored");
    }
    assert!(d.shim_log().is_empty());
}

#[test]
fn privileged_goes_through_sudo_with_literal_argv() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    // Whole-command privilege: run as root, so no `-u`. The empty argument
    // and the shell metacharacters must reach sudo untouched.
    let mut root = req(
        "pty-priv-root",
        &["echo", "as root", "", "$HOME;x"],
        "pty harness root",
    );
    root.privileged = true;
    let h = d.request_async(&root);
    let prompt = d.answer(b'y');
    assert!(prompt.contains("Execute as root?"), "prompt: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "as root  $HOME;x\n");

    // A plan step run as a named user: `-u nobody`.
    let mut user = common::make_req("pty-priv-user", vec![]);
    user.plan = Some(Plan::RunAs {
        who: RunAs::User {
            name: "nobody".into(),
        },
        body: Box::new(Plan::Exec {
            argv: vec!["echo".into(), "as-nobody".into()],
        }),
    });
    let h = d.request_async(&user);
    let prompt = d.answer(b'y');
    assert!(
        prompt.contains("Execute with elevated privileges?"),
        "prompt: {prompt}"
    );
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "as-nobody\n");

    // Assert only on the `-u` target and the argv after `--`: the `K=V`
    // part carries the runner's HOME/USER. The command is the path the prompt
    // resolved, so sudo's `secure_path` never gets a second lookup (#62).
    let echo = sudo_proxy::executor::resolve_command("echo", "/")
        .expect("echo on default PATH")
        .path;
    let echo = echo.to_str().unwrap();
    let log = d.shim_log();
    assert_eq!(log.len(), 2, "one sudo spawn per privileged step: {log:?}");
    let (u, argv) = split_sudo(&log[0]);
    assert_eq!(u, None);
    assert_eq!(argv, [echo, "as root", "", "$HOME;x"]);
    let (u, argv) = split_sudo(&log[1]);
    assert_eq!(u, Some("nobody"));
    assert_eq!(argv, [echo, "as-nobody"]);
}

/// Issue #62: the prompt and the spawn resolve `argv[0]` once, on the child's
/// PATH — never the daemon's. A daemon started from a shell whose PATH holds a
/// fake `id` and a tool that exists only there must neither show those files
/// nor be told to run something it then cannot find. A relative name resolves
/// against the plan's `chdir`, where the child starts.
#[test]
fn resolves_line_names_the_binary_that_runs() {
    let fake = tempfile::tempdir_in("/tmp").expect("tempdir");
    let bin = fake.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    for (name, body) in [("id", "echo FAKE-id"), ("only-here", "echo hello")] {
        let f = bin.join(name);
        std::fs::write(&f, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    let fake_bin = bin.to_str().unwrap();
    let mut d = PtyDaemon::spawn(PtyOpts {
        extra_path: vec![bin.clone()],
        ..Default::default()
    });

    // `id`: the prompt names the system binary, and that is what runs.
    let real_id = sudo_proxy::executor::resolve_command("id", "/")
        .expect("id on default PATH")
        .path;
    let h = d.request_async(&req("pty-62-id", &["id"], "issue 62"));
    let prompt = d.answer(b'y');
    assert!(
        prompt.contains(&format!("Resolves: {}", real_id.display())),
        "prompt: {prompt}"
    );
    assert!(
        !prompt.contains(fake_bin),
        "prompt shows the daemon's PATH: {prompt}"
    );
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    let out = common::decode_stdout(&resp);
    assert!(out.starts_with("uid="), "the fake ran: {out:?}");

    // `only-here`: shown as not found, and refused without a second lookup.
    let h = d.request_async(&req("pty-62-only", &["only-here"], "issue 62"));
    let prompt = d.answer(b'y');
    assert!(
        prompt.contains("Resolves: (not found in PATH)"),
        "prompt: {prompt}"
    );
    let resp = h.join().unwrap();
    assert_ne!(resp.status, Status::Ok, "{resp:?}");
    assert!(
        format!("{resp:?}").contains("command not found: only-here"),
        "{resp:?}"
    );

    // `./bin/only-here` under `chdir`: resolved in, and run from, that dir.
    let mut rel = common::make_req("pty-62-rel", vec![]);
    rel.plan = Some(Plan::Chdir {
        dir: fake.path().to_str().unwrap().into(),
        body: Box::new(Plan::Exec {
            argv: vec!["./bin/only-here".into()],
        }),
    });
    let h = d.request_async(&rel);
    let prompt = d.answer(b'y');
    assert!(
        prompt.contains(&format!("{}/./bin/only-here", fake.path().display())),
        "prompt: {prompt}"
    );
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "hello\n");
}

/// Issue #88: under `--pkexec` (with a display, so `Mode::Local`), a
/// privileged multi-step plan must not be handed to pkexec's single-argv
/// dialog: it gets the TUI prompt and, once approved, sudo. Checks the real
/// CLI wiring (`--pkexec` → `pkexec_only`, `Mode::detect`). The leaves name a
/// nonexistent program, so a regressed gate fails at `build_command` and never
/// raises a polkit dialog for the test argv.
#[test]
fn pkexec_flag_multi_step_plan_gets_the_tui_prompt() {
    const NO_SUCH: &str = "sudo-proxy-test-88-no-such-cmd";
    let mut d = PtyDaemon::spawn(PtyOpts {
        args: vec!["--pkexec".into()],
        env: vec![("DISPLAY".into(), ":99".into())],
        ..Default::default()
    });
    let step = |n: &str| Plan::Exec {
        argv: vec![NO_SUCH.into(), n.into()],
    };
    let mut r = common::make_req("pty-pkexec-88", vec![]);
    r.privileged = true;
    r.plan = Some(Plan::Run {
        steps: vec![step("step-one"), step("step-two")],
    });
    let h = d.request_async(&r);
    let prompt = d.answer(b'n');
    assert!(prompt.contains("Execute as root?"), "prompt: {prompt}");
    assert!(prompt.contains("step-one"), "prompt: {prompt}");
    assert!(prompt.contains("step-two"), "prompt: {prompt}");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Denied, "{resp:?}");
    assert!(
        d.shim_log().is_empty(),
        "sudo ran on denial: {:?}",
        d.shim_log()
    );
    // Not vacuous: the daemon really ran in local (pkexec-capable) mode.
    let log = d.daemon_log();
    assert!(
        log.contains("mode: local (TUI + pkexec)"),
        "daemon log: {log}"
    );
}

/// GHSA-gx9w-4f7x-2gcp, end to end: a `sudo` planted first on the daemon's
/// own PATH never runs. The approved privileged request goes through the
/// escalator the daemon was given (`--sudo-path`, the shim), and the startup
/// report names it.
#[test]
fn planted_sudo_on_daemon_path_never_runs() {
    let plant = tempfile::tempdir_in("/tmp").expect("tempdir");
    let marker = plant.path().join("PLANTED");
    let fake = plant.path().join("sudo");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\ntouch '{}'\nexit 97\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let mut d = PtyDaemon::spawn(PtyOpts {
        extra_path: vec![plant.path().to_path_buf()],
        ..Default::default()
    });

    let mut r = req("pty-gx9w", &["echo", "real"], "GHSA-gx9w");
    r.privileged = true;
    let h = d.request_async(&r);
    d.answer(b'y');
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(common::decode_stdout(&resp), "real\n");
    assert!(
        !marker.exists(),
        "the sudo planted on the daemon's PATH ran"
    );
    assert_eq!(d.shim_log().len(), 1, "the --sudo-path escalator ran once");
    let log = d.daemon_log();
    assert!(
        log.contains("--sudo-path; not checked"),
        "daemon log: {log}"
    );
}
