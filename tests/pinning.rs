#![cfg(unix)]
//! Issue #105: each program a request runs is resolved once and pinned from
//! the `no_shell` check through the prompt to the spawn.
//!
//! The `ScriptedPrompter` response runs while the request waits for
//! approval, so it changes the filesystem *between the prompt and the spawn*
//! with no hook in the daemon itself. Bare names resolve on the root-owned
//! login PATH, so every case uses `chdir` into a temp directory and a
//! `./name` program, which is resolved there.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sudo_proxy::protocol::{Plan, Request, Response, Status};
use sudo_proxy::tui::PromptResult;

mod common;
use common::*;

fn plan_req(id: &str, dir: &Path, argv: &[&str]) -> Request {
    let plan = Plan::Chdir {
        dir: dir.to_str().unwrap().to_string(),
        body: Box::new(Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }),
    };
    let mut req = Request::new_plan(
        String::new(),
        "test".into(),
        plan,
        Default::default(),
        String::new(),
        false,
        false,
    );
    req.id = id.to_string();
    req.time = iso_now();
    req
}

fn stdout(resp: &Response) -> String {
    String::from_utf8_lossy(&b64_decode(resp.stdout.as_deref().unwrap_or(""))).into_owned()
}

/// An executable `#!/bin/sh` script at `path`.
fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A server whose prompt runs `during` and then approves.
fn server_with(no_shell: bool, during: impl Fn() + Send + Sync + 'static) -> TestServer {
    let s = start_test_server(TestServerOpts {
        no_shell,
        ..Default::default()
    });
    s.prompter.set_response(move |_| {
        during();
        (Duration::ZERO, PromptResult::Approved)
    });
    s
}

fn assert_refused(resp: &Response, what: &str) {
    assert_eq!(resp.status, Status::Error, "{what}: {resp:?}");
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("changed since it was approved"),
        "{what}: {msg}"
    );
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in("/tmp").unwrap()
}

/// A file renamed over the approved one is a different inode: refused, and
/// neither the old nor the new file runs.
#[test]
fn file_replaced_after_approval_is_refused() {
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    script(&d.join("tool"), &format!("touch {}/ran-old", d.display()));
    let swap = d.clone();
    let s = server_with(false, move || {
        script(
            &swap.join("tool.new"),
            &format!("touch {}/ran-new", swap.display()),
        );
        std::fs::rename(swap.join("tool.new"), swap.join("tool")).unwrap();
    });
    let resp = s.send(&plan_req("pin-rename", &d, &["./tool"]));
    assert_refused(&resp, "renamed over");
    assert!(!d.join("ran-old").exists() && !d.join("ran-new").exists());
}

/// The no_shell bypass #105 closes: the check sees a symlink to `true`, and
/// the symlink points at a shell by spawn time.
#[test]
fn symlink_retargeted_to_a_shell_is_refused() {
    let Some(truth) = sudo_proxy::executor::resolve_command("true", "/") else {
        return;
    };
    let Some(sh) = sudo_proxy::executor::resolve_command("sh", "/") else {
        return;
    };
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    symlink(&truth.path, d.join("x")).unwrap();
    let swap = d.clone();
    let s = server_with(true, move || {
        std::fs::remove_file(swap.join("x")).unwrap();
        symlink(&sh.path, swap.join("x")).unwrap();
    });
    let marker = d.join("shell-ran");
    let cmd = format!("touch {}", marker.display());
    let resp = s.send(&plan_req("pin-symlink", &d, &["./x", "-c", &cmd]));
    assert_eq!(
        s.prompter.call_count(),
        1,
        "transparent at the check, so prompted"
    );
    assert_refused(&resp, "retargeted symlink");
    assert!(!marker.exists(), "the shell ran");
}

/// A program run by a wrapper is pinned too: swapping it is refused, and
/// left alone it runs under its absolute path, so `env` never searches.
#[test]
fn wrapped_program_is_pinned_and_named_by_path() {
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    script(&d.join("x"), "echo \"$0\"");

    let s = server_with(false, || {});
    let resp = s.send(&plan_req("pin-wrapped-ok", &d, &["env", "./x"]));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(
        stdout(&resp).trim_end(),
        d.join("./x").to_str().unwrap(),
        "absolute path"
    );

    let swap = d.clone();
    let s = server_with(false, move || {
        script(
            &swap.join("x.new"),
            &format!("touch {}/ran-new", swap.display()),
        );
        std::fs::rename(swap.join("x.new"), swap.join("x")).unwrap();
    });
    let resp = s.send(&plan_req("pin-wrapped-swap", &d, &["env", "./x"]));
    assert_refused(&resp, "wrapped program swapped");
    assert!(!d.join("ran-new").exists());
}

/// A wrapped program that is not found is refused before the spawn instead
/// of being searched for by the wrapper.
#[test]
fn unresolved_wrapped_program_is_refused() {
    let dir = tempdir();
    let s = server_with(false, || {});
    let resp = s.send(&plan_req(
        "pin-wrapped-missing",
        dir.path(),
        &["env", "./absent"],
    ));
    assert_eq!(resp.status, Status::Error, "{resp:?}");
    let msg = resp.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("command not found: ./absent (run by env)"),
        "{msg}"
    );
}

/// An unchanged program runs, and a binary executed through its pinned
/// descriptor keeps the requested argv[0] (a copy of `sh` here, so `$0`
/// shows it; renamed, it is not recognised as a shell, the known residual
/// of a copy as opposed to a symlink).
#[test]
fn unchanged_binary_runs_with_its_argv0() {
    let Some(sh) = sudo_proxy::executor::resolve_command("sh", "/") else {
        return;
    };
    let real = std::fs::canonicalize(&sh.path).unwrap();
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    std::fs::copy(&real, d.join("tool")).unwrap();
    let s = server_with(false, || {});
    let resp = s.send(&plan_req("pin-argv0", &d, &["./tool", "-c", "echo \"$0\""]));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(stdout(&resp), "./tool\n");
}

/// The documented residual: pinning fixes which file runs, not what is in
/// it. A script rewritten in place (same inode) runs its new contents.
#[test]
fn contents_rewritten_in_place_still_run() {
    let dir = tempdir();
    let d: PathBuf = dir.path().to_path_buf();
    script(&d.join("tool"), "echo old");
    let swap = d.clone();
    let s = server_with(false, move || {
        // `fs::write` truncates and rewrites the same inode.
        std::fs::write(swap.join("tool"), "#!/bin/sh\necho new\n").unwrap();
    });
    let resp = s.send(&plan_req("pin-inplace", &d, &["./tool"]));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(stdout(&resp), "new\n");
}

/// Review of #108: a script with no `#!` line is not a native binary, so it is
/// spawned by path (libc hands it to `/bin/sh`), not through its descriptor,
/// whose `/proc/self/fd` path would no longer open in the shell.
#[test]
fn script_without_shebang_still_runs() {
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    std::fs::write(d.join("plain"), "echo plain\n").unwrap();
    std::fs::set_permissions(d.join("plain"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let s = server_with(false, || {});
    let resp = s.send(&plan_req("pin-no-shebang", &d, &["./plain"]));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(stdout(&resp), "plain\n");
}

/// Review of #108: a pipe stage refused before its spawn (here a wrapped
/// program that is not found) refuses the whole pipe before any stage starts,
/// instead of killing the earlier stages part-way.
#[test]
fn pipe_refuses_before_any_stage_starts() {
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    let marker = d.join("first-ran");
    let exec = |argv: &[&str]| Plan::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
    };
    let plan = Plan::Chdir {
        dir: d.to_str().unwrap().to_string(),
        body: Box::new(Plan::Pipe {
            stages: vec![
                exec(&["touch", marker.to_str().unwrap()]),
                exec(&["env", "./absent"]),
            ],
        }),
    };
    let mut req = Request::new_plan(
        String::new(),
        "test".into(),
        plan,
        Default::default(),
        String::new(),
        false,
        false,
    );
    req.id = "pin-pipe-preflight".into();
    req.time = iso_now();
    let s = server_with(false, || {});
    let resp = s.send(&req);
    assert_eq!(resp.status, Status::Error, "{resp:?}");
    assert!(
        resp.message
            .as_deref()
            .unwrap_or("")
            .contains("command not found: ./absent"),
        "{resp:?}"
    );
    assert!(!marker.exists(), "the first stage started");
}

/// Send `req` while the test holds the TTY lock, run `meanwhile` once the
/// request is queued behind it, then release the lock.
fn send_while_queued(s: &TestServer, req: Request, meanwhile: impl FnOnce()) -> Response {
    let guard = s.tty_lock.lock().unwrap();
    let path = s.socket_path.clone();
    let t = std::thread::spawn(move || send_request(&path, &req));
    std::thread::sleep(Duration::from_millis(300));
    meanwhile();
    drop(guard);
    t.join().unwrap()
}

/// Review of #108: a request that queued for the TTY lock while one of its
/// programs was replaced (an upgrade by another request) is compiled again
/// before its prompt, so the human approves the file there now and it runs.
#[test]
fn queued_request_is_prepared_again_when_stale() {
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    script(&d.join("tool"), "echo old");
    let s = server_with(false, || {});
    let resp = send_while_queued(&s, plan_req("pin-queued", &d, &["./tool"]), || {
        script(&d.join("tool.new"), "echo new");
        std::fs::rename(d.join("tool.new"), d.join("tool")).unwrap();
    });
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    assert_eq!(stdout(&resp), "new\n");
    assert_eq!(s.prompter.call_count(), 1);
}

/// ...and the `no_shell` policy is applied to the new resolution: a symlink
/// retargeted to a shell while queued is refused without a prompt.
#[test]
fn queued_request_retargeted_to_a_shell_is_refused_by_no_shell() {
    let Some(truth) = sudo_proxy::executor::resolve_command("true", "/") else {
        return;
    };
    let Some(sh) = sudo_proxy::executor::resolve_command("sh", "/") else {
        return;
    };
    let dir = tempdir();
    let d = dir.path().to_path_buf();
    symlink(&truth.path, d.join("x")).unwrap();
    let s = server_with(true, || {});
    let resp = send_while_queued(
        &s,
        plan_req("pin-queued-sh", &d, &["./x", "-c", "true"]),
        || {
            std::fs::remove_file(d.join("x")).unwrap();
            symlink(&sh.path, d.join("x")).unwrap();
        },
    );
    assert_eq!(resp.status, Status::Error, "{resp:?}");
    assert!(
        resp.message.as_deref().unwrap_or("").contains("no_shell"),
        "{resp:?}"
    );
    assert_eq!(s.prompter.call_count(), 0, "refused before the prompt");
}
