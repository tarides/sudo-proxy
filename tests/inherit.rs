#![cfg(unix)]

//! `--inherit-path` / `--inherit-env` (issue #101).
//!
//! Its own test binary: it sets this process's environment and the
//! process-wide `sudo` override once ([`setup`]), so the daemon threads it
//! starts see a dev-shell-like environment and a stand-in `sudo`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use sudo_proxy::executor::prepare_with;
use sudo_proxy::inherit::{parse_patterns, InheritMode, Inherited};
use sudo_proxy::protocol::{Plan, Request, RunAs, Status, ValidatedRequest};

mod common;

/// The login PATH an env-cleared child gets without the flags.
const LOGIN_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

struct Setup {
    _dir: tempfile::TempDir,
    /// The dev shell's bin directory, first on the inherited PATH.
    bin: PathBuf,
    /// The stand-in `sudo` (`tests/shims/sudo`), copied here.
    sudo_dir: PathBuf,
    path: String,
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn mkdir755(p: &Path) {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn setup() -> &'static Setup {
    static S: OnceLock<Setup> = OnceLock::new();
    S.get_or_init(|| {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let root = dir.path().to_path_buf();
        mkdir755(&root);
        let bin = root.join("bin");
        mkdir755(&bin);
        // A dev-shell tool, found only on the inherited PATH.
        script(&bin.join("devtool"), "exec env");

        let sudo_dir = root.join("sudo");
        mkdir755(&sudo_dir);
        let shim = sudo_dir.join("sudo");
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/shims/sudo"), &shim).unwrap();
        sudo_proxy::helper::set_sudo_override(&shim).unwrap();

        let path = format!("{}:/usr/bin:/bin", bin.display());
        // The daemon's own environment, as a dev shell would leave it.
        std::env::set_var("PATH", &path);
        std::env::set_var("REPO_ROOT", "/repo");
        std::env::set_var("TF_VAR_region", "eu");
        Setup { _dir: dir, bin, sudo_dir, path }
    })
}

fn inherited(patterns: &str) -> Arc<Inherited> {
    let s = setup();
    let env: Vec<(OsString, OsString)> = [
        ("PATH", s.path.as_str()),
        ("REPO_ROOT", "/repo"),
        ("TF_VAR_region", "eu"),
        ("OTHER", "x"),
        ("PYTHONPATH", "/py"),
    ]
    .iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let uid = unsafe { libc::geteuid() };
    Arc::new(Inherited::from_env(InheritMode::Env, parse_patterns(patterns).unwrap(), env, uid).unwrap())
}

fn exec(argv: &[&str]) -> Plan {
    Plan::Exec { argv: argv.iter().map(|s| s.to_string()).collect() }
}

fn plan_req(plan: Plan, env: HashMap<String, String>) -> Request {
    let mut r = Request::new_plan(String::new(), "test".into(), plan, env, String::new(), false, false);
    r.time = common::iso_now();
    r
}

fn env_lines(out: &str) -> HashMap<String, String> {
    out.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn unprivileged_step_runs_with_the_inherited_path_and_variables() {
    let s = setup();
    let server = common::start_test_server(common::TestServerOpts {
        inherit: Some(inherited("REPO_ROOT,TF_VAR_*")),
        ..Default::default()
    });

    // `devtool` is found only on the inherited PATH.
    let resp = server.send(&plan_req(exec(&["devtool"]), HashMap::new()));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    let env = env_lines(&common::decode_stdout(&resp));
    assert_eq!(env.get("PATH").map(String::as_str), Some(s.path.as_str()));
    assert_eq!(env.get("REPO_ROOT").map(String::as_str), Some("/repo"));
    assert_eq!(env.get("TF_VAR_region").map(String::as_str), Some("eu"));
    assert!(!env.contains_key("OTHER"), "not matched: {env:?}");
    assert!(!env.contains_key("PYTHONPATH"), "never matched by a wildcard: {env:?}");
    // Login defaults fill the names the inherited layer leaves unset.
    assert!(env.contains_key("HOME") && env.contains_key("USER"), "{env:?}");

    // The request's own allowlisted variables still win.
    let resp = server.send(&plan_req(exec(&["devtool"]), HashMap::from([("HOME".into(), "/req".into())])));
    let env = env_lines(&common::decode_stdout(&resp));
    assert_eq!(env.get("HOME").map(String::as_str), Some("/req"));
}

#[test]
fn without_the_flags_the_login_path_is_used() {
    setup();
    let server = common::start_test_server(common::TestServerOpts::default());
    let resp = server.send(&plan_req(exec(&["devtool"]), HashMap::new()));
    assert_ne!(resp.status, Status::Ok, "devtool must not resolve without --inherit-path: {resp:?}");
    let resp = server.send(&plan_req(exec(&["env"]), HashMap::new()));
    let env = env_lines(&common::decode_stdout(&resp));
    assert_eq!(env.get("PATH").map(String::as_str), Some(LOGIN_PATH));
    assert!(!env.contains_key("REPO_ROOT"), "{env:?}");
}

/// `gen | sudo tee`: a request with any escalated step inherits nothing, in
/// none of its steps. (A `sudo` planted on the daemon's PATH is covered by
/// `tests/escalator_stub.rs`; here the stand-in is named directly.)
#[test]
fn escalated_request_gets_nothing_inherited() {
    let s = setup();
    let server = common::start_test_server(common::TestServerOpts {
        inherit: Some(inherited("REPO_ROOT,TF_VAR_*")),
        ..Default::default()
    });
    let plan = Plan::Pipe {
        stages: vec![
            exec(&["env"]),
            Plan::RunAs { who: RunAs::Root, body: Box::new(exec(&["cat"])) },
        ],
    };
    let resp = server.send(&plan_req(plan, HashMap::new()));
    assert_eq!(resp.status, Status::Ok, "{resp:?}");
    let out = common::decode_stdout(&resp);
    let env = env_lines(&out);
    assert_eq!(env.get("PATH").map(String::as_str), Some(LOGIN_PATH), "{out}");
    for n in ["REPO_ROOT", "TF_VAR_region"] {
        assert!(!env.contains_key(n), "{n} reached a step of an escalated request:\n{out}");
    }
    // The escalated step: sudo's argv and environment carry no inherited name.
    let argv = std::fs::read_to_string(s.sudo_dir.join("sudo.log")).unwrap();
    let senv = std::fs::read_to_string(s.sudo_dir.join("sudo.env")).unwrap();
    for n in ["REPO_ROOT", "TF_VAR_region", &s.bin.display().to_string()] {
        assert!(!argv.contains(n), "sudo argv carries {n}: {argv:?}");
        assert!(!senv.contains(n), "sudo environment carries {n}: {senv}");
    }
}

#[test]
fn prepare_refuses_to_inherit_into_an_escalated_request() {
    setup();
    let inh = inherited("REPO_ROOT");
    let req = ValidatedRequest::validate(plan_req(
        Plan::RunAs { who: RunAs::Root, body: Box::new(exec(&["true"])) },
        HashMap::new(),
    ))
    .unwrap();
    assert!(prepare_with(&req, &HashMap::new(), Some(inh)).is_err());
}

/// An `env` wrapper that sets an inherited name says so at the prompt.
#[test]
fn env_wrapper_overriding_an_inherited_name_is_marked() {
    setup();
    let req = ValidatedRequest::validate(plan_req(
        exec(&["env", "TF_VAR_region=us", "OTHER=1", "devtool"]),
        HashMap::new(),
    ))
    .unwrap();
    let p = prepare_with(&req, &HashMap::new(), Some(inherited("REPO_ROOT,TF_VAR_*"))).unwrap();
    let env_hop = &p.views()[0].programs[0];
    assert_eq!(env_hop.overrides_inherited, ["TF_VAR_region"]);
    // The wrapped program resolved on the inherited PATH.
    let devtool = &p.views()[0].programs[1];
    assert!(devtool.resolved.as_ref().is_some_and(|r| r.path.starts_with(&setup().bin)), "{:?}", devtool.resolved);
}

// --- Startup refusals ----------------------------------------------------

/// Run the daemon with only `vars` in its environment (plus a throwaway
/// HOME, so no real hosts.json is read) and expect it to exit with an error
/// mentioning `needle` before it binds.
fn refused(vars: &[(&str, &str)], args: &[&str], needle: &str) {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let sock = dir.path().join("d.sock");
    let mut c = Command::new(env!("CARGO_BIN_EXE_sudo-proxy"));
    c.env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("cfg"))
        .arg("--socket")
        .arg(&sock)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in vars {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon started with {args:?}; expected a refusal mentioning {needle:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
    assert!(!status.success(), "{args:?}: {err}");
    assert!(err.contains(needle), "{args:?}: expected {needle:?} in: {err}");
    assert!(!sock.exists(), "{args:?}: socket bound");
}

#[test]
fn startup_refusals() {
    let path = [("PATH", "/usr/bin:/bin")];
    refused(&path, &["--host", "example", "--inherit-path"], "not forwarded with --host");
    refused(&path, &["--host", "example", "--inherit-env=A"], "not forwarded with --host");
    refused(&path, &["--inherit-env", "A", "--host", "example"], "not forwarded with --host");
    refused(&path, &["--inherit-env", "A", "--inherit-env", "B"], "given twice");
    refused(&path, &["--inherit-env"], "requires a value");
    refused(&path, &["--inherit-env="], "needs a value");
    refused(&path, &["--inherit-env=A,,B"], "empty element");
    refused(&path, &["--inherit-env=A*B"], "not a variable name");
    refused(&path, &["--inherit-env=SSH_AUTH_SOCK"], "SSH_AUTH_SOCK");
    refused(&path, &["--inherit-path", "--unattended-eligible"], "excludes --unattended-eligible");
    refused(&path, &["--inherit-env=A", "--unattended-eligible"], "excludes --unattended-eligible");
    // With no_shell on, a code-loading variable cannot be inherited.
    refused(
        &[("PATH", "/usr/bin:/bin"), ("PYTHONPATH", "/py")],
        &["--no-shell", "--inherit-env=PYTHONPATH"],
        "code-loading",
    );
    refused(&[], &["--inherit-path"], "PATH is unset");
    refused(&[("PATH", "")], &["--inherit-path"], "PATH is empty");
    refused(&[("PATH", ".:/usr/bin")], &["--inherit-path"], "relative");
    refused(&[("PATH", "/usr/bin::/bin")], &["--inherit-path"], "empty entry");
    let ww = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(ww.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let ww_path = format!("{}:/usr/bin", ww.path().display());
    if unsafe { libc::geteuid() } != 0 {
        refused(&[("PATH", &ww_path)], &["--inherit-path"], "group/world-writable");
    }
    // A sticky world-writable directory is refused as an entry (anyone can
    // add a program there), though it is fine above one.
    refused(&[("PATH", "/tmp:/usr/bin")], &["--inherit-path"], "lets others add programs");
}

/// Neither launcher can carry the flags: `sudo-proxy-mcp` builds a fixed
/// command line, and `--host` is refused above.
#[test]
fn mcp_never_passes_the_flags() {
    let src = include_str!("../src/mcp.rs");
    assert!(!src.contains("--inherit"), "sudo-proxy-mcp must never pass --inherit-*");
}
