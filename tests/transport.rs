#![cfg(unix)]

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sudo_proxy::protocol::Status;
use sudo_proxy::server;
use sudo_proxy::tui::NoopResultSink;

mod common;
use common::*;

/// The bind→chmod TOCTOU was closed in 0.7.0 by setting umask(0o077)
/// around the bind. Verify the socket is created with 0600 permissions
/// from the start, not after a separate chmod that an attacker could
/// race against.
#[test]
fn socket_has_0600_permissions() {
    let s = start_test_server(TestServerOpts::default());

    let meta = fs::metadata(&s.socket_path).expect("socket exists");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "socket file has mode {:o}, expected 0600",
        mode
    );
}

/// 0.7.0 added a connect-probe before clobbering an existing socket
/// file: if a peer is listening, refuse to start. Verify a second
/// `server::run` to the same path returns AddrInUse with the actionable
/// "already running" message rather than silently replacing the
/// existing daemon.
#[test]
fn refuses_to_clobber_active_server() {
    let s = start_test_server(TestServerOpts::default());

    let path = s.socket_path.clone();
    let prompter = Arc::new(common::ScriptedPrompter::new());
    let sink = Arc::new(NoopResultSink);
    let shutdown = AtomicBool::new(false);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    let result = server::run(
        &path,
        server::ServerConfig::default(),
        prompter,
        sink,
        &shutdown,
        in_flight,
        tty_lock,
    );

    let err = result.expect_err("second bind to active socket should fail");
    assert_eq!(err.kind(), ErrorKind::AddrInUse, "got: {:?}", err);
    assert!(
        err.to_string().contains("already running"),
        "expected 'already running' message, got: {}",
        err
    );
}

/// A leftover socket file from a crashed daemon (no live listener) must
/// be replaced cleanly, not refuse-to-start. The connect-probe distinguishes
/// stale-file from active-server: connect to a leftover file fails, so
/// bind_listener removes it and re-binds.
#[test]
fn replaces_stale_socket_file() {
    let tempdir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let path = tempdir.path().join("stale.sock");

    // Pre-create a regular file at the socket path. bind() will fail with
    // AddrInUse; the connect-probe will fail (no listener); bind_listener
    // should remove the file and rebind.
    fs::write(&path, b"leftover bytes from a crashed daemon").unwrap();
    assert!(path.exists());

    let prompter = Arc::new(common::ScriptedPrompter::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    let p_for_thread = Arc::clone(&prompter);
    let s_for_thread = Arc::clone(&shutdown);
    let inflight_thread = Arc::clone(&in_flight);
    let tty_lock_thread = Arc::clone(&tty_lock);
    let path_for_thread = path.clone();

    let handle = thread::spawn(move || {
        let config = server::ServerConfig {
            confirm_unprivileged: true,
            ..Default::default()
        };
        server::run(
            &path_for_thread,
            config,
            p_for_thread,
            Arc::new(NoopResultSink),
            &s_for_thread,
            inflight_thread,
            tty_lock_thread,
        )
    });

    // Wait until the socket is connectable (i.e., the daemon has replaced
    // the stale file with a real listener).
    let connectable = wait_until(Duration::from_secs(2), || {
        UnixStream::connect(&path).is_ok()
    });
    assert!(
        connectable,
        "daemon failed to replace stale file at {}",
        path.display()
    );

    // Stat: the path is now a Unix socket (not the regular file we wrote).
    let meta = fs::metadata(&path).unwrap();
    assert!(
        meta.file_type().is_socket(),
        "expected unix socket; got {:?}",
        meta.file_type()
    );
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // Confirm the daemon actually services requests on the replaced socket.
    let resp = send_request(&path, &make_req("stale-1", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok);

    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && in_flight.load(Ordering::Relaxed) > 0 {
        thread::sleep(Duration::from_millis(5));
    }
}

/// Issue #13: a client that sends bytes but closes without a trailing
/// newline must produce a specific error response, not the misleading
/// "invalid JSON" path that downstream parsing would otherwise return.
/// Empty connections (the case below) remain the silent success path.
#[test]
fn eof_without_newline_returns_error() {
    use std::io::{BufRead, BufReader, Write};

    let s = start_test_server(TestServerOpts::default());

    let mut stream = UnixStream::connect(&s.socket_path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"{\"id\":\"x\",\"pipeline\":[[\"true\"]]}").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response");
    let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("parse");
    assert_eq!(parsed["status"], "error", "got: {line:?}");
    let msg = parsed["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("newline") || msg.contains("missing"),
        "expected missing-newline error, got: {msg:?}"
    );
}

/// A client that connects and immediately closes its end (read_line
/// returns Ok(0)) must be handled silently — no panic, no half-baked
/// response, daemon stays responsive to subsequent connections.
#[test]
fn client_close_without_data_keeps_daemon_responsive() {
    let s = start_test_server(TestServerOpts::default());

    for _ in 0..6 {
        let stream = UnixStream::connect(&s.socket_path).expect("connect");
        drop(stream);
    }

    let resp = s.send(&make_req("after-drive-bys", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok);
}

/// The daemon stamps its own VERSION on every Response. Clients can rely
/// on this to detect skew without having to parse `--version` output.
#[test]
fn response_carries_daemon_version() {
    let s = start_test_server(TestServerOpts::default());
    let resp = s.send(&make_req("ver-stamp", vec![vec!["true"]]));
    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.version, sudo_proxy::protocol::VERSION);
}

/// Forward-compat: a Request from an older client without a `version`
/// field must still be accepted; on parse it deserializes to the empty
/// string so the prompt/log can render `(unknown)`.
#[test]
fn request_without_version_field_accepted() {
    use std::io::{BufRead, BufReader, Write};

    let s = start_test_server(TestServerOpts::default());

    let id = "legacy-no-version";
    let time = iso_now();
    let line = format!(
        "{{\"id\":\"{id}\",\"host\":\"\",\"session\":\"old-client\",\"time\":\"{time}\",\"pipeline\":[[\"true\"]],\"env\":{{}},\"reason\":\"\",\"privileged\":false,\"forward_agent\":false}}\n"
    );

    let mut stream = UnixStream::connect(&s.socket_path).expect("connect");
    stream.write_all(line.as_bytes()).expect("write");
    let mut reader = BufReader::new(&stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).expect("read");

    let resp: sudo_proxy::protocol::Response =
        serde_json::from_str(buf.trim()).expect("parse response");
    assert_eq!(resp.id, id);
    assert_eq!(resp.status, Status::Ok, "got: {:?}", resp.message);
    // Round-trip preserves daemon version on the response.
    assert_eq!(resp.version, sudo_proxy::protocol::VERSION);
}

/// Forward-compat: a Response JSON missing the `version` field
/// (i.e. emitted by a daemon predating this change) deserializes to an
/// empty version string so callers can render `(unknown)`.
#[test]
fn response_without_version_field_deserializes() {
    let json = r#"{"id":"legacy","status":"ok","stages":[],"stdout":null}"#;
    let resp: sudo_proxy::protocol::Response =
        serde_json::from_str(json).expect("parse");
    assert_eq!(resp.version, "");
}
