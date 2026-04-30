#![cfg(unix)]

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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

    let result = server::run(
        &path,
        server::ServerConfig::default(),
        prompter,
        sink,
        &shutdown,
        in_flight,
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

    let p_for_thread = Arc::clone(&prompter);
    let s_for_thread = Arc::clone(&shutdown);
    let inflight_thread = Arc::clone(&in_flight);
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
