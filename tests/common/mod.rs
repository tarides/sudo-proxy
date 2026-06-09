#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sudo_proxy::mode::Mode;
use sudo_proxy::protocol::{Request, Response};
use sudo_proxy::server;
use sudo_proxy::tui::{Prompter, PromptResult, ResultSink};
use tempfile::TempDir;

pub type ResponseFn = dyn Fn(&Request) -> (Duration, PromptResult) + Send + Sync;

#[derive(Clone, Debug)]
pub struct RecordedCall {
    pub req: Request,
    pub at: Instant,
}

pub struct ScriptedPrompter {
    response: Mutex<Box<ResponseFn>>,
    calls: Mutex<Vec<RecordedCall>>,
}

impl ScriptedPrompter {
    pub fn new() -> Self {
        Self::with_response(|_| (Duration::ZERO, PromptResult::Approved))
    }

    pub fn with_response<F>(f: F) -> Self
    where
        F: Fn(&Request) -> (Duration, PromptResult) + Send + Sync + 'static,
    {
        Self {
            response: Mutex::new(Box::new(f)),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn set_response<F>(&self, f: F)
    where
        F: Fn(&Request) -> (Duration, PromptResult) + Send + Sync + 'static,
    {
        *self.response.lock().unwrap() = Box::new(f);
    }

    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Prompter for ScriptedPrompter {
    fn prompt(&self, req: &Request, _timeout: Duration) -> std::io::Result<PromptResult> {
        self.calls.lock().unwrap().push(RecordedCall {
            req: req.clone(),
            at: Instant::now(),
        });
        let (delay, result) = (self.response.lock().unwrap())(req);
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        Ok(result)
    }
}

pub struct RecordingSink {
    captured: Mutex<Vec<Response>>,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
        }
    }

    pub fn captured(&self) -> Vec<Response> {
        self.captured.lock().unwrap().clone()
    }
}

impl ResultSink for RecordingSink {
    fn display(&self, resp: &Response) -> std::io::Result<()> {
        self.captured.lock().unwrap().push(resp.clone());
        Ok(())
    }
}

pub struct TestServerOpts {
    pub confirm_unprivileged: bool,
    pub pkexec_only: bool,
    pub mode: Mode,
    pub max_in_flight: usize,
}

impl Default for TestServerOpts {
    fn default() -> Self {
        Self {
            confirm_unprivileged: true,
            pkexec_only: false,
            mode: Mode::Local,
            max_in_flight: sudo_proxy::server::DEFAULT_MAX_IN_FLIGHT,
        }
    }
}

pub struct TestServer {
    pub socket_path: PathBuf,
    pub prompter: Arc<ScriptedPrompter>,
    pub sink: Arc<RecordingSink>,
    pub in_flight: Arc<AtomicUsize>,
    pub tty_lock: Arc<Mutex<()>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    _tempdir: TempDir,
}

pub fn start_test_server(opts: TestServerOpts) -> TestServer {
    let tempdir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let socket_path = tempdir.path().join("p.sock");
    let prompter = Arc::new(ScriptedPrompter::new());
    let sink = Arc::new(RecordingSink::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let tty_lock = Arc::new(Mutex::new(()));

    let prompter_arc = Arc::clone(&prompter);
    let sink_arc = Arc::clone(&sink);
    let sh_arc = Arc::clone(&shutdown);
    let inflight_arc = Arc::clone(&in_flight);
    let tty_lock_arc = Arc::clone(&tty_lock);
    let path = socket_path.clone();

    let handle = thread::spawn(move || {
        let config = server::ServerConfig {
            mode: opts.mode,
            pkexec_only: opts.pkexec_only,
            verbose: false,
            confirm_unprivileged: opts.confirm_unprivileged,
            max_in_flight: opts.max_in_flight,
        };
        // Coercion to Arc<dyn Trait> happens here at the function-argument
        // site, where the parameter type is known.
        let _ = server::run(
            &path,
            config,
            prompter_arc,
            sink_arc,
            &sh_arc,
            inflight_arc,
            tty_lock_arc,
        );
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if UnixStream::connect(&socket_path).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    // The connect probe above wakes a handler thread that briefly counts
    // toward in_flight. Wait for it to drain so tests start from a clean
    // slate (otherwise the probe races with cap/load tests).
    let drain_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < drain_deadline {
        if in_flight.load(Ordering::Relaxed) == 0 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    TestServer {
        socket_path,
        prompter,
        sink,
        in_flight,
        tty_lock,
        shutdown,
        handle: Some(handle),
        _tempdir: tempdir,
    }
}

impl TestServer {
    pub fn send(&self, req: &Request) -> Response {
        send_request(&self.socket_path, req)
    }

    pub fn send_raw(&self, line: &[u8]) -> Vec<u8> {
        send_raw(&self.socket_path, line)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Wait briefly for in-flight connection threads to release the
        // socket / Arc'd state before the TempDir is unlinked.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && self.in_flight.load(Ordering::Relaxed) > 0 {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

pub fn send_request(socket: &Path, req: &Request) -> Response {
    let line = serde_json::to_string(req).expect("serialize") + "\n";
    let bytes = send_raw(socket, line.as_bytes());
    let text = String::from_utf8(bytes).expect("utf8");
    serde_json::from_str(text.trim()).expect("parse response")
}

pub fn send_raw(socket: &Path, line: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // BrokenPipe is expected when the server rejects oversize input mid-write.
    let _ = stream.write_all(line);
    let mut reader = BufReader::new(stream);
    let mut line_buf = String::new();
    let _ = reader.read_line(&mut line_buf);
    line_buf.into_bytes()
}

pub fn make_req(id: &str, pipeline: Vec<Vec<&str>>) -> Request {
    Request {
        id: id.to_string(),
        host: String::new(),
        session: "test".to_string(),
        time: iso_now(),
        pipeline: pipeline
            .into_iter()
            .map(|v| v.into_iter().map(String::from).collect())
            .collect(),
        env: Default::default(),
        reason: String::new(),
        privileged: false,
        forward_agent: false,
        version: sudo_proxy::protocol::VERSION.to_string(),
    }
}

pub fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    iso_format(secs)
}

pub fn iso_offset(delta_secs: i64) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    iso_format((secs + delta_secs).max(0) as u64)
}

/// Format a Unix timestamp as ISO 8601 UTC. Shares the crate's date logic
/// (`sudo_proxy::datetime`); agrees with the `server::parse_age` reverse
/// parser for every timestamp in the era these tests exercise.
pub fn iso_format(epoch_secs: u64) -> String {
    sudo_proxy::datetime::epoch_to_iso(epoch_secs)
}

/// Block until `cond` returns true, or `deadline` passes.
pub fn wait_until<F: Fn() -> bool>(deadline: Duration, cond: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    cond()
}

/// `executor::which`, wrapped so a test can `return` early when a binary it
/// depends on isn't on PATH.
pub fn which_or_skip(name: &str) -> Option<PathBuf> {
    sudo_proxy::executor::which(name)
}

/// Base64-decode a wire `stdout` field to raw bytes (empty on error).
pub fn b64_decode(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap_or_default()
}

/// Decode a response's base64 `stdout` to a UTF-8 string (empty on error).
pub fn decode_stdout(resp: &Response) -> String {
    String::from_utf8(b64_decode(resp.stdout.as_deref().unwrap_or(""))).unwrap_or_default()
}

pub fn skip_if_no_sleep_binary() -> bool {
    sudo_proxy::executor::which("sleep").is_none()
}
