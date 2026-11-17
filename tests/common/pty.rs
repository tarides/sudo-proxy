//! Drive the real `sudo-proxy` daemon through a pseudo-terminal.
//!
//! The daemon's prompt, banner and result display all go through `/dev/tty`
//! (`src/tui.rs`), so the harness makes a fresh pty the daemon's *controlling
//! terminal* (`setsid` + `TIOCSCTTY`) and leaves fds 0/1/2 alone. The test
//! reads what the daemon drew from the master side and types answers into it.
//!
//! Key timing: the prompt flushes its question line *before* switching the
//! tty to raw mode with `TCSAFLUSH`, which discards input already queued. A key
//! sent as soon as the `Execute?` question shows up can land in that window and be thrown
//! away, leaving the prompt to time out. [`PtyDaemon::answer`] therefore waits
//! until the slave's termios (visible through the master on Linux) has
//! `ICANON` cleared before writing the key.
//!
//! The daemon runs with a cleared environment: no `DISPLAY`/`WAYLAND_DISPLAY`
//! (so `Mode::Remote`: TUI prompt + sudo), a private `HOME`/`XDG_CONFIG_HOME`
//! (no developer `hosts.json` policy leaks in), and `tests/shims` first on
//! `PATH`, so privileged steps reach the logging `sudo` shim, not real sudo.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sudo_proxy::protocol::{Request, Response};
use tempfile::TempDir;

/// Upper bound for any single wait (daemon start, a prompt appearing, raw
/// mode). Generous: the happy path takes milliseconds, and a miss panics
/// with the full capture rather than hanging until the 60 s prompt timeout.
pub const STEP: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct PtyOpts {
    /// Extra daemon flags (e.g. `--unattended-eligible`).
    pub args: Vec<String>,
    /// Leave colours on (no `NO_COLOR`). Bell and blink are always off so a
    /// capture is stable.
    pub color: bool,
}

/// What the reader thread has seen on the master, and whether it hit EOF.
type Capture = Arc<(Mutex<(Vec<u8>, bool)>, Condvar)>;

pub struct PtyDaemon {
    pub socket: PathBuf,
    child: Child,
    master: File,
    /// Held open for the daemon's lifetime: the daemon opens `/dev/tty` only
    /// while it draws, and with no slave fd open anywhere the master reads
    /// `EIO` and the line is hung up between prompts.
    _slave: File,
    capture: Capture,
    /// Bytes of the capture already consumed by `expect`.
    cursor: usize,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    dir: TempDir,
}

fn shim_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/shims")
}

impl PtyDaemon {
    pub fn spawn(opts: PtyOpts) -> Self {
        let shims = shim_dir();
        let mode = std::fs::metadata(shims.join("sudo")).expect("tests/shims/sudo").permissions().mode();
        assert!(mode & 0o111 != 0, "tests/shims/sudo must be executable");

        // Under /tmp so the socket path fits in sun_path.
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let socket = dir.path().join("p.sock");
        for sub in ["home", "config"] {
            std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }

        let (master, slave) = open_pty();
        let slave_fd = slave.as_raw_fd();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sudo-proxy"));
        cmd.arg("--socket").arg(&socket).arg("-v").args(&opts.args);
        let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        cmd.env_clear()
            .env("PATH", format!("{}:{path}", shims.display()))
            .env("HOME", dir.path().join("home"))
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("SUDO_SHIM_LOG", dir.path().join("sudo.log"))
            .env("SUDO_PROXY_NO_BELL", "1")
            .env("SUDO_PROXY_NO_BLINK", "1");
        if !opts.color {
            cmd.env("NO_COLOR", "1");
        }
        let log = File::create(dir.path().join("daemon.log")).expect("daemon.log");
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(log);
        // SAFETY: only async-signal-safe calls (setsid, ioctl, errno read)
        // between fork and exec. `slave_fd` is a plain integer copied in; the
        // fd is CLOEXEC, so it is gone after exec while the controlling-tty
        // association it established stays.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn sudo-proxy");

        let capture: Capture = Arc::new((Mutex::new((Vec::new(), false)), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let master = master.try_clone().expect("dup master");
            let capture = Arc::clone(&capture);
            let stop = Arc::clone(&stop);
            thread::spawn(move || read_loop(master, &capture, &stop))
        };

        let mut d = Self { socket, child, master, _slave: slave, capture, cursor: 0, stop, reader: Some(reader), dir };
        let deadline = Instant::now() + STEP;
        while UnixStream::connect(&d.socket).is_err() {
            if Instant::now() >= deadline {
                d.fail("daemon did not start listening");
            }
            if let Ok(Some(st)) = d.child.try_wait() {
                d.fail(&format!("daemon exited early: {st}"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        d
    }

    /// Send `req` from a background thread; the client blocks until the
    /// prompt is answered, so join the handle after answering.
    pub fn request_async(&self, req: &Request) -> JoinHandle<Response> {
        let socket = self.socket.clone();
        let req = req.clone();
        thread::spawn(move || super::send_request(&socket, &req))
    }

    /// Wait for `needle` to appear after the cursor; return the text from
    /// the cursor up to and including it, and move the cursor past it.
    pub fn expect(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + STEP;
        let (lock, cv) = &*self.capture;
        let mut g = lock.lock().unwrap();
        loop {
            let hay = &g.0[self.cursor..];
            if let Some(pos) = find(hay, needle.as_bytes()) {
                let end = self.cursor + pos + needle.len();
                let span = normalize(&g.0[self.cursor..end]);
                self.cursor = end;
                return span;
            }
            let now = Instant::now();
            if g.1 || now >= deadline {
                let why = if g.1 { "pty closed" } else { "timed out" };
                drop(g);
                self.fail(&format!("{why} waiting for {needle:?}"));
            }
            g = cv.wait_timeout(g, deadline - now).unwrap().0;
        }
    }

    /// Answer the next prompt with `key`. Waits for the prompt block, then
    /// for the tty to be in raw mode (see the module doc), then types. Returns
    /// the prompt text from its header through the question.
    pub fn answer(&mut self, key: u8) -> String {
        self.expect("Privilege Request");
        // Every question ends in a `[y/N]` / `[y/N/a]` choice list.
        let body = self.expect("[y/N");
        self.wait_raw_mode();
        self.master.write_all(&[key]).expect("write key");
        format!("Privilege Request{body}")
    }

    /// True while the slave is in canonical (cooked) mode with echo on: the
    /// state the daemon must restore after every prompt.
    pub fn is_cooked(&self) -> bool {
        let t = self.termios();
        t.c_lflag & libc::ICANON != 0 && t.c_lflag & libc::ECHO != 0
    }

    fn wait_raw_mode(&self) {
        let deadline = Instant::now() + STEP;
        while self.termios().c_lflag & libc::ICANON != 0 {
            if Instant::now() >= deadline {
                self.fail("tty never left canonical mode");
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn termios(&self) -> libc::termios {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // On Linux the termios of a pty pair is shared: reading it through
        // the master shows what the daemon set on the slave.
        let rc = unsafe { libc::tcgetattr(self.master.as_raw_fd(), &mut t) };
        assert_eq!(rc, 0, "tcgetattr: {}", io::Error::last_os_error());
        t
    }

    /// Everything the daemon drew so far, `\r\n` folded to `\n`.
    pub fn capture(&self) -> String {
        normalize(&self.capture.0.lock().unwrap().0)
    }

    /// Each argv the `sudo` shim was invoked with, in order.
    pub fn shim_log(&self) -> Vec<Vec<String>> {
        let Ok(bytes) = std::fs::read(self.dir.path().join("sudo.log")) else {
            return Vec::new();
        };
        bytes
            .split(|&b| b == b'\n')
            .filter(|rec| !rec.is_empty())
            .map(|rec| {
                rec.split(|&b| b == 0)
                    .filter(|a| !a.is_empty())
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect()
            })
            .collect()
    }

    fn fail(&self, what: &str) -> ! {
        let log = std::fs::read_to_string(self.dir.path().join("daemon.log")).unwrap_or_default();
        panic!(
            "{what}\n--- pty capture (escapes visible) ---\n{}\n--- daemon stderr ---\n{log}",
            visible(&self.capture.0.lock().unwrap().0)
        );
    }
}

impl Drop for PtyDaemon {
    fn drop(&mut self) {
        // SIGTERM lets the daemon's handler unlink the socket.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

fn open_pty() -> (File, File) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws) };
    assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
    for fd in [master, slave] {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
    }
    // SAFETY: openpty just returned these fds; nothing else owns them.
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}

/// Copy master output into the capture until `stop` (or a read error, which
/// cannot happen while `PtyDaemon` holds the slave open). Polls with a short
/// timeout so `Drop` can join it.
fn read_loop(mut master: File, capture: &Capture, stop: &AtomicBool) {
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd { fd: master.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 50) };
        if n <= 0 {
            continue;
        }
        match master.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                capture.0.lock().unwrap().0.extend_from_slice(&buf[..k]);
                capture.1.notify_all();
            }
        }
    }
    capture.0.lock().unwrap().1 = true;
    capture.1.notify_all();
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn normalize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

/// Render control bytes visibly for failure dumps.
pub fn visible(bytes: &[u8]) -> String {
    normalize(bytes).replace('\x1b', "\\e").replace('\x07', "\\a").replace('\r', "\\r")
}
