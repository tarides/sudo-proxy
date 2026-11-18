//! Drive the real `sudo-proxy` daemon through a pseudo-terminal.
//!
//! The daemon's prompt, banner and result display all go through `/dev/tty`
//! (`src/tui.rs`), so the harness makes a fresh pty the daemon's *controlling
//! terminal* (`setsid` + `TIOCSCTTY`) without putting it on fds 0/1/2 (stdin
//! and stdout are null, stderr goes to `daemon.log`). The test reads what the
//! daemon drew from the master side and types answers into it.
//!
//! Key timing: the prompt flushes its question line *before* switching the
//! tty to raw mode with `TCSAFLUSH`, which discards input already queued. A key
//! sent as soon as the `Execute?` question shows up can land in that window
//! and be thrown away, leaving the prompt to time out. [`PtyDaemon::answer`] therefore waits
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
    /// Write `config/sudo-proxy/hosts.json` with these contents and mode
    /// before the daemon starts.
    pub hosts_json: Option<(String, u32)>,
    /// Directories put first on the daemon's own PATH (before the shims), as
    /// a dev shell would. Requested commands must not be resolved on it.
    pub extra_path: Vec<PathBuf>,
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
        if let Some((json, mode)) = &opts.hosts_json {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(dir.path().join("config"), std::fs::Permissions::from_mode(0o700)).unwrap();
            let cfg = dir.path().join("config/sudo-proxy");
            std::fs::create_dir(&cfg).expect("mkdir");
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o700)).unwrap();
            let f = cfg.join("hosts.json");
            std::fs::write(&f, json).expect("hosts.json");
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(*mode)).unwrap();
        }

        let (master, slave) = open_pty();
        let slave_fd = slave.as_raw_fd();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sudo-proxy"));
        cmd.arg("--socket")
            .arg(&socket)
            .arg("-v")
            .arg("--no-syslog")
            .args(&opts.args);
        let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        let mut daemon_path: Vec<String> =
            opts.extra_path.iter().map(|p| p.display().to_string()).collect();
        daemon_path.push(shims.display().to_string());
        daemon_path.push(path);
        cmd.env_clear()
            .env("PATH", daemon_path.join(":"))
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
        self.expect_within(needle, STEP)
    }

    /// [`Self::expect`] with a caller-chosen deadline, for waits longer than
    /// [`STEP`] (the 60 s prompt timeout).
    pub fn expect_within(&mut self, needle: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
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

    /// Type `key` once the tty is in raw mode, for a prompt already consumed.
    pub fn answer_raw(&mut self, key: u8) {
        self.wait_raw_mode();
        self.master.write_all(&[key]).expect("write key");
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

    /// The per-daemon temp dir (removed on drop): a place for test files
    /// that must not outlive a failing test.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The daemon's stderr so far (`-v` output, `[unattended]` audit lines).
    pub fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("daemon.log")).unwrap_or_default()
    }

    /// Everything the daemon drew so far, `\r\n` folded to `\n`.
    pub fn capture(&self) -> String {
        normalize(&self.capture.0.lock().unwrap().0)
    }

    /// Each argv the `sudo` shim was invoked with, in order. A record is the
    /// arguments, each NUL-terminated, then `\n` (argv cannot contain a
    /// newline: the daemon rejects one at validation).
    pub fn shim_log(&self) -> Vec<Vec<String>> {
        let Ok(bytes) = std::fs::read(self.dir.path().join("sudo.log")) else {
            return Vec::new();
        };
        bytes
            .split(|&b| b == b'\n')
            .filter(|rec| !rec.is_empty())
            .map(|rec| {
                // Strip the last terminator rather than filtering empties, so
                // a genuine "" argument is kept.
                let rec = rec.strip_suffix(&[0]).unwrap_or(rec);
                rec.split(|&b| b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
            })
            .collect()
    }

    fn fail(&self, what: &str) -> ! {
        let log = self.daemon_log();
        panic!(
            "{what}\n--- pty capture (escapes visible) ---\n{}\n--- daemon stderr ---\n{log}",
            visible(&self.capture.0.lock().unwrap().0)
        );
    }
}

impl Drop for PtyDaemon {
    fn drop(&mut self) {
        // SIGTERM lets the daemon's handler unlink the socket. Only while it
        // is unreaped: after a reap (e.g. the early-exit path in `spawn`) the
        // pid may already belong to another process.
        if matches!(self.child.try_wait(), Ok(None)) {
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
            }
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

/// Open a pty pair with both fds CLOEXEC from the start. `openpty(3)` returns
/// them inheritable, and a test on another thread spawning its daemon between
/// `openpty` and a later `fcntl` would leak this pty into that daemon and its
/// children.
fn open_pty() -> (File, File) {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(master >= 0, "posix_openpt: {}", io::Error::last_os_error());
    // SAFETY: posix_openpt just returned this fd; nothing else owns it.
    let master = unsafe { File::from_raw_fd(master) };
    let m = master.as_raw_fd();
    assert_eq!(unsafe { libc::grantpt(m) }, 0, "grantpt: {}", io::Error::last_os_error());
    assert_eq!(unsafe { libc::unlockpt(m) }, 0, "unlockpt: {}", io::Error::last_os_error());
    let mut name = [0 as libc::c_char; 128];
    assert_eq!(unsafe { libc::ptsname_r(m, name.as_mut_ptr(), name.len()) }, 0, "ptsname_r");
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(slave >= 0, "open slave: {}", io::Error::last_os_error());
    // SAFETY: open just returned this fd; nothing else owns it.
    let slave = unsafe { File::from_raw_fd(slave) };
    let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    assert_eq!(unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &ws) }, 0);
    (master, slave)
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
