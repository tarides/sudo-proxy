use crate::inherit::Inherited;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::protocol::{
    Plan, RedirTarget, Response, RunAs, ShellProc, StageResult, Stream, ValidatedRequest, WriteMode,
};

/// Hard cap on captured stdout/stderr per stream. A privileged
/// `cat /dev/zero` would otherwise OOM the daemon. When the cap is
/// reached, the drainer stops reading and the child is killed so it
/// doesn't wedge on a full pipe.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Default per-command execution timeout. Bounds how long any one
/// privileged command can hold a handler thread (D-state, infinite
/// loops, blocked on stdin). Override via SUDO_PROXY_EXEC_TIMEOUT_SECS.
pub const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// How often to poll `try_wait` while waiting for a child.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Resolve the per-command execution timeout from the environment, or
/// fall back to DEFAULT_EXEC_TIMEOUT.
pub fn exec_timeout() -> Duration {
    crate::cli::env_timeout("SUDO_PROXY_EXEC_TIMEOUT_SECS", DEFAULT_EXEC_TIMEOUT)
}

/// Only these env var names (or prefixes) are allowed through.
/// The name must also be a valid shell variable name, so an `LC_` prefix cannot
/// carry shell syntax into the prompt's `export K=…` / `sudo K=V` rendering.
fn is_env_allowed(key: &str) -> bool {
    crate::protocol::is_valid_env_name(key)
        && (matches!(key, "LANG" | "TZ" | "HOME" | "DEBIAN_FRONTEND" | "TERM")
            || key.starts_with("LC_"))
}

/// Sanitize the environment from a request.
///
/// Hard rejection model: every var must be on the allowlist, otherwise
/// the whole request fails. There is no silent stripping — `LD_PRELOAD`
/// and friends fail loudly the same way any unknown var does.
pub fn sanitize_env(env: &HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (k, v) in env {
        // SSH_AUTH_SOCK is owned by the daemon's environment (set by sshd
        // when the user opened the tunnel with -A). Accepting a request-
        // supplied value would let a local peer point a child at an
        // arbitrary socket. Use `forward_agent: true` instead.
        if k == "SSH_AUTH_SOCK" {
            return Err(
                "SSH_AUTH_SOCK cannot be set in request env; use forward_agent instead".to_string(),
            );
        }
        if !is_env_allowed(k) {
            return Err(format!("environment variable not allowed: {k}"));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

/// Default PATH injected when none is set in the request. Mirrors
/// `/etc/login.defs`'s ENV_PATH on Debian/Ubuntu.
const DEFAULT_LOGIN_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Login-shell env (HOME/USER/LOGNAME/PATH) for the daemon's effective
/// uid. PAM's `session` stack would set these on an interactive SSH
/// login, but command-mode SSH (`ssh host sudo-proxy`) bypasses it —
/// so the daemon inherits a stripped env and any `env_clear()`'d child
/// sees nothing. Computed once via getpwuid; cached in `OnceLock`.
fn login_env_defaults() -> &'static HashMap<String, String> {
    static CACHE: OnceLock<HashMap<String, String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = HashMap::new();
        let pw = unsafe { libc::getpwuid(libc::geteuid()) };
        if !pw.is_null() {
            unsafe {
                if let Ok(name) = std::ffi::CStr::from_ptr((*pw).pw_name).to_str() {
                    if !name.is_empty() {
                        out.insert("USER".into(), name.to_string());
                        out.insert("LOGNAME".into(), name.to_string());
                    }
                }
                if let Ok(dir) = std::ffi::CStr::from_ptr((*pw).pw_dir).to_str() {
                    if !dir.is_empty() {
                        out.insert("HOME".into(), dir.to_string());
                    }
                }
            }
        }
        out.insert("PATH".into(), DEFAULT_LOGIN_PATH.into());
        out
    })
}

/// Fill in missing login env (HOME / USER / LOGNAME / PATH) from the
/// daemon's /etc/passwd entry. Only inserts keys that aren't already
/// set, so a caller-supplied HOME wins. Callers can't currently supply
/// USER / LOGNAME / PATH (allowlist rejects them), so those are
/// effectively always daemon-derived.
pub fn apply_login_env_defaults(env: &mut HashMap<String, String>) {
    for (k, v) in login_env_defaults() {
        env.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

/// Resolve a command name to an absolute path by searching the **daemon's**
/// PATH. Not for a requested command (see [`resolve_command`]), and not for
/// a program the daemon runs itself either: that PATH may hold
/// user-writable directories (GHSA-gx9w-4f7x-2gcp), so helpers go through
/// [`crate::helper`]. Kept for tests that probe the environment.
pub fn which(name: &str) -> Option<PathBuf> {
    resolve_on(name, "", &std::env::var("PATH").unwrap_or_default()).map(|r| r.path)
}

/// A program resolved once for a request and pinned (issue #105).
///
/// The file is opened (`O_PATH`) when it is found, and that descriptor is the
/// pin: `(dev, ino)` and the canonical target both come from it, not from a
/// second lookup of the path. The policy check, the prompt and the spawn all
/// read this one value. At spawn the path must still name the same inode
/// ([`Resolved::still_pinned`]), and a direct binary is executed through the
/// descriptor itself, so a file swapped in after approval never runs.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The path found (`PATH` dir + name, or the leaf cwd + a name with `/`).
    pub path: PathBuf,
    /// The pinned file's real path, read through the descriptor. `None` when
    /// it cannot be (no `/proc`): the prompt then says `(canonicalize
    /// failed)` rather than showing a second lookup of the path.
    pub canonical: Option<PathBuf>,
    pub dev: u64,
    pub ino: u64,
    /// A native (ELF) binary, which the kernel runs from the descriptor
    /// itself. Anything else (a `#!` script, a script without `#!` that
    /// `execvp` hands to `/bin/sh`, a binfmt_misc format) makes the kernel or
    /// libc pass an interpreter a path, and the close-on-exec descriptor's
    /// path no longer opens once that interpreter runs. Those are spawned by
    /// path after the identity check.
    pub native: bool,
    /// The daemon's user could replace what runs: it may write the file, the
    /// directory it was found in, or (for a symlink) the directory of the
    /// target. The prompt marks it `(user-writable)` (#101). Pinning fixes
    /// which file runs, not what is in it.
    pub user_writable: bool,
    fd: Arc<OwnedFd>,
}

/// Same file found at the same path. The descriptor is not compared.
impl PartialEq for Resolved {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.dev == other.dev && self.ino == other.ino
    }
}

impl Eq for Resolved {}

impl Resolved {
    /// Open `path` and pin it if it is a regular file (and, when `need_exec`,
    /// has an execute bit). Symlinks are followed: the pin is their target.
    fn open(path: PathBuf, need_exec: bool) -> Option<Resolved> {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return None;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return None;
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        let proc_path = fd_path(fd.as_raw_fd());
        // A PATH candidate must be executable by the daemon's user, as
        // `execvp` requires (an effective-UID access check), so a decoy
        // without execute permission for us is skipped here just as a
        // wrapper's own lookup would skip it (#101). Asked of the pinned
        // inode through the descriptor; the mode bits stand in without /proc.
        if need_exec && !executable_by_me(&proc_path, st.st_mode) {
            return None;
        }
        // Through the descriptor, so it describes the pinned inode even if the
        // path changes now.
        let canonical = std::fs::read_link(&proc_path).ok();
        let native = std::fs::File::open(&proc_path)
            .and_then(|f| {
                let mut magic = [0u8; 4];
                std::os::unix::fs::FileExt::read_exact_at(&f, &mut magic, 0)?;
                Ok(magic == *b"\x7fELF")
            })
            .unwrap_or(false);
        let file = if proc_fd_available() {
            proc_path.as_path()
        } else {
            path.as_path()
        };
        // Owning counts as writing: the owner can `chmod u+w` first, as the
        // helper check (1.2.3) already treats ownership as control.
        let euid = unsafe { libc::geteuid() };
        let user_writable = st.st_uid == euid
            || writable_by_me(file)
            || path.parent().is_some_and(|d| controlled_by(d, euid))
            || canonical
                .as_deref()
                .and_then(Path::parent)
                .is_some_and(|d| controlled_by(d, euid));
        Some(Resolved {
            path,
            canonical,
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            native,
            user_writable,
            fd: Arc::new(fd),
        })
    }

    /// The canonical target, if it could be read.
    pub fn canonical(&self) -> Option<&Path> {
        self.canonical.as_deref()
    }

    /// The path still names the pinned file (`stat` follows symlinks, as the
    /// exec would).
    pub fn still_pinned(&self) -> bool {
        std::fs::metadata(&self.path).is_ok_and(|m| m.dev() == self.dev && m.ino() == self.ino)
    }

    /// The path to `exec` that runs exactly the pinned inode, when there is
    /// one: `/proc/self/fd/N`, for a native binary while `/proc` is mounted. In
    /// the forked child the descriptor is still open (`O_CLOEXEC` closes it
    /// only once the exec has succeeded), so the kernel opens the pinned
    /// file, whatever the original path names by then.
    fn exec_path(&self) -> Option<PathBuf> {
        (self.native && proc_fd_available()).then(|| fd_path(self.fd.as_raw_fd()))
    }

    /// A resolution for unit tests that build leaves by hand: pinned to
    /// `/dev/null`, so it is never executed through the descriptor.
    #[cfg(test)]
    pub(crate) fn fake(path: &str) -> Resolved {
        let f = File::open("/dev/null").unwrap();
        Resolved {
            path: PathBuf::from(path),
            canonical: Some(PathBuf::from(path)),
            dev: 0,
            ino: 0,
            native: false,
            user_writable: false,
            fd: Arc::new(OwnedFd::from(f)),
        }
    }
}

/// The soft `RLIMIT_NOFILE` the daemon started with, if [`raise_fd_limit`]
/// raised it; children get it back (see [`restore_fd_limit`]).
static STARTUP_NOFILE: OnceLock<libc::rlimit> = OnceLock::new();

/// Raise the soft open-file limit to the hard one. A prepared request holds
/// one descriptor per program it runs until it finishes (issue #105), and up
/// to `max_in_flight` requests of up to `MAX_PLAN_NODES` nodes each can wait
/// at once, which can exceed the usual soft limit of 1024. Called once at
/// daemon start.
pub fn raise_fd_limit() {
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0
        || lim.rlim_cur >= lim.rlim_max
    {
        return;
    }
    let raised = libc::rlimit {
        rlim_cur: lim.rlim_max,
        rlim_max: lim.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        let _ = STARTUP_NOFILE.set(lim);
    }
}

/// In a forked child, before exec: put back the soft open-file limit the
/// daemon started with, so a program that still uses `select()` does not see
/// descriptors past `FD_SETSIZE`. Only `setrlimit` (async-signal-safe).
fn restore_fd_limit() {
    if let Some(lim) = STARTUP_NOFILE.get() {
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, lim);
        }
    }
}

/// Whether the daemon's effective uid may execute the file at `proc_path`
/// (a `/proc/self/fd/N` link to the pinned inode); `mode` decides when
/// `/proc` is not mounted.
fn executable_by_me(proc_path: &Path, mode: libc::mode_t) -> bool {
    if !proc_fd_available() {
        return mode & 0o111 != 0;
    }
    let Ok(c) = std::ffi::CString::new(proc_path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

/// Whether the daemon's effective uid may write `path`, by the kernel's own
/// answer (ACLs count). For a `/proc/self/fd/N` link it is the pinned inode.
fn writable_by_me(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

/// Whether `euid` owns `dir` or may write it: either way it can change what
/// the directory holds.
fn controlled_by(dir: &Path, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).is_ok_and(|m| m.uid() == euid) || writable_by_me(dir)
}

fn fd_path(fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

fn proc_fd_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| Path::new("/proc/self/fd").is_dir())
}

/// Resolve a requested command's `argv[0]` exactly as its child would: a bare
/// name is searched on the child's PATH ([`DEFAULT_LOGIN_PATH`] — no request
/// can set PATH), and a name containing `/` is taken relative to the leaf's
/// working directory, where the child starts. The result is pinned (see
/// [`Resolved`]): the prompt shows it and the executor spawns it, so the two
/// cannot name different files (issues #62, #105).
pub fn resolve_command(name: &str, cwd: &str) -> Option<Resolved> {
    resolve_on(name, cwd, DEFAULT_LOGIN_PATH)
}

/// [`resolve_command`] with an explicit search PATH. Entries that are empty
/// or relative are skipped: they would resolve against the daemon's working
/// directory, while the child (and a wrapper it runs) starts in the leaf's.
fn resolve_on(name: &str, cwd: &str, path_var: &str) -> Option<Resolved> {
    if name.contains('/') {
        return Resolved::open(Path::new(cwd).join(name), false);
    }
    path_var
        .split(':')
        .filter(|dir| dir.starts_with('/'))
        .find_map(|dir| Resolved::open(Path::new(dir).join(name), true))
}

/// True if the basename of `p` names a shell interpreter (see
/// [`crate::wrappers::SHELLS`]).
#[cfg(test)]
fn is_shell_name(p: &Path) -> bool {
    p.to_str().is_some_and(crate::wrappers::is_shell_name)
}

/// Top-level escalation mechanism chosen by the dispatcher. It governs how an
/// *escalated* leaf (one running as root or a named user) is spawned; a leaf
/// running as the daemon's own user is always spawned directly, regardless of
/// mode. `Direct` means the request is unprivileged — every leaf runs as the
/// daemon user.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscalationMode {
    Direct,
    Sudo,
    Pkexec,
}

/// Execute a prepared request's plan under pkexec (local/graphical mode).
pub fn exec_pkexec(req: &PreparedRequest, tty_lock: &Mutex<()>) -> Response {
    run_plan(req, EscalationMode::Pkexec, Some(tty_lock))
}

/// Execute a prepared request's plan under sudo (remote/TUI mode).
pub fn exec_sudo(req: &PreparedRequest, tty_lock: &Mutex<()>) -> Response {
    run_plan(req, EscalationMode::Sudo, Some(tty_lock))
}

/// Execute a prepared request's plan directly as the current user (no
/// escalation).
pub fn exec_direct(req: &PreparedRequest) -> Response {
    run_plan(req, EscalationMode::Direct, None)
}

/// [`prepare`] then [`exec_direct`]: for callers (tests, tools) that have no
/// prompt between the two. The daemon prepares once and passes the result.
pub fn prepare_and_exec_direct(req: &ValidatedRequest, env: &HashMap<String, String>) -> Response {
    match prepare(req, env) {
        Ok(p) => exec_direct(&p),
        Err(e) => Response::error(&req.id, &format!("invalid plan: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Structured plan execution
//
// A request's command is canonically a `Plan` tree (`Request::exec_plan`; a
// flat `pipeline` desugars into one). Execution is two passes:
//
//   Pass A (`compile_plan`): a pure walk that threads an immutable context
//   (env / cwd / run-as / accepted-exit-codes / stdio) down the tree. Context
//   modifiers (setenv, chdir, run-as, with-accepted-exit-codes) and stdio
//   modifiers (redirect, with-stdin-from) are transparent — they adjust the
//   context and recurse. Only `run`/`system` leaves produce a process. The
//   output is a flat `Vec<LeafPlan>` (one per leaf, in pre-order = prompt
//   order) plus a `SeqNode` sequencing tree that references leaves by index.
//
//   Pass B (`run_seq`): interprets the sequencing tree — a `Pipe` group spawns
//   its leaves connected by pipes, a `Run` (`&&`) runs children in order and
//   stops at the first non-accepted exit, a `Seq` (`;`) runs them all, an `Alt`
//   (`||`) stops at the first success, a `Leaf` runs one process. Every
//   process shares one plan-wide deadline.
//
// No shell command line is ever built (G3.1): each leaf fork/execs its argv
// word for word (program words replaced by their pinned paths, #105), and an
// escalated leaf is `sudo [-u user] [K=V…] -- program args` / `pkexec
// [--user user] env -C dir -- program args`. The daemon never *adds* a shell;
// a leaf that runs one (an explicit `Shell` node, or an `Exec` of `sh`/`bash`/…,
// directly or behind a wrapper such as `env`/`nice`/`timeout`), an inline-code
// interpreter or a program runner is flagged opaque at the prompt and rejected
// outright under the `no_shell` policy (see `crate::wrappers`).
// ---------------------------------------------------------------------------

/// Per-leaf run-as context, resolved from the ambient `privileged` flag and any
/// enclosing `RunAs` node.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LeafRunAs {
    /// Run as the daemon's own user (no escalation).
    Direct,
    Root,
    User(String),
}

impl LeafRunAs {
    fn is_escalated(&self) -> bool {
        !matches!(self, LeafRunAs::Direct)
    }
}

#[derive(Clone, Debug)]
enum InSpec {
    Null,
    File(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OutSpec {
    /// Captured into the response (piped + drained).
    Capture,
    File {
        path: String,
        append: bool,
    },
    DevNull,
}

#[derive(Clone, Debug)]
enum ErrSpec {
    Capture,
    File {
        path: String,
        append: bool,
    },
    DevNull,
    /// `2>&1` — stderr follows wherever stdout points.
    ToStdout,
}

/// One fully-resolved process: the leaf of a compiled plan.
struct LeafPlan {
    argv: Vec<String>,
    env: HashMap<String, String>,
    cwd: String,
    runas: LeafRunAs,
    stdin: InSpec,
    stdout: OutSpec,
    stderr: ErrSpec,
    /// Why the leaf is opaque: an explicit `Shell` node, or a program the
    /// prompt cannot show stage by stage (a shell, an inline-code interpreter,
    /// a runner), directly or behind a wrapper (see [`crate::wrappers`]).
    /// The prompt flags it; the `no_shell` policy rejects it.
    opaque: Option<Opacity>,
    /// The programs the leaf runs: `argv[0]`, then each program a wrapper runs.
    programs: Vec<ProgramHop>,
    /// `argv[0]` resolved and pinned once (see [`Resolved`]). The `no_shell`
    /// check and the prompt read it and [`build_command`] spawns it, so they
    /// can never disagree; `None` means the stage is refused at spawn rather
    /// than looked up again.
    resolved_bin: Option<Resolved>,
    /// Exit codes treated as success (besides 0) for seq short-circuiting.
    accepted: Vec<i32>,
    forward_agent: bool,
    /// The daemon environment this leaf runs with (`--inherit-path` /
    /// `--inherit-env`, #101). Set only on leaves of a request with no
    /// escalated step, and applied only in the `Direct` arm of
    /// [`build_command`].
    inherit: Option<Arc<Inherited>>,
    /// Pre-order index == position in the response's `stages` and in the
    /// prompt render.
    stage_id: usize,
}

/// The sequencing skeleton over the leaf list.
enum SeqNode {
    Leaf(usize),
    Pipe(Vec<usize>),
    /// `&&` — run in order, stop at first failure.
    Run(Vec<SeqNode>),
    /// `;` — run all in order regardless of exit status.
    Seq(Vec<SeqNode>),
    /// `||` — run in order, stop at first success.
    Alt(Vec<SeqNode>),
}

/// Immutable compile context threaded down the tree.
#[derive(Clone)]
struct Ctx {
    env: HashMap<String, String>,
    cwd: String,
    /// The PATH bare program names are resolved on: the login PATH, or the
    /// inherited one (#101).
    lookup_path: String,
    inherit: Option<Arc<Inherited>>,
    runas: LeafRunAs,
    accepted: Vec<i32>,
    forward_agent: bool,
    stdin: InSpec,
    stdout: OutSpec,
    stderr: ErrSpec,
}

impl Ctx {
    fn stdio_is_default(&self) -> bool {
        matches!(self.stdin, InSpec::Null)
            && self.stdout == OutSpec::Capture
            && matches!(self.stderr, ErrSpec::Capture)
    }
}

struct Compiled {
    leaves: Vec<LeafPlan>,
    seq: SeqNode,
}

/// Compile `req.exec_plan()` into leaves + a sequencing tree. Ambient run-as is
/// seeded from `req.privileged` (root when set, else the daemon user); `RunAs`
/// nodes override it per-subtree.
fn compile_plan(
    req: &ValidatedRequest,
    env: &HashMap<String, String>,
    inherit: Option<&Arc<Inherited>>,
) -> Result<Compiled, String> {
    // Whether the request inherits was decided once, by the caller, from
    // `effective_privileged()` (#101); a request with an escalated step never
    // does. Checked again here and on the compiled leaves, failing closed.
    if inherit.is_some() && req.effective_privileged() {
        return Err("internal error: daemon environment offered to an escalated request".into());
    }
    let ambient = if req.privileged {
        LeafRunAs::Root
    } else {
        LeafRunAs::Direct
    };
    let ctx = Ctx {
        env: env.clone(),
        cwd: "/".to_string(),
        lookup_path: inherit.map_or_else(|| DEFAULT_LOGIN_PATH.to_string(), |i| i.path.clone()),
        inherit: inherit.cloned(),
        runas: ambient,
        accepted: Vec::new(),
        forward_agent: req.forward_agent,
        stdin: InSpec::Null,
        stdout: OutSpec::Capture,
        stderr: ErrSpec::Capture,
    };
    let plan = req.exec_plan();
    let mut leaves = Vec::new();
    let seq = compile_seq(&plan, ctx, &mut leaves)?;
    if leaves
        .iter()
        .any(|l| l.inherit.is_some() && l.runas.is_escalated())
    {
        return Err("internal error: daemon environment reached an escalated step".into());
    }
    Ok(Compiled { leaves, seq })
}

/// Apply a `Setenv` node to a context, holding it to the same env allowlist as
/// the request-level env so it cannot become a bypass.
fn apply_setenv(ctx: &mut Ctx, key: &str, value: &str) -> Result<(), String> {
    if key == "SSH_AUTH_SOCK" {
        return Err("SSH_AUTH_SOCK cannot be set by setenv; use forward_agent instead".to_string());
    }
    if !is_env_allowed(key) {
        return Err(format!("environment variable not allowed: {key}"));
    }
    ctx.env.insert(key.to_string(), value.to_string());
    Ok(())
}

/// Apply a `RunAs` node to a context.
fn apply_runas(ctx: &mut Ctx, who: &RunAs) {
    ctx.runas = match who {
        RunAs::Root => LeafRunAs::Root,
        RunAs::User { name } => LeafRunAs::User(name.clone()),
    };
    // An escalated subtree never carries the daemon's agent socket.
    ctx.forward_agent = false;
}

/// Compile a plan that may expand to a sequence / pipe / single process. The
/// *context* modifiers (setenv / chdir / run-as / with-accepted-exit-codes) are
/// transparent and may wrap a composite — they adjust the context and recurse.
/// The *stdio* modifiers (redirect / with-stdin-from) target a single process,
/// so they (and bare leaves) are delegated to `compile_leaf`.
fn compile_seq(plan: &Plan, mut ctx: Ctx, leaves: &mut Vec<LeafPlan>) -> Result<SeqNode, String> {
    match plan {
        Plan::Setenv { key, value, body } => {
            apply_setenv(&mut ctx, key, value)?;
            compile_seq(body, ctx, leaves)
        }
        Plan::Chdir { dir, body } => {
            ctx.cwd = dir.clone();
            compile_seq(body, ctx, leaves)
        }
        Plan::RunAs { who, body } => {
            apply_runas(&mut ctx, who);
            compile_seq(body, ctx, leaves)
        }
        Plan::WithAcceptedExitCodes { codes, body } => {
            ctx.accepted = codes.clone();
            compile_seq(body, ctx, leaves)
        }
        Plan::Run { steps } => {
            if !ctx.stdio_is_default() {
                return Err("redirect / stdin-from of a run is not supported".to_string());
            }
            let mut nodes = Vec::with_capacity(steps.len());
            for s in steps {
                nodes.push(compile_seq(s, ctx.clone(), leaves)?);
            }
            Ok(SeqNode::Run(nodes))
        }
        Plan::Seq { steps } => {
            if !ctx.stdio_is_default() {
                return Err("redirect / stdin-from of a seq is not supported".to_string());
            }
            let mut nodes = Vec::with_capacity(steps.len());
            for s in steps {
                nodes.push(compile_seq(s, ctx.clone(), leaves)?);
            }
            Ok(SeqNode::Seq(nodes))
        }
        Plan::Alt { steps } => {
            if !ctx.stdio_is_default() {
                return Err("redirect / stdin-from of an alt is not supported".to_string());
            }
            let mut nodes = Vec::with_capacity(steps.len());
            for s in steps {
                nodes.push(compile_seq(s, ctx.clone(), leaves)?);
            }
            Ok(SeqNode::Alt(nodes))
        }
        Plan::Pipe { stages } => {
            if !ctx.stdio_is_default() {
                return Err("redirect / stdin-from of a pipe is not supported".to_string());
            }
            compile_pipe(stages, ctx, leaves)
        }
        // Redirect / with-stdin-from / bare leaves — a single process.
        _ => Ok(SeqNode::Leaf(compile_leaf(plan, ctx, leaves)?)),
    }
}

/// Compile a plan that must resolve to exactly one process (a pipe stage, or a
/// redirect / stdin-from body). Peels the transparent context and stdio
/// modifiers and errors on a composite.
fn compile_leaf(plan: &Plan, mut ctx: Ctx, leaves: &mut Vec<LeafPlan>) -> Result<usize, String> {
    match plan {
        Plan::Exec { argv } => Ok(push_leaf(argv.clone(), false, ctx, leaves)),
        Plan::Shell { shell, script } => {
            let bin = match shell {
                ShellProc::Sh => "sh",
                ShellProc::Bash => "bash",
            };
            let argv = vec![bin.to_string(), "-c".to_string(), script.clone()];
            Ok(push_leaf(argv, true, ctx, leaves))
        }
        Plan::Setenv { key, value, body } => {
            apply_setenv(&mut ctx, key, value)?;
            compile_leaf(body, ctx, leaves)
        }
        Plan::Chdir { dir, body } => {
            ctx.cwd = dir.clone();
            compile_leaf(body, ctx, leaves)
        }
        Plan::RunAs { who, body } => {
            apply_runas(&mut ctx, who);
            compile_leaf(body, ctx, leaves)
        }
        Plan::WithAcceptedExitCodes { codes, body } => {
            ctx.accepted = codes.clone();
            compile_leaf(body, ctx, leaves)
        }
        Plan::Redirect {
            stream,
            target,
            body,
        } => {
            apply_redirect(&mut ctx, *stream, target)?;
            compile_leaf(body, ctx, leaves)
        }
        Plan::WithStdinFrom { path, body } => {
            if !matches!(ctx.stdin, InSpec::Null) {
                return Err("stdin is redirected twice".to_string());
            }
            ctx.stdin = InSpec::File(path.clone());
            compile_leaf(body, ctx, leaves)
        }
        Plan::Run { .. } | Plan::Seq { .. } | Plan::Alt { .. } | Plan::Pipe { .. } => {
            Err("expected a single command here, found a composite plan".to_string())
        }
    }
}

fn apply_redirect(ctx: &mut Ctx, stream: Stream, target: &RedirTarget) -> Result<(), String> {
    let out = |t: &RedirTarget| -> OutSpec {
        match t {
            RedirTarget::File { path, mode } => OutSpec::File {
                path: path.clone(),
                append: *mode == WriteMode::Append,
            },
            RedirTarget::DevNull => OutSpec::DevNull,
        }
    };
    let err = |t: &RedirTarget| -> ErrSpec {
        match t {
            RedirTarget::File { path, mode } => ErrSpec::File {
                path: path.clone(),
                append: *mode == WriteMode::Append,
            },
            RedirTarget::DevNull => ErrSpec::DevNull,
        }
    };
    // Validation (`Plan::validate_stdio`) already rejects this; kept as a
    // backstop so the executor never silently drops an outer redirect.
    let out_taken = ctx.stdout != OutSpec::Capture;
    let err_taken = !matches!(ctx.stderr, ErrSpec::Capture);
    let clash = match stream {
        Stream::Stdout => out_taken,
        Stream::Stderr => err_taken,
        Stream::Both => out_taken || err_taken,
    };
    if clash {
        return Err("a stream is redirected twice".to_string());
    }
    match stream {
        Stream::Stdout => ctx.stdout = out(target),
        Stream::Stderr => ctx.stderr = err(target),
        Stream::Both => {
            // `&>file` / `with-outputs-to`: stdout to the target, stderr dup'd
            // onto it (2>&1). This keeps a single file handle, not two racing
            // truncating opens.
            ctx.stdout = out(target);
            ctx.stderr = ErrSpec::ToStdout;
        }
    }
    Ok(())
}

/// One program a leaf runs: `argv[0]`, or a program run by a wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramHop {
    /// The program word as written in argv.
    pub name: String,
    /// Index of that word in the leaf's argv.
    pub argv_index: usize,
    /// Its pinned resolution (`resolve_command`). For `argv[0]` this is the
    /// leaf's `resolved_bin`. `None` when not found, and always `None` when
    /// `runtime_lookup` or `applet` is set.
    pub resolved: Option<Resolved>,
    /// The wrapper (as written) that runs it; `None` for `argv[0]`.
    pub via: Option<String>,
    /// That wrapper's index in the leaf's argv.
    pub via_index: Option<usize>,
    /// An inner program of an escalated leaf: the wrapper looks it up at run
    /// time on the escalated PATH (sudo's `secure_path`, pkexec's environment),
    /// not the PATH the daemon resolves with, so no path is shown.
    pub runtime_lookup: bool,
    /// An applet of a multi-call dispatcher (`busybox sh`): the dispatcher
    /// runs its built-in applet, so its PATH resolution is not shown
    /// (`resolved` is `None`).
    pub applet: bool,
    /// Inherited names this program, an `env` wrapper, sets or unsets (#101).
    pub overrides_inherited: Vec<String>,
}

/// Why a leaf is opaque, described once for both the prompt and the
/// `no_shell` rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opacity {
    /// Index into the leaf's `programs` of the program the reason is about.
    pub at: usize,
    /// [`crate::wrappers::OpaqueReason::describe`].
    pub reason: String,
    /// The reason is a shell (the prompt keeps "resolves only the shell").
    pub is_shell: bool,
    /// The reason is about the program itself, so its path is shown.
    pub names_program: bool,
}

/// The leaf cwd with an accumulated `env -C` directory applied.
fn hop_cwd(cwd: &str, chdir: Option<&str>) -> String {
    match chdir {
        Some(d) => Path::new(cwd).join(d).to_string_lossy().into_owned(),
        None => cwd.to_string(),
    }
}

/// Append a resolved leaf to the list and return its index (= stage id).
///
/// Every program the leaf runs is resolved here, once (issue #105): the
/// opacity decision, the prompt and the spawn all read these pins.
fn push_leaf(argv: Vec<String>, shell_op: bool, ctx: Ctx, leaves: &mut Vec<LeafPlan>) -> usize {
    let resolve = |i: usize, chdir: Option<&str>| -> Option<Resolved> {
        resolve_on(&argv[i], &hop_cwd(&ctx.cwd, chdir), &ctx.lookup_path)
    };
    let resolved_bin = argv.first().and_then(|_| resolve(0, None));
    // The walk asks for the canonical name of each hop's binary; remember each
    // resolution it makes so the hop list below reuses it instead of looking
    // the name up again.
    // (argv index, `env -C` dir) -> resolution.
    type Seen = Vec<((usize, Option<String>), Option<Resolved>)>;
    let seen: std::cell::RefCell<Seen> = std::cell::RefCell::new(Vec::new());
    let lookup = |i: usize, chdir: Option<&str>| -> Option<Resolved> {
        if i == 0 {
            return resolved_bin.clone();
        }
        let key = (i, chdir.map(str::to_string));
        if let Some((_, r)) = seen.borrow().iter().find(|(k, _)| *k == key) {
            return r.clone();
        }
        let r = resolve(i, chdir);
        seen.borrow_mut().push((key, r.clone()));
        r
    };
    // Decide opacity here, the one place every leaf is created, so the
    // prompt, the resolve block and the `no_shell` policy all read the same
    // value. The canonical name of each hop's binary catches a renamed
    // symlink (`/bin/sh -> dash`, `innocuous -> bash`, `innocuous -> env`).
    let canonical = |i: usize, chdir: Option<&str>| -> Option<String> {
        let r = lookup(i, chdir)?;
        let c = r.canonical()?;
        c.file_name().and_then(|n| n.to_str()).map(str::to_string)
    };
    let (hops, reason) = crate::wrappers::unwrap(&argv, canonical);
    let reason = if shell_op {
        Some(crate::wrappers::OpaqueReason::ShellOp)
    } else {
        reason
    };
    let opaque = reason.map(|r| Opacity {
        at: r.hop().min(hops.len().saturating_sub(1)),
        reason: r.describe(&hops, &argv),
        is_shell: r.is_shell(),
        names_program: r.names_program(),
    });
    let escalated = ctx.runas.is_escalated();
    let programs = hops
        .iter()
        .map(|h| {
            let name = argv[h.argv_index].clone();
            let inner = h.argv_index != 0;
            let resolved = if !inner {
                resolved_bin.clone()
            } else if escalated || h.applet {
                None
            } else {
                lookup(h.argv_index, h.chdir.as_deref())
            };
            let overrides_inherited = match &ctx.inherit {
                Some(i) => h.touches.iter().filter(|n| i.has(n)).cloned().collect(),
                None => Vec::new(),
            };
            ProgramHop {
                name,
                argv_index: h.argv_index,
                resolved,
                overrides_inherited,
                via: h.via.map(|p| argv[hops[p].argv_index].clone()),
                via_index: h.via.map(|p| hops[p].argv_index),
                runtime_lookup: inner && escalated && !h.applet,
                applet: h.applet,
            }
        })
        .collect();
    let stage_id = leaves.len();
    leaves.push(LeafPlan {
        argv,
        env: ctx.env,
        cwd: ctx.cwd,
        runas: ctx.runas,
        stdin: ctx.stdin,
        stdout: ctx.stdout,
        stderr: ctx.stderr,
        opaque,
        programs,
        resolved_bin,
        accepted: ctx.accepted,
        forward_agent: ctx.forward_agent,
        inherit: ctx.inherit,
        stage_id,
    });
    stage_id
}

fn compile_pipe(stages: &[Plan], ctx: Ctx, leaves: &mut Vec<LeafPlan>) -> Result<SeqNode, String> {
    let n = stages.len();
    let mut indices = Vec::with_capacity(n);
    for (pos, stage) in stages.iter().enumerate() {
        let idx = compile_leaf(stage, ctx.clone(), leaves)?;
        // The pipe owns the stdout of every non-final stage, so it must not be
        // independently redirected. (Put the redirect on the final stage.)
        let is_last = pos == n - 1;
        if !is_last && leaves[idx].stdout != OutSpec::Capture {
            return Err(
                "cannot redirect stdout of a non-final pipe stage; redirect the last stage"
                    .to_string(),
            );
        }
        // Likewise every stage but the first reads the previous stage, so its
        // own stdin redirect would be silently ignored.
        if pos > 0 && !matches!(leaves[idx].stdin, InSpec::Null) {
            return Err("with-stdin-from is only allowed on the first pipe stage".to_string());
        }
        indices.push(idx);
    }
    Ok(SeqNode::Pipe(indices))
}

// ---------------------------------------------------------------------------
// Display projection — what the approval prompt renders
// ---------------------------------------------------------------------------

/// A leaf's run-as context for display at the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafPrivilege {
    /// Runs as the daemon's own user — no tag.
    Direct,
    /// `[ROOT]`.
    Root,
    /// `[as <name>]`.
    User(String),
}

/// A displayable projection of one compiled plan leaf. The approval prompt
/// renders these, so the human sees exactly the stages — resolved binary,
/// run-as, redirections — that the executor will run. Built by the same
/// `compile_plan` walk the executor uses, so the two cannot diverge.
pub struct LeafView {
    pub stage_id: usize,
    pub argv: Vec<String>,
    pub privilege: LeafPrivilege,
    /// `argv[0]` resolved through PATH, pinned (the spawn runs this file).
    pub resolved_bin: Option<Resolved>,
    /// True for an opaque leaf (see `opaque_reason`) — rendered "opaque", and
    /// rejected under the `no_shell` policy.
    pub opaque: bool,
    /// Why the leaf is opaque, and which of `programs` it is about.
    pub opaque_reason: Option<Opacity>,
    /// Every program the leaf runs: `argv[0]` first, then each program a
    /// wrapper runs (`env X=1 true` → `env`, `true`).
    pub programs: Vec<ProgramHop>,
    /// Human-readable redirection summary, e.g. `> /tmp/out`, `< in`, `2>&1`.
    pub redirects: String,
    /// True if this leaf is a stage of a pipe.
    pub in_pipe: bool,
}

/// A request compiled once, with every program it runs resolved and pinned
/// (issue #105). The `no_shell` check, the pkexec decision and the prompt read
/// its [`views`](PreparedRequest::views); `exec_*` run its leaves. Nothing
/// downstream compiles the plan or looks a program up again, so the file the
/// human approved is the file that runs.
pub struct PreparedRequest<'a> {
    req: &'a ValidatedRequest,
    compiled: Compiled,
    views: Vec<LeafView>,
    inherit: Option<Arc<Inherited>>,
}

impl<'a> PreparedRequest<'a> {
    pub fn request(&self) -> &'a ValidatedRequest {
        self.req
    }

    /// Every pinned program's path still names the pinned file.
    pub fn pins_current(&self) -> bool {
        self.compiled.leaves.iter().all(|l| check_pins(l).is_ok())
    }

    pub fn views(&self) -> &[LeafView] {
        &self.views
    }

    /// The daemon environment this request runs with, if any (#101).
    pub fn inherit(&self) -> Option<&Arc<Inherited>> {
        self.inherit.as_ref()
    }
}

impl std::ops::Deref for PreparedRequest<'_> {
    type Target = ValidatedRequest;
    fn deref(&self) -> &ValidatedRequest {
        self.req
    }
}

/// Compile `req` with the environment its leaves will run with, resolving
/// and pinning every program. The only errors are structural: a plan that
/// fails here is never shown or run.
pub fn prepare<'a>(
    req: &'a ValidatedRequest,
    env: &HashMap<String, String>,
) -> Result<PreparedRequest<'a>, String> {
    prepare_with(req, env, None)
}

/// [`prepare`] for a request that runs with the daemon environment `inherit`
/// (`--inherit-path` / `--inherit-env`, #101). The caller decides, once,
/// that the request has no escalated step; a request that has one is refused.
/// `env` then holds only the request's own variables: the login defaults are
/// applied at spawn, under the inherited layer.
pub fn prepare_with<'a>(
    req: &'a ValidatedRequest,
    env: &HashMap<String, String>,
    inherit: Option<Arc<Inherited>>,
) -> Result<PreparedRequest<'a>, String> {
    let compiled = compile_plan(req, env, inherit.as_ref())?;
    let views = leaf_views(&compiled);
    Ok(PreparedRequest {
        req,
        compiled,
        views,
        inherit,
    })
}

/// The prompt's view of a request with no environment: the structure and
/// resolutions are those [`prepare`] gives (the environment cannot change
/// either, since no request can set PATH). For display-only callers and tests.
pub fn plan_display(req: &ValidatedRequest) -> Result<Vec<LeafView>, String> {
    prepare(req, &HashMap::new()).map(|p| p.views)
}

fn leaf_views(compiled: &Compiled) -> Vec<LeafView> {
    let mut in_pipe = vec![false; compiled.leaves.len()];
    mark_pipe_members(&compiled.seq, &mut in_pipe);
    compiled
        .leaves
        .iter()
        .map(|l| LeafView {
            stage_id: l.stage_id,
            argv: l.argv.clone(),
            privilege: match &l.runas {
                LeafRunAs::Direct => LeafPrivilege::Direct,
                LeafRunAs::Root => LeafPrivilege::Root,
                LeafRunAs::User(n) => LeafPrivilege::User(n.clone()),
            },
            resolved_bin: l.resolved_bin.clone(),
            opaque: l.opaque.is_some(),
            opaque_reason: l.opaque.clone(),
            programs: l.programs.clone(),
            redirects: summarize_redirects(l),
            in_pipe: in_pipe[l.stage_id],
        })
        .collect()
}

fn mark_pipe_members(node: &SeqNode, in_pipe: &mut [bool]) {
    match node {
        SeqNode::Leaf(_) => {}
        SeqNode::Pipe(indices) => {
            for &i in indices {
                in_pipe[i] = true;
            }
        }
        SeqNode::Run(nodes) | SeqNode::Seq(nodes) | SeqNode::Alt(nodes) => {
            for n in nodes {
                mark_pipe_members(n, in_pipe);
            }
        }
    }
}

fn summarize_redirects(l: &LeafPlan) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let InSpec::File(p) = &l.stdin {
        parts.push(format!("< {p}"));
    }
    match &l.stdout {
        OutSpec::Capture => {}
        OutSpec::DevNull => parts.push("> /dev/null".to_string()),
        OutSpec::File { path, append } => {
            parts.push(format!("{} {path}", if *append { ">>" } else { ">" }))
        }
    }
    match &l.stderr {
        ErrSpec::Capture => {}
        ErrSpec::DevNull => parts.push("2> /dev/null".to_string()),
        ErrSpec::ToStdout => parts.push("2>&1".to_string()),
        ErrSpec::File { path, append } => {
            parts.push(format!("2{} {path}", if *append { ">>" } else { ">" }))
        }
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// Pass B — run the compiled plan
// ---------------------------------------------------------------------------

/// Raw result of one leaf process. `ran == false` is a leaf that a short-
/// circuited seq never reached.
#[derive(Clone)]
struct Outcome {
    ran: bool,
    exit: i32,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
    /// Whether this leaf's stdout contributes to the aggregate response stdout
    /// (true iff its stdout was `Capture`).
    captured_stdout: bool,
}

impl Default for Outcome {
    fn default() -> Self {
        Outcome {
            ran: false,
            exit: -1,
            stdout: Vec::new(),
            stdout_truncated: false,
            stderr: Vec::new(),
            stderr_truncated: false,
            captured_stdout: false,
        }
    }
}

/// Status a sequencing node reports up to its parent `seq`: enough to decide
/// whether to short-circuit the sequence.
struct StepStatus {
    timed_out: bool,
    spawn_error: Option<String>,
    success: bool,
}

fn run_plan(
    prepared: &PreparedRequest,
    mode: EscalationMode,
    tty_lock: Option<&Mutex<()>>,
) -> Response {
    let req = prepared.req;
    let compiled = &prepared.compiled;
    if mode == EscalationMode::Pkexec {
        if let Err(e) = check_pkexec_leaves(&compiled.leaves, env_supports_chdir()) {
            return Response::error(&req.id, &e);
        }
    }
    let total = exec_timeout();
    let deadline = Instant::now() + total;
    let mut outcomes = vec![Outcome::default(); compiled.leaves.len()];

    let status = run_seq(
        &compiled.seq,
        &compiled.leaves,
        mode,
        deadline,
        tty_lock,
        &mut outcomes,
    );

    if status.timed_out {
        return Response::error(
            &req.id,
            &format!("command timed out after {}s", total.as_secs()),
        );
    }
    if let Some(msg) = status.spawn_error {
        return Response::error(&req.id, &msg);
    }

    // Build the positional stage list (one per leaf, pre-order) and the
    // aggregate stdout (every captured leaf, in order).
    let mut stages = Vec::with_capacity(outcomes.len());
    let mut stdout = Vec::new();
    let mut stdout_truncated = false;
    for o in &outcomes {
        stages.push(StageResult {
            exit_code: o.exit,
            stderr: B64.encode(&o.stderr),
            stderr_truncated: o.stderr_truncated,
        });
        if o.captured_stdout && o.ran {
            stdout.extend_from_slice(&o.stdout);
            stdout_truncated |= o.stdout_truncated;
        }
    }
    Response::ok_with_truncation(&req.id, stages, &stdout, stdout_truncated)
}

/// The `env` pkexec runs to re-enter the approved directory: a trusted one
/// from the helper search list (GHSA-gx9w-4f7x-2gcp), passed by absolute
/// path. A bare `env` would be looked up by pkexec on the PATH it is given,
/// whose `/usr/local/bin` precedes `/usr/bin`.
fn trusted_env() -> Result<&'static Path, String> {
    static ENV: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    ENV.get_or_init(|| crate::helper::find_trusted("env", false, crate::helper::HELPER_PATH))
        .as_deref()
        .map_err(Clone::clone)
}

/// Whether this host's `env` understands `-C DIR` (GNU coreutils ≥ 8.28,
/// uutils). Probed once, on the trusted `env` pkexec mode runs
/// ([`trusted_env`]), never one from the daemon's PATH; none found counts
/// as no.
fn env_supports_chdir() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let truth = crate::helper::find_trusted("true", false, crate::helper::HELPER_PATH);
        let (Ok(env), Ok(truth)) = (trusted_env(), truth) else {
            return false;
        };
        env_chdir_probe(env, &truth)
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// The `env -C / -- TRUE` probe. Both programs are trusted absolute paths
/// (GHSA-gx9w-4f7x-2gcp), and the probe runs with a cleared environment and
/// the helper search list as PATH: the daemon's own PATH may hold
/// user-writable directories (#101's `--inherit-path` makes it so on
/// purpose), where a planted `true` could turn pkexec mode off or run code as
/// the daemon's user.
fn env_chdir_probe(env: &Path, truth: &Path) -> Command {
    let mut c = Command::new(env);
    c.args([
        "-C".as_ref(),
        "/".as_ref(),
        "--".as_ref(),
        truth.as_os_str(),
    ])
    .env_clear()
    .env("PATH", crate::helper::HELPER_PATH)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    c
}

/// The daemon variables the `sudo` process receives: `TERM`, `LANG` and
/// `LC_*`. Everything else is cleared before sudo runs (#101).
fn sudo_env_keep(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|n| n == "TERM" || n == "LANG" || n.starts_with("LC_"))
}

/// Preconditions for running escalated leaves as `pkexec env -C DIR -- argv`:
/// `env` must support `-C` (otherwise the approved `chdir` could not be
/// honoured), and argv[0] must not contain `=`, which `env` would take as an
/// environment assignment rather than the command.
fn check_pkexec_leaves(leaves: &[LeafPlan], env_has_chdir: bool) -> Result<(), String> {
    for leaf in leaves.iter().filter(|l| l.runas.is_escalated()) {
        if !env_has_chdir {
            return Err(
                "pkexec mode needs an `env` that supports -C to keep the working directory"
                    .to_string(),
            );
        }
        if leaf_program(leaf).is_some_and(|p| p.as_os_str().as_encoded_bytes().contains(&b'=')) {
            return Err("under pkexec, a command name must not contain '='".to_string());
        }
    }
    Ok(())
}

fn run_seq(
    node: &SeqNode,
    leaves: &[LeafPlan],
    mode: EscalationMode,
    deadline: Instant,
    tty_lock: Option<&Mutex<()>>,
    outcomes: &mut [Outcome],
) -> StepStatus {
    match node {
        SeqNode::Leaf(idx) => {
            let leaf = &leaves[*idx];
            // A single escalated leaf gets the controlling-tty foreground so a
            // sudo/pkexec password prompt doesn't EIO. Unprivileged leaves run
            // with stdin=null and never touch /dev/tty.
            let fg = if leaf.runas.is_escalated() {
                tty_lock
            } else {
                None
            };
            let o = run_one(leaf, mode, deadline, fg);
            let st = StepStatus {
                timed_out: o.timed_out,
                spawn_error: o.spawn_error.clone(),
                success: !o.timed_out
                    && o.spawn_error.is_none()
                    && exit_accepted(o.exit, &leaf.accepted),
            };
            outcomes[*idx] = o.into_outcome(leaf.stdout == OutSpec::Capture);
            st
        }
        SeqNode::Pipe(indices) => run_pipe(indices, leaves, mode, deadline, outcomes),
        SeqNode::Run(nodes) => {
            // `&&` — run in order, stop at the first non-accepted failure (or a
            // timeout / spawn error). Status is the last step that ran.
            let mut last = StepStatus {
                timed_out: false,
                spawn_error: None,
                success: true,
            };
            for n in nodes {
                let st = run_seq(n, leaves, mode, deadline, tty_lock, outcomes);
                let stop = st.timed_out || st.spawn_error.is_some() || !st.success;
                last = st;
                if stop {
                    break;
                }
            }
            last
        }
        SeqNode::Seq(nodes) => {
            // `;` — run every step regardless of exit status. Only a timeout or
            // spawn failure (infrastructure errors the daemon treats as fatal
            // everywhere) aborts; a non-accepted exit does not. Status is the
            // last step that ran.
            let mut last = StepStatus {
                timed_out: false,
                spawn_error: None,
                success: true,
            };
            for n in nodes {
                let st = run_seq(n, leaves, mode, deadline, tty_lock, outcomes);
                let stop = st.timed_out || st.spawn_error.is_some();
                last = st;
                if stop {
                    break;
                }
            }
            last
        }
        SeqNode::Alt(nodes) => {
            // Dual of `Run`: run steps until one succeeds. Keep going past a
            // non-accepted failure; stop on the first success (and on a timeout
            // or spawn error, which abort the whole alt just as they do a run).
            let mut last = StepStatus {
                timed_out: false,
                spawn_error: None,
                success: false,
            };
            for n in nodes {
                let st = run_seq(n, leaves, mode, deadline, tty_lock, outcomes);
                let stop = st.timed_out || st.spawn_error.is_some() || st.success;
                last = st;
                if stop {
                    break;
                }
            }
            last
        }
    }
}

fn exit_accepted(exit: i32, accepted: &[i32]) -> bool {
    exit == 0 || accepted.contains(&exit)
}

/// One process: its raw run result plus the control-flow flags the sequencer
/// needs. Distinct from `Outcome` so the per-leaf accepted-code and stdout-
/// capture decisions stay with the caller.
struct RunResult {
    exit: i32,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
    timed_out: bool,
    spawn_error: Option<String>,
}

impl RunResult {
    fn into_outcome(self, captured_stdout: bool) -> Outcome {
        Outcome {
            ran: self.spawn_error.is_none(),
            exit: self.exit,
            stdout: self.stdout,
            stdout_truncated: self.stdout_truncated,
            stderr: self.stderr,
            stderr_truncated: self.stderr_truncated,
            captured_stdout,
        }
    }
}

/// Spawn and wait for a single leaf process against the shared deadline.
fn run_one(
    leaf: &LeafPlan,
    mode: EscalationMode,
    deadline: Instant,
    fg_lock: Option<&Mutex<()>>,
) -> RunResult {
    let mut cmd = match build_command(leaf, mode) {
        Ok(c) => c,
        Err(e) => return spawn_err(e),
    };
    let stdout_file = match set_stdout(&mut cmd, &leaf.stdout) {
        Ok(f) => f,
        Err(e) => return spawn_err(format!("failed to open stdout redirect: {e}")),
    };
    if let Err(e) = set_stdin(&mut cmd, &leaf.stdin) {
        return spawn_err(format!("failed to open stdin redirect: {e}"));
    }
    if let Err(e) = set_stderr(&mut cmd, &leaf.stderr, stdout_file.as_ref()) {
        return spawn_err(format!("failed to open stderr redirect: {e}"));
    }

    let needs_tty = fg_lock.is_some();
    unsafe {
        cmd.pre_exec(move || {
            // New process group so kill_group SIGKILLs the whole group on
            // timeout. An escalated child uses setpgid (not setsid), which
            // keeps it in the daemon's session so it can reach /dev/tty for
            // a password prompt — see issue #19.
            //
            // An unprivileged child gets its own session (setsid), so it has
            // no controlling terminal: a child sharing the daemon's could
            // inject keystrokes into the approval prompt with TIOCSTI (where
            // `dev.tty.legacy_tiocsti` allows it) and approve a later
            // privileged request, e.g. a background job left by a command
            // run under the session `a` grant (GHSA-cpmp-67wf-gwmx). It never
            // reads /dev/tty anyway; setsid also makes it a group leader, so
            // kill_group still works.
            if needs_tty {
                libc::setpgid(0, 0);
            } else {
                libc::setsid();
            }
            libc::umask(0o077);
            restore_fd_limit();
            Ok(())
        });
    }

    // Last, after the redirects are open (a FIFO can block), so the window
    // between the check and the exec is as short as it can be.
    if let Err(e) = check_pins(leaf) {
        return spawn_err(e);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return spawn_err(format!("failed to execute command: {e}")),
    };

    let cpid = child.id() as libc::pid_t;
    // (Not for a setsid child: a session leader cannot change group, and
    // setsid already made it the leader of group `cpid`.)
    if needs_tty {
        unsafe {
            let _ = libc::setpgid(cpid, cpid);
        }
    }
    let _fg = fg_lock.and_then(|m| ForegroundGuard::take(cpid, m));

    let stdout_handle = child
        .stdout
        .take()
        .map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));
    let stderr_handle = child
        .stderr
        .take()
        .map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));

    let exit = match wait_with_deadline(&mut child, deadline) {
        Ok(s) => s.code().unwrap_or(-1),
        Err(WaitError::Timeout) => {
            kill_group(&mut child);
            drain_join(stdout_handle);
            drain_join(stderr_handle);
            return RunResult {
                exit: -1,
                stdout: Vec::new(),
                stdout_truncated: false,
                stderr: Vec::new(),
                stderr_truncated: false,
                timed_out: true,
                spawn_error: None,
            };
        }
        Err(WaitError::Io(e)) => {
            kill_group(&mut child);
            drain_join(stdout_handle);
            drain_join(stderr_handle);
            return spawn_err(format!("wait failed: {e}"));
        }
    };

    let (stdout_bytes, stdout_truncated) = drain_join(stdout_handle);
    let (stderr_bytes, stderr_truncated) = drain_join(stderr_handle);

    RunResult {
        exit,
        stdout: stdout_bytes,
        stdout_truncated,
        stderr: stderr_bytes,
        stderr_truncated,
        timed_out: false,
        spawn_error: None,
    }
}

fn drain_join(h: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>) -> (Vec<u8>, bool) {
    h.map(|h| h.join().unwrap_or_default()).unwrap_or_default()
}

fn spawn_err(msg: String) -> RunResult {
    RunResult {
        exit: -1,
        stdout: Vec::new(),
        stdout_truncated: false,
        stderr: Vec::new(),
        stderr_truncated: false,
        timed_out: false,
        spawn_error: Some(msg),
    }
}

/// Build the `Command` for a leaf: program + args + env + cwd, with escalation
/// applied. Stdio is configured by the caller (so pipe wiring can override it).
/// No shell is ever introduced here — an escalated leaf is `sudo … -- argv` or
/// `pkexec … argv`.
///
/// The program is always the prompt-displayed `resolved_bin`, never `argv[0]`
/// looked up again (by `Command`, `sudo`'s `secure_path`, or `env`), so the
/// file that runs is the file the human approved (issue #62). An unresolved
/// name is refused here instead of being searched for a second time.
///
/// A direct leaf runs the pinned descriptor itself when it can
/// ([`Resolved::exec_path`]), and each program a wrapper runs is named by its
/// pinned absolute path ([`spawn_argv`]), so the wrapper never searches PATH
/// either (issue #105). The caller checks the pins ([`check_pins`]) just
/// before the spawn.
fn build_command(leaf: &LeafPlan, mode: EscalationMode) -> Result<Command, String> {
    let resolved = leaf.resolved_bin.as_ref().ok_or_else(|| {
        // Quoted like a `Command:` word (G4.6): this text reaches the TTY.
        format!("command not found: {}", crate::tui::shquote(&leaf.argv[0]))
    })?;
    let program = resolved.path.as_path();
    Ok(match &leaf.runas {
        LeafRunAs::Direct => {
            let argv = spawn_argv(leaf)?;
            let mut c = Command::new(resolved.exec_path().as_deref().unwrap_or(program));
            // Keep the requested argv[0] (multi-call binaries dispatch on it).
            c.arg0(&argv[0]);
            c.args(&argv[1..]);
            c.env_clear();
            // With `--inherit-path` / `--inherit-env` (#101), in order, a
            // later layer replacing an earlier one: the inherited variables;
            // the login defaults for names still unset; the request's `env`
            // and the plan's `setenv`. No request can set PATH, so a PATH in
            // `leaf.env` can only be a login default and never replaces the
            // inherited one.
            if let Some(inh) = &leaf.inherit {
                c.env("PATH", &inh.path);
                c.envs(&inh.vars);
                for (k, v) in login_env_defaults() {
                    if !inh.has(k) {
                        c.env(k, v);
                    }
                }
            }
            for (k, v) in &leaf.env {
                if leaf.inherit.is_some() && k == "PATH" {
                    continue;
                }
                c.env(k, v);
            }
            if leaf.forward_agent {
                if let Some(sock) = crate::server::forwarded_agent_socket() {
                    c.env("SSH_AUTH_SOCK", &sock);
                }
            }
            c.current_dir(&leaf.cwd);
            c
        }
        escalated => match mode {
            EscalationMode::Pkexec => {
                // Never the daemon's PATH (GHSA-gx9w-4f7x-2gcp).
                let mut c = Command::new(crate::helper::pkexec()?);
                if let LeafRunAs::User(name) = escalated {
                    c.arg("--user");
                    c.arg(name);
                }
                // pkexec runs PROGRAM in the target user's home unless told
                // otherwise, which would ignore the plan's `chdir`. `env -C`
                // re-enters the approved directory; `--` keeps an argv[0]
                // that looks like an option from being parsed by `env`, and
                // `check_pkexec_leaves` has already refused an argv[0] that
                // `env` would read as a `NAME=VALUE` assignment.
                // (`pkexec --keep-cwd` exists only in polkit ≥ 121.) The
                // probed, trusted `env`, by absolute path: pkexec would look
                // a bare name up on the PATH below.
                c.arg(trusted_env()?);
                c.arg("-C");
                c.arg(&leaf.cwd);
                c.arg("--");
                c.arg(program);
                c.args(&leaf.argv[1..]);
                c.env_clear();
                for (k, v) in &leaf.env {
                    c.env(k, v);
                }
                // pkexec needs these to show its dialog.
                for key in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"] {
                    if let Ok(v) = std::env::var(key) {
                        c.env(key, v);
                    }
                }
                c.current_dir(&leaf.cwd);
                c
            }
            _ => {
                // sudo: `sudo [-u user] K=V … -- argv`. The `--` stops option
                // parsing so an argv[0] beginning with `-` is treated as the
                // command, not a sudo flag.
                // Never the daemon's PATH (GHSA-gx9w-4f7x-2gcp).
                let mut c = Command::new(crate::helper::sudo()?);
                // The sudo process itself gets a cleared environment plus the
                // few names a root command needs to render text. sudo's
                // `env_reset` drops most of the daemon's environment, but
                // `env_keep` passes some names (`DISPLAY`, …) on to the root
                // command; nothing from the daemon's environment beyond these
                // may reach it (#101).
                c.env_clear();
                c.envs(std::env::vars_os().filter(|(k, _)| sudo_env_keep(k)));
                if let LeafRunAs::User(name) = escalated {
                    c.arg("-u");
                    c.arg(name);
                }
                for (k, v) in &leaf.env {
                    c.arg(format!("{k}={v}"));
                }
                c.arg("--");
                c.arg(program);
                c.args(&leaf.argv[1..]);
                c.current_dir(&leaf.cwd);
                c
            }
        },
    })
}

/// The file a leaf will execute: its prompt-displayed resolution.
fn leaf_program(leaf: &LeafPlan) -> Option<&Path> {
    leaf.resolved_bin.as_ref().map(|r| r.path.as_path())
}

/// The argv a direct leaf is spawned with: as written, except that each
/// program a wrapper runs (`env X=1 just`, `nice make`, `timeout 5 tofu`) is
/// replaced by its pinned absolute path, whose basename is the same word, so
/// the wrapper does not look it up again on PATH (issue #105). Left alone:
/// applets, which their dispatcher picks by name; and a `find -execdir` /
/// `-okdir` program containing `/`, which `find` runs from each match's
/// directory rather than from the leaf's (a bare name is still pinned: `find`
/// looks it up on PATH).
///
/// In a transparent leaf, a wrapped program that was not found is refused
/// here, as an unresolved `argv[0]` is, instead of letting the wrapper search
/// for it later. So is a path containing `=` behind `env`, which would read
/// it as an assignment. An opaque leaf keeps such a word as written: the
/// prompt already says it cannot show what that leaf runs.
fn spawn_argv(leaf: &LeafPlan) -> Result<Vec<String>, String> {
    let mut argv = leaf.argv.clone();
    for prog in leaf
        .programs
        .iter()
        .filter(|p| p.argv_index != 0 && !p.applet && !p.runtime_lookup)
    {
        if runs_from_match_dir(leaf, prog) {
            continue;
        }
        let via = prog.via.as_deref().unwrap_or("");
        match &prog.resolved {
            Some(r) => {
                let path = r.path.to_string_lossy();
                if path.contains('=') && via_kind_is(leaf, prog, crate::wrappers::Kind::Env) {
                    if leaf.opaque.is_some() {
                        continue;
                    }
                    return Err(format!(
                        "stage {}: {} run by {via} resolves to a path containing '=': {path}",
                        leaf.stage_id, prog.name
                    ));
                }
                argv[prog.argv_index] = path.into_owned();
            }
            None if leaf.opaque.is_some() => {}
            None => {
                return Err(format!(
                    "stage {}: command not found: {} (run by {})",
                    leaf.stage_id,
                    crate::tui::shquote(&prog.name),
                    crate::tui::shquote(via)
                ))
            }
        }
    }
    Ok(argv)
}

/// The wrapper that runs `prog` is of `kind`, by its name as written or by
/// the canonical name of its pinned binary (`innocuous -> env`).
fn via_kind_is(leaf: &LeafPlan, prog: &ProgramHop, kind: crate::wrappers::Kind) -> bool {
    let Some(at) = prog.via_index else {
        return false;
    };
    let is = |name: &str| matches!(crate::wrappers::classify(name), crate::wrappers::Class::Wrapper(w) if w.kind == kind);
    let canonical = leaf
        .programs
        .iter()
        .find(|p| p.argv_index == at)
        .and_then(|p| p.resolved.as_ref())
        .and_then(|r| r.canonical())
        .and_then(|c| c.to_str());
    is(&leaf.argv[at]) || canonical.is_some_and(is)
}

/// A `find -execdir` / `-okdir` program named with a `/`: `find` runs it
/// relative to each matched file's directory, which is not known here.
fn runs_from_match_dir(leaf: &LeafPlan, prog: &ProgramHop) -> bool {
    prog.name.contains('/')
        && via_kind_is(leaf, prog, crate::wrappers::Kind::FindExec)
        && matches!(
            leaf.argv
                .get(prog.argv_index.wrapping_sub(1))
                .map(String::as_str),
            Some("-execdir" | "-okdir")
        )
}

/// Refuse to spawn a leaf when a program it runs is no longer the file that
/// was resolved, checked and shown (issue #105): its path now names another
/// inode (a file renamed over it, a symlink retargeted, a file removed).
///
/// That includes a binary replaced by an earlier step of the same request
/// (`cargo build && ./target/debug/app`, `apt-get upgrade && systemctl …`):
/// the human approved the old file, so the new one is not run. Such a step
/// goes in a request of its own.
fn check_pins(leaf: &LeafPlan) -> Result<(), String> {
    let hops = leaf
        .programs
        .iter()
        .filter(|p| p.argv_index != 0)
        .filter_map(|p| p.resolved.as_ref().map(|r| (p.name.as_str(), r)));
    let argv0 = leaf
        .resolved_bin
        .as_ref()
        .map(|r| (leaf.argv[0].as_str(), r));
    for (name, r) in argv0.into_iter().chain(hops) {
        if !r.still_pinned() {
            return Err(format!(
                "stage {}: {name} changed since it was approved ({}); not run. \
                 If an earlier step of this request rebuilt or upgraded it, \
                 run it in a separate request",
                leaf.stage_id,
                r.path.display()
            ));
        }
    }
    Ok(())
}

fn open_out(path: &str, append: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create(true);
    if append {
        o.append(true);
    } else {
        o.truncate(true);
    }
    o.open(path)
}

/// Configure a command's stdout. Returns the opened file handle when the target
/// is a file, so a sibling `2>&1` stderr can be dup'd onto the same handle.
fn set_stdout(cmd: &mut Command, spec: &OutSpec) -> std::io::Result<Option<File>> {
    match spec {
        OutSpec::Capture => {
            cmd.stdout(Stdio::piped());
            Ok(None)
        }
        OutSpec::DevNull => {
            cmd.stdout(Stdio::null());
            Ok(None)
        }
        OutSpec::File { path, append } => {
            let f = open_out(path, *append)?;
            cmd.stdout(f.try_clone()?);
            Ok(Some(f))
        }
    }
}

fn set_stdin(cmd: &mut Command, spec: &InSpec) -> std::io::Result<()> {
    match spec {
        InSpec::Null => {
            cmd.stdin(Stdio::null());
        }
        InSpec::File(path) => {
            cmd.stdin(File::open(path)?);
        }
    }
    Ok(())
}

fn set_stderr(
    cmd: &mut Command,
    spec: &ErrSpec,
    stdout_file: Option<&File>,
) -> std::io::Result<()> {
    match spec {
        ErrSpec::Capture => {
            cmd.stderr(Stdio::piped());
        }
        ErrSpec::DevNull => {
            cmd.stderr(Stdio::null());
        }
        ErrSpec::File { path, append } => {
            cmd.stderr(open_out(path, *append)?);
        }
        ErrSpec::ToStdout => match stdout_file {
            // `2>&1` only ever pairs with a `Both` redirect, whose target is a
            // file or /dev/null — so stdout is a real fd we can dup, never a
            // capture pipe.
            Some(f) => {
                cmd.stderr(f.try_clone()?);
            }
            None => {
                cmd.stderr(Stdio::null());
            }
        },
    }
    Ok(())
}

/// Run a pipe group: spawn every stage connected by pipes, then collect all
/// their results against the shared deadline.
///
/// Pipe stages use `setsid` (not the `setpgid` + foreground-guard a lone
/// escalated leaf gets in `run_one`). The reason is job control, not a property
/// of `setsid` itself: a controlling terminal has exactly **one** foreground
/// process group, and pipe stages run **concurrently** — so they cannot each be
/// handed the tty to prompt on. Rather than arbitrate the tty across live
/// pipeline members, the daemon detaches them all (`setsid`, no controlling tty).
/// A standalone leaf has no such concurrency, so it keeps `setpgid` (stays in the
/// daemon's session) and is handed the tty foreground, and *can* prompt.
///
/// This is the point where the daemon is, in effect, a shell's *executor*:
/// fork/exec, pipe wiring, process groups, and tty job control (the
/// `ForegroundGuard` `tcsetpgrp` handoff, `setsid` for pipeline members) are
/// exactly what an interactive shell does. What it deliberately omits is the
/// shell's *parser* (word-splitting, globbing, `$(…)`, profile) — so "no shell on
/// the privileged path" means no shell *language* on the path, not no process
/// orchestration, which is now the daemon's own.
///
/// Consequence: a privileged stage *inside a pipe* cannot prompt, and because it
/// has no controlling tty, a credential cached on the daemon's tty may not be
/// visible to it (depends on the host's sudoers `timestamp_type`: `global` yes,
/// the common `tty` default likely not). Such a stage needs NOPASSWD or an
/// already-`global`-cached credential, or it fails fast with "no tty present".
/// Prefer a single privileged stage, which runs with `setpgid` + the foreground
/// guard and *can* prompt. See the "Partial-`run` retry hazard and the
/// sudo-credential-in-pipe caveat" item in backlog.md.
fn run_pipe(
    indices: &[usize],
    leaves: &[LeafPlan],
    mode: EscalationMode,
    deadline: Instant,
    outcomes: &mut [Outcome],
) -> StepStatus {
    let n = indices.len();
    // Every refusal a stage can meet before its spawn (pins, an unresolved
    // program, the wrapped-program checks, a missing escalator), for every
    // stage before any starts: a stage refused later would leave the earlier
    // ones killed part-way. The pins are checked again just before each
    // spawn.
    let preflight =
        |leaf: &LeafPlan| check_pins(leaf).and_then(|()| build_command(leaf, mode).map(drop));
    if let Some(e) = indices.iter().find_map(|&li| preflight(&leaves[li]).err()) {
        return spawn_error_status(e);
    }
    let mut children: Vec<Child> = Vec::with_capacity(n);
    let mut prev_stdout: Option<Stdio> = None;

    for (pos, &li) in indices.iter().enumerate() {
        let leaf = &leaves[li];
        let is_first = pos == 0;
        let is_last = pos == n - 1;

        let mut cmd = match build_command(leaf, mode) {
            Ok(c) => c,
            Err(e) => {
                let _guard = KillOnDrop::new(children);
                return spawn_error_status(e);
            }
        };

        // stdin: first stage honours its own spec; later stages read the
        // previous stage's stdout.
        if let Some(prev) = prev_stdout.take() {
            cmd.stdin(prev);
        } else if is_first {
            if let Err(e) = set_stdin(&mut cmd, &leaf.stdin) {
                let _guard = KillOnDrop::new(children);
                return spawn_error_status(format!("failed to open stdin redirect: {e}"));
            }
        }

        // stdout: non-final stages feed the next stage; the final stage honours
        // its own spec.
        let stdout_file = if is_last {
            match set_stdout(&mut cmd, &leaf.stdout) {
                Ok(f) => f,
                Err(e) => {
                    let _guard = KillOnDrop::new(children);
                    return spawn_error_status(format!("failed to open stdout redirect: {e}"));
                }
            }
        } else {
            cmd.stdout(Stdio::piped());
            None
        };
        if let Err(e) = set_stderr(&mut cmd, &leaf.stderr, stdout_file.as_ref()) {
            let _guard = KillOnDrop::new(children);
            return spawn_error_status(format!("failed to open stderr redirect: {e}"));
        }

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::umask(0o077);
                restore_fd_limit();
                Ok(())
            });
        }

        if let Err(e) = check_pins(leaf) {
            let _guard = KillOnDrop::new(children);
            return spawn_error_status(e);
        }
        match cmd.spawn() {
            Ok(mut child) => {
                if !is_last {
                    if let Some(stdout) = child.stdout.take() {
                        prev_stdout = Some(Stdio::from(stdout));
                    }
                }
                children.push(child);
            }
            Err(e) => {
                let _guard = KillOnDrop::new(children);
                return spawn_error_status(format!("failed to spawn pipeline stage {pos}: {e}"));
            }
        }
    }

    collect_group(indices, leaves, children, deadline, outcomes)
}

fn spawn_error_status(msg: String) -> StepStatus {
    StepStatus {
        timed_out: false,
        spawn_error: Some(msg),
        success: false,
    }
}

/// Collect results from a spawned pipe group, writing each stage's outcome into
/// `outcomes[stage_id]`. The group's controlling exit is the final stage's.
fn collect_group(
    indices: &[usize],
    leaves: &[LeafPlan],
    children: Vec<Child>,
    deadline: Instant,
    outcomes: &mut [Outcome],
) -> StepStatus {
    let n = children.len();
    let mut guard = KillOnDrop::new(children);

    // One stderr drainer per child (only where stderr was piped), plus the
    // final stage's stdout drainer (only where it was captured).
    let mut stderr_handles = Vec::with_capacity(n);
    for child in guard.children.iter_mut() {
        let pipe = child.stderr.take();
        stderr_handles.push(pipe.map(|s| spawn_drain(s, MAX_OUTPUT_BYTES)));
    }
    let stdout_handle = guard
        .children
        .last_mut()
        .and_then(|c| c.stdout.take())
        .map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));

    let mut exits: Vec<Option<ExitStatus>> = vec![None; n];
    loop {
        let mut all_done = true;
        for (i, child) in guard.children.iter_mut().enumerate() {
            if exits[i].is_some() {
                continue;
            }
            match child.try_wait() {
                Ok(Some(s)) => exits[i] = Some(s),
                Ok(None) => all_done = false,
                Err(_) => exits[i] = Some(synthetic_failure_status()),
            }
        }
        if all_done || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }

    let mut timed_out = false;
    for (i, child) in guard.children.iter_mut().enumerate() {
        if exits[i].is_none() {
            timed_out = true;
            kill_group(child);
            exits[i] = Some(synthetic_failure_status());
        }
    }

    let (stdout_bytes, stdout_truncated) = drain_join(stdout_handle);
    let last_pos = n - 1;
    for (i, h) in stderr_handles.into_iter().enumerate() {
        let (bytes, truncated) = drain_join(h);
        let li = indices[i];
        let exit = exits[i].as_ref().and_then(|s| s.code()).unwrap_or(-1);
        let captured = leaves[li].stdout == OutSpec::Capture;
        outcomes[li] = Outcome {
            ran: true,
            exit,
            stdout: if i == last_pos {
                stdout_bytes.clone()
            } else {
                Vec::new()
            },
            stdout_truncated: i == last_pos && stdout_truncated,
            stderr: bytes,
            stderr_truncated: truncated,
            captured_stdout: captured && i == last_pos,
        };
    }

    let _ = guard.into_inner();

    let controlling_exit = outcomes[indices[last_pos]].exit;
    let last_accepted = &leaves[indices[last_pos]].accepted;
    StepStatus {
        timed_out,
        spawn_error: None,
        success: !timed_out && exit_accepted(controlling_exit, last_accepted),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// RAII handoff of the controlling tty's foreground process group.
///
/// On `take`, opens /dev/tty, saves the current foreground pgid, and
/// installs `child_pgid` as the new foreground (with SIGTTOU blocked
/// across the syscall — without that the daemon would self-suspend if
/// it itself were in a background pgrp). On drop, the previous
/// foreground is restored and the saved signal mask reinstated.
///
/// Holds `tty_lock` (a per-server `Mutex<()>` owned by `server::run`) for
/// its lifetime. The same lock is taken by the prompt path in `server`,
/// so prompts and exec foreground-swaps are mutually exclusive — without
/// that, an in-flight swap would leave the daemon in a background pgrp
/// on /dev/tty and any concurrent prompt would EIO (PR #22 turned the
/// prior SIGTTIN-stop into EIO).
///
/// Best-effort: returns `None` if the daemon has no controlling tty,
/// or if `tcgetpgrp`/`tcsetpgrp` fails. In those cases the caller
/// proceeds without the swap; kill-group reaping (via the `setpgid` in
/// `pre_exec`) is independent and unaffected.
struct ForegroundGuard<'a> {
    _lock: MutexGuard<'a, ()>,
    tty_fd: libc::c_int,
    prev_pgrp: libc::pid_t,
    saved_mask: libc::sigset_t,
}

impl<'a> ForegroundGuard<'a> {
    fn take(child_pgid: libc::pid_t, tty_lock: &'a Mutex<()>) -> Option<Self> {
        let lock = tty_lock.lock().unwrap_or_else(|e| e.into_inner());

        unsafe {
            let tty_fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            if tty_fd < 0 {
                return None;
            }

            let mut to_block: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut to_block);
            libc::sigaddset(&mut to_block, libc::SIGTTOU);
            let mut saved_mask: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &to_block, &mut saved_mask);

            let prev_pgrp = libc::tcgetpgrp(tty_fd);
            if prev_pgrp < 0 {
                libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
                libc::close(tty_fd);
                return None;
            }

            if libc::tcsetpgrp(tty_fd, child_pgid) != 0 {
                libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut());
                libc::close(tty_fd);
                return None;
            }

            Some(Self {
                _lock: lock,
                tty_fd,
                prev_pgrp,
                saved_mask,
            })
        }
    }
}

impl Drop for ForegroundGuard<'_> {
    fn drop(&mut self) {
        // Best-effort restore. Failures are silently ignored: the
        // daemon may have already lost the controlling tty (e.g. ssh
        // tunnel collapsed) or the prior pgid may have died.
        unsafe {
            libc::tcsetpgrp(self.tty_fd, self.prev_pgrp);
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved_mask, std::ptr::null_mut());
            libc::close(self.tty_fd);
        }
    }
}

#[derive(Debug)]
pub(crate) enum WaitError {
    Timeout,
    Io(std::io::Error),
}

pub(crate) fn wait_with_deadline(
    child: &mut Child,
    deadline: Instant,
) -> Result<ExitStatus, WaitError> {
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => {}
            Err(e) => return Err(WaitError::Io(e)),
        }
        if Instant::now() >= deadline {
            return Err(WaitError::Timeout);
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
}

/// Drain `reader` into a Vec, capping at `max` bytes. Reading stops as
/// soon as the cap is exceeded; the caller must arrange for the producer
/// to be killed so it doesn't wedge on a full pipe.
fn spawn_drain<R: Read + Send + 'static>(
    mut reader: R,
    max: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if buf.len() + n > max {
                let take = max.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..take]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if truncated {
            // Drain any remaining bytes from the pipe to unblock the
            // child, but don't keep them. Bounded by best-effort: if
            // the child writes forever, the eventual kill will close it.
            let mut sink = [0u8; 65536];
            while let Ok(n) = reader.read(&mut sink) {
                if n == 0 {
                    break;
                }
            }
        }
        (buf, truncated)
    })
}

/// Send SIGKILL to the child's entire process group (it's a group leader
/// because of `setsid` in `pre_exec`), then reap. Falls back to a single
/// `kill()` + `wait()` if the killpg syscall fails for any reason.
fn kill_group(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    unsafe {
        if libc::killpg(pid, libc::SIGKILL) != 0 {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

fn synthetic_failure_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    // 137 is the conventional "killed by SIGKILL" exit (128 + 9).
    ExitStatus::from_raw(137 << 8)
}

/// Kill every child that hasn't been claimed by the success path. Used to
/// avoid orphaning processes when a panic unwinds out of the pipeline
/// collection logic — `Vec<Child>::drop` does NOT kill its members.
struct KillOnDrop {
    children: Vec<Child>,
}

impl KillOnDrop {
    fn new(children: Vec<Child>) -> Self {
        Self { children }
    }
    fn into_inner(mut self) -> Vec<Child> {
        std::mem::take(&mut self.children)
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        for child in &mut self.children {
            kill_group(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn leaf(argv: &[&str], runas: LeafRunAs) -> LeafPlan {
        LeafPlan {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: HashMap::new(),
            cwd: "/".into(),
            runas,
            stdin: InSpec::Null,
            stdout: OutSpec::Capture,
            stderr: ErrSpec::Capture,
            opaque: None,
            programs: vec![],
            resolved_bin: Some(Resolved::fake(&format!("/usr/bin/{}", argv[0]))),
            accepted: vec![],
            forward_agent: false,
            inherit: None,
            stage_id: 0,
        }
    }

    /// The `env -C` probe runs with a cleared environment and the helper
    /// search list as PATH, whatever the daemon's own environment holds (#101).
    /// A stand-in `env` records the environment and the arguments it was
    /// given; `true` is passed as the absolute path, never looked up.
    #[test]
    fn env_chdir_probe_clears_the_environment() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("env.out");
        let args = d.path().join("env.args");
        let fake = d.path().join("env");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nexport -p >'{}'\nprintf '%s\\n' \"$@\" >'{}'\n",
                out.display(),
                args.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let truth = Path::new("/trusted/true");
        assert!(env_chdir_probe(&fake, truth).status().unwrap().success());
        assert_eq!(
            std::fs::read_to_string(&args).unwrap(),
            "-C\n/\n--\n/trusted/true\n"
        );
        let seen = std::fs::read_to_string(&out).unwrap();
        let names: Vec<&str> = seen
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        // The shell itself may export PWD (and OLDPWD/SHLVL); nothing else.
        for n in &names {
            assert!(
                matches!(*n, "PATH" | "PWD" | "OLDPWD" | "SHLVL"),
                "unexpected name in the probe's environment: {n}\n{seen}"
            );
        }
        assert!(
            seen.contains(&format!("PATH='{}'", crate::helper::HELPER_PATH))
                || seen.contains(&format!("PATH=\"{}\"", crate::helper::HELPER_PATH)),
            "PATH must be the helper search list: {seen}"
        );
    }

    /// A PATH candidate the daemon's user cannot execute is skipped, as
    /// `execvp` skips it, and the next one is pinned (#101).
    #[test]
    fn path_lookup_skips_files_not_executable_by_me() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root may execute any file with an x bit
        }
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        for (dir, mode) in [(&a, 0o010), (&b, 0o755)] {
            let f = dir.join("tool");
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let path = format!("{}:{}", a.display(), b.display());
        let r = resolve_on("tool", "/", &path).expect("resolves");
        assert_eq!(
            r.path,
            b.join("tool"),
            "group-only x bit is not executable by its owner"
        );
    }

    /// A program the daemon's user owns is `user-writable` even when its mode
    /// and its directory's deny writing: the owner can `chmod` both (#101).
    #[test]
    fn owned_read_only_program_is_user_writable() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ro");
        std::fs::create_dir(&dir).unwrap();
        let tool = dir.join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = resolve_on("tool", "/", &dir.display().to_string());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.expect("resolves").user_writable);
        let sys = resolve_on("env", "/", "/usr/bin:/bin").expect("env");
        assert!(!sys.user_writable, "{:?}", sys.path);
    }

    #[test]
    fn sudo_env_keeps_only_terminal_and_locale_names() {
        use std::ffi::OsStr;
        for k in ["TERM", "LANG", "LC_ALL", "LC_CTYPE"] {
            assert!(sudo_env_keep(OsStr::new(k)), "{k}");
        }
        for k in [
            "DISPLAY",
            "PATH",
            "HOME",
            "XAUTHORITY",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
            "TERMINFO",
            "LANGUAGE",
            "XLC_X",
        ] {
            assert!(!sudo_env_keep(OsStr::new(k)), "{k}");
        }
    }

    /// Under pkexec an escalated leaf runs as `pkexec ENV -C DIR -- BIN args`,
    /// so it keeps the approved cwd; `ENV` is the trusted `env` by absolute
    /// path, never a name pkexec would look up; `env` must support `-C`, and
    /// a program path that `env` would take as `NAME=VALUE` is refused.
    #[test]
    fn pkexec_leaves_keep_cwd_through_env() {
        let mut l = leaf(&["id"], LeafRunAs::Root);
        l.cwd = "/srv".into();
        // The program is the trusted absolute pkexec (GHSA-gx9w-4f7x-2gcp);
        // a host without one refuses, and the argv shape is checked where it
        // can be built.
        if let (Ok(pkexec), Ok(env)) = (crate::helper::pkexec(), trusted_env()) {
            let c = build_command(&l, EscalationMode::Pkexec).unwrap();
            let args: Vec<_> = c
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert_eq!(Path::new(c.get_program()), pkexec);
            assert!(env.is_absolute(), "{env:?}");
            assert_eq!(
                args,
                [&*env.to_string_lossy(), "-C", "/srv", "--", "/usr/bin/id"]
            );
        } else {
            assert!(build_command(&l, EscalationMode::Pkexec).is_err());
        }

        let ok = [
            leaf(&["id"], LeafRunAs::Root),
            leaf(&["A=B"], LeafRunAs::Direct),
        ];
        assert!(check_pkexec_leaves(&ok, true).is_ok());
        assert!(check_pkexec_leaves(&ok, false).unwrap_err().contains("-C"));
        let bad = [leaf(&["LD_PRELOAD=/x", "id"], LeafRunAs::Root)];
        assert!(check_pkexec_leaves(&bad, true).unwrap_err().contains("'='"));
        // The check covers the path actually handed to `env`: a relative name
        // resolved under a `chdir` containing '=' is refused too.
        let mut l = leaf(&["./tool"], LeafRunAs::Root);
        l.resolved_bin = Some(Resolved::fake("/opt/a=b/tool"));
        assert!(check_pkexec_leaves(&[l], true).unwrap_err().contains("'='"));
    }

    #[test]
    fn sanitize_env_rejects_ld_preload() {
        // Issue #16: LD_PRELOAD must not be silently stripped. It now
        // takes the same hard-reject path as any other non-allowlisted
        // var.
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let err = sanitize_env(&env).expect_err("LD_PRELOAD must be rejected");
        assert!(
            err.contains("LD_PRELOAD"),
            "expected error to mention LD_PRELOAD, got: {err:?}"
        );
    }

    #[test]
    fn sanitize_env_rejects_path_override() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/tmp/evil".to_string());
        let err = sanitize_env(&env).expect_err("PATH must be rejected");
        assert!(err.contains("PATH"), "got: {err:?}");
    }

    #[test]
    fn sanitize_env_allows_lang() {
        let mut env = HashMap::new();
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        let out = sanitize_env(&env).expect("LANG is on the allowlist");
        assert_eq!(out.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    }

    #[test]
    fn kill_on_drop_terminates_running_child() {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        // Sanity: the child is alive.
        std::thread::sleep(Duration::from_millis(20));
        assert!(pid_alive(pid));

        {
            let _guard = KillOnDrop::new(vec![child]);
        } // drop: kill+wait

        // SIGKILL is delivered synchronously inside Drop and we waited,
        // so the child must already be reaped.
        assert!(!pid_alive(pid), "child {pid} survived KillOnDrop");
    }

    #[test]
    fn into_inner_defuses_the_guard() {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        let guard = KillOnDrop::new(vec![child]);
        let mut released = guard.into_inner();
        assert!(pid_alive(pid), "into_inner must not kill");

        // Test cleanup: actually kill the released child so we don't
        // leak an orphan from the test process.
        for c in &mut released {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    // The shell_escape round-trip property that lived here is retired with the
    // code it guarded: this increment removes all shell-string assembly from
    // the execution path (`pipeline_to_shell` / `pkexec sh -c` are gone). The
    // only surviving shell is an explicit `System` leaf, whose script is passed
    // verbatim as a single `-c` argument — nothing is quoted or re-assembled,
    // so there is no escaping grammar left to verify. The structural
    // invariant that the daemon adds no shell (G3.1) is checked by the two
    // tests below.

    // === Structured-plan properties (Rung 2) ============================
    use crate::prop::Rng;
    use crate::protocol::{Plan, Request, RunAs, ShellProc, ValidatedRequest};

    fn mk_plan_req(plan: Plan, privileged: bool) -> ValidatedRequest {
        let req = Request::new_plan(
            String::new(),
            "test".into(),
            plan,
            HashMap::new(),
            String::new(),
            privileged,
            false,
        );
        ValidatedRequest::validate(req).expect("valid plan request")
    }

    /// Count `Run`/`System` leaves in a plan tree (the pre-order leaf set the
    /// executor and the prompt both enumerate).
    fn count_leaves(p: &Plan) -> usize {
        match p {
            Plan::Exec { .. } | Plan::Shell { .. } => 1,
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter().map(count_leaves).sum()
            }
            Plan::Pipe { stages } => stages.iter().map(count_leaves).sum(),
            Plan::Redirect { body, .. }
            | Plan::WithStdinFrom { body, .. }
            | Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::RunAs { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => count_leaves(body),
        }
    }

    fn word(rng: &mut Rng) -> String {
        // Benign, allowlist-safe characters only; never empty.
        let alpha = b"abcdef0123456789";
        let s = rng.string(alpha, 5);
        if s.is_empty() {
            "x".into()
        } else {
            s
        }
    }

    /// A plan that always compiles to exactly one leaf: bare leaves plus the
    /// single-process modifiers. Used for pipe stages and redirect bodies.
    fn random_single(rng: &mut Rng, depth: usize) -> Plan {
        if depth == 0 || rng.below(2) == 0 {
            if rng.below(6) == 0 {
                return Plan::Shell {
                    shell: if rng.below(2) == 0 {
                        ShellProc::Sh
                    } else {
                        ShellProc::Bash
                    },
                    script: word(rng),
                };
            }
            let n = 1 + rng.below(3);
            return Plan::Exec {
                argv: (0..n).map(|_| word(rng)).collect(),
            };
        }
        match rng.below(4) {
            0 => Plan::Setenv {
                key: "LANG".into(),
                value: word(rng),
                body: Box::new(random_single(rng, depth - 1)),
            },
            1 => Plan::Chdir {
                dir: "/".into(),
                body: Box::new(random_single(rng, depth - 1)),
            },
            2 => Plan::RunAs {
                who: if rng.below(2) == 0 {
                    RunAs::Root
                } else {
                    RunAs::User { name: word(rng) }
                },
                body: Box::new(random_single(rng, depth - 1)),
            },
            _ => Plan::WithAcceptedExitCodes {
                codes: vec![rng.below(5) as i32],
                body: Box::new(random_single(rng, depth - 1)),
            },
        }
    }

    /// A random, always-compilable plan tree. Composite modifiers wrap
    /// composites; stdio modifiers and pipe stages wrap single processes.
    fn random_plan(rng: &mut Rng, depth: usize) -> Plan {
        if depth == 0 || rng.below(3) == 0 {
            return random_single(rng, depth);
        }
        match rng.below(8) {
            0 => Plan::Run {
                steps: (0..1 + rng.below(3))
                    .map(|_| random_plan(rng, depth - 1))
                    .collect(),
            },
            6 => Plan::Alt {
                steps: (0..1 + rng.below(3))
                    .map(|_| random_plan(rng, depth - 1))
                    .collect(),
            },
            7 => Plan::Seq {
                steps: (0..1 + rng.below(3))
                    .map(|_| random_plan(rng, depth - 1))
                    .collect(),
            },
            1 => Plan::Pipe {
                stages: (0..2 + rng.below(2))
                    .map(|_| random_single(rng, depth - 1))
                    .collect(),
            },
            2 => Plan::Setenv {
                key: "TZ".into(),
                value: word(rng),
                body: Box::new(random_plan(rng, depth - 1)),
            },
            3 => Plan::RunAs {
                who: RunAs::Root,
                body: Box::new(random_plan(rng, depth - 1)),
            },
            4 => Plan::Redirect {
                stream: Stream::Stdout,
                target: RedirTarget::DevNull,
                body: Box::new(random_single(rng, depth - 1)),
            },
            _ => Plan::WithStdinFrom {
                path: "/dev/null".into(),
                body: Box::new(random_single(rng, depth - 1)),
            },
        }
    }

    // Spec clause (Rung 2): `plan_display` is total and panic-free over random
    // plan trees, and its leaf set is **structurally identical** to the tree's
    // pre-order `Run`/`System` leaves — same count, contiguous stage ids
    // `0..n`, same `argv[0]` in order. This is the regression that would have
    // caught the `bash -lc` hollowing: the rendered stages are exactly the
    // stages the executor runs.
    #[test]
    fn prop_plan_display_is_structurally_identical_to_the_tree() {
        let mut rng = Rng::new(0xD1CE_5EED_u64);
        for _ in 0..4000 {
            let plan = random_plan(&mut rng, 5);
            let privileged = rng.below(2) == 0;
            let req = mk_plan_req(plan.clone(), privileged);

            let views = plan_display(&req).expect("random plan must compile");
            // Same number of stages as Run/System leaves.
            assert_eq!(views.len(), count_leaves(&plan), "leaf count mismatch");
            // Stage ids are exactly 0..n, in order.
            for (i, v) in views.iter().enumerate() {
                assert_eq!(v.stage_id, i, "stage ids must be contiguous 0..n");
                assert!(!v.argv.is_empty(), "every stage has a command");
            }
        }
    }

    // Spec clause (Rung 2): compiling a random plan for execution is total and
    // panic-free, and produces exactly `count_leaves` planned processes.
    #[test]
    fn prop_compile_plan_is_total() {
        let mut rng = Rng::new(0x5EED_D1CE_u64);
        for _ in 0..4000 {
            let plan = random_plan(&mut rng, 5);
            let privileged = rng.below(2) == 0;
            let req = mk_plan_req(plan.clone(), privileged);
            let compiled = compile_plan(&req, &HashMap::new(), None).expect("compiles");
            assert_eq!(compiled.leaves.len(), count_leaves(&plan));
        }
    }

    // Spec clause (Rung 2, G3.1): over random leaves (run-as root or a named
    // user, argv words full of shell metacharacters and option look-alikes
    // such as `-c` and `--`, random env), the built command is exactly
    // `sudo [-u user] K=V… -- <resolved program> argv[1..]`, or
    // `pkexec [--user user] <env> -C <cwd> -- <resolved program> argv[1..]`,
    // and a direct leaf passes argv[1..] unchanged: no word is added, split,
    // joined or reordered, so no `sh -c` can appear that the request did not
    // put there. Escalation helpers missing on this host are skipped, as in
    // the example test below.
    #[test]
    fn prop_built_command_is_the_argv_word_for_word() {
        const WORD: &[u8] = b"aZ09-_=./ '\"$`;&|<>(){}*?!#~";
        let mut rng = Rng::new(0xB111_D0C5_u64);
        for _ in 0..200 {
            let mut argv = vec!["sysctl".to_string()];
            for _ in 0..rng.below(6) {
                argv.push(match rng.below(4) {
                    0 => ["-c", "--", "-u", "sh -c id", ""][rng.below(5)].to_string(),
                    _ => rng.string(WORD, 10),
                });
            }
            let mut env = HashMap::new();
            for _ in 0..rng.below(3) {
                env.insert(format!("K{}", rng.below(100)), rng.string(WORD, 8));
            }
            let runas = match rng.below(3) {
                0 => LeafRunAs::Root,
                1 => LeafRunAs::User(format!("u{}", rng.below(10))),
                _ => LeafRunAs::Direct,
            };
            let leaf = LeafPlan {
                argv: argv.clone(),
                env: env.clone(),
                cwd: "/".into(),
                runas: runas.clone(),
                stdin: InSpec::Null,
                stdout: OutSpec::Capture,
                stderr: ErrSpec::Capture,
                opaque: None,
                programs: vec![],
                resolved_bin: Some(Resolved::fake("/usr/sbin/sysctl")),
                accepted: Vec::new(),
                forward_agent: false,
                inherit: None,
                stage_id: 0,
            };
            let args_of = |c: &Command| -> Vec<String> {
                c.get_args()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect()
            };
            let tail: Vec<String> = std::iter::once("/usr/sbin/sysctl".to_string())
                .chain(argv[1..].iter().cloned())
                .collect();
            match &runas {
                LeafRunAs::Direct => {
                    let c = build_command(&leaf, EscalationMode::Direct).unwrap();
                    assert_eq!(args_of(&c), argv[1..].to_vec(), "direct {argv:?}");
                }
                escalated => {
                    if crate::helper::sudo().is_ok() {
                        let c = build_command(&leaf, EscalationMode::Sudo).unwrap();
                        let mut want = Vec::new();
                        if let LeafRunAs::User(n) = escalated {
                            want.extend(["-u".to_string(), n.clone()]);
                        }
                        want.extend(leaf.env.iter().map(|(k, v)| format!("{k}={v}")));
                        want.push("--".into());
                        want.extend(tail.iter().cloned());
                        assert_eq!(args_of(&c), want, "sudo {argv:?}");
                    }
                    if let (Ok(_), Ok(env_bin)) = (crate::helper::pkexec(), trusted_env()) {
                        let c = build_command(&leaf, EscalationMode::Pkexec).unwrap();
                        let mut want = Vec::new();
                        if let LeafRunAs::User(n) = escalated {
                            want.extend(["--user".to_string(), n.clone()]);
                        }
                        want.push(env_bin.to_string_lossy().into_owned());
                        want.extend(["-C".to_string(), "/".into(), "--".into()]);
                        want.extend(tail.iter().cloned());
                        assert_eq!(args_of(&c), want, "pkexec {argv:?}");
                    }
                }
            }
        }
    }

    // Spec clause (Rung 2): the daemon adds no shell (G3.1), checked
    // structurally on the built `Command`, one example per escalation mode
    // (the property above covers random leaves). An escalated leaf is spawned
    // as `sudo [-u user] K=V… -- <resolved program> argv[1..]` or
    // `pkexec [--user u] <env> -C <cwd> -- <resolved program> argv[1..]`, and
    // no `sh -c` / `bash -c` wrapper is introduced. A shell runs only where
    // the plan names one (a `shell` op, or a shell as the program).
    #[test]
    fn escalated_leaf_is_literal_argv_never_a_shell_wrapper() {
        let leaf = |runas: LeafRunAs| LeafPlan {
            argv: vec!["sysctl".into(), "-w".into(), "vm.mmap_rnd_bits=28".into()],
            env: HashMap::new(),
            cwd: "/".into(),
            runas,
            stdin: InSpec::Null,
            stdout: OutSpec::Capture,
            stderr: ErrSpec::Capture,
            opaque: None,
            programs: vec![],
            resolved_bin: Some(Resolved::fake("/usr/sbin/sysctl")),
            accepted: Vec::new(),
            forward_agent: false,
            inherit: None,
            stage_id: 0,
        };

        // Root under sudo: `sudo -- /usr/sbin/sysctl -w …`, no shell. The
        // program is the trusted, absolute `sudo` (GHSA-gx9w-4f7x-2gcp); a host
        // with none (a CI container) refuses instead.
        let Ok(sudo) = crate::helper::sudo() else {
            let err = build_command(&leaf(LeafRunAs::Root), EscalationMode::Sudo).unwrap_err();
            assert!(err.contains("sudo"), "{err}");
            return;
        };
        let c = build_command(&leaf(LeafRunAs::Root), EscalationMode::Sudo).unwrap();
        assert!(sudo.is_absolute());
        assert_eq!(Path::new(c.get_program()), sudo);
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.contains(&"--".to_string()),
            "sudo must use -- : {args:?}"
        );
        assert!(args.ends_with(&[
            "/usr/sbin/sysctl".into(),
            "-w".into(),
            "vm.mmap_rnd_bits=28".into()
        ]));
        assert!(
            !args.iter().any(|a| a == "-c"),
            "no shell -c on the privileged path: {args:?}"
        );

        // Named user under sudo: `sudo -u alice -- …`.
        let c =
            build_command(&leaf(LeafRunAs::User("alice".into())), EscalationMode::Sudo).unwrap();
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&args[0], "-u");
        assert_eq!(&args[1], "alice");

        // Pkexec root: `pkexec env -C / -- sysctl …` (no shell), from the
        // trusted absolute `pkexec` when there is one.
        match crate::helper::pkexec() {
            Ok(pkexec) => {
                let c = build_command(&leaf(LeafRunAs::Root), EscalationMode::Pkexec).unwrap();
                assert_eq!(Path::new(c.get_program()), pkexec);
            }
            Err(_) => {
                assert!(build_command(&leaf(LeafRunAs::Root), EscalationMode::Pkexec).is_err());
            }
        }

        // Direct leaf: the program is the resolved binary, argv[0] unchanged.
        let c = build_command(&leaf(LeafRunAs::Direct), EscalationMode::Direct).unwrap();
        assert_eq!(c.get_program().to_str().unwrap(), "/usr/sbin/sysctl");
    }

    // Issue #62: an unresolved leaf is refused at spawn, in every mode, rather
    // than handed to a second PATH lookup the prompt never showed.
    #[test]
    fn unresolved_leaf_is_refused_not_looked_up_again() {
        for (runas, mode) in [
            (LeafRunAs::Direct, EscalationMode::Direct),
            (LeafRunAs::Root, EscalationMode::Sudo),
            (LeafRunAs::Root, EscalationMode::Pkexec),
        ] {
            let mut l = leaf(&["only-here"], runas);
            l.resolved_bin = None;
            let err = build_command(&l, mode).unwrap_err();
            assert!(err.contains("command not found: only-here"), "{err}");
        }
    }

    // Issue #62: resolution ignores the daemon's PATH (the child never sees
    // it) and takes a relative name against the leaf's cwd, not the daemon's.
    #[test]
    fn resolve_command_uses_child_path_and_leaf_cwd() {
        let dir = std::env::temp_dir().join(format!("sp-resolve-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let tool = dir.join("bin/only-here-62");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

        // A bare name only on some other PATH is not found…
        assert_eq!(resolve_command("only-here-62", "/"), None);
        // …while a system binary resolves on the child's default PATH.
        let sh = resolve_command("sh", "/").expect("sh on default PATH");
        assert!(DEFAULT_LOGIN_PATH
            .split(':')
            .any(|d| sh.path.parent() == Some(Path::new(d))));
        // A relative name resolves against the leaf cwd.
        let cwd = dir.to_str().unwrap();
        assert_eq!(
            resolve_command("bin/only-here-62", cwd).map(|r| r.path),
            Some(dir.join("bin/only-here-62"))
        );
        assert_eq!(resolve_command("./bin/only-here-62", "/"), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Spec clause: an `Exec` whose program is a shell is opaque, exactly like
    // an explicit `Shell` node — by name or path, with or without `-c`, in a
    // plan or a legacy flat pipeline. Non-shell programs (even with "sh" as
    // an argument or a name prefix) are not.
    #[test]
    fn exec_of_a_shell_is_opaque() {
        let ex = |argv: &[&str]| Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        };
        let opaque = |plan: Plan| -> Vec<bool> {
            plan_display(&mk_plan_req(plan, false))
                .expect("compiles")
                .iter()
                .map(|v| v.opaque)
                .collect()
        };
        assert_eq!(opaque(ex(&["sh", "-c", "x"])), [true]);
        assert_eq!(opaque(ex(&["/bin/bash", "s.sh"])), [true]);
        assert_eq!(opaque(ex(&["zsh"])), [true]);
        assert_eq!(opaque(ex(&["echo", "sh"])), [false]);
        assert_eq!(opaque(ex(&["shellcheck", "x"])), [false]);
        assert_eq!(opaque(ex(&["true"])), [false]);
        assert_eq!(
            opaque(Plan::Pipe {
                stages: vec![ex(&["echo", "x"]), ex(&["dash", "-c", "cat"])]
            }),
            [false, true]
        );

        // Legacy flat pipeline desugars through the same compile path.
        let mut req = Request::new_plan(
            String::new(),
            "test".into(),
            ex(&["true"]),
            HashMap::new(),
            String::new(),
            false,
            false,
        );
        req.plan = None;
        req.pipeline = vec![
            vec!["echo".into(), "x".into()],
            vec!["bash".into(), "-lc".into(), "cat".into()],
        ];
        let req = ValidatedRequest::validate(req).expect("valid");
        let flags: Vec<bool> = plan_display(&req)
            .unwrap()
            .iter()
            .map(|v| v.opaque)
            .collect();
        assert_eq!(flags, [false, true]);

        // Issue #87: a shell or an inline-code interpreter behind a wrapper is
        // opaque too, in a plan and in a legacy flat pipeline.
        assert_eq!(opaque(ex(&["env", "sh", "-c", "x"])), [true]);
        assert_eq!(opaque(ex(&["nice", "bash"])), [true]);
        assert_eq!(opaque(ex(&["timeout", "5", "sh", "-c", "x"])), [true]);
        assert_eq!(opaque(ex(&["python3", "-c", "x"])), [true]);
        assert_eq!(opaque(ex(&["env", "FOO=1", "true"])), [false]);
        assert_eq!(opaque(ex(&["env", "LD_PRELOAD=/x", "true"])), [true]);
        let mut req = Request::new_plan(
            String::new(),
            "test".into(),
            ex(&["true"]),
            HashMap::new(),
            String::new(),
            false,
            false,
        );
        req.plan = None;
        req.pipeline = vec![
            vec!["echo".into(), "x".into()],
            vec!["env".into(), "bash".into(), "-lc".into(), "cat".into()],
        ];
        let req = ValidatedRequest::validate(req).expect("valid");
        let views = plan_display(&req).unwrap();
        let flags: Vec<bool> = views.iter().map(|v| v.opaque).collect();
        assert_eq!(flags, [false, true]);
        let why = views[1].opaque_reason.as_ref().unwrap();
        assert_eq!((why.at, why.is_shell), (1, true));
        assert_eq!(views[1].programs[why.at].via.as_deref(), Some("env"));
    }

    /// The prompt lists every program a wrapper runs: with its path for a
    /// leaf running as the daemon user, and as looked up at run time for an
    /// escalated leaf (the wrapper searches sudo's `secure_path`, not ours).
    #[test]
    fn plan_display_lists_wrapped_programs() {
        let ex = Plan::Exec {
            argv: vec!["env".into(), "X=1".into(), "true".into()],
        };
        let views = plan_display(&mk_plan_req(ex.clone(), false)).unwrap();
        let p = &views[0].programs;
        assert_eq!(
            p.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            ["env", "true"]
        );
        assert_eq!(p[0].via, None);
        assert_eq!(p[1].via.as_deref(), Some("env"));
        assert_eq!(p[0].resolved, views[0].resolved_bin);
        assert_eq!(p[1].resolved, resolve_command("true", "/"));
        assert!(p[1].resolved.is_some());
        assert!(!p[0].runtime_lookup && !p[1].runtime_lookup);
        assert!(!views[0].opaque);

        let rooted = Plan::RunAs {
            who: RunAs::Root,
            body: Box::new(ex),
        };
        let views = plan_display(&mk_plan_req(rooted, false)).unwrap();
        let p = &views[0].programs;
        assert!(!p[0].runtime_lookup && p[0].resolved.is_some());
        assert!(p[1].runtime_lookup);
        assert_eq!(p[1].resolved, None);
    }

    /// Review C5: a multi-call dispatcher runs its built-in applet, so the
    /// applet's PATH resolution is not shown.
    #[test]
    fn plan_display_shows_no_path_for_an_applet() {
        let ex = Plan::Exec {
            argv: vec!["busybox".into(), "true".into()],
        };
        let views = plan_display(&mk_plan_req(ex, false)).unwrap();
        let p = &views[0].programs;
        assert_eq!(
            p.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            ["busybox", "true"]
        );
        assert!(!p[0].applet && p[1].applet);
        assert!(!p[1].runtime_lookup);
        assert_eq!(p[1].resolved, None);
    }

    /// A symlink with an innocuous name pointing at a shell is still a shell:
    /// the canonical resolved binary is checked, not just the name.
    #[test]
    fn renamed_symlink_to_a_shell_is_opaque() {
        let Some(sh) = which("sh") else { return };
        // On a multi-call system (`/bin/sh -> busybox`) the target's own name
        // is not a shell, so there is nothing to detect through a rename.
        if !is_shell_name(&std::fs::canonicalize(&sh).unwrap()) {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("innocuous");
        std::os::unix::fs::symlink(&sh, &link).expect("symlink");
        let ex = |argv: &[&str]| Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        };
        let views = plan_display(&mk_plan_req(ex(&[link.to_str().unwrap()]), false)).unwrap();
        assert!(views[0].opaque);
        assert!(views[0].opaque_reason.as_ref().unwrap().is_shell);
        let views = plan_display(&mk_plan_req(ex(&["true"]), false)).unwrap();
        assert!(!views[0].opaque);
    }

    /// A symlink with an innocuous name pointing at `env` is unwrapped as
    /// `env` (the canonical class wins over a plain written name).
    #[test]
    fn renamed_symlink_to_env_is_unwrapped() {
        let Some(env) = which("env") else { return };
        // On a multi-call system (`/usr/bin/env -> busybox`) the target's name
        // is the dispatcher, which is ignored for classification.
        let canonical = std::fs::canonicalize(&env).unwrap();
        if canonical.file_name().and_then(|n| n.to_str()) != Some("env") {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("innocuous");
        std::os::unix::fs::symlink(&env, &link).expect("symlink");
        let link = link.to_str().unwrap().to_string();
        let ex = |argv: Vec<String>| Plan::Exec { argv };
        let views = plan_display(&mk_plan_req(ex(vec![link.clone(), "sh".into()]), false)).unwrap();
        assert!(views[0].opaque, "innocuous -> env running sh");
        let views =
            plan_display(&mk_plan_req(ex(vec![link.clone(), "true".into()]), false)).unwrap();
        assert!(!views[0].opaque);
        let names: Vec<&str> = views[0].programs.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, [link.as_str(), "true"]);
        assert_eq!(views[0].programs[1].via.as_deref(), Some(link.as_str()));
    }

    /// Issue #105: the pin is the file found, its `(dev, ino)` from the
    /// descriptor, and its canonical target read through that descriptor.
    #[test]
    fn resolution_pins_the_inode_it_found() {
        let r = resolve_command("true", "/").expect("true on the login PATH");
        let m = std::fs::metadata(&r.path).unwrap();
        assert_eq!((r.dev, r.ino), (m.dev(), m.ino()));
        assert_eq!(
            r.canonical().unwrap(),
            std::fs::canonicalize(&r.path).unwrap()
        );
        assert!(r.still_pinned());

        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        let r = resolve_command("./tool", dir.path().to_str().unwrap()).unwrap();
        assert!(!r.native, "a #! script is not run from its descriptor");
        std::fs::rename(&tool, dir.path().join("moved")).unwrap();
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        assert!(!r.still_pinned(), "another inode at the path");
    }

    /// A direct, non-script leaf is executed through its pinned descriptor;
    /// argv[0] is the requested word.
    #[test]
    fn direct_binary_execs_its_descriptor() {
        let Some(r) = resolve_command("true", "/").filter(|r| r.native) else {
            return;
        };
        if !proc_fd_available() {
            return;
        }
        let mut l = leaf(&["true"], LeafRunAs::Direct);
        l.resolved_bin = Some(r);
        let c = build_command(&l, EscalationMode::Direct).unwrap();
        assert!(
            c.get_program()
                .to_str()
                .unwrap()
                .starts_with("/proc/self/fd/"),
            "{c:?}"
        );
    }

    fn hop(name: &str, argv_index: usize, resolved: Option<Resolved>) -> ProgramHop {
        ProgramHop {
            name: name.into(),
            argv_index,
            resolved,
            via: Some("env".into()),
            via_index: Some(0),
            runtime_lookup: false,
            applet: false,
            overrides_inherited: Vec::new(),
        }
    }

    /// A wrapped program is spawned under its pinned path (same basename); a
    /// missing one, or one whose path `env` would read as an assignment, is
    /// refused in a transparent leaf and left as written in an opaque one.
    #[test]
    fn spawn_argv_names_wrapped_programs_by_path() {
        let mut l = leaf(&["env", "X=1", "just", "deploy"], LeafRunAs::Direct);
        l.programs = vec![
            hop("env", 0, None),
            hop("just", 2, Some(Resolved::fake("/opt/bin/just"))),
        ];
        assert_eq!(
            spawn_argv(&l).unwrap(),
            ["env", "X=1", "/opt/bin/just", "deploy"]
        );

        l.programs[1].applet = true;
        assert_eq!(
            spawn_argv(&l).unwrap()[2],
            "just",
            "applets keep their name"
        );
        l.programs[1].applet = false;

        l.programs[1].resolved = None;
        let err = spawn_argv(&l).unwrap_err();
        assert!(
            err.contains("command not found: just (run by env)"),
            "{err}"
        );

        l.programs[1].resolved = Some(Resolved::fake("/opt/a=b/just"));
        assert!(spawn_argv(&l).unwrap_err().contains("'='"));

        // Only `env` reads a word with '=' as an assignment.
        let mut n = leaf(&["nice", "just"], LeafRunAs::Direct);
        n.programs = vec![
            hop("nice", 0, None),
            hop("just", 1, Some(Resolved::fake("/opt/a=b/just"))),
        ];
        assert_eq!(spawn_argv(&n).unwrap(), ["nice", "/opt/a=b/just"]);

        l.opaque = Some(Opacity {
            at: 1,
            reason: "r".into(),
            is_shell: false,
            names_program: true,
        });
        assert_eq!(spawn_argv(&l).unwrap()[2], "just");
        l.programs[1].resolved = None;
        assert_eq!(spawn_argv(&l).unwrap()[2], "just");
    }

    /// `find -execdir ./x` runs `./x` from each match's directory, so the word
    /// is kept (and a missing one at the leaf cwd is not refused); a bare name
    /// is still pinned, since `find` looks it up on PATH.
    #[test]
    fn spawn_argv_keeps_execdir_relative_programs() {
        let mut l = leaf(
            &["find", ".", "-execdir", "./configure", ";"],
            LeafRunAs::Direct,
        );
        l.programs = vec![hop("find", 0, None), hop("./configure", 3, None)];
        assert_eq!(spawn_argv(&l).unwrap()[3], "./configure");

        let mut l = leaf(&["find", ".", "-execdir", "make", ";"], LeafRunAs::Direct);
        l.programs = vec![
            hop("find", 0, None),
            hop("make", 3, Some(Resolved::fake("/usr/bin/make"))),
        ];
        assert_eq!(spawn_argv(&l).unwrap()[3], "/usr/bin/make");

        let mut l = leaf(&["find", ".", "-exec", "./tool", ";"], LeafRunAs::Direct);
        l.programs = vec![
            hop("find", 0, None),
            hop("./tool", 3, Some(Resolved::fake("/srv/./tool"))),
        ];
        assert_eq!(
            spawn_argv(&l).unwrap()[3],
            "/srv/./tool",
            "-exec runs from the leaf cwd"
        );
    }
}
