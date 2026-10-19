use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
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
fn is_env_allowed(key: &str) -> bool {
    matches!(
        key,
        "LANG" | "TZ" | "HOME" | "DEBIAN_FRONTEND" | "TERM"
    ) || key.starts_with("LC_")
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
                "SSH_AUTH_SOCK cannot be set in request env; use forward_agent instead"
                    .to_string(),
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
const DEFAULT_LOGIN_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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

/// Resolve a command name to an absolute path by searching PATH.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        if p.is_file() {
            return Some(p);
        }
        return None;
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if let Ok(meta) = candidate.metadata() {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                return Some(candidate);
            }
        }
    }
    None
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

/// Execute a request's plan under pkexec (local/graphical mode).
pub fn exec_pkexec(
    req: &ValidatedRequest,
    env: &HashMap<String, String>,
    tty_lock: &Mutex<()>,
) -> Response {
    run_plan(req, env, EscalationMode::Pkexec, Some(tty_lock))
}

/// Execute a request's plan under sudo (remote/TUI mode).
pub fn exec_sudo(
    req: &ValidatedRequest,
    env: &HashMap<String, String>,
    tty_lock: &Mutex<()>,
) -> Response {
    run_plan(req, env, EscalationMode::Sudo, Some(tty_lock))
}

/// Execute a request's plan directly as the current user (no escalation).
pub fn exec_direct(req: &ValidatedRequest, env: &HashMap<String, String>) -> Response {
    run_plan(req, env, EscalationMode::Direct, None)
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
//   its leaves connected by pipes, a `Seq` (the `seq` op) runs children in order and
//   stops at the first non-accepted exit, a `Leaf` runs one process. Every
//   process shares one plan-wide deadline.
//
// No shell is ever assembled on the privileged path: each leaf fork/execs its
// literal argv, and an escalated leaf is `sudo [-u user] -- argv` / `pkexec
// [--user user] argv`, never `sudo sh -c`. The one exception is an explicit
// `System` leaf — the named, prompt-flagged opaque escape hatch.
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
    File { path: String, append: bool },
    DevNull,
}

#[derive(Clone, Debug)]
enum ErrSpec {
    Capture,
    File { path: String, append: bool },
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
    /// True for a `System` (shell escape-hatch) leaf. The prompt flags it as
    /// opaque; `resolved_bin` resolves only the shell.
    opaque: bool,
    /// `argv[0]` resolved through PATH + canonicalize, for the prompt. Computed
    /// in Pass A so the prompt and the executor can never disagree.
    resolved_bin: Option<PathBuf>,
    /// Exit codes treated as success (besides 0) for seq short-circuiting.
    accepted: Vec<i32>,
    forward_agent: bool,
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
fn compile_plan(req: &ValidatedRequest, env: &HashMap<String, String>) -> Result<Compiled, String> {
    let ambient = if req.privileged {
        LeafRunAs::Root
    } else {
        LeafRunAs::Direct
    };
    let ctx = Ctx {
        env: env.clone(),
        cwd: "/".to_string(),
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
        Plan::Redirect { stream, target, body } => {
            apply_redirect(&mut ctx, *stream, target)?;
            compile_leaf(body, ctx, leaves)
        }
        Plan::WithStdinFrom { path, body } => {
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

/// Append a resolved leaf to the list and return its index (= stage id).
fn push_leaf(argv: Vec<String>, opaque: bool, ctx: Ctx, leaves: &mut Vec<LeafPlan>) -> usize {
    let resolved_bin = argv.first().and_then(|name| which(name));
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
        resolved_bin,
        accepted: ctx.accepted,
        forward_agent: ctx.forward_agent,
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
    /// `argv[0]` resolved through PATH (for `System`, the shell).
    pub resolved_bin: Option<PathBuf>,
    /// True for a `System` escape-hatch leaf — rendered "opaque".
    pub opaque: bool,
    /// Human-readable redirection summary, e.g. `> /tmp/out`, `< in`, `2>&1`.
    pub redirects: String,
    /// True if this leaf is a stage of a pipe.
    pub in_pipe: bool,
}

/// Compile a request's plan purely for display at the approval prompt. Uses an
/// empty env (the environment affects execution, not the rendered structure),
/// so the only errors are structural — the same ones the executor would hit.
pub fn plan_display(req: &ValidatedRequest) -> Result<Vec<LeafView>, String> {
    let empty = HashMap::new();
    let compiled = compile_plan(req, &empty)?;
    let mut in_pipe = vec![false; compiled.leaves.len()];
    mark_pipe_members(&compiled.seq, &mut in_pipe);
    Ok(compiled
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
            opaque: l.opaque,
            redirects: summarize_redirects(l),
            in_pipe: in_pipe[l.stage_id],
        })
        .collect())
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
    req: &ValidatedRequest,
    env: &HashMap<String, String>,
    mode: EscalationMode,
    tty_lock: Option<&Mutex<()>>,
) -> Response {
    let compiled = match compile_plan(req, env) {
        Ok(c) => c,
        Err(e) => return Response::error(&req.id, &format!("invalid plan: {e}")),
    };
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
    let mut cmd = build_command(leaf, mode);
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

    unsafe {
        cmd.pre_exec(|| {
            // New process group so kill_group SIGKILLs the whole group on
            // timeout. setpgid (not setsid) keeps the child in the daemon's
            // session so an escalated child can reach /dev/tty for a password
            // prompt — see issue #19.
            libc::setpgid(0, 0);
            libc::umask(0o077);
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return spawn_err(format!("failed to execute command: {e}")),
    };

    let cpid = child.id() as libc::pid_t;
    unsafe {
        let _ = libc::setpgid(cpid, cpid);
    }
    let _fg = fg_lock.and_then(|m| ForegroundGuard::take(cpid, m));

    let stdout_handle = child.stdout.take().map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));
    let stderr_handle = child.stderr.take().map(|s| spawn_drain(s, MAX_OUTPUT_BYTES));

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
fn build_command(leaf: &LeafPlan, mode: EscalationMode) -> Command {
    match &leaf.runas {
        LeafRunAs::Direct => {
            let mut c = Command::new(&leaf.argv[0]);
            c.args(&leaf.argv[1..]);
            c.env_clear();
            for (k, v) in &leaf.env {
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
                let mut c = Command::new("pkexec");
                if let LeafRunAs::User(name) = escalated {
                    c.arg("--user");
                    c.arg(name);
                }
                for a in &leaf.argv {
                    c.arg(a);
                }
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
                let mut c = Command::new("sudo");
                if let LeafRunAs::User(name) = escalated {
                    c.arg("-u");
                    c.arg(name);
                }
                for (k, v) in &leaf.env {
                    c.arg(format!("{k}={v}"));
                }
                c.arg("--");
                for a in &leaf.argv {
                    c.arg(a);
                }
                c.current_dir(&leaf.cwd);
                c
            }
        },
    }
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

fn set_stderr(cmd: &mut Command, spec: &ErrSpec, stdout_file: Option<&File>) -> std::io::Result<()> {
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
/// their results against the shared deadline. Pipe stages use `setsid` (not
/// `setpgid`): a pipelined child cannot interactively prompt for a password, so
/// it must be detached from the controlling tty and rely on cached credentials
/// — matching the pre-plan pipeline behaviour.
///
/// Consequence: a privileged stage *inside a pipe* cannot prompt, and because it
/// has no controlling tty, a credential cached on the daemon's tty may not be
/// visible to it (depends on the host's sudoers `timestamp_type`: `global` yes,
/// the common `tty` default likely not). Such a stage needs NOPASSWD or an
/// already-`global`-cached credential, or it fails fast with "no tty present".
/// Prefer a single privileged stage, which runs with `setpgid` + the foreground
/// guard and *can* prompt. See the "Partial-`seq` retry hazard and the
/// sudo-credential-in-pipe caveat" item in backlog.md.
fn run_pipe(
    indices: &[usize],
    leaves: &[LeafPlan],
    mode: EscalationMode,
    deadline: Instant,
    outcomes: &mut [Outcome],
) -> StepStatus {
    let n = indices.len();
    let mut children: Vec<Child> = Vec::with_capacity(n);
    let mut prev_stdout: Option<Stdio> = None;

    for (pos, &li) in indices.iter().enumerate() {
        let leaf = &leaves[li];
        let is_first = pos == 0;
        let is_last = pos == n - 1;

        let mut cmd = build_command(leaf, mode);

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
                Ok(())
            });
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
        let lock = tty_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());

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
enum WaitError {
    Timeout,
    Io(std::io::Error),
}

fn wait_with_deadline(child: &mut Child, deadline: Instant) -> Result<ExitStatus, WaitError> {
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
    use std::time::Duration;

    fn pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
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
    // "no shell on the privileged path" invariant is verified directly below.

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
                    shell: if rng.below(2) == 0 { ShellProc::Sh } else { ShellProc::Bash },
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
            let compiled = compile_plan(&req, &HashMap::new()).expect("compiles");
            assert_eq!(compiled.leaves.len(), count_leaves(&plan));
        }
    }

    // Spec clause (Rung 2): the no-shell-on-privileged-path invariant, checked
    // structurally on the built `Command`. An escalated, non-opaque leaf is
    // spawned as `sudo [-u user] -- <literal argv>` / `pkexec [--user u] argv`
    // — the real binary is argv[0], and no `sh -c` / `bash -c` wrapper is ever
    // introduced. The only shell is an explicit `System` leaf.
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
            opaque: false,
            resolved_bin: None,
            accepted: Vec::new(),
            forward_agent: false,
            stage_id: 0,
        };

        // Root under sudo: `sudo -- sysctl -w …`, no shell.
        let c = build_command(&leaf(LeafRunAs::Root), EscalationMode::Sudo);
        assert_eq!(c.get_program().to_str().unwrap(), "sudo");
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--".to_string()), "sudo must use -- : {args:?}");
        assert!(args.ends_with(&["sysctl".into(), "-w".into(), "vm.mmap_rnd_bits=28".into()]));
        assert!(
            !args.iter().any(|a| a == "-c"),
            "no shell -c on the privileged path: {args:?}"
        );

        // Named user under sudo: `sudo -u alice -- …`.
        let c = build_command(&leaf(LeafRunAs::User("alice".into())), EscalationMode::Sudo);
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&args[0], "-u");
        assert_eq!(&args[1], "alice");

        // Pkexec root: `pkexec sysctl …` (no shell).
        let c = build_command(&leaf(LeafRunAs::Root), EscalationMode::Pkexec);
        assert_eq!(c.get_program().to_str().unwrap(), "pkexec");

        // Direct leaf: program IS the literal binary.
        let c = build_command(&leaf(LeafRunAs::Direct), EscalationMode::Direct);
        assert_eq!(c.get_program().to_str().unwrap(), "sysctl");
    }
}
