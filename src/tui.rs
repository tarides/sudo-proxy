use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::executor::{plan_display, which, LeafPrivilege, LeafView};
use crate::protocol::{Plan, RedirTarget, Response, RunAs, Status, Stream, ValidatedRequest};

/// Quote a single token for safe, paste-able POSIX shell. Anything outside a
/// conservative unquoted-safe set is wrapped in single quotes (with embedded
/// single quotes escaped as `'\''`), so a token like `a;b` or `$x` cannot be
/// re-parsed by the shell. This is what makes the `Command:` one-liner copyable.
pub fn shquote(a: &str) -> String {
    let safe = !a.is_empty()
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=@%+,-".contains(&b));
    if safe {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', "'\\''"))
    }
}

/// Join argv into a shell command string with each token safely quoted.
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shquote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Join a pipeline of stages into a shell-like display string with ` | ` separators.
pub fn pipeline_join(pipeline: &[Vec<String>]) -> String {
    pipeline
        .iter()
        .map(|argv| shell_join(argv))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// A one-line, copy-paste-executable shell rendering of a request's command:
/// the `Steps:` block flattened onto one line. Both are printed from the same
/// [`Lay`] tree, so they carry exactly the same parentheses and must parse, as
/// shell, to the same tree (see [`steps_shell_text`]). `setenv`/`chdir` become
/// scoped subshells, pipes and mixed-operator chains are parenthesized, and
/// `run-as` is threaded onto each leaf as `sudo`/`sudo -u` (matching the
/// executor's per-leaf escalation) — so a privilege-free plan pastes and runs as
/// you, and a privileged one pastes and runs with auth. Used for the `Command:`
/// line, logs, and the compact banner.
pub fn command_summary(req: &ValidatedRequest) -> String {
    lay_command(&request_layout(req))
}

/// The `Steps:` block as plain shell text — uncoloured, unnumbered, one step per
/// line, indented by parenthesis depth. This is what bash reads if the block is
/// pasted, and it must parse to the same tree as [`command_summary`]: the
/// operator reviews one and may paste the other, so they can never disagree.
pub fn steps_shell_text(req: &ValidatedRequest) -> String {
    steps_lines(&request_layout(req), &style_for(true))
        .iter()
        .map(|l| format!("{}{}", "  ".repeat(l.depth), l.text))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Ambient escalation context: a `privileged` request runs every leaf as root,
/// mirroring the executor, so each leaf gets its own `sudo` (never a single
/// `sudo sh -c '…'`, which would put a shell back on the root path) and reads
/// light red. A `run-as` node overrides it per subtree.
fn ambient_ctx(privileged: bool) -> LayCtx {
    LayCtx {
        sudo: if privileged { "sudo ".into() } else { String::new() },
        esc: Esc {
            uid: if privileged { StepUid::Root } else { StepUid::Default },
            boundary: false,
        },
    }
}

fn request_layout(req: &ValidatedRequest) -> Lay {
    layout(&req.exec_plan(), &ambient_ctx(req.privileged))
}

/// The shell operators of the display.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Seq,
    And,
    Or,
    Pipe,
}

impl Op {
    fn sym(self) -> &'static str {
        match self {
            Op::Seq => ";",
            Op::And => "&&",
            Op::Or => "||",
            Op::Pipe => "|",
        }
    }
}

/// The display layout of a plan, shared by the `Command:` line and the `Steps:`
/// block so both show the same grouping by construction. The grouping rules
/// (see `docs/testing.md`, "How the prompt shows grouping"):
///
/// - a chain holds one operator; a nested chain of the same operator is flattened
///   into it, one of another operator is parenthesized — so every line of a
///   `Steps:` group ends with the same operator;
/// - a pipe is always parenthesized;
/// - a `cd`/`export` scope is `( cd D ; ( body ) )`, so nothing leaks out of it,
///   even when the whole plan is the scope (the `Command:` line is pasted into a
///   stateful shell).
enum Lay {
    /// One command line: `cmd` (with any `sudo` prefix) plus its redirections.
    /// A `scope` leaf is the `cd`/`export` header of a scope, never escalated.
    Leaf {
        cmd: String,
        redir: String,
        esc: Esc,
        scope: bool,
    },
    /// Explicit parentheses, with redirections applied to the whole group.
    Group { inner: Box<Lay>, redir: String },
    /// Two or more items joined by one operator.
    Chain { op: Op, items: Vec<Lay> },
}

/// The `sudo` prefix and colouring threaded down from the enclosing `run-as`.
struct LayCtx {
    sudo: String,
    esc: Esc,
}

fn layout(plan: &Plan, ctx: &LayCtx) -> Lay {
    match plan {
        Plan::Exec { argv } => lay_leaf(format!("{}{}", ctx.sudo, shell_join(argv)), ctx.esc),
        Plan::Shell { shell, script } => {
            let bin = match shell {
                crate::protocol::ShellProc::Sh => "sh",
                crate::protocol::ShellProc::Bash => "bash",
            };
            lay_leaf(format!("{}{bin} -c {}", ctx.sudo, shquote(script)), ctx.esc)
        }
        Plan::Pipe { stages } => lay_group(lay_chain(Op::Pipe, stages, ctx)),
        Plan::Run { steps } => lay_chain(Op::And, steps, ctx),
        Plan::Alt { steps } => lay_chain(Op::Or, steps, ctx),
        Plan::Seq { steps } => lay_chain(Op::Seq, steps, ctx),
        Plan::Redirect { stream, target, body } => {
            lay_redirect(layout(body, ctx), redir_suffix(*stream, target))
        }
        Plan::WithStdinFrom { path, body } => {
            lay_redirect(layout(body, ctx), format!("< {}", shquote(path)))
        }
        Plan::Setenv { key, value, body } => {
            lay_scope(format!("export {key}={}", shquote(value)), layout(body, ctx))
        }
        Plan::Chdir { dir, body } => lay_scope(format!("cd {}", shquote(dir)), layout(body, ctx)),
        Plan::RunAs { who, body } => {
            let ctx2 = match who {
                RunAs::Root => LayCtx {
                    sudo: "sudo ".into(),
                    esc: Esc { uid: StepUid::Root, boundary: true },
                },
                RunAs::User { name } => LayCtx {
                    sudo: format!("sudo -u {} ", shquote(name)),
                    esc: Esc { uid: StepUid::User, boundary: true },
                },
            };
            layout(body, &ctx2)
        }
        Plan::WithAcceptedExitCodes { body, .. } => layout(body, ctx),
    }
}

fn lay_leaf(cmd: String, esc: Esc) -> Lay {
    Lay::Leaf { cmd, redir: String::new(), esc, scope: false }
}

/// Parenthesize, unless the layout already is a bare group.
fn lay_group(l: Lay) -> Lay {
    match l {
        g @ Lay::Group { .. } if matches!(&g, Lay::Group { redir, .. } if redir.is_empty()) => g,
        other => Lay::Group { inner: Box::new(other), redir: String::new() },
    }
}

fn lay_chain(op: Op, steps: &[Plan], ctx: &LayCtx) -> Lay {
    let mut items = Vec::new();
    for s in steps {
        match layout(s, ctx) {
            // Same operator: associative, so flatten into this chain.
            Lay::Chain { op: o, items: sub } if o == op => items.extend(sub),
            // Another operator: its own group, so a line's operator never
            // reaches further than its group.
            c @ Lay::Chain { .. } => items.push(lay_group(c)),
            other => items.push(other),
        }
    }
    if items.len() == 1 {
        return items.pop().expect("one item");
    }
    Lay::Chain { op, items }
}

fn lay_redirect(l: Lay, suffix: String) -> Lay {
    match l {
        Lay::Leaf { cmd, redir, esc, scope } => {
            Lay::Leaf { cmd, redir: join_suffix(redir, &suffix), esc, scope }
        }
        Lay::Group { inner, redir } => Lay::Group { inner, redir: join_suffix(redir, &suffix) },
        c @ Lay::Chain { .. } => Lay::Group { inner: Box::new(c), redir: suffix },
    }
}

/// `( header ; ( body ) )` — the scope's own parentheses keep `cd`/`export` from
/// leaking past it.
fn lay_scope(header: String, body: Lay) -> Lay {
    let head = Lay::Leaf {
        cmd: header,
        redir: String::new(),
        esc: Esc { uid: StepUid::Default, boundary: false },
        scope: true,
    };
    Lay::Group {
        inner: Box::new(Lay::Chain { op: Op::Seq, items: vec![head, lay_group(body)] }),
        redir: String::new(),
    }
}

fn join_suffix(s: String, suffix: &str) -> String {
    match (s.is_empty(), suffix.is_empty()) {
        (_, true) => s,
        (true, false) => suffix.to_string(),
        (false, false) => format!("{s} {suffix}"),
    }
}

/// The `Command:` one-liner: the layout with every group on one line.
fn lay_command(l: &Lay) -> String {
    match l {
        Lay::Leaf { cmd, redir, .. } => join_suffix(cmd.clone(), redir),
        Lay::Group { inner, redir } => {
            let s = lay_command(inner);
            // `((` would open an arithmetic command in bash: keep openers apart.
            let open = if s.starts_with('(') { "( " } else { "(" };
            join_suffix(format!("{open}{s})"), redir)
        }
        Lay::Chain { op, items } => {
            let sep = match op {
                Op::Seq => "; ".to_string(),
                _ => format!(" {} ", op.sym()),
            };
            items.iter().map(lay_command).collect::<Vec<_>>().join(&sep)
        }
    }
}

/// The redirection suffix for a stream/target pair, paths safely quoted.
fn redir_suffix(stream: Stream, target: &RedirTarget) -> String {
    match (stream, target) {
        (Stream::Stdout, RedirTarget::File { path, mode }) => {
            format!("{} {}", redir_arrow(*mode), shquote(path))
        }
        (Stream::Stderr, RedirTarget::File { path, mode }) => {
            format!("2{} {}", redir_arrow(*mode), shquote(path))
        }
        (Stream::Both, RedirTarget::File { path, mode }) => {
            format!("{} {} 2>&1", redir_arrow(*mode), shquote(path))
        }
        (Stream::Stdout, RedirTarget::DevNull) => "> /dev/null".to_string(),
        (Stream::Stderr, RedirTarget::DevNull) => "2> /dev/null".to_string(),
        (Stream::Both, RedirTarget::DevNull) => "> /dev/null 2>&1".to_string(),
    }
}

fn redir_arrow(mode: crate::protocol::WriteMode) -> &'static str {
    match mode {
        crate::protocol::WriteMode::Append => ">>",
        crate::protocol::WriteMode::Truncate => ">",
    }
}

/// Styling for the approval prompt. `bold`/`dim`/`reset` are weight-only. A
/// step's command is colored by the uid it runs as, in two red intensities so
/// the escalation *boundary* stands out from ambient escalation: `root` (light
/// red) = a leaf that runs as root because the whole request is privileged;
/// `root_boundary` (bright red) = the explicit `run-as`/`sudo` leaf; `user`
/// (bright yellow) = a `run-as` to a named non-root user. Operators of an
/// all-escalated group are tinted `root` too. All escapes are empty when
/// NO_COLOR is set (https://no-color.org); output always targets /dev/tty.
#[derive(Clone, Copy)]
struct Style {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
    /// Ambient root (whole plan privileged) — light red.
    root: &'static str,
    /// Explicit `run-as`/`sudo` root boundary — bright red.
    root_boundary: &'static str,
    /// `run-as` to a named non-root user — bright yellow.
    user: &'static str,
}

fn style() -> Style {
    style_for(std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()))
}

/// Pure split so the NO_COLOR mapping is unit-testable without mutating the
/// process-wide environment.
fn style_for(no_color: bool) -> Style {
    if no_color {
        Style { bold: "", dim: "", reset: "", root: "", root_boundary: "", user: "" }
    } else {
        Style {
            bold: "\x1b[1m",
            dim: "\x1b[2m",
            reset: "\x1b[0m",
            root: "\x1b[38;5;210m",          // light red
            root_boundary: "\x1b[38;5;196m", // bright red
            user: "\x1b[38;5;226m",          // bright yellow
        }
    }
}

/// Attention cues emitted just before the `Execute?` question so an unfocused or
/// off-screen daemon terminal does not sit silently until the timeout denies the
/// request. The terminal bell (BEL) is the primary cue — terminals map it to an
/// audible beep and, for an unfocused window, the WM/dock urgency hint; the
/// blink wraps the question text as an in-window fallback for terminals that
/// render no bell. Both default on; each is independently suppressed by its own
/// env var (gated separately from NO_COLOR, which governs color/weight).
#[derive(Clone, Copy)]
struct Alert {
    bell: &'static str,      // "\x07" or ""
    blink_on: &'static str,  // "\x1b[5m" or ""
    blink_off: &'static str, // "\x1b[25m" or ""
}

fn alert() -> Alert {
    alert_for(
        std::env::var_os("SUDO_PROXY_NO_BELL").is_some_and(|v| !v.is_empty()),
        std::env::var_os("SUDO_PROXY_NO_BLINK").is_some_and(|v| !v.is_empty()),
    )
}

/// Pure split so the env mapping is unit-testable without mutating the
/// process-wide environment (same pattern as `style_for`). Bell and blink are
/// independent — each honors only its own flag.
fn alert_for(no_bell: bool, no_blink: bool) -> Alert {
    Alert {
        bell: if no_bell { "" } else { "\x07" },
        blink_on: if no_blink { "" } else { "\x1b[5m" },
        blink_off: if no_blink { "" } else { "\x1b[25m" },
    }
}

/// Upper bound on the command string shown at the approval prompt. A caller
/// could otherwise submit a multi-kilobyte argument that wraps over dozens of
/// lines and pushes the `[y/N]` question off-screen, so the human approves
/// without it in view. Bounded display keeps the prompt anchored; the marker
/// makes truncation explicit so an over-long command reads as suspicious
/// rather than benign.
const MAX_DISPLAY_CMD_CHARS: usize = 1024;

/// Upper bound on the number of plan stages rendered line-by-line at the prompt.
/// A plan with more stages than this has its tail hidden behind an explicit
/// marker, so a wide plan cannot push the `[y/N]` question off-screen — the same
/// anti-flooding rationale as `MAX_DISPLAY_CMD_CHARS`, applied to stage count.
const MAX_DISPLAY_STAGES: usize = 32;

/// Truncate an approval-prompt command string to a bounded number of
/// characters, appending an explicit marker when it was shortened.
pub fn truncate_for_display(s: &str) -> String {
    let count = s.chars().count();
    if count <= MAX_DISPLAY_CMD_CHARS {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX_DISPLAY_CMD_CHARS).collect();
    let hidden = count - MAX_DISPLAY_CMD_CHARS;
    format!("{head}… [{hidden} more chars hidden — full command not shown]")
}

#[derive(Debug, PartialEq)]
pub enum PromptResult {
    Approved,
    /// Approve this request *and*, if the daemon is eligible, grant unattended
    /// unprivileged execution for the rest of this session (in-memory, never
    /// persisted). Only emitted for unprivileged requests; privileged prompts
    /// never offer this. The dispatcher grants the session only when the
    /// daemon's `unattended_eligible` policy is set — otherwise this approves
    /// the single command and nothing more.
    ApprovedAlways,
    Denied,
    Timeout,
}

/// Asks the user to approve or deny a privilege request. `eligible` reflects
/// the daemon's `unattended_eligible` policy: when set (and the request is
/// unprivileged) the prompt offers the session-scoped `a` answer, otherwise it
/// shows a plain `[y/N]`.
pub trait Prompter: Send + Sync {
    fn prompt(
        &self,
        req: &ValidatedRequest,
        eligible: bool,
        timeout: Duration,
    ) -> io::Result<PromptResult>;
}

/// Echoes the result of a completed command back to the user.
pub trait ResultSink: Send + Sync {
    fn display(&self, resp: &Response) -> io::Result<()>;
}

pub struct TtyPrompter;

impl Prompter for TtyPrompter {
    fn prompt(
        &self,
        req: &ValidatedRequest,
        eligible: bool,
        timeout: Duration,
    ) -> io::Result<PromptResult> {
        prompt_tty(req, eligible, timeout)
    }
}

pub struct TtyResultSink;

impl ResultSink for TtyResultSink {
    fn display(&self, resp: &Response) -> io::Result<()> {
        display_result(resp)
    }
}

pub struct NoopResultSink;

impl ResultSink for NoopResultSink {
    fn display(&self, _resp: &Response) -> io::Result<()> {
        Ok(())
    }
}

/// Classify a single keypress into an approval decision. Pure (no I/O): the
/// sole source of `ApprovedAlways` is `'a'`/`'A'` on an *unprivileged* request;
/// the sole source of `Approved` is `'y'`/`'Y'`; `None` (the read timed out) is
/// `Timeout`; every other byte denies. This is the transition function the
/// Rung 4 state-machine model and the Rung 5 dispatch contract both target —
/// keeping it free of the TTY writes lets the property test cover it
/// exhaustively over the whole `(Option<u8>, bool)` input domain.
pub(crate) fn classify_key(key: Option<u8>, privileged: bool) -> PromptResult {
    match key {
        None => PromptResult::Timeout,
        Some(b'y' | b'Y') => PromptResult::Approved,
        Some(b'a' | b'A') if !privileged => PromptResult::ApprovedAlways,
        Some(_) => PromptResult::Denied,
    }
}

/// Display a privilege request on /dev/tty and ask for Y/N confirmation.
/// `eligible` gates whether the session-scoped `a` answer is offered (only for
/// unprivileged requests on a daemon whose `unattended_eligible` policy is set).
pub fn prompt_tty(
    req: &ValidatedRequest,
    eligible: bool,
    timeout: Duration,
) -> io::Result<PromptResult> {
    let mut tty_w = OpenOptions::new().write(true).open("/dev/tty")?;
    let tty_r = File::open("/dev/tty")?;

    let st = style();
    let Style { bold, dim, reset, .. } = st;

    writeln!(tty_w, "\n{bold}━━━ Privilege Request ━━━{reset}")?;
    writeln!(
        tty_w,
        "From:    {} @ {}",
        req.session,
        if req.host.is_empty() { "local" } else { &req.host }
    )?;
    let client_ver = if req.version.is_empty() { "(unknown)" } else { req.version.as_str() };
    writeln!(tty_w, "Client:  sudo-proxy {client_ver}")?;
    if !req.time.is_empty() {
        writeln!(tty_w, "Time:    {}", req.time)?;
    }
    writeln!(tty_w, "ID:      {}", req.id)?;
    if !req.reason.is_empty() {
        writeln!(tty_w, "Reason:  {bold}{}{reset}", req.reason)?;
    }
    let agent_tag = if req.forward_agent {
        format!(" {dim}(agent forwarded){reset}")
    } else {
        String::new()
    };
    writeln!(
        tty_w,
        "Command: {bold}{}{reset}{agent_tag}",
        truncate_for_display(&command_summary(req))
    )?;

    // Render every stage the executor will run, each with its run-as context
    // and its resolved real binary. This is the structural guarantee the plan
    // model buys: the vacuous single `/usr/bin/bash` resolves line is replaced
    // by one resolved binary per literal stage, so a bundle of root effects can
    // no longer hide inside one opaque command. Built from the same
    // `compile_plan` walk the executor uses, so prompt and execution agree.
    match plan_display(req) {
        Ok(views) => write_plan_stages(&mut tty_w, &req.exec_plan(), &views, req.privileged, &st)?,
        Err(e) => writeln!(tty_w, "{bold}⚠ invalid plan: {e}{reset}")?,
    }

    if !req.env.is_empty() {
        let env_display: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        writeln!(tty_w, "Env:     {}", env_display.join(" "))?;
    }

    // Effective privilege, not the raw `privileged` flag: a plan that smuggles
    // a `RunAs` node is gated exactly like a top-level privileged request, so
    // `a` is never offered for it and root wording is shown when any stage is
    // root. `a` is offered only when this daemon is `unattended_eligible` (an
    // out-of-band operator opt-in).
    let effective_priv = req.effective_privileged();
    let offer_always = eligible && !effective_priv;
    let (question, choices) = if req.runs_as_root() {
        ("Execute as root?", "[y/N]")
    } else if effective_priv {
        // Escalation only to a named non-root user (no root stage).
        ("Execute with elevated privileges?", "[y/N]")
    } else if offer_always {
        writeln!(
            tty_w,
            "{dim}a = approve and allow unprivileged on this host for this session \
             (not saved){reset}"
        )?;
        ("Execute?", "[y/N/a]")
    } else {
        ("Execute?", "[y/N]")
    };
    let cues = alert();
    write_question_line(&mut tty_w, &cues, question, choices, timeout.as_secs())?;
    tty_w.flush()?;

    // Read single keypress with timeout (no Enter needed), then classify it
    // with the pure decision function so the TTY echo and the security-
    // relevant mapping cannot drift apart. Pass effective privilege so `a`
    // (ApprovedAlways) can never be produced for a plan that escalates.
    let result = classify_key(read_key_timeout(&tty_r, timeout)?, effective_priv);
    let label = match result {
        PromptResult::Timeout => "Timeout",
        PromptResult::Approved => "Approved",
        // `a` on an eligible daemon grants the session; pressed when `a` was
        // not offered it degrades to a plain approve-once (the dispatcher will
        // not grant), so label it honestly.
        PromptResult::ApprovedAlways if offer_always => "Approved (unattended for this session)",
        PromptResult::ApprovedAlways => "Approved",
        PromptResult::Denied => "Denied",
    };
    // Answered or timed out: the question no longer needs attention.
    write_settled_question_line(&mut tty_w, &cues, question, choices, timeout.as_secs())?;
    writeln!(tty_w, "\n→ {label}")?;
    writeln!(tty_w, "{bold}━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")?;

    Ok(result)
}

/// Write the `Execute?` question line, wrapped with the attention cues. The BEL
/// leads (fires when the line first renders); the blink wraps only the text, so
/// the trailing space before the resting cursor does not blink. Kept writer-
/// generic and free of I/O side effects so the emitted bytes are unit-testable
/// against a buffer, without touching /dev/tty.
fn write_question_line<W: Write>(
    w: &mut W,
    alert: &Alert,
    question: &str,
    choices: &str,
    timeout_secs: u64,
) -> io::Result<()> {
    let Alert { bell, blink_on, blink_off } = *alert;
    let text = question_text(question, choices, timeout_secs);
    write!(w, "{bell}{blink_on}{text}{blink_off} ")
}

fn question_text(question: &str, choices: &str, timeout_secs: u64) -> String {
    format!("{question} {choices} ({timeout_secs}s timeout, default=N)")
}

/// Once the prompt is answered or has timed out, redraw the question line
/// without blink: a terminal keeps blinking cells that were drawn blinking, so
/// stopping it means rewriting them. Echo is off while the key is read, so the
/// cursor is still on the question line: return to its start (`\r`), clear it
/// (`ESC [2K`), and print the same text plain. Emits nothing when blink is
/// suppressed. A question wrapped over several lines by a very narrow terminal
/// only has its last line redrawn.
fn write_settled_question_line<W: Write>(
    w: &mut W,
    alert: &Alert,
    question: &str,
    choices: &str,
    timeout_secs: u64,
) -> io::Result<()> {
    if alert.blink_on.is_empty() {
        return Ok(());
    }
    let text = question_text(question, choices, timeout_secs);
    write!(w, "\r\x1b[2K{text} ")
}

/// Render a plan below the `Command:` line, in two bands: a deduplicated
/// **Resolves** block (every distinct real binary the plan runs, shown once),
/// then an indented, line-numbered **Steps** block — the structure spread across
/// lines with `&&`/`||`/`|`/`;`, each command colored by uid (red = root), for
/// readability and so the human can reference a line ("decline, change line 3").
/// A single plain unprivileged stage degrades to the classic one-line
/// `Resolves:` form so simple prompts stay simple.
fn write_plan_stages<W: Write>(
    w: &mut W,
    plan: &Plan,
    views: &[LeafView],
    privileged: bool,
    style: &Style,
) -> io::Result<()> {
    // Simple case: one stage, no escalation, not opaque, no redirections — keep
    // the familiar single `Resolves:` line.
    if !privileged
        && views.len() == 1
        && views[0].privilege == LeafPrivilege::Direct
        && !views[0].opaque
        && views[0].redirects.is_empty()
    {
        if let Some(name) = views[0].argv.first() {
            return write_resolves_line(w, name, style);
        }
        return Ok(());
    }

    write_resolve_block(w, views, style)?;
    write_steps(w, &layout(plan, &ambient_ctx(privileged)), style)?;
    Ok(())
}

/// Uid a step runs as, for coloring. `Root` → red, `User` → yellow, `Default` →
/// no color (the daemon's own user).
#[derive(Clone, Copy, PartialEq)]
enum StepUid {
    Default,
    Root,
    User,
}

/// Escalation context threaded through the Steps render: which uid a leaf runs
/// as, and whether it sits at an explicit `run-as`/`sudo` boundary (which gets
/// the brighter shade).
#[derive(Clone, Copy)]
struct Esc {
    uid: StepUid,
    boundary: bool,
}

fn colorize(esc: Esc, text: &str, style: &Style) -> String {
    let color = match esc.uid {
        StepUid::Default => "",
        // Ambient root is light red; the explicit run-as boundary is bright red.
        StepUid::Root if esc.boundary => style.root_boundary,
        StepUid::Root => style.root,
        StepUid::User => style.user,
    };
    if color.is_empty() {
        text.to_string()
    } else {
        format!("{color}{text}{}", style.reset)
    }
}

/// One line of the `Steps:` block, at a parenthesis depth. A `numbered` line
/// holds a command; a line holding only parentheses is not numbered.
struct StepLine {
    depth: usize,
    text: String,
    numbered: bool,
}

/// The `Steps:` block — one command per line, indented by parenthesis depth,
/// numbered (0-based, dim, flush-left) so the human can reference a line,
/// coloured by uid. It is valid shell grouping exactly like the `Command:` line.
fn write_steps<W: Write>(w: &mut W, lay: &Lay, style: &Style) -> io::Result<()> {
    let lines = steps_lines(lay, style);
    if lines.is_empty() {
        return Ok(());
    }
    let Style { dim, reset, bold, .. } = *style;
    writeln!(w, "Steps:")?;
    let shown = lines.len().min(MAX_DISPLAY_STAGES);
    let numbered = lines[..shown].iter().filter(|l| l.numbered).count();
    let width = numbered.saturating_sub(1).to_string().len();
    let mut n = 0usize;
    for ln in &lines[..shown] {
        let indent = "  ".repeat(ln.depth + 1);
        if ln.numbered {
            writeln!(w, "{dim}{n:<width$}{reset}{indent}{}", ln.text)?;
            n += 1;
        } else {
            writeln!(w, "{:width$}{indent}{}", "", ln.text)?;
        }
    }
    if lines.len() > shown {
        let hidden = lines.len() - shown;
        writeln!(w, "{bold}… {hidden} more line(s) hidden — see Command:{reset}")?;
    }
    Ok(())
}

fn steps_lines(lay: &Lay, style: &Style) -> Vec<StepLine> {
    let mut out = Vec::new();
    steps_emit(lay, 0, false, style, &mut out);
    out
}

/// Emit the lines of a layout subtree. `followed` says an operator comes right
/// after this subtree, which decides where a group's `)` goes.
fn steps_emit(lay: &Lay, depth: usize, followed: bool, style: &Style, out: &mut Vec<StepLine>) {
    match lay {
        Lay::Leaf { cmd, redir, esc, scope } => {
            let text = if *scope { cmd.clone() } else { colorize(*esc, cmd, style) };
            out.push(StepLine { depth, text: join_suffix(text, redir), numbered: true });
        }
        Lay::Chain { op, items } => {
            let plain = format!(" {}", op.sym());
            // Tint the operator when every command in the chain runs escalated,
            // so a contiguous privileged region reads as one coloured block.
            let op_str = if lay_all_escalated(lay) && !style.root.is_empty() {
                format!("{}{plain}{}", style.root, style.reset)
            } else {
                plain
            };
            for (i, item) in items.iter().enumerate() {
                let last = i + 1 == items.len();
                steps_emit(item, depth, !last, style, out);
                if !last {
                    out.last_mut().expect("an item emits a line").text.push_str(&op_str);
                }
            }
        }
        Lay::Group { inner, redir } => {
            // Egyptian brackets: `(` ends the line leading into the group, or
            // sits on a line of its own when nothing precedes it.
            let opener_depth = match out.last_mut() {
                Some(prev) => {
                    prev.text.push_str(" (");
                    prev.depth
                }
                None => {
                    out.push(StepLine { depth, text: "(".into(), numbered: false });
                    depth
                }
            };
            steps_emit(inner, depth + 1, false, style, out);
            // `)` ends the group's last line when an operator or a redirection
            // follows; otherwise it closes on its own line, under its opener.
            let close = join_suffix(")".into(), redir);
            if followed || !redir.is_empty() {
                let last = out.last_mut().expect("a group emits a line");
                last.text.push(' ');
                last.text.push_str(&close);
            } else {
                out.push(StepLine { depth: opener_depth, text: close, numbered: false });
            }
        }
    }
}

/// Whether every command (scope headers aside) in this layout runs escalated.
fn lay_all_escalated(lay: &Lay) -> bool {
    fn walk(l: &Lay, seen: &mut bool) -> bool {
        match l {
            Lay::Leaf { scope: true, .. } => true,
            Lay::Leaf { esc, .. } => {
                *seen = true;
                esc.uid != StepUid::Default
            }
            Lay::Group { inner, .. } => walk(inner, seen),
            Lay::Chain { items, .. } => items.iter().all(|i| walk(i, seen)),
        }
    }
    let mut seen = false;
    walk(lay, &mut seen) && seen
}

/// The deduplicated `Resolves:` block: one line per distinct binary the plan
/// runs, in first-seen order, so a binary used by several stages appears once.
/// Entries with the same name *and* resolution collapse; distinct names stay
/// apart even when they share a multi-call binary (`echo` vs `cat` on uutils).
/// `System`/`Shell` stages render as the opaque-shell marker.
fn write_resolve_block<W: Write>(w: &mut W, views: &[LeafView], style: &Style) -> io::Result<()> {
    let Style { bold, reset, .. } = *style;
    let mut seen = std::collections::HashSet::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for view in views {
        let name = view.argv.first().cloned().unwrap_or_default();
        let detail = if view.opaque {
            match &view.resolved_bin {
                Some(p) => format!(
                    "{bold}opaque — resolves only the shell: {}{reset}",
                    p.display()
                ),
                None => format!("{bold}opaque — shell not found in PATH{reset}"),
            }
        } else {
            resolve_detail(&name, style)
        };
        if seen.insert(format!("{name}\u{0}{detail}")) {
            entries.push((name, detail));
        }
    }
    if entries.is_empty() {
        return Ok(());
    }
    let width = entries.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
    writeln!(w, "Resolves:")?;
    for (name, detail) in &entries {
        writeln!(w, "  {name:<width$}  {detail}")?;
    }
    Ok(())
}

/// The resolution detail for a command name (the text after `Resolves:`),
/// always naming a concrete path. Used by the consolidated resolve block; it
/// mirrors `write_resolves_line`'s symlink display but never elides — the block
/// shows every binary, even one supplied as an already-canonical absolute path.
fn resolve_detail(cmd_name: &str, style: &Style) -> String {
    let Style { bold, dim, reset, .. } = *style;
    let resolved = match which(cmd_name) {
        Some(p) => p,
        None => return format!("{bold}(not found in PATH){reset}"),
    };
    let resolved_str = resolved.display().to_string();
    match std::fs::canonicalize(&resolved) {
        Ok(canonical) => {
            let canonical_str = canonical.display().to_string();
            if canonical_str != resolved_str {
                format!("{resolved_str} {bold}->{reset} {canonical_str}")
            } else {
                resolved_str
            }
        }
        Err(_) => format!("{resolved_str} {dim}(canonicalize failed){reset}"),
    }
}

/// Write the `Resolves:` line for a command name. PATH-searches the
/// name (or accepts an absolute path), then `canonicalize`s the result
/// so symlink redirection — including `/usr/local/bin/foo -> /tmp/evil`
/// when the absolute path was supplied directly — is visible.
///
/// Display rules:
/// - request matches resolved matches canonical: nothing printed.
/// - request differs from resolved (PATH search): show resolved path,
///   appending `-> canonical` if canonical also differs.
/// - request matches resolved but canonical differs (absolute symlink):
///   show `request -> canonical` in bold.
/// - canonicalize fails (broken symlink, EACCES): show what we know and
///   flag `(canonicalize failed)` so the prompt is honest about not
///   having verified the target.
fn write_resolves_line<W: Write>(w: &mut W, cmd_name: &str, style: &Style) -> io::Result<()> {
    let Style { bold, dim, reset, .. } = *style;
    let resolved = match which(cmd_name) {
        Some(p) => p,
        None => {
            return writeln!(w, "Resolves: {bold}(not found in PATH){reset}");
        }
    };
    let resolved_str = resolved.display().to_string();
    let resolved_differs = resolved_str != *cmd_name;

    match std::fs::canonicalize(&resolved) {
        Ok(canonical) => {
            let canonical_str = canonical.display().to_string();
            let canonical_differs = canonical_str != resolved_str;
            match (resolved_differs, canonical_differs) {
                (false, false) => Ok(()),
                (true, false) => writeln!(w, "Resolves: {resolved_str}"),
                (false, true) => writeln!(
                    w,
                    "Resolves: {bold}{resolved_str} -> {canonical_str}{reset}"
                ),
                (true, true) => writeln!(
                    w,
                    "Resolves: {resolved_str} {bold}->{reset} {canonical_str}"
                ),
            }
        }
        Err(_) => writeln!(
            w,
            "Resolves: {resolved_str} {dim}(canonicalize failed){reset}"
        ),
    }
}

const MAX_DISPLAY_LINES: usize = 3;

/// Print a one-line non-interactive banner on /dev/tty announcing an
/// unprivileged command that is about to run. Best-effort: silently
/// returns Ok if /dev/tty cannot be opened (headless daemon).
pub fn display_banner(req: &ValidatedRequest) -> io::Result<()> {
    let mut tty = match OpenOptions::new().write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let Style { dim, reset, .. } = style();
    let cmd = command_summary(req);
    if req.forward_agent {
        writeln!(tty, "{dim}\u{25b6}{reset} {cmd} {dim}(agent forwarded){reset}")?;
    } else {
        writeln!(tty, "{dim}\u{25b6}{reset} {cmd}")?;
    }
    Ok(())
}

/// Print a one-line dim notice on /dev/tty (e.g. "stopped by <session>").
/// Best-effort: silently returns Ok if /dev/tty cannot be opened.
pub fn display_notice(msg: &str) -> io::Result<()> {
    let mut tty = match OpenOptions::new().write(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let Style { dim, reset, .. } = style();
    writeln!(tty, "{dim}\u{25a0}{reset} {msg}")
}

/// Display the command result on /dev/tty. Truncate stdout/stderr to 3 lines.
pub fn display_result(resp: &Response) -> io::Result<()> {
    let mut tty = OpenOptions::new().write(true).open("/dev/tty")?;
    write_result(&mut tty, resp)
}

/// Write the command result to any writer. Truncate stdout/stderr to 3 lines.
pub fn write_result(w: &mut impl Write, resp: &Response) -> io::Result<()> {
    let Style { bold, dim, reset, .. } = style();

    match resp.status {
        Status::Ok => {
            let exit_code = resp.exit_code();
            let multi_stage = resp.stages.len() > 1;

            if multi_stage {
                // Show all exit codes for multi-stage
                let codes: Vec<String> =
                    resp.stages.iter().map(|s| s.exit_code.to_string()).collect();
                let label = format!("exit [{}]", codes.join(", "));
                if exit_code == 0 {
                    writeln!(w, "{dim}{label}{reset}")?;
                } else {
                    writeln!(w, "{bold}{label}{reset}")?;
                }
            } else if exit_code == 0 {
                writeln!(w, "{dim}exit 0{reset}")?;
            } else {
                writeln!(w, "{bold}exit {exit_code}{reset}")?;
            }

            if let Some(ref b64) = resp.stdout {
                if let Ok(bytes) = B64.decode(b64) {
                    print_truncated(w, &bytes, "stdout")?;
                }
            }

            for (i, stage) in resp.stages.iter().enumerate() {
                if let Ok(bytes) = B64.decode(&stage.stderr) {
                    if !bytes.is_empty() {
                        let label = if multi_stage {
                            format!("stderr[{i}]")
                        } else {
                            "stderr".to_string()
                        };
                        print_truncated(w, &bytes, &label)?;
                    }
                }
            }
        }
        Status::Denied => {
            writeln!(w, "{dim}denied{reset}")?;
        }
        Status::Timeout => {
            writeln!(w, "{dim}timeout{reset}")?;
        }
        Status::Error => {
            let msg = resp.message.as_deref().unwrap_or("unknown error");
            writeln!(w, "{bold}error: {msg}{reset}")?;
        }
    }
    Ok(())
}

fn print_truncated(tty: &mut impl Write, bytes: &[u8], label: &str) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let Style { dim, reset, .. } = style();
    let truncated = lines.len() > MAX_DISPLAY_LINES;
    let shown = if truncated { &lines[..MAX_DISPLAY_LINES] } else { &lines };

    let trunc_tag = if truncated { ", truncated" } else { "" };
    writeln!(
        tty,
        "{dim}== {label} == ({} lines{trunc_tag}){reset}",
        lines.len()
    )?;
    for line in shown {
        writeln!(tty, "{line}")?;
    }
    Ok(())
}

/// Restores `tcsetattr` to a saved termios on drop. Manual restore would be
/// skipped on panic, leaving the user's TTY in raw (no-echo, non-canonical)
/// mode for subsequent shells.
struct TermiosGuard {
    fd: std::os::unix::io::RawFd,
    orig: libc::termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Read a single keypress from a file descriptor with a timeout using poll(2).
/// Switches the terminal to non-canonical mode so Enter is not required.
/// Returns None on timeout, Some(char) otherwise.
fn read_key_timeout(file: &File, timeout: Duration) -> io::Result<Option<u8>> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut raw = orig;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    // TCSAFLUSH (vs TCSANOW): atomically discard any input that has been
    // received but not yet read. Without this, a stray byte buffered in
    // canonical mode before the prompt arrived (a leftover Enter, a
    // mistyped keystroke, paste residue) is delivered immediately by
    // poll/read in the new raw mode; anything other than y/Y resolves as
    // Denied without the user touching the keyboard.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = TermiosGuard { fd, orig };

    let timeout_ms = timeout.as_millis() as i32;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret == 0 {
        return Ok(None);
    }

    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf[0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Property: the session grant is set only by an interactive `a` keypress
    //
    // Spec clause (Rung 2; proof obligation for the Rung 4 state-machine model
    // and the Rung 5 dispatch contract): the *only* signal that can set the
    // session-scoped unattended grant (invariant G7, barrier 2) is
    // `ApprovedAlways`, and `classify_key` emits `ApprovedAlways` iff the
    // keypress is `'a'`/`'A'` AND the request is unprivileged. No timeout, no
    // other key, and no privileged request can produce it. The dispatch side —
    // that `ApprovedAlways` grants only when the daemon is *eligible*, never
    // persists, and grants nothing otherwise — is covered by tests/approval.rs.
    //
    // The input domain `(Option<u8>, bool)` is tiny, so this is checked
    // exhaustively rather than sampled.
    #[test]
    fn prop_approved_always_only_from_a_key_when_unprivileged() {
        let approved_always = |key: Option<u8>, privileged: bool| {
            matches!(classify_key(key, privileged), PromptResult::ApprovedAlways)
        };
        for privileged in [false, true] {
            // Timeout (None) never approves-always.
            assert!(!approved_always(None, privileged));
            for byte in 0u8..=255 {
                let is_a = byte == b'a' || byte == b'A';
                assert_eq!(
                    approved_always(Some(byte), privileged),
                    is_a && !privileged,
                    "classify_key({byte:?}, privileged={privileged}) ApprovedAlways mismatch"
                );
            }
        }

        // Corollary: a privileged request can never yield ApprovedAlways, and
        // 'y' is the only Approved source.
        for byte in 0u8..=255 {
            assert!(!matches!(
                classify_key(Some(byte), true),
                PromptResult::ApprovedAlways
            ));
            let is_y = byte == b'y' || byte == b'Y';
            assert_eq!(
                matches!(classify_key(Some(byte), true), PromptResult::Approved),
                is_y
            );
        }
    }

    fn render_resolves(cmd_name: &str) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let st = Style { bold: "B", dim: "D", reset: "R", root: "ROOT", root_boundary: "RB", user: "USR" };
        write_resolves_line(&mut buf, cmd_name, &st).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// Every stage of a plan is rendered with its run-as tag and its own
    /// resolved binary — the structural fix for the vacuous single
    /// `/usr/bin/bash` resolves line. A `System` stage is flagged opaque.
    #[test]
    fn plan_stages_render_per_leaf_privilege_and_resolves() {
        use crate::protocol::{Plan, Request, RunAs, ShellProc, ValidatedRequest};

        let plan = Plan::Run {
            steps: vec![
                Plan::RunAs {
                    who: RunAs::Root,
                    body: Box::new(Plan::Exec { argv: vec!["true".into()] }),
                },
                Plan::RunAs {
                    who: RunAs::User { name: "alice".into() },
                    body: Box::new(Plan::Exec { argv: vec!["true".into()] }),
                },
                Plan::Shell {
                    shell: ShellProc::Sh,
                    script: "echo hi".into(),
                },
            ],
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            false,
            false,
        ))
        .expect("valid");

        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = Style { bold: "", dim: "", reset: "", root: "", root_boundary: "", user: "" };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");

        // Privilege is now shown by color, not text tags — the old brackets are gone.
        assert!(!out.contains("[ROOT]"), "run-as tag should be color, not text: {out}");
        assert!(!out.contains("[as alice]"), "run-as tag should be color, not text: {out}");
        // The Shell leaf is still flagged opaque in the resolve block.
        assert!(
            out.contains("opaque — resolves only the shell"),
            "Shell stage must be flagged opaque: {out}"
        );
        // One consolidated resolve block, above a single Steps block.
        assert_eq!(
            out.matches("Resolves:").count(),
            1,
            "a single consolidated resolve block: {out}"
        );
        let resolves_at = out.find("Resolves:").unwrap();
        let steps_at = out.find("Steps:").expect("a Steps block");
        assert!(resolves_at < steps_at, "resolve block must precede the steps: {out}");
        // The three leaves appear in the Steps block.
        assert!(out.contains("sh -c 'echo hi'"), "shell leaf in steps: {out}");
    }

    /// The resolve block de-duplicates: a binary run by several stages appears
    /// once. Uses a name guaranteed absent from PATH so the resolution is
    /// deterministic (`(not found in PATH)`), then asserts it shows up once
    /// despite two stages using it.
    #[test]
    fn resolve_block_dedupes_repeated_binary() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let missing = "sudo-proxy-no-such-binary-xyz";
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec { argv: vec![missing.into(), "a".into()] },
                Plan::Exec { argv: vec![missing.into(), "b".into()] },
                Plan::Exec { argv: vec!["echo".into(), "done".into()] },
            ],
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            false,
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = Style { bold: "", dim: "", reset: "", root: "", root_boundary: "", user: "" };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        // Two stages run the missing binary, but it resolves once in the block.
        assert_eq!(
            out.matches("(not found in PATH)").count(),
            1,
            "repeated binary must de-duplicate in the resolve block: {out}"
        );
        // ...while both invocations still appear in the Steps block.
        assert!(out.contains("Steps:"), "{out}");
        assert_eq!(
            out.matches(missing).count(),
            3,
            "missing binary: once in resolves + twice in steps: {out}"
        );
    }

    /// `command_summary` threads `sudo` onto each leaf for a privileged request
    /// (never a single `sudo sh -c`), and adds nothing for an unprivileged one.
    #[test]
    fn command_threads_ambient_sudo_for_privileged_request() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let exec = |a: &[&str]| Plan::Exec { argv: a.iter().map(|s| s.to_string()).collect() };
        let mk = |privileged: bool| {
            let plan = Plan::Run { steps: vec![exec(&["id", "-un"]), exec(&["id", "-u"])] };
            ValidatedRequest::validate(Request::new_plan(
                String::new(),
                "t".into(),
                plan,
                std::collections::HashMap::new(),
                String::new(),
                privileged,
                false,
            ))
            .expect("valid")
        };
        assert_eq!(command_summary(&mk(true)), "sudo id -un && sudo id -u");
        assert_eq!(command_summary(&mk(false)), "id -un && id -u");
    }

    // Shared sentinel style for the coloring tests: LIGHT = ambient root,
    // BRIGHT = run-as boundary, R = reset.
    fn color_style() -> Style {
        Style { bold: "", dim: "", reset: "R", root: "LIGHT", root_boundary: "BRIGHT", user: "YEL" }
    }

    /// Combination B — single escalated leaf amid default ones (unprivileged
    /// request plus one `run-as root`): the run-as leaf is bright red, the rest
    /// default, and the operator is NOT tinted (the group is not all-escalated).
    #[test]
    fn single_runas_is_bright_red_rest_default() {
        use crate::protocol::{Plan, Request, RunAs, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec { argv: vec!["echo".into(), "hi".into()] },
                Plan::RunAs {
                    who: RunAs::Root,
                    body: Box::new(Plan::Exec { argv: vec!["whoami".into()] }),
                },
            ],
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            false, // unprivileged: ambient Default, only the run-as leaf escalates
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = color_style();
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("BRIGHTsudo whoamiR"), "run-as leaf must be bright red: {out}");
        assert!(
            out.contains("echo hi") && !out.contains("LIGHTecho") && !out.contains("BRIGHTecho"),
            "the default leaf must stay uncolored: {out}"
        );
        // Mixed group → operator not tinted.
        assert!(!out.contains("LIGHT &&"), "operator must not be tinted in a mixed group: {out}");
    }

    /// Combination A — wholly escalated (`privileged: true`, no `run-as`): every
    /// leaf is light red, the operator is tinted too, and nothing is bright.
    #[test]
    fn whole_escalated_plan_is_light_red_with_tinted_operator() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec { argv: vec!["echo".into(), "a".into()] },
                Plan::Exec { argv: vec!["echo".into(), "b".into()] },
            ],
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            true, // privileged → ambient root for every leaf
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = color_style();
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("LIGHTsudo echo aR"), "leaf a must be light red: {out}");
        assert!(out.contains("LIGHTsudo echo bR"), "leaf b must be light red: {out}");
        assert!(out.contains("LIGHT &&R"), "operator must be tinted in an all-root group: {out}");
        assert!(!out.contains("BRIGHT"), "no bright red without an explicit run-as: {out}");
    }

    /// Combination C — wholly escalated AND one explicit `run-as root`: ambient
    /// leaves light red, the run-as leaf bright red (exactly one), operator tinted.
    #[test]
    fn escalated_plan_with_runas_is_light_red_one_bright() {
        use crate::protocol::{Plan, Request, RunAs, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec { argv: vec!["id".into(), "-un".into()] },
                Plan::RunAs {
                    who: RunAs::Root,
                    body: Box::new(Plan::Exec { argv: vec!["whoami".into()] }),
                },
            ],
        };
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            true, // privileged → ambient root
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = color_style();
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("LIGHTsudo id -unR"), "ambient leaf must be light red: {out}");
        assert_eq!(
            out.matches("BRIGHT").count(),
            1,
            "exactly the run-as leaf is bright red: {out}"
        );
        assert!(out.contains("BRIGHTsudo whoamiR"), "run-as leaf must be bright red: {out}");
        assert!(out.contains("LIGHT &&R"), "operator tinted in an all-root group: {out}");
    }

    /// A simple single unprivileged command keeps the classic one-line
    /// `Resolves:` form (no numbered stage block).
    #[test]
    fn single_plain_command_uses_compact_resolves() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            Plan::Exec { argv: vec!["true".into()] },
            std::collections::HashMap::new(),
            String::new(),
            false,
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = Style { bold: "", dim: "", reset: "", root: "", root_boundary: "", user: "" };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.starts_with("Resolves:"), "compact form expected: {out}");
        assert!(!out.contains("1. "), "no numbered block for a single plain stage: {out}");
    }

    #[test]
    fn style_for_honors_no_color() {
        let on = style_for(false);
        assert_eq!(on.bold, "\x1b[1m");
        assert_eq!(on.dim, "\x1b[2m");
        assert_eq!(on.reset, "\x1b[0m");

        let off = style_for(true);
        assert_eq!(off.bold, "");
        assert_eq!(off.dim, "");
        assert_eq!(off.reset, "");
    }

    #[test]
    fn alert_for_honors_env() {
        let on = alert_for(false, false);
        assert_eq!(on.bell, "\x07");
        assert_eq!(on.blink_on, "\x1b[5m");
        assert_eq!(on.blink_off, "\x1b[25m");

        let off = alert_for(true, true);
        assert_eq!(off.bell, "");
        assert_eq!(off.blink_on, "");
        assert_eq!(off.blink_off, "");

        // Bell and blink are independent — each flag gates only its own cue.
        let no_bell = alert_for(true, false);
        assert_eq!(no_bell.bell, "");
        assert_eq!(no_bell.blink_on, "\x1b[5m");
        assert_eq!(no_bell.blink_off, "\x1b[25m");

        let no_blink = alert_for(false, true);
        assert_eq!(no_blink.bell, "\x07");
        assert_eq!(no_blink.blink_on, "");
        assert_eq!(no_blink.blink_off, "");
    }

    fn render_question(alert: &Alert) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_question_line(&mut buf, alert, "Execute as root?", "[y/N]", 60).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn write_question_line_emits_and_suppresses_cues() {
        // Default (all cues on): BEL and the blink pair are present, wrapping the
        // question text, which itself is always rendered.
        let on = render_question(&alert_for(false, false));
        assert!(on.contains('\x07'), "bell byte missing: {on:?}");
        assert!(on.contains("\x1b[5m"), "blink-on missing: {on:?}");
        assert!(on.contains("\x1b[25m"), "blink-off missing: {on:?}");
        assert!(on.contains("Execute as root? [y/N]"), "question text missing: {on:?}");

        // Both cues suppressed: none of the three escapes appear, but the
        // question line is otherwise identical and still printed.
        let off = render_question(&alert_for(true, true));
        assert!(!off.contains('\x07'), "bell leaked: {off:?}");
        assert!(!off.contains("\x1b[5m"), "blink-on leaked: {off:?}");
        assert!(!off.contains("\x1b[25m"), "blink-off leaked: {off:?}");
        assert!(off.contains("Execute as root? [y/N]"), "question text missing: {off:?}");
        assert_eq!(off, "Execute as root? [y/N] (60s timeout, default=N) ");
    }

    /// After the answer (or timeout) the blinking question is redrawn plain, in
    /// place; with blink suppressed there is nothing to redraw.
    #[test]
    fn settled_question_line_stops_the_blink() {
        let mut buf: Vec<u8> = Vec::new();
        write_settled_question_line(&mut buf, &alert_for(false, false), "Execute?", "[y/N]", 60)
            .expect("write");
        let s = String::from_utf8(buf).expect("utf8");
        assert_eq!(s, "\r\x1b[2KExecute? [y/N] (60s timeout, default=N) ");
        assert!(!s.contains("\x1b[5m") && !s.contains('\x07'), "no blink, no bell: {s:?}");

        let mut buf: Vec<u8> = Vec::new();
        write_settled_question_line(&mut buf, &alert_for(false, true), "Execute?", "[y/N]", 60)
            .expect("write");
        assert!(buf.is_empty(), "blink suppressed: nothing to redraw");
    }

    #[test]
    fn truncate_for_display_bounds_long_commands() {
        let short = "ls -l /tmp";
        assert_eq!(truncate_for_display(short), short);

        let long: String = "x".repeat(MAX_DISPLAY_CMD_CHARS + 500);
        let out = truncate_for_display(&long);
        assert!(out.chars().count() < long.chars().count());
        assert!(out.contains("more chars hidden"));
        // Exactly at the boundary is not truncated.
        let exact: String = "y".repeat(MAX_DISPLAY_CMD_CHARS);
        assert_eq!(truncate_for_display(&exact), exact);
    }

    #[test]
    fn resolves_line_path_search_no_symlink() {
        // `true` resolves via PATH and is unlikely to be symlinked.
        // The line should mention the resolved path; arrow only if canonical differs.
        let out = render_resolves("true");
        assert!(out.starts_with("Resolves: "), "got: {out:?}");
        assert!(out.trim().ends_with('e') || out.contains("->"));
    }

    #[test]
    fn resolves_line_absolute_symlink_shows_arrow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target.sh");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();

        let link = tmp.path().join("foo");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let out = render_resolves(link.to_str().unwrap());
        assert!(
            out.contains("->"),
            "absolute path that is a symlink must show '->': {out:?}"
        );
        // Bold marker B should wrap the symlink redirect for visibility.
        assert!(out.contains('B'), "expected bold marker in: {out:?}");
        assert!(
            out.contains(target.to_str().unwrap()),
            "must show canonical target {target:?} in: {out:?}"
        );
    }

    #[test]
    fn resolves_line_not_in_path() {
        let out = render_resolves("definitely-no-such-binary-9f2a");
        assert!(out.contains("not found in PATH"), "got: {out:?}");
    }

    /// If a panic unwinds out of the raw-mode block, the TermiosGuard must
    /// still call tcsetattr to restore the saved flags. Without the guard,
    /// the user's tty would be left with ICANON/ECHO cleared.
    #[test]
    fn termios_guard_restores_on_panic() {
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", io::Error::last_os_error());

        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut orig) }, 0);

        // Pre-condition: the freshly-opened pty has ICANON and ECHO set.
        assert!(orig.c_lflag & libc::ICANON != 0);
        assert!(orig.c_lflag & libc::ECHO != 0);

        let result = std::panic::catch_unwind(|| {
            let _g = TermiosGuard { fd: slave, orig };
            let mut raw = orig;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            unsafe { libc::tcsetattr(slave, libc::TCSANOW, &raw) };
            panic!("synthetic panic mid-prompt");
        });
        assert!(result.is_err());

        let mut after: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut after) }, 0);
        assert_ne!(
            after.c_lflag & libc::ICANON,
            0,
            "ICANON must be restored after panic"
        );
        assert_ne!(
            after.c_lflag & libc::ECHO,
            0,
            "ECHO must be restored after panic"
        );

        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// Regression: input pending in the line-discipline buffer at the
    /// moment the prompt switches to raw mode must be discarded, not
    /// returned by the next read. Without TCSAFLUSH, a stray byte queued
    /// before the prompt was rendered would be delivered immediately and
    /// — unless it happens to be y/Y — resolve as Denied with the user
    /// having pressed nothing.
    #[test]
    fn read_key_timeout_discards_pre_prompt_input() {
        use std::os::unix::io::FromRawFd;
        use std::time::Duration;

        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", io::Error::last_os_error());

        // Stuff the input queue with a stray byte plus a newline so the
        // line discipline (still ICANON at this point) commits it.
        let stray = b"q\n";
        let n = unsafe {
            libc::write(master, stray.as_ptr() as *const libc::c_void, stray.len())
        };
        assert_eq!(n as usize, stray.len(), "write to pty master failed");
        // Give the kernel a moment to enqueue.
        std::thread::sleep(Duration::from_millis(50));

        let slave_file = unsafe { File::from_raw_fd(slave) };
        let result =
            read_key_timeout(&slave_file, Duration::from_millis(200)).expect("read_key_timeout");
        assert_eq!(
            result, None,
            "buffered input must be flushed by TCSAFLUSH (got {result:?})"
        );

        // slave_file's Drop closes slave.
        unsafe {
            libc::close(master);
        }
    }

    // === Display grouping: Steps ≡ Command ≡ executed plan ================
    //
    // Security-relevant display property: the `Steps:` block the operator
    // reviews, the `Command:` line they may paste, and the plan the executor
    // runs must all mean the same thing. Checked three ways below: golden
    // layouts for the agreed examples, a `bash` parse-tree comparison over
    // random plans, and a differential run (executor vs `sh`) over random
    // side-effect-free plans.

    use crate::protocol::{Plan, Request, RunAs, ShellProc, ValidatedRequest};

    fn ex(argv: &[&str]) -> Plan {
        Plan::Exec { argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    fn mk_req(plan: Plan, privileged: bool) -> ValidatedRequest {
        ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            plan,
            std::collections::HashMap::new(),
            String::new(),
            privileged,
            false,
        ))
        .expect("valid")
    }

    /// The uncoloured `Steps:` block body, as the operator sees it.
    fn steps_block(req: &ValidatedRequest) -> String {
        let mut buf = Vec::new();
        let lay = layout(&req.exec_plan(), &ambient_ctx(req.privileged));
        write_steps(&mut buf, &lay, &style_for(true)).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        out.strip_prefix("Steps:\n").expect("Steps header").to_string()
    }

    /// The agreed layouts (examples 1–4 of the design discussion; 5–6 are the
    /// corpus cases 23 and 22, covered in `tests/manual_corpus.rs`).
    #[test]
    fn steps_layout_matches_agreed_examples() {
        // 1. a && (b || c) — the case the old layout showed as (a && b) || c.
        let req = mk_req(
            Plan::Run { steps: vec![ex(&["false"]), Plan::Alt { steps: vec![ex(&["true"]), ex(&["echo", "RAN"])] }] },
            false,
        );
        assert_eq!(command_summary(&req), "false && (true || echo RAN)");
        assert_eq!(steps_block(&req), "0  false && (\n1    true ||\n2    echo RAN\n   )\n");

        // 2. (a; b) && c — a group with no line before its `(`.
        let req = mk_req(
            Plan::Run { steps: vec![Plan::Seq { steps: vec![ex(&["false"]), ex(&["true"])] }, ex(&["echo", "C"])] },
            false,
        );
        assert_eq!(command_summary(&req), "(false; true) && echo C");
        assert_eq!(steps_block(&req), "   (\n0    false ;\n1    true ) &&\n2  echo C\n");

        // 3. (a || b) && c — mixed operators always get their own group.
        let req = mk_req(
            Plan::Run { steps: vec![Plan::Alt { steps: vec![ex(&["false"]), ex(&["true"])] }, ex(&["echo", "C"])] },
            false,
        );
        assert_eq!(command_summary(&req), "(false || true) && echo C");
        assert_eq!(steps_block(&req), "   (\n0    false ||\n1    true ) &&\n2  echo C\n");

        // 4. Showcase — export scope, parenthesized pipe, `sudo` on the run-as leaf.
        let req = mk_req(
            Plan::Setenv {
                key: "LANG".into(),
                value: "C".into(),
                body: Box::new(Plan::Run {
                    steps: vec![
                        ex(&["echo", "a;b"]),
                        Plan::Pipe { stages: vec![ex(&["echo", "hello world"]), ex(&["wc", "-w"])] },
                        Plan::RunAs { who: RunAs::Root, body: Box::new(ex(&["id", "-un"])) },
                    ],
                }),
            },
            false,
        );
        assert_eq!(
            command_summary(&req),
            "(export LANG=C; (echo 'a;b' && (echo 'hello world' | wc -w) && sudo id -un))"
        );
        assert_eq!(
            steps_block(&req),
            "   (\n\
             0    export LANG=C ; (\n\
             1      echo 'a;b' && (\n\
             2        echo 'hello world' |\n\
             3        wc -w ) &&\n\
             4      sudo id -un\n\
             \x20    )\n\
             \x20  )\n"
        );
    }

    /// Adjacent openers are written `( (`: bash reads `((` as arithmetic.
    #[test]
    fn command_never_opens_with_double_paren() {
        let req = mk_req(
            Plan::Seq {
                steps: vec![
                    ex(&["echo", "x"]),
                    Plan::Run {
                        steps: vec![
                            Plan::Pipe { stages: vec![ex(&["echo", "a"]), ex(&["cat"])] },
                            ex(&["echo", "kept"]),
                        ],
                    },
                ],
            },
            false,
        );
        let cmd = command_summary(&req);
        assert_eq!(cmd, "echo x; ( (echo a | cat) && echo kept)");
        assert!(!cmd.contains("(("), "{cmd}");
    }

    /// Without colour, the Steps block still says which steps escalate.
    #[test]
    fn steps_show_escalation_as_text() {
        let req = mk_req(
            Plan::Seq {
                steps: vec![
                    Plan::RunAs { who: RunAs::Root, body: Box::new(ex(&["id"])) },
                    Plan::RunAs { who: RunAs::User { name: "nobody".into() }, body: Box::new(ex(&["id"])) },
                ],
            },
            false,
        );
        assert_eq!(steps_block(&req), "0  sudo id ;\n1  sudo -u nobody id\n");
    }

    /// `bash`'s canonical form of a script (`declare -f` of a wrapper
    /// function), whitespace-squeezed. Two texts with equal canonical forms
    /// parse to the same shell tree.
    fn bash_tree(text: &str) -> String {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("f() {{\n{text}\n}}\ndeclare -f f"))
            .output()
            .expect("run bash");
        assert!(out.status.success(), "bash rejected:\n{text}\n{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn pick<'a>(rng: &mut crate::prop::Rng, xs: &[&'a str]) -> &'a str {
        xs[rng.below(xs.len())]
    }

    /// Any plan, including run-as, opaque shells, redirections and argv that
    /// needs quoting. Only parsed, never run.
    fn random_any(rng: &mut crate::prop::Rng, depth: usize) -> Plan {
        const WORDS: &[&str] = &["a", "x y", "a;b", "$v", "(", ")", "it's", "&&", "-n", "*"];
        let leaf = |rng: &mut crate::prop::Rng| match rng.below(8) {
            0 => Plan::Shell { shell: ShellProc::Sh, script: "echo s; exit 1".into() },
            _ => Plan::Exec {
                argv: (0..1 + rng.below(3)).map(|_| pick(rng, WORDS).to_string()).collect(),
            },
        };
        if depth == 0 || rng.below(4) == 0 {
            return leaf(rng);
        }
        let kids = |rng: &mut crate::prop::Rng, min: usize| -> Vec<Plan> {
            (0..min + rng.below(3)).map(|_| random_any(rng, depth - 1)).collect()
        };
        match rng.below(11) {
            0 => Plan::Run { steps: kids(rng, 1) },
            1 => Plan::Alt { steps: kids(rng, 1) },
            2 => Plan::Seq { steps: kids(rng, 1) },
            3 => Plan::Pipe { stages: (0..2 + rng.below(2)).map(|_| leaf(rng)).collect() },
            4 => Plan::Chdir { dir: "/tmp/a b".into(), body: Box::new(random_any(rng, depth - 1)) },
            5 => Plan::Setenv { key: "TZ".into(), value: "x y".into(), body: Box::new(random_any(rng, depth - 1)) },
            6 => Plan::RunAs { who: RunAs::Root, body: Box::new(random_any(rng, depth - 1)) },
            7 => Plan::RunAs { who: RunAs::User { name: "nobody".into() }, body: Box::new(random_any(rng, depth - 1)) },
            8 => Plan::Redirect {
                stream: [Stream::Stdout, Stream::Stderr, Stream::Both][rng.below(3)],
                target: RedirTarget::File { path: "/tmp/o u t".into(), mode: crate::protocol::WriteMode::Append },
                body: Box::new(leaf(rng)),
            },
            9 => Plan::WithStdinFrom { path: "/dev/null".into(), body: Box::new(leaf(rng)) },
            _ => Plan::WithAcceptedExitCodes { codes: vec![1], body: Box::new(random_any(rng, depth - 1)) },
        }
    }

    // Spec clause (Rung 2): for every plan, the `Steps:` text and the
    // `Command:` line parse, under bash, to the same tree.
    #[test]
    fn prop_steps_and_command_parse_to_the_same_tree() {
        let mut rng = crate::prop::Rng::new(0x5EED_57E9_u64);
        for _ in 0..300 {
            let plan = random_any(&mut rng, 4);
            let req = mk_req(plan, rng.below(2) == 0);
            let steps = steps_shell_text(&req);
            let cmd = command_summary(&req);
            assert!(!cmd.contains("(("), "{cmd}");
            assert_eq!(bash_tree(&steps), bash_tree(&cmd), "Steps:\n{steps}\nCommand: {cmd}");
        }
    }

    /// Side-effect-free, privilege-free plans whose stdout reveals which leaves
    /// ran, and in which directory / environment.
    fn random_runnable(rng: &mut crate::prop::Rng, depth: usize) -> Plan {
        let leaf = |rng: &mut crate::prop::Rng| match rng.below(8) {
            0 => ex(&["false"]),
            1 => ex(&["true"]),
            2 => ex(&["pwd"]),
            3 => ex(&["printenv", "TZ"]),
            4 => Plan::Shell { shell: ShellProc::Sh, script: "echo s; exit 1".into() },
            _ => ex(&["echo", pick(rng, &["1", "2", "3", "4", "5"])]),
        };
        if depth == 0 || rng.below(4) == 0 {
            return leaf(rng);
        }
        let kids = |rng: &mut crate::prop::Rng| -> Vec<Plan> {
            (0..1 + rng.below(3)).map(|_| random_runnable(rng, depth - 1)).collect()
        };
        match rng.below(8) {
            0 => Plan::Run { steps: kids(rng) },
            1 => Plan::Alt { steps: kids(rng) },
            2 => Plan::Seq { steps: kids(rng) },
            3 => Plan::Pipe { stages: vec![leaf(rng), ex(&["cat"])] },
            4 => Plan::Chdir { dir: "/tmp".into(), body: Box::new(random_runnable(rng, depth - 1)) },
            5 => Plan::Setenv { key: "TZ".into(), value: "UTC".into(), body: Box::new(random_runnable(rng, depth - 1)) },
            6 => Plan::Redirect { stream: Stream::Stdout, target: RedirTarget::DevNull, body: Box::new(leaf(rng)) },
            _ => Plan::WithStdinFrom { path: "/dev/null".into(), body: Box::new(ex(&["cat"])) },
        }
    }

    fn run_sh(text: &str) -> String {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(text)
            .env_clear()
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir("/")
            .output()
            .expect("run sh");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    // Spec clause (Rung 2): the displayed text means what runs. For random
    // side-effect-free plans, the executor's output equals `sh` running the
    // `Command:` line and `sh` running the `Steps:` text.
    #[test]
    fn prop_displayed_text_runs_like_the_executor() {
        let mut rng = crate::prop::Rng::new(0xD15B_1A7E_u64);
        for _ in 0..150 {
            let req = mk_req(random_runnable(&mut rng, 4), false);
            let resp = crate::executor::exec_direct(&req, &std::collections::HashMap::new());
            let via_plan =
                String::from_utf8_lossy(&B64.decode(resp.stdout.as_deref().unwrap_or("")).expect("b64")).into_owned();
            let cmd = command_summary(&req);
            let steps = steps_shell_text(&req);
            assert_eq!(run_sh(&cmd), via_plan, "Command: {cmd}");
            assert_eq!(run_sh(&steps), via_plan, "Steps:\n{steps}");
        }
    }
}
