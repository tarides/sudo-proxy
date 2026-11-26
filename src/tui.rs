use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::executor::{LeafPrivilege, LeafView, PreparedRequest, Resolved};
use crate::protocol::{
    escape_dangerous, Plan, RedirTarget, Response, RunAs, Status, Stream, ValidatedRequest,
};

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
        .map(|l| {
            format!(
                "{}{}{}",
                "  ".repeat(l.depth),
                l.text,
                l.comment(&style_for(true))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Ambient escalation context: a `privileged` request runs every leaf as root,
/// mirroring the executor, so each leaf gets its own `sudo` (never a single
/// `sudo sh -c '…'`, which would put a shell back on the root path) and reads
/// light red. A `run-as` node overrides it per subtree.
fn ambient_ctx(privileged: bool) -> LayCtx {
    LayCtx {
        sudo: if privileged {
            "sudo ".into()
        } else {
            String::new()
        },
        accepted: Vec::new(),
        esc: Esc {
            uid: if privileged {
                StepUid::Root
            } else {
                StepUid::Default
            },
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
/// - a `cd`/`export` scope is `( cd D && ( body ) )`: nothing leaks out of it,
///   even when the whole plan is the scope (the `Command:` line is pasted into a
///   stateful shell), and a failed `cd` skips the body instead of running it in
///   the previous directory.
enum Lay {
    /// One command line: `cmd` (with any `sudo` prefix) plus its redirections.
    /// A `scope` leaf is the `cd`/`export` header of a scope, never escalated.
    Leaf {
        cmd: String,
        redir: String,
        esc: Esc,
        scope: bool,
        /// A remark for the `Steps:` block only, printed as a trailing shell
        /// comment (e.g. which exit codes count as success). Never part of the
        /// `Command:` line.
        note: String,
    },
    /// Explicit parentheses, with redirections applied to the whole group.
    Group { inner: Box<Lay>, redir: String },
    /// Two or more items joined by one operator.
    Chain { op: Op, items: Vec<Lay> },
}

/// The `sudo` prefix and colouring threaded down from the enclosing `run-as`,
/// and the exit codes the enclosing `with-accepted-exit-codes` treats as
/// success (the innermost one wins, as in the executor).
struct LayCtx {
    sudo: String,
    esc: Esc,
    accepted: Vec<i32>,
}

fn layout(plan: &Plan, ctx: &LayCtx) -> Lay {
    match plan {
        Plan::Exec { argv } => lay_leaf(format!("{}{}", ctx.sudo, shell_join(argv)), ctx),
        Plan::Shell { shell, script } => {
            let bin = match shell {
                crate::protocol::ShellProc::Sh => "sh",
                crate::protocol::ShellProc::Bash => "bash",
            };
            lay_leaf(format!("{}{bin} -c {}", ctx.sudo, shquote(script)), ctx)
        }
        Plan::Pipe { stages } => lay_group(lay_chain(Op::Pipe, stages, ctx)),
        Plan::Run { steps } => lay_chain(Op::And, steps, ctx),
        Plan::Alt { steps } => lay_chain(Op::Or, steps, ctx),
        Plan::Seq { steps } => lay_chain(Op::Seq, steps, ctx),
        Plan::Redirect {
            stream,
            target,
            body,
        } => lay_redirect(layout(body, ctx), redir_suffix(*stream, target)),
        Plan::WithStdinFrom { path, body } => {
            lay_redirect(layout(body, ctx), format!("< {}", shquote(path)))
        }
        Plan::Setenv { key, value, body } => lay_scope(
            format!("export {key}={}", shquote(value)),
            layout(body, ctx),
        ),
        Plan::Chdir { dir, body } => lay_scope(format!("cd {}", shquote(dir)), layout(body, ctx)),
        Plan::RunAs { who, body } => {
            let ctx2 = match who {
                RunAs::Root => LayCtx {
                    sudo: "sudo ".into(),
                    esc: Esc {
                        uid: StepUid::Root,
                        boundary: true,
                    },
                    accepted: ctx.accepted.clone(),
                },
                RunAs::User { name } => LayCtx {
                    sudo: format!("sudo -u {} ", shquote(name)),
                    esc: Esc {
                        uid: StepUid::User,
                        boundary: true,
                    },
                    accepted: ctx.accepted.clone(),
                },
            };
            layout(body, &ctx2)
        }
        Plan::WithAcceptedExitCodes { codes, body } => {
            let ctx2 = LayCtx {
                sudo: ctx.sudo.clone(),
                esc: ctx.esc,
                accepted: codes.clone(),
            };
            layout(body, &ctx2)
        }
    }
}

/// A command leaf. Under `with-accepted-exit-codes`, the command is wrapped so
/// that, as shell, an accepted non-zero exit counts as success exactly as it
/// does for the executor's `&&` / `||` / pipe status:
/// `{ cmd || [ $? -eq 1 ]; }`, or with several codes
/// `{ cmd || case $? in 1|2) ;; *) false ;; esac; }`. The `Steps:` block also
/// spells the accepted codes out in a trailing comment.
fn lay_leaf(cmd: String, ctx: &LayCtx) -> Lay {
    let mut codes: Vec<i32> = ctx.accepted.iter().copied().filter(|&c| c != 0).collect();
    codes.sort_unstable();
    codes.dedup();
    let (cmd, note) = match codes.as_slice() {
        [] => (cmd, String::new()),
        [c] => (
            format!("{{ {cmd} || [ $? -eq {c} ]; }}"),
            format!("exit {c} accepted"),
        ),
        cs => {
            let list = cs.iter().map(i32::to_string).collect::<Vec<_>>();
            (
                format!(
                    "{{ {cmd} || case $? in {}) ;; *) false ;; esac; }}",
                    list.join("|")
                ),
                format!("exits {} accepted", list.join(", ")),
            )
        }
    };
    Lay::Leaf {
        cmd,
        redir: String::new(),
        esc: ctx.esc,
        scope: false,
        note,
    }
}

/// Parenthesize, unless the layout already is a bare group.
fn lay_group(l: Lay) -> Lay {
    match l {
        g @ Lay::Group { .. } if matches!(&g, Lay::Group { redir, .. } if redir.is_empty()) => g,
        other => Lay::Group {
            inner: Box::new(other),
            redir: String::new(),
        },
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
        Lay::Leaf {
            cmd,
            redir,
            esc,
            scope,
            note,
        } => Lay::Leaf {
            cmd,
            redir: join_suffix(redir, &suffix),
            esc,
            scope,
            note,
        },
        Lay::Group { inner, redir } => Lay::Group {
            inner,
            redir: join_suffix(redir, &suffix),
        },
        c @ Lay::Chain { .. } => Lay::Group {
            inner: Box::new(c),
            redir: suffix,
        },
    }
}

/// `( header && ( body ) )` — the scope's own parentheses keep `cd`/`export` from
/// leaking past it, and `&&` skips the body when the header fails (a failed
/// `cd` must not run the body in the previous directory; the executor refuses
/// it too).
fn lay_scope(header: String, body: Lay) -> Lay {
    let head = Lay::Leaf {
        cmd: header,
        redir: String::new(),
        esc: Esc {
            uid: StepUid::Default,
            boundary: false,
        },
        scope: true,
        note: String::new(),
    };
    Lay::Group {
        inner: Box::new(Lay::Chain {
            op: Op::And,
            items: vec![head, lay_group(body)],
        }),
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
        Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        }
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

/// Upper bound, in characters, on one `Steps:` line (its text and trailing
/// `# note`, not the gutter or indent), and on each name and path of the
/// `Resolves:` block and line. Two 80-column rows. The same anti-flooding
/// rationale as `MAX_DISPLAY_CMD_CHARS` (G4.3): one huge argument shown in full
/// on the plan render path would push the `[y/N]` question off-screen just as
/// it would on the `Command:` line.
const MAX_DISPLAY_LINE_CHARS: usize = 160;

/// Upper bound, in characters, on each request-derived metadata field shown at
/// the prompt (`reason`, `session`, `host`, `requester`, `version`, `id`,
/// `time`, each env `KEY=value`). They are validated for characters but not
/// for length, so a long one would flood the prompt like a long command
/// (G4.3). Matches the audit log's per-field bound.
const MAX_DISPLAY_FIELD_CHARS: usize = 256;

/// Upper bound on the number of entries of the `Resolves:` block, which could
/// otherwise list up to `MAX_PLAN_NODES` distinct binaries and push the
/// `[y/N]` question off-screen (G4.3).
const MAX_DISPLAY_RESOLVES: usize = MAX_DISPLAY_STAGES;

/// `Some((head, hidden))` when `s` has more than `max` chars: `head` is its
/// first `max` chars (a UTF-8 sequence is never split) and `hidden` the number
/// of chars cut. `None` when `s` fits. The one truncation rule behind
/// `truncate_for_display` and `clip`, so the two cannot drift apart.
fn split_at_chars(s: &str, max: usize) -> Option<(&str, usize)> {
    let (cut, _) = s.char_indices().nth(max)?;
    Some((&s[..cut], s[cut..].chars().count()))
}

/// Truncate an approval-prompt command string to a bounded number of
/// characters, appending an explicit marker when it was shortened.
pub fn truncate_for_display(s: &str) -> String {
    match split_at_chars(s, MAX_DISPLAY_CMD_CHARS) {
        None => s.to_string(),
        Some((head, hidden)) => {
            format!("{head}… [{hidden} more chars hidden — full command not shown]")
        }
    }
}

/// Clip plain (uncoloured) prompt text to `max` chars, appending the explicit
/// marker `… [N more chars hidden]` (`N` in chars) when it was shortened. The
/// same policy as `truncate_for_display`, for the other prompt lines.
fn clip(s: &str, max: usize) -> String {
    match split_at_chars(s, max) {
        None => s.to_string(),
        Some((head, hidden)) => format!("{head}… [{hidden} more chars hidden]"),
    }
}

/// Request- or filesystem-derived text as one prompt line shows it (a path, an
/// opaque reason, a plan error): forbidden characters escaped (#86), then
/// length-bounded (G4.3, #85). Escaping comes first so that the bound applies
/// to what is actually printed, which escaping can lengthen, and so that
/// clipping never cuts a raw control character.
fn shown(text: &str) -> String {
    clip(&escape_dangerous(text), MAX_DISPLAY_LINE_CHARS)
}

/// A filesystem path as the `Resolves:` lines show it: escaped like [`shown`],
/// but a long one is clipped in the **middle**, so its end, the binary's
/// name, stays visible (#101). The marker `…[N more chars hidden]…` sits
/// between two kept parts, so `/usr/bin/…[N more chars hidden]…/x` cannot be
/// read as `/usr/bin/x`. A `->` target and the `(user-writable)` marker are
/// added outside the clipped text.
fn shown_path(path: &str) -> String {
    let text = escape_dangerous(path);
    let n = text.chars().count();
    if n <= MAX_DISPLAY_LINE_CHARS {
        return text;
    }
    let tail = MAX_DISPLAY_LINE_CHARS / 2;
    let head = MAX_DISPLAY_LINE_CHARS - tail;
    let hidden = n - head - tail;
    let start: String = text.chars().take(head).collect();
    let end: String = text.chars().skip(n - tail).collect();
    format!("{start}…[{hidden} more chars hidden]…{end}")
}

/// Byte length of the CSI escape sequence (`ESC [`, parameter bytes, then a
/// final byte in `0x40..=0x7E`) starting at `s[i..]`, if one starts there.
fn csi_len(s: &[u8], i: usize) -> Option<usize> {
    if s.get(i) != Some(&0x1b) || s.get(i + 1) != Some(&b'[') {
        return None;
    }
    let end = s[i + 2..]
        .iter()
        .position(|b| (0x40..=0x7e).contains(b))
        .map_or(s.len(), |p| i + 2 + p + 1);
    Some(end - i)
}

/// [`clip`] for a line that already carries the daemon's own colour escapes.
/// A CSI sequence is copied through and counts as zero width, so `max` and the
/// hidden count `N` are both in *visible* chars (escapes excluded). When the
/// line is cut, its visible tail is dropped together with the escapes inside
/// it, `style.reset` is written so a colour span cut in the middle does not
/// bleed, and the marker is `{bold}… [N more chars hidden]{reset}`. A line that
/// fits is returned byte-identical.
///
/// Precondition: request-derived text contains no ESC (0x1B).
/// `has_dangerous_chars` (G4.1) rejects every control char below 0x20 except
/// tab (0x09), so every ESC in the line comes from `Style`. Tabs may appear in
/// request text; each counts as one char here, although a terminal may expand
/// it to up to 8 columns (see the Sn4.3 residual in `docs/assurance-case.md`).
///
/// On a `Steps:` line the clipped tail may hold the chain operator (`&&`, `||`,
/// `|`, `;`), a group's `(` opener or `)` closer, or a redirection (`> path`,
/// `2>&1`, `< path`); the `Command:` line still shows them as long as it stays
/// under `MAX_DISPLAY_CMD_CHARS`, and past that they are hidden there too
/// (the marker is shown). Keeping them out of the budget is #97.
fn clip_styled(s: &str, max: usize, style: &Style) -> String {
    let bytes = s.as_bytes();
    let mut visible = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        if let Some(n) = csi_len(bytes, i) {
            i += n;
            continue;
        }
        if visible == max {
            let Style { bold, reset, .. } = *style;
            let hidden = visible_chars(&s[i..]);
            return format!(
                "{}{reset}{bold}… [{hidden} more chars hidden]{reset}",
                &s[..i]
            );
        }
        visible += 1;
        i += s[i..].chars().next().map_or(1, char::len_utf8);
    }
    s.to_string()
}

/// Number of visible chars of `s`: the chars outside CSI escape sequences.
fn visible_chars(s: &str) -> usize {
    let bytes = s.as_bytes();
    let (mut n, mut i) = (0usize, 0usize);
    while i < s.len() {
        match csi_len(bytes, i) {
            Some(len) => i += len,
            None => {
                n += 1;
                i += s[i..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    n
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
        req: &PreparedRequest,
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
        req: &PreparedRequest,
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

/// The plan part of the prompt: the `Command:`/`Steps:`/`Resolves:` block.
///
/// It renders the request's own compiled views, the ones the `no_shell` check
/// read and the executor will spawn (issue #105). A [`PreparedRequest`] exists
/// only for a plan that compiled, so there is no error case to show.
fn write_plan_section<W: Write>(w: &mut W, req: &PreparedRequest, style: &Style) -> io::Result<()> {
    write_plan_stages(w, &req.exec_plan(), req.views(), req.privileged, style)
}

/// Display a privilege request on /dev/tty and ask for Y/N confirmation.
/// `eligible` gates whether the session-scoped `a` answer is offered (only for
/// unprivileged requests on a daemon whose `unattended_eligible` policy is set).
pub fn prompt_tty(
    req: &PreparedRequest,
    eligible: bool,
    timeout: Duration,
) -> io::Result<PromptResult> {
    let mut tty_w = OpenOptions::new().write(true).open("/dev/tty")?;
    let tty_r = File::open("/dev/tty")?;

    let st = style();
    let Style {
        bold, dim, reset, ..
    } = st;

    write_request_header(&mut tty_w, req, &st)?;
    write_request_meta(&mut tty_w, req, &st)?;

    // Render every stage the executor will run, each with its run-as context
    // and its resolved real binary. This is the structural guarantee the plan
    // model buys: the vacuous single `/usr/bin/bash` resolves line is replaced
    // by one resolved binary per literal stage, so a bundle of root effects can
    // no longer hide inside one opaque command. Built from the same
    // `compile_plan` walk the executor uses, so prompt and execution agree.
    write_plan_section(&mut tty_w, req, &st)?;

    write_env_line(&mut tty_w, req)?;
    write_inherit_line(&mut tty_w, req.inherit().map(|i| &**i), &st)?;

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
        // The grant is keyed by the request's `session` (issue #8): name it, so
        // the operator sees exactly which client `a` opens the gate for.
        writeln!(
            tty_w,
            "{dim}a = approve, and run later unprivileged requests from session \
             '{}' on this host without asking until the daemon exits (not saved){reset}",
            clip(&req.session, MAX_DISPLAY_FIELD_CHARS)
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
        PromptResult::ApprovedAlways if offer_always => {
            "Approved (unattended for this session name)"
        }
        PromptResult::ApprovedAlways => "Approved",
        PromptResult::Denied => "Denied",
    };
    // Answered or timed out: the question no longer needs attention.
    write_settled_question_line(&mut tty_w, &cues, question, choices, timeout.as_secs())?;
    writeln!(tty_w, "\n→ {label}")?;
    writeln!(tty_w, "{bold}━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")?;

    Ok(result)
}

/// Why this daemon's terminal accepts injected keystrokes, when the operator
/// started it anyway (`--allow-injectable-tty`, GHSA-cpmp-67wf-gwmx). Set once
/// at startup; every prompt then carries a warning line.
static INJECTABLE_TTY: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Record the injectable-terminal reasons shown in every prompt header.
pub fn set_injectable_tty_warning(reasons: Vec<String>) {
    let _ = INJECTABLE_TTY.set(reasons);
}

/// The prompt's warning line for an injectable terminal, or `None`. Each
/// reason is `<mechanism>: <how>`; the line names the mechanisms.
fn injectable_tty_line(reasons: &[String], style: &Style) -> Option<String> {
    if reasons.is_empty() {
        return None;
    }
    let Style { bold, reset, .. } = *style;
    Some(format!(
        "{bold}⚠ Other processes can type into this terminal ({}). \
         Approve only what you asked for.{reset}",
        reasons
            .iter()
            .map(|r| r.split(": ").next().unwrap_or(r).trim())
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

/// Write the prompt header: the `━━━ Privilege Request ━━━` title, the `From:`
/// line and, when the requester declared one, its self-identification (issue
/// #25). A requester declaring itself an AI (`ai` / `ai:<id>`) gets a single
/// bold yellow `[AI-AGENT REQUEST]` banner above the title — one eye-catcher,
/// the rest of the prompt stays uncolored. The value is client-asserted, so the
/// line says so; an empty one (legacy peer) renders nothing. Writer-generic so
/// the bytes are unit-testable without /dev/tty.
fn write_request_header<W: Write>(w: &mut W, req: &ValidatedRequest, st: &Style) -> io::Result<()> {
    let Style {
        bold, reset, user, ..
    } = *st;
    writeln!(w)?;
    if req.requester_is_ai() {
        writeln!(w, "{bold}{user}[AI-AGENT REQUEST]{reset}")?;
    }
    writeln!(w, "{bold}━━━ Privilege Request ━━━{reset}")?;
    if let Some(line) = INJECTABLE_TTY
        .get()
        .and_then(|r| injectable_tty_line(r, st))
    {
        writeln!(w, "{line}")?;
    }
    writeln!(
        w,
        "From:    {} @ {}",
        clip(&req.session, MAX_DISPLAY_FIELD_CHARS),
        if req.host.is_empty() {
            "local".to_string()
        } else {
            clip(&req.host, MAX_DISPLAY_FIELD_CHARS)
        }
    )?;
    if !req.requester.is_empty() {
        writeln!(
            w,
            "Requester: {} (self-declared, not verified)",
            clip(&req.requester, MAX_DISPLAY_FIELD_CHARS)
        )?;
    }
    Ok(())
}

/// Write the request metadata below the header, from `Client:` through the
/// `Command:` line. Every request-derived field is clipped (G4.3): the fields to
/// `MAX_DISPLAY_FIELD_CHARS`, the command to `MAX_DISPLAY_CMD_CHARS`.
/// Writer-generic so the bytes are unit-testable without /dev/tty.
fn write_request_meta<W: Write>(w: &mut W, req: &ValidatedRequest, st: &Style) -> io::Result<()> {
    let Style {
        bold, dim, reset, ..
    } = *st;
    let field = |s: &str| clip(s, MAX_DISPLAY_FIELD_CHARS);
    let client_ver = if req.version.is_empty() {
        "(unknown)".to_string()
    } else {
        field(&req.version)
    };
    writeln!(w, "Client:  sudo-proxy {client_ver}")?;
    if !req.time.is_empty() {
        writeln!(w, "Time:    {}", field(&req.time))?;
    }
    writeln!(w, "ID:      {}", field(&req.id))?;
    if !req.reason.is_empty() {
        writeln!(w, "Reason:  {bold}{}{reset}", field(&req.reason))?;
    }
    let agent_tag = if req.forward_agent {
        format!(" {dim}(agent forwarded){reset}")
    } else {
        String::new()
    };
    writeln!(
        w,
        "Command: {bold}{}{reset}{agent_tag}",
        truncate_for_display(&command_summary(req))
    )
}

/// Write the fixed `Env:` line of a request that runs with the daemon
/// environment (`--inherit-path` / `--inherit-env`, #101): which flag, and the
/// code-loading variables it carries, if any. Values are never shown.
fn write_inherit_line<W: Write>(
    w: &mut W,
    inherit: Option<&crate::inherit::Inherited>,
    style: &Style,
) -> io::Result<()> {
    let Some(i) = inherit else {
        return Ok(());
    };
    let Style { bold, reset, .. } = *style;
    let loading = if i.code_loading.is_empty() {
        String::new()
    } else {
        let names = clip(&i.code_loading.join(" "), MAX_DISPLAY_CMD_CHARS);
        format!(" {bold}with code-loading {names}{reset}")
    };
    writeln!(
        w,
        "Env:     daemon environment ({}){loading}",
        i.mode.flag()
    )
}

/// Write the `Env:` line, if the request sets any variable. Each `KEY=value` is
/// clipped to `MAX_DISPLAY_FIELD_CHARS` and the joined line to
/// `MAX_DISPLAY_CMD_CHARS`, which bounds both the entry length and the entry
/// count (G4.3).
fn write_env_line<W: Write>(w: &mut W, req: &ValidatedRequest) -> io::Result<()> {
    if req.env.is_empty() {
        return Ok(());
    }
    let env_display: Vec<String> = req
        .env
        .iter()
        .map(|(k, v)| clip(&format!("{k}={v}"), MAX_DISPLAY_FIELD_CHARS))
        .collect();
    writeln!(
        w,
        "Env:     {}",
        clip(&env_display.join(" "), MAX_DISPLAY_CMD_CHARS)
    )
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
    let Alert {
        bell,
        blink_on,
        blink_off,
    } = *alert;
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
    // Simple case: one stage running one program (no wrapper), no escalation,
    // not opaque, no redirections — keep the familiar single `Resolves:` line.
    if !privileged
        && views.len() == 1
        && views[0].privilege == LeafPrivilege::Direct
        && !views[0].opaque
        && views[0].programs.len() == 1
        && views[0].redirects.is_empty()
    {
        if let Some(name) = views[0].argv.first() {
            return write_resolves_line(w, name, views[0].resolved_bin.as_ref(), style);
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
    /// Trailing remark, written after everything else on the line as a shell
    /// comment, so operators and parentheses appended to `text` stay before it.
    note: String,
}

impl StepLine {
    fn comment(&self, style: &Style) -> String {
        if self.note.is_empty() {
            String::new()
        } else {
            format!("  {}# {}{}", style.dim, self.note, style.reset)
        }
    }
}

/// The `Steps:` block — one command per line, indented by parenthesis depth,
/// numbered (0-based, dim, flush-left) so the human can reference a line,
/// coloured by uid. It is valid shell grouping exactly like the `Command:` line.
fn write_steps<W: Write>(w: &mut W, lay: &Lay, style: &Style) -> io::Result<()> {
    let lines = steps_lines(lay, style);
    if lines.is_empty() {
        return Ok(());
    }
    let Style {
        dim, reset, bold, ..
    } = *style;
    writeln!(w, "Steps:")?;
    let shown = lines.len().min(MAX_DISPLAY_STAGES);
    let numbered = lines[..shown].iter().filter(|l| l.numbered).count();
    let width = numbered.saturating_sub(1).to_string().len();
    let mut n = 0usize;
    for ln in &lines[..shown] {
        let indent = "  ".repeat(ln.depth + 1);
        // The gutter and indent are bounded already (32 lines, plan depth);
        // the text and note carry request data, so they are clipped (G4.3).
        let body = clip_styled(
            &format!("{}{}", ln.text, ln.comment(style)),
            MAX_DISPLAY_LINE_CHARS,
            style,
        );
        if ln.numbered {
            writeln!(w, "{dim}{n:<width$}{reset}{indent}{body}")?;
            n += 1;
        } else {
            writeln!(w, "{:width$}{indent}{body}", "")?;
        }
    }
    if lines.len() > shown {
        let hidden = lines.len() - shown;
        writeln!(
            w,
            "{bold}… {hidden} more line(s) hidden — see Command:{reset}"
        )?;
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
        Lay::Leaf {
            cmd,
            redir,
            esc,
            scope,
            note,
        } => {
            let text = if *scope {
                cmd.clone()
            } else {
                colorize(*esc, cmd, style)
            };
            out.push(StepLine {
                depth,
                text: join_suffix(text, redir),
                numbered: true,
                note: note.clone(),
            });
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
                    out.last_mut()
                        .expect("an item emits a line")
                        .text
                        .push_str(&op_str);
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
                    out.push(StepLine {
                        depth,
                        text: "(".into(),
                        numbered: false,
                        note: String::new(),
                    });
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
                out.push(StepLine {
                    depth: opener_depth,
                    text: close,
                    numbered: false,
                    note: String::new(),
                });
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
/// Every program a stage runs is an entry: `argv[0]`, then each program a
/// wrapper runs, suffixed `(run by <wrapper>)`. For an escalated stage the
/// wrapper looks its program up at run time on the escalated PATH, so that
/// entry shows no path and says `looked up at run time`. The entry an opaque
/// stage's reason points at shows the reason in bold instead (a shell keeps
/// the `opaque — resolves only the shell` marker).
fn write_resolve_block<W: Write>(w: &mut W, views: &[LeafView], style: &Style) -> io::Result<()> {
    let Style {
        bold, dim, reset, ..
    } = *style;
    let mut seen = std::collections::HashSet::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for view in views {
        for (i, prog) in view.programs.iter().enumerate() {
            // Every argv-derived word is clipped (G4.3, #85): the name before
            // the dedup key and the width, so one long name cannot widen every
            // row. Filesystem-derived text (paths, and the canonical path an
            // `Ambiguous` reason quotes) also goes through `shown` (#86).
            let name = clip(&prog.name, MAX_DISPLAY_LINE_CHARS);
            let no_path = prog.runtime_lookup || prog.applet;
            let suffix = match (
                prog.via.as_deref().map(|v| clip(v, MAX_DISPLAY_LINE_CHARS)),
                prog.applet,
                prog.runtime_lookup,
            ) {
                (Some(v), true, _) => format!(" {dim}(applet of {v}){reset}"),
                (Some(v), false, true) => {
                    format!(" {dim}(run by {v}; looked up at run time){reset}")
                }
                (Some(v), false, false) => format!(" {dim}(run by {v}){reset}"),
                (None, ..) => String::new(),
            };
            let path = prog.resolved.as_ref().filter(|_| !no_path);
            let detail = match view.opaque_reason.as_ref().filter(|o| o.at == i) {
                Some(o) => {
                    let reason = shown(&o.reason);
                    let text = if !o.names_program || no_path {
                        reason
                    } else {
                        match path {
                            Some(p) => format!(
                                "{reason}: {}{}",
                                shown_path(&p.path.display().to_string()),
                                writable_tag(p, style)
                            ),
                            None if o.is_shell => "shell not found in PATH".to_string(),
                            None => format!("{reason} (not found in PATH)"),
                        }
                    };
                    format!("{bold}opaque — {text}{reset}{suffix}")
                }
                None if no_path => suffix.trim_start().to_string(),
                None => format!("{}{suffix}", resolve_detail(path, style)),
            };
            // An `env` wrapper that sets or unsets an inherited name (#101).
            let detail = if prog.overrides_inherited.is_empty() {
                detail
            } else {
                let names = clip(&prog.overrides_inherited.join(" "), MAX_DISPLAY_LINE_CHARS);
                format!("{detail} {bold}(overrides inherited {names}){reset}")
            };
            if seen.insert(format!("{name}\u{0}{detail}")) {
                entries.push((name, detail));
            }
        }
    }
    if entries.is_empty() {
        return Ok(());
    }
    let shown = entries.len().min(MAX_DISPLAY_RESOLVES);
    let width = entries[..shown]
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    writeln!(w, "Resolves:")?;
    for (name, detail) in &entries[..shown] {
        writeln!(w, "  {name:<width$}  {detail}")?;
    }
    if entries.len() > shown {
        let hidden = entries.len() - shown;
        writeln!(w, "{bold}… {hidden} more binaries hidden{reset}")?;
    }
    Ok(())
}

/// The resolution detail for a command name (the text after `Resolves:`),
/// always naming a concrete path. Used by the consolidated resolve block; it
/// mirrors `write_resolves_line`'s symlink display but never elides — the block
/// shows every binary, even one supplied as an already-canonical absolute path.
///
/// Both paths are printed through `escape_dangerous` (issue #86). Only the
/// canonical path is caller-influenced (a symlink's target name never goes
/// through `ValidatedRequest::validate`); the resolved path is built from the
/// validated `argv[0]`/cwd and the constant login PATH, so escaping it is
/// defence in depth. Comparisons use the raw strings.
fn resolve_detail(resolved: Option<&Resolved>, style: &Style) -> String {
    let Style {
        bold, dim, reset, ..
    } = *style;
    let resolved = match resolved {
        Some(r) => r,
        None => return format!("{bold}(not found in PATH){reset}"),
    };
    let resolved_str = resolved.path.display().to_string();
    // The canonical target read through the pinned descriptor when the plan
    // was compiled (issue #105), not a fresh `canonicalize` of the path.
    let detail = match resolved.canonical() {
        Some(canonical) => {
            let canonical_str = canonical.display().to_string();
            // Compared unclipped, shown clipped (G4.3).
            if canonical_str != resolved_str {
                format!(
                    "{} {bold}->{reset} {}",
                    shown_path(&resolved_str),
                    shown_path(&canonical_str)
                )
            } else {
                shown_path(&resolved_str)
            }
        }
        None => format!(
            "{} {dim}(canonicalize failed){reset}",
            shown_path(&resolved_str)
        ),
    };
    format!("{detail}{}", writable_tag(resolved, style))
}

/// ` (user-writable)` when the daemon's user could replace what runs (#101).
fn writable_tag(resolved: &Resolved, style: &Style) -> String {
    let Style { bold, reset, .. } = *style;
    if resolved.user_writable {
        format!(" {bold}(user-writable){reset}")
    } else {
        String::new()
    }
}

/// Write the `Resolves:` line for a command name, given the plan's own
/// resolution of it (`resolve_command` — the file the executor will spawn,
/// never a fresh lookup), with the canonical target read from the same pin
/// (issue #105), so symlink redirection — including `/usr/local/bin/foo -> /tmp/evil`
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
///
/// Printed paths go through `escape_dangerous` (issue #86), as in
/// `resolve_detail`; the comparisons use the raw strings.
fn write_resolves_line<W: Write>(
    w: &mut W,
    cmd_name: &str,
    resolved: Option<&Resolved>,
    style: &Style,
) -> io::Result<()> {
    let Style {
        bold, dim, reset, ..
    } = *style;
    let resolved = match resolved {
        Some(r) => r,
        None => {
            return writeln!(w, "Resolves: {bold}(not found in PATH){reset}");
        }
    };
    let resolved_full = resolved.path.display().to_string();
    // Branch on the raw, unclipped strings; show them escaped (#86), then
    // clipped (G4.3): neither step may change which rule applies.
    let resolved_differs = resolved_full != *cmd_name;
    let resolved_shown = shown_path(&resolved_full);
    let tag = writable_tag(resolved, style);

    match resolved.canonical() {
        Some(canonical) => {
            let canonical_full = canonical.display().to_string();
            let canonical_differs = canonical_full != resolved_full;
            let resolved_str = &resolved_shown;
            let canonical_str = shown_path(&canonical_full);
            match (resolved_differs, canonical_differs) {
                // Nothing to add about the path, but a writable file is
                // always named.
                (false, false) if tag.is_empty() => Ok(()),
                (false, false) | (true, false) => writeln!(w, "Resolves: {resolved_str}{tag}"),
                (false, true) => writeln!(
                    w,
                    "Resolves: {bold}{resolved_str} -> {canonical_str}{reset}{tag}"
                ),
                (true, true) => writeln!(
                    w,
                    "Resolves: {resolved_str} {bold}->{reset} {canonical_str}{tag}"
                ),
            }
        }
        None => writeln!(
            w,
            "Resolves: {resolved_shown} {dim}(canonicalize failed){reset}{tag}"
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
        writeln!(
            tty,
            "{dim}\u{25b6}{reset} {cmd} {dim}(agent forwarded){reset}"
        )?;
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
    let Style {
        bold, dim, reset, ..
    } = style();

    match resp.status {
        Status::Ok => {
            let exit_code = resp.exit_code();
            let multi_stage = resp.stages.len() > 1;

            if multi_stage {
                // Show all exit codes for multi-stage
                let codes: Vec<String> = resp
                    .stages
                    .iter()
                    .map(|s| s.exit_code.to_string())
                    .collect();
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
    let shown = if truncated {
        &lines[..MAX_DISPLAY_LINES]
    } else {
        &lines
    };

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
    use crate::executor::plan_display;

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
        let st = Style {
            bold: "B",
            dim: "D",
            reset: "R",
            root: "ROOT",
            root_boundary: "RB",
            user: "USR",
        };
        let resolved = crate::executor::resolve_command(cmd_name, "/");
        write_resolves_line(&mut buf, cmd_name, resolved.as_ref(), &st).expect("write");
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
                    body: Box::new(Plan::Exec {
                        argv: vec!["true".into()],
                    }),
                },
                Plan::RunAs {
                    who: RunAs::User {
                        name: "alice".into(),
                    },
                    body: Box::new(Plan::Exec {
                        argv: vec!["true".into()],
                    }),
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
        let st = Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");

        // Privilege is now shown by color, not text tags — the old brackets are gone.
        assert!(
            !out.contains("[ROOT]"),
            "run-as tag should be color, not text: {out}"
        );
        assert!(
            !out.contains("[as alice]"),
            "run-as tag should be color, not text: {out}"
        );
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
        assert!(
            resolves_at < steps_at,
            "resolve block must precede the steps: {out}"
        );
        // The three leaves appear in the Steps block.
        assert!(
            out.contains("sh -c 'echo hi'"),
            "shell leaf in steps: {out}"
        );
    }

    /// A lone `exec sh -c` stage is opaque: it must not take the simple
    /// single-`Resolves:` path that would show it as a tame binary.
    #[test]
    fn exec_of_shell_renders_opaque() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let plan = Plan::Exec {
            argv: vec!["sh".into(), "-c".into(), "echo hi; rm -f x".into()],
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
        let st = Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(
            out.contains("opaque — resolves only the shell")
                || out.contains("opaque — shell not found"),
            "exec of a shell must be flagged opaque: {out}"
        );
    }

    fn render_plan(plan: crate::protocol::Plan) -> String {
        use crate::protocol::{Request, ValidatedRequest};
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
        let st = Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    fn exec(argv: &[&str]) -> crate::protocol::Plan {
        crate::protocol::Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Issue #87: a shell behind a wrapper is flagged with the same marker,
    /// on the shell's own entry, which names the wrapper that runs it.
    #[test]
    fn wrapped_shell_renders_opaque_run_by_wrapper() {
        let out = render_plan(exec(&["env", "sh", "-c", "echo hi"]));
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with("sh "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(line.contains("opaque — resolves only the shell"), "{out}");
        assert!(line.contains("(run by env)"), "{out}");
        assert!(
            out.lines().any(|l| l.trim_start().starts_with("env ")),
            "{out}"
        );
    }

    /// A transparent wrapper takes the block form and lists the program it
    /// runs, with its path.
    #[test]
    fn wrapped_program_takes_the_block_form() {
        let out = render_plan(exec(&["env", "X=1", "true"]));
        assert!(
            out.starts_with("Resolves:\n"),
            "block form, not the single line: {out}"
        );
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with("true "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(line.contains("(run by env)") && line.contains('/'), "{out}");
        assert!(!out.contains("opaque"), "{out}");
    }

    /// Review C5: an applet of a multi-call dispatcher shows no path, since
    /// the dispatcher runs its built-in applet.
    #[test]
    fn applet_renders_without_a_path() {
        let out = render_plan(exec(&["busybox", "sh", "-c", "true"]));
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with("sh "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(
            line.contains("opaque — resolves only the shell (applet of busybox)"),
            "{out}"
        );
        assert!(!line.contains('/'), "{out}");
    }

    /// For an escalated stage the wrapper looks its program up at run time, on
    /// sudo's PATH, so the prompt shows no path for it.
    #[test]
    fn escalated_wrapped_program_is_looked_up_at_run_time() {
        use crate::protocol::{Plan, RunAs};
        let out = render_plan(Plan::RunAs {
            who: RunAs::Root,
            body: Box::new(exec(&["env", "X=1", "true"])),
        });
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with("true "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(
            line.contains("(run by env; looked up at run time)"),
            "{out}"
        );
        assert!(!line.contains('/'), "no path for a run-time lookup: {out}");
        let out = render_plan(Plan::RunAs {
            who: RunAs::Root,
            body: Box::new(exec(&["timeout", "5", "sh", "-c", "true"])),
        });
        assert!(
            out.contains(
                "opaque — resolves only the shell (run by timeout; looked up at run time)"
            ),
            "{out}"
        );
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
                Plan::Exec {
                    argv: vec![missing.into(), "a".into()],
                },
                Plan::Exec {
                    argv: vec![missing.into(), "b".into()],
                },
                Plan::Exec {
                    argv: vec!["echo".into(), "done".into()],
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
        let st = Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        };
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
        let exec = |a: &[&str]| Plan::Exec {
            argv: a.iter().map(|s| s.to_string()).collect(),
        };
        let mk = |privileged: bool| {
            let plan = Plan::Run {
                steps: vec![exec(&["id", "-un"]), exec(&["id", "-u"])],
            };
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
        Style {
            bold: "",
            dim: "",
            reset: "R",
            root: "LIGHT",
            root_boundary: "BRIGHT",
            user: "YEL",
        }
    }

    /// Combination B — single escalated leaf amid default ones (unprivileged
    /// request plus one `run-as root`): the run-as leaf is bright red, the rest
    /// default, and the operator is NOT tinted (the group is not all-escalated).
    #[test]
    fn single_runas_is_bright_red_rest_default() {
        use crate::protocol::{Plan, Request, RunAs, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec {
                    argv: vec!["echo".into(), "hi".into()],
                },
                Plan::RunAs {
                    who: RunAs::Root,
                    body: Box::new(Plan::Exec {
                        argv: vec!["whoami".into()],
                    }),
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
        assert!(
            out.contains("BRIGHTsudo whoamiR"),
            "run-as leaf must be bright red: {out}"
        );
        assert!(
            out.contains("echo hi") && !out.contains("LIGHTecho") && !out.contains("BRIGHTecho"),
            "the default leaf must stay uncolored: {out}"
        );
        // Mixed group → operator not tinted.
        assert!(
            !out.contains("LIGHT &&"),
            "operator must not be tinted in a mixed group: {out}"
        );
    }

    /// Combination A — wholly escalated (`privileged: true`, no `run-as`): every
    /// leaf is light red, the operator is tinted too, and nothing is bright.
    #[test]
    fn whole_escalated_plan_is_light_red_with_tinted_operator() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec {
                    argv: vec!["echo".into(), "a".into()],
                },
                Plan::Exec {
                    argv: vec!["echo".into(), "b".into()],
                },
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
        assert!(
            out.contains("LIGHTsudo echo aR"),
            "leaf a must be light red: {out}"
        );
        assert!(
            out.contains("LIGHTsudo echo bR"),
            "leaf b must be light red: {out}"
        );
        assert!(
            out.contains("LIGHT &&R"),
            "operator must be tinted in an all-root group: {out}"
        );
        assert!(
            !out.contains("BRIGHT"),
            "no bright red without an explicit run-as: {out}"
        );
    }

    /// Combination C — wholly escalated AND one explicit `run-as root`: ambient
    /// leaves light red, the run-as leaf bright red (exactly one), operator tinted.
    #[test]
    fn escalated_plan_with_runas_is_light_red_one_bright() {
        use crate::protocol::{Plan, Request, RunAs, ValidatedRequest};
        let plan = Plan::Run {
            steps: vec![
                Plan::Exec {
                    argv: vec!["id".into(), "-un".into()],
                },
                Plan::RunAs {
                    who: RunAs::Root,
                    body: Box::new(Plan::Exec {
                        argv: vec!["whoami".into()],
                    }),
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
        assert!(
            out.contains("LIGHTsudo id -unR"),
            "ambient leaf must be light red: {out}"
        );
        assert_eq!(
            out.matches("BRIGHT").count(),
            1,
            "exactly the run-as leaf is bright red: {out}"
        );
        assert!(
            out.contains("BRIGHTsudo whoamiR"),
            "run-as leaf must be bright red: {out}"
        );
        assert!(
            out.contains("LIGHT &&R"),
            "operator tinted in an all-root group: {out}"
        );
    }

    /// A simple single unprivileged command keeps the classic one-line
    /// `Resolves:` form (no numbered stage block).
    #[test]
    fn single_plain_command_uses_compact_resolves() {
        use crate::protocol::{Plan, Request, ValidatedRequest};
        let req = ValidatedRequest::validate(Request::new_plan(
            String::new(),
            "t".into(),
            Plan::Exec {
                argv: vec!["true".into()],
            },
            std::collections::HashMap::new(),
            String::new(),
            false,
            false,
        ))
        .expect("valid");
        let views = plan_display(&req).expect("compiles");
        let mut buf: Vec<u8> = Vec::new();
        let st = Style {
            bold: "",
            dim: "",
            reset: "",
            root: "",
            root_boundary: "",
            user: "",
        };
        write_plan_stages(&mut buf, &req.exec_plan(), &views, req.privileged, &st).expect("write");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.starts_with("Resolves:"), "compact form expected: {out}");
        assert!(
            !out.contains("1. "),
            "no numbered block for a single plain stage: {out}"
        );
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
    fn injectable_tty_line_names_each_mechanism() {
        let st = Style {
            bold: "B",
            dim: "D",
            reset: "R",
            root: "",
            root_boundary: "",
            user: "",
        };
        assert_eq!(injectable_tty_line(&[], &st), None);
        let line = injectable_tty_line(
            &[
                "terminal multiplexer (TERM=tmux-256color): `tmux send-keys` can type into it"
                    .into(),
                "X11 session (DISPLAY=:0, no Wayland): any X client can synthesise keys".into(),
            ],
            &st,
        )
        .unwrap();
        assert!(line.starts_with("B⚠"), "{line}");
        assert!(line.ends_with('R'), "{line}");
        assert!(
            line.contains(
                "terminal multiplexer (TERM=tmux-256color); X11 session (DISPLAY=:0, no Wayland)"
            ),
            "{line}"
        );
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
        assert!(
            on.contains("Execute as root? [y/N]"),
            "question text missing: {on:?}"
        );

        // Both cues suppressed: none of the three escapes appear, but the
        // question line is otherwise identical and still printed.
        let off = render_question(&alert_for(true, true));
        assert!(!off.contains('\x07'), "bell leaked: {off:?}");
        assert!(!off.contains("\x1b[5m"), "blink-on leaked: {off:?}");
        assert!(!off.contains("\x1b[25m"), "blink-off leaked: {off:?}");
        assert!(
            off.contains("Execute as root? [y/N]"),
            "question text missing: {off:?}"
        );
        assert_eq!(off, "Execute as root? [y/N] (60s timeout, default=N) ");
    }

    fn render_header(requester: &str, style: &Style) -> String {
        use crate::protocol::{Request, ValidatedRequest};
        let mut req = Request::new(
            String::new(),
            "s".into(),
            vec![vec!["id".into()]],
            Default::default(),
            String::new(),
            false,
            false,
        );
        req.requester = requester.into();
        let req = ValidatedRequest::validate(req).expect("valid");
        let mut buf: Vec<u8> = Vec::new();
        write_request_header(&mut buf, &req, style).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// Issue #25: an AI requester gets the banner above the title plus the
    /// self-declared line; a human one only the line; a legacy (empty) one
    /// neither. Under NO_COLOR the banner text stays, its escapes go.
    #[test]
    fn request_header_discloses_self_declared_requester() {
        let ai = render_header("ai:claude", &style_for(false));
        let banner = ai.find("[AI-AGENT REQUEST]").expect("banner missing");
        assert!(
            banner < ai.find("Privilege Request").unwrap(),
            "banner must lead: {ai:?}"
        );
        assert!(
            ai.contains("\x1b[38;5;226m[AI-AGENT REQUEST]"),
            "banner not yellow: {ai:?}"
        );
        assert!(
            ai.contains("Requester: ai:claude (self-declared, not verified)"),
            "{ai:?}"
        );

        let human = render_header("human", &style_for(false));
        assert!(!human.contains("AI-AGENT"), "{human:?}");
        assert!(
            human.contains("Requester: human (self-declared, not verified)"),
            "{human:?}"
        );

        let legacy = render_header("", &style_for(false));
        assert!(
            !legacy.contains("AI-AGENT") && !legacy.contains("Requester"),
            "{legacy:?}"
        );

        let plain = render_header("ai", &style_for(true));
        assert!(
            plain.contains("[AI-AGENT REQUEST]") && !plain.contains('\x1b'),
            "{plain:?}"
        );
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
        assert!(
            !s.contains("\x1b[5m") && !s.contains('\x07'),
            "no blink, no bell: {s:?}"
        );

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
        let n = unsafe { libc::write(master, stray.as_ptr() as *const libc::c_void, stray.len()) };
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
        Plan::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
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
        out.strip_prefix("Steps:\n")
            .expect("Steps header")
            .to_string()
    }

    /// The agreed layouts (examples 1–4 of the design discussion; 5–6 are the
    /// corpus cases 23 and 22, covered in `tests/manual_corpus.rs`).
    #[test]
    fn steps_layout_matches_agreed_examples() {
        // 1. a && (b || c) — the case the old layout showed as (a && b) || c.
        let req = mk_req(
            Plan::Run {
                steps: vec![
                    ex(&["false"]),
                    Plan::Alt {
                        steps: vec![ex(&["true"]), ex(&["echo", "RAN"])],
                    },
                ],
            },
            false,
        );
        assert_eq!(command_summary(&req), "false && (true || echo RAN)");
        assert_eq!(
            steps_block(&req),
            "0  false && (\n1    true ||\n2    echo RAN\n   )\n"
        );

        // 2. (a; b) && c — a group with no line before its `(`.
        let req = mk_req(
            Plan::Run {
                steps: vec![
                    Plan::Seq {
                        steps: vec![ex(&["false"]), ex(&["true"])],
                    },
                    ex(&["echo", "C"]),
                ],
            },
            false,
        );
        assert_eq!(command_summary(&req), "(false; true) && echo C");
        assert_eq!(
            steps_block(&req),
            "   (\n0    false ;\n1    true ) &&\n2  echo C\n"
        );

        // 3. (a || b) && c — mixed operators always get their own group.
        let req = mk_req(
            Plan::Run {
                steps: vec![
                    Plan::Alt {
                        steps: vec![ex(&["false"]), ex(&["true"])],
                    },
                    ex(&["echo", "C"]),
                ],
            },
            false,
        );
        assert_eq!(command_summary(&req), "(false || true) && echo C");
        assert_eq!(
            steps_block(&req),
            "   (\n0    false ||\n1    true ) &&\n2  echo C\n"
        );

        // 4. Showcase — export scope, parenthesized pipe, `sudo` on the run-as leaf.
        let req = mk_req(
            Plan::Setenv {
                key: "LANG".into(),
                value: "C".into(),
                body: Box::new(Plan::Run {
                    steps: vec![
                        ex(&["echo", "a;b"]),
                        Plan::Pipe {
                            stages: vec![ex(&["echo", "hello world"]), ex(&["wc", "-w"])],
                        },
                        Plan::RunAs {
                            who: RunAs::Root,
                            body: Box::new(ex(&["id", "-un"])),
                        },
                    ],
                }),
            },
            false,
        );
        assert_eq!(
            command_summary(&req),
            "(export LANG=C && (echo 'a;b' && (echo 'hello world' | wc -w) && sudo id -un))"
        );
        assert_eq!(
            steps_block(&req),
            "   (\n\
             0    export LANG=C && (\n\
             1      echo 'a;b' && (\n\
             2        echo 'hello world' |\n\
             3        wc -w ) &&\n\
             4      sudo id -un\n\
             \x20    )\n\
             \x20  )\n"
        );
    }

    /// An accepted non-zero exit lets the chain go on, in the executor and in
    /// the displayed shell alike; the Steps block also names the codes.
    #[test]
    fn accepted_exit_codes_are_shown_and_mean_what_runs() {
        let req = mk_req(
            Plan::Run {
                steps: vec![
                    Plan::WithAcceptedExitCodes {
                        codes: vec![1],
                        body: Box::new(ex(&["false"])),
                    },
                    ex(&["echo", "ran"]),
                ],
            },
            false,
        );
        let cmd = command_summary(&req);
        assert_eq!(cmd, "{ false || [ $? -eq 1 ]; } && echo ran");
        assert_eq!(
            steps_block(&req),
            "0  { false || [ $? -eq 1 ]; } &&  # exit 1 accepted\n1  echo ran\n"
        );
        assert_eq!(run_sh(&cmd), "ran\n");
        assert_eq!(run_sh(&steps_shell_text(&req)), "ran\n");

        let req = mk_req(
            Plan::WithAcceptedExitCodes {
                codes: vec![2, 1, 0],
                body: Box::new(ex(&["false"])),
            },
            false,
        );
        assert_eq!(
            command_summary(&req),
            "{ false || case $? in 1|2) ;; *) false ;; esac; }"
        );
        assert_eq!(
            steps_block(&req),
            "0  { false || case $? in 1|2) ;; *) false ;; esac; }  # exits 1, 2 accepted\n"
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
                            Plan::Pipe {
                                stages: vec![ex(&["echo", "a"]), ex(&["cat"])],
                            },
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
                    Plan::RunAs {
                        who: RunAs::Root,
                        body: Box::new(ex(&["id"])),
                    },
                    Plan::RunAs {
                        who: RunAs::User {
                            name: "nobody".into(),
                        },
                        body: Box::new(ex(&["id"])),
                    },
                ],
            },
            false,
        );
        assert_eq!(steps_block(&req), "0  sudo id ;\n1  sudo -u nobody id\n");
    }

    /// A failed `cd` must not run the scope's body: the executor refuses it, and
    /// the displayed `( cd D && ( body ) )` skips it too.
    #[test]
    fn failed_cd_skips_the_scope_body_in_display_and_executor() {
        let req = mk_req(
            Plan::Chdir {
                dir: "/nonexistent-sudo-proxy-dir".into(),
                body: Box::new(ex(&["echo", "body-ran"])),
            },
            false,
        );
        let cmd = command_summary(&req);
        assert_eq!(cmd, "(cd /nonexistent-sudo-proxy-dir && (echo body-ran))");
        let resp =
            crate::executor::prepare_and_exec_direct(&req, &std::collections::HashMap::new());
        let via_plan = String::from_utf8_lossy(
            &B64.decode(resp.stdout.as_deref().unwrap_or(""))
                .expect("b64"),
        )
        .into_owned();
        assert!(
            !via_plan.contains("body-ran"),
            "executor ran the body: {via_plan:?}"
        );
        assert!(
            !run_sh(&cmd).contains("body-ran"),
            "Command line ran the body"
        );
        assert!(
            !run_sh(&steps_shell_text(&req)).contains("body-ran"),
            "Steps ran the body"
        );
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
        assert!(
            out.status.success(),
            "bash rejected:\n{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn pick<'a>(rng: &mut crate::prop::Rng, xs: &[&'a str]) -> &'a str {
        xs[rng.below(xs.len())]
    }

    /// Any plan, including run-as, opaque shells, redirections and argv that
    /// needs quoting. Only parsed, never run.
    fn random_any(rng: &mut crate::prop::Rng, depth: usize) -> Plan {
        const WORDS: &[&str] = &["a", "x y", "a;b", "$v", "(", ")", "it's", "&&", "-n", "*"];
        let leaf = |rng: &mut crate::prop::Rng| match rng.below(8) {
            0 => Plan::Shell {
                shell: ShellProc::Sh,
                script: "echo s; exit 1".into(),
            },
            _ => Plan::Exec {
                argv: (0..1 + rng.below(3))
                    .map(|_| pick(rng, WORDS).to_string())
                    .collect(),
            },
        };
        if depth == 0 || rng.below(4) == 0 {
            return leaf(rng);
        }
        let kids = |rng: &mut crate::prop::Rng, min: usize| -> Vec<Plan> {
            (0..min + rng.below(3))
                .map(|_| random_any(rng, depth - 1))
                .collect()
        };
        match rng.below(11) {
            0 => Plan::Run {
                steps: kids(rng, 1),
            },
            1 => Plan::Alt {
                steps: kids(rng, 1),
            },
            2 => Plan::Seq {
                steps: kids(rng, 1),
            },
            3 => Plan::Pipe {
                stages: (0..2 + rng.below(2)).map(|_| leaf(rng)).collect(),
            },
            4 => Plan::Chdir {
                dir: "/tmp/a b".into(),
                body: Box::new(random_any(rng, depth - 1)),
            },
            5 => Plan::Setenv {
                key: "TZ".into(),
                value: "x y".into(),
                body: Box::new(random_any(rng, depth - 1)),
            },
            6 => Plan::RunAs {
                who: RunAs::Root,
                body: Box::new(random_any(rng, depth - 1)),
            },
            7 => Plan::RunAs {
                who: RunAs::User {
                    name: "nobody".into(),
                },
                body: Box::new(random_any(rng, depth - 1)),
            },
            8 => Plan::Redirect {
                stream: [Stream::Stdout, Stream::Stderr, Stream::Both][rng.below(3)],
                target: RedirTarget::File {
                    path: "/tmp/o u t".into(),
                    mode: crate::protocol::WriteMode::Append,
                },
                body: Box::new(leaf(rng)),
            },
            9 => Plan::WithStdinFrom {
                path: "/dev/null".into(),
                body: Box::new(leaf(rng)),
            },
            _ => Plan::WithAcceptedExitCodes {
                codes: [vec![1], vec![1, 2]][rng.below(2)].clone(),
                body: Box::new(random_any(rng, depth - 1)),
            },
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
            assert_eq!(
                bash_tree(&steps),
                bash_tree(&cmd),
                "Steps:\n{steps}\nCommand: {cmd}"
            );
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
            4 => Plan::Shell {
                shell: ShellProc::Sh,
                script: "echo s; exit 1".into(),
            },
            5 => Plan::Shell {
                shell: ShellProc::Sh,
                script: "echo t; exit 2".into(),
            },
            _ => ex(&["echo", pick(rng, &["1", "2", "3", "4", "5"])]),
        };
        if depth == 0 || rng.below(4) == 0 {
            return leaf(rng);
        }
        let kids = |rng: &mut crate::prop::Rng| -> Vec<Plan> {
            (0..1 + rng.below(3))
                .map(|_| random_runnable(rng, depth - 1))
                .collect()
        };
        match rng.below(10) {
            0 => Plan::Run { steps: kids(rng) },
            1 => Plan::Alt { steps: kids(rng) },
            2 => Plan::Seq { steps: kids(rng) },
            3 => Plan::Pipe {
                stages: vec![leaf(rng), ex(&["cat"])],
            },
            4 => Plan::Chdir {
                dir: pick(rng, &["/tmp", "/usr", "/usr/bin"]).into(),
                body: Box::new(random_runnable(rng, depth - 1)),
            },
            8 | 9 => Plan::WithAcceptedExitCodes {
                codes: [vec![1], vec![1, 2], vec![0, 7]][rng.below(3)].clone(),
                body: Box::new(random_runnable(rng, depth - 1)),
            },
            5 => Plan::Setenv {
                key: "TZ".into(),
                value: "UTC".into(),
                body: Box::new(random_runnable(rng, depth - 1)),
            },
            6 => Plan::Redirect {
                stream: Stream::Stdout,
                target: RedirTarget::DevNull,
                body: Box::new(leaf(rng)),
            },
            _ => Plan::WithStdinFrom {
                path: "/dev/null".into(),
                body: Box::new(ex(&["cat"])),
            },
        }
    }

    fn run_sh(text: &str) -> String {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(text)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
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
            let resp =
                crate::executor::prepare_and_exec_direct(&req, &std::collections::HashMap::new());
            let via_plan = String::from_utf8_lossy(
                &B64.decode(resp.stdout.as_deref().unwrap_or(""))
                    .expect("b64"),
            )
            .into_owned();
            let cmd = command_summary(&req);
            let steps = steps_shell_text(&req);
            assert_eq!(run_sh(&cmd), via_plan, "Command: {cmd}");
            assert_eq!(run_sh(&steps), via_plan, "Steps:\n{steps}");
        }
    }

    // === Property: every approval-prompt line is length-bounded (G4.3, #85)
    //
    // Whatever the size of the request, every line the prompt writes has a
    // visible length (daemon escapes removed) bounded by a constant per line
    // kind, and the number of lines is bounded too. Clipping only cuts a
    // line's tail: what is shown is a prefix of the unclipped text.

    /// Maximum visible length of the `clip`/`clip_styled` marker
    /// `… [N more chars hidden]`: `… [` + at most 7 digits (`N` is under
    /// the 1 MiB request cap) + ` more chars hidden]` = 29, rounded up.
    const MARKER_MAX: usize = 32;
    /// Maximum visible length of `truncate_for_display`'s marker
    /// `… [N more chars hidden — full command not shown]` (≤ 54), rounded up.
    const CMD_MARKER_MAX: usize = 64;
    /// Any metadata line, `Command:` and `Env:` included: label and fixed text
    /// (≤ 64, with the agent tag) + the longest clipped value and its marker.
    const META_BOUND: usize = MAX_DISPLAY_CMD_CHARS + CMD_MARKER_MAX + 64;
    /// A `Steps:` line: gutter (≤ 2 digits + separator) + indent (each plan
    /// level adds at most two parenthesis levels, a `cd`/`export` scope) + the
    /// clipped text and its marker.
    const STEPS_BOUND: usize =
        6 + 2 * (2 * crate::protocol::MAX_PLAN_DEPTH + 3) + MAX_DISPLAY_LINE_CHARS + MARKER_MAX;
    /// A `Resolves:` row or line: up to three clipped strings (name, resolved,
    /// canonical) and fixed separators.
    const RESOLVES_BOUND: usize = 3 * (MAX_DISPLAY_LINE_CHARS + MARKER_MAX) + 32;
    const PLAN_BOUND: usize = if STEPS_BOUND > RESOLVES_BOUND {
        STEPS_BOUND
    } else {
        RESOLVES_BOUND
    };

    /// `s` with every CSI escape removed: what the terminal shows.
    fn strip_csi(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < s.len() {
            match csi_len(bytes, i) {
                Some(n) => i += n,
                None => {
                    let c = s[i..].chars().next().unwrap();
                    out.push(c);
                    i += c.len_utf8();
                }
            }
        }
        out
    }

    /// The plan section exactly as `prompt_tty` writes it.
    fn plan_output(req: &ValidatedRequest, style: &Style) -> String {
        let prepared =
            crate::executor::prepare(req, &std::collections::HashMap::new()).expect("compiles");
        let mut buf = Vec::new();
        write_plan_section(&mut buf, &prepared, style).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// The `Steps:` lines and the `Resolves:` lines (block rows included) of a
    /// rendered plan, escapes stripped.
    fn split_plan_output(out: &str) -> (Vec<String>, Vec<String>) {
        let (mut steps, mut resolves) = (Vec::new(), Vec::new());
        let mut in_steps = false;
        for line in out.lines().map(strip_csi) {
            if line == "Steps:" {
                in_steps = true;
            } else if in_steps {
                steps.push(line);
            } else {
                resolves.push(line);
            }
        }
        (steps, resolves)
    }

    /// An absolute path to `echo`, `2 * reps + 9` bytes long (2 009 for
    /// `reps = 1_000`): under PATH_MAX for every `reps` used here, so it is
    /// found and canonicalizes to the real binary.
    fn long_echo_path(reps: usize) -> String {
        format!("/{}bin/echo", "./".repeat(reps))
    }

    #[test]
    fn clip_bounds_and_marks() {
        assert_eq!(clip("abc", 4), "abc");
        assert_eq!(clip("abcd", 4), "abcd");
        assert_eq!(clip("abcde", 4), "abcd… [1 more chars hidden]");
        // Multi-byte chars are never split, and the count is in chars.
        assert_eq!(clip("éé漢漢漢", 2), "éé… [3 more chars hidden]");
        let big = clip(&"x".repeat(1_048_576), 10);
        assert!(big.chars().count() - 10 <= MARKER_MAX, "{big}");
        // `truncate_for_display` keeps its own wording.
        let cmd = truncate_for_display(&"y".repeat(MAX_DISPLAY_CMD_CHARS + 1_048_576));
        assert!(
            cmd.ends_with("… [1048576 more chars hidden — full command not shown]"),
            "{cmd}"
        );
        assert!(cmd.chars().count() - MAX_DISPLAY_CMD_CHARS <= CMD_MARKER_MAX);
    }

    #[test]
    fn clip_styled_ignores_escapes_and_resets() {
        let st = style_for(false);
        let line = format!("\x1b[38;5;210m{}\x1b[0m", "A".repeat(300));
        let out = clip_styled(&line, MAX_DISPLAY_LINE_CHARS, &st);
        let marker = format!("{}… [140 more chars hidden]{}", st.bold, st.reset);
        assert!(
            out.ends_with(&format!("{}{marker}", st.reset)),
            "reset before the marker: {out:?}"
        );
        let head = out.strip_suffix(&marker).unwrap();
        assert_eq!(strip_csi(head), "A".repeat(MAX_DISPLAY_LINE_CHARS));
        // A line that fits passes through byte-identical, escapes and all.
        let short = format!(
            "\x1b[38;5;210m{}\x1b[0m",
            "A".repeat(MAX_DISPLAY_LINE_CHARS)
        );
        assert_eq!(clip_styled(&short, MAX_DISPLAY_LINE_CHARS, &st), short);
        // Without colour, no escape at all.
        let plain = clip_styled(&"A".repeat(300), MAX_DISPLAY_LINE_CHARS, &style_for(true));
        assert!(!plain.contains('\x1b'), "{plain:?}");
        assert_eq!(plain, clip(&"A".repeat(300), MAX_DISPLAY_LINE_CHARS));
        // A tab counts as one char and is passed through unchanged.
        let tabs = format!("a\tb{}", "\t".repeat(200));
        let out = clip_styled(&tabs, 10, &style_for(true));
        assert_eq!(
            out,
            format!("a\tb{}… [193 more chars hidden]", "\t".repeat(7))
        );
    }

    #[test]
    fn steps_line_is_bounded_for_huge_argument() {
        let req = mk_req(ex(&["echo", &"A".repeat(200_000)]), true);
        for st in [style_for(false), style_for(true)] {
            let out = plan_output(&req, &st);
            assert!(out.len() < 4096, "{} bytes", out.len());
            let (steps, resolves) = split_plan_output(&out);
            for l in &steps {
                assert!(
                    l.chars().count() <= STEPS_BOUND,
                    "Steps line of {} chars",
                    l.chars().count()
                );
            }
            for l in &resolves {
                assert!(
                    l.chars().count() <= RESOLVES_BOUND,
                    "Resolves line of {} chars",
                    l.chars().count()
                );
            }
            // Line 0, escapes (dim gutter, root colour) stripped, gutter removed.
            let line0 = steps[0].strip_prefix("0  ").expect("gutter");
            assert!(line0.starts_with("sudo echo AAAA"), "{line0}");
            assert!(line0.contains("more chars hidden"), "{line0}");
        }
    }

    #[test]
    fn resolves_block_bounds_long_names_and_count() {
        // (a) A long, resolvable absolute argv[0] in a multi-leaf plan.
        let long = long_echo_path(1_000);
        assert_eq!(long.len(), 2_009);
        let req = mk_req(
            Plan::Run {
                steps: vec![ex(&[&long, "x"]), ex(&["id"])],
            },
            true,
        );
        let out = plan_output(&req, &style_for(true));
        let (_, resolves) = split_plan_output(&out);
        let row = resolves
            .iter()
            .find(|l| l.starts_with("  /./"))
            .expect("long row");
        assert!(row.contains("->"), "{row}");
        assert_eq!(
            row.matches("more chars hidden").count(),
            2,
            "name and resolved path clipped: {row}"
        );
        for l in &resolves {
            assert!(
                l.chars().count() <= RESOLVES_BOUND,
                "Resolves row of {} chars",
                l.chars().count()
            );
        }
        // The short entry's padding follows the clipped name, not the 2 009-char one.
        let id_row = resolves
            .iter()
            .find(|l| l.starts_with("  id "))
            .expect("id row");
        assert!(
            id_row.chars().count() <= MAX_DISPLAY_LINE_CHARS + MARKER_MAX + 64,
            "id row of {} chars",
            id_row.chars().count()
        );

        // (b) 40 distinct binaries: 32 rows, then the marker.
        let steps = (0..40)
            .map(|i| ex(&[&format!("sudo-proxy-no-such-binary-{i}")]))
            .collect();
        let out = plan_output(&mk_req(Plan::Seq { steps }, false), &style_for(true));
        let (_, resolves) = split_plan_output(&out);
        assert_eq!(
            resolves.iter().filter(|l| l.starts_with("  ")).count(),
            MAX_DISPLAY_RESOLVES,
            "{out}"
        );
        assert_eq!(
            resolves.last().map(String::as_str),
            Some("… 8 more binaries hidden"),
            "{out}"
        );
    }

    #[test]
    fn resolves_line_bounds_long_absolute_path() {
        let req = mk_req(ex(&[&long_echo_path(1_000), "x"]), false);
        let out = plan_output(&req, &style_for(true));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "{out}");
        assert!(lines[0].starts_with("Resolves: "), "{out}");
        assert!(
            lines[0].contains("->") && lines[0].contains("more chars hidden"),
            "{out}"
        );
        assert!(
            lines[0].chars().count() <= RESOLVES_BOUND,
            "{} chars",
            lines[0].chars().count()
        );
    }

    /// A long path is clipped in the middle: its start and the binary's name
    /// stay visible, with the marker between them (#101).
    #[test]
    fn long_paths_are_clipped_in_the_middle() {
        let long = format!("/usr/{}/bin/the-tool", "d".repeat(500));
        let out = shown_path(&long);
        assert!(out.starts_with("/usr/ddd"), "{out}");
        assert!(out.ends_with("/bin/the-tool"), "{out}");
        assert!(
            out.contains("…[") && out.contains("more chars hidden]…"),
            "{out}"
        );
        assert!(out.chars().count() < MAX_DISPLAY_LINE_CHARS + 40, "{out}");
        assert_eq!(shown_path("/usr/bin/x"), "/usr/bin/x");
    }

    /// A writable program is always named, even when the one-line form would
    /// otherwise print nothing (an absolute path that is its own target).
    #[test]
    fn user_writable_program_is_always_marked() {
        let st = style_for(true);
        let mut r = Resolved::fake("/home/u/.venv/bin/tool");
        let line = |r: &Resolved| {
            let mut buf = Vec::new();
            write_resolves_line(&mut buf, "/home/u/.venv/bin/tool", Some(r), &st).unwrap();
            String::from_utf8(buf).unwrap()
        };
        assert_eq!(line(&r), "");
        r.user_writable = true;
        assert_eq!(
            line(&r),
            "Resolves: /home/u/.venv/bin/tool (user-writable)\n"
        );
        assert!(resolve_detail(Some(&r), &st).ends_with("(user-writable)"));
    }

    /// An opaque program's path carries the marker too (#101).
    #[test]
    fn opaque_program_is_marked_user_writable() {
        let req = mk_req(ex(&["sh", "-c", "echo hi"]), false);
        let mut views = plan_display(&req).expect("compiles");
        let r = views[0].programs[0].resolved.as_mut().expect("sh resolves");
        r.user_writable = true;
        let st = style_for(true);
        let mut buf = Vec::new();
        write_resolve_block(&mut buf, &views, &st).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let line = out
            .lines()
            .find(|l| l.contains("opaque — "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(line.contains("/sh (user-writable)"), "{out}");
    }

    #[test]
    fn inherit_line_names_the_flag_and_code_loading_names_only() {
        let st = style_for(true);
        let d = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = vec![
            ("PATH".into(), d.path().as_os_str().to_owned()),
            ("PYTHONPATH".into(), "/secret/py".into()),
            ("REPO_ROOT".into(), "/secret/r".into()),
        ];
        let uid = unsafe { libc::geteuid() };
        let pats = crate::inherit::parse_patterns("PYTHONPATH,REPO_ROOT").unwrap();
        let i =
            crate::inherit::Inherited::from_env(crate::inherit::InheritMode::Env, pats, env, uid)
                .unwrap();
        let mut buf = Vec::new();
        write_inherit_line(&mut buf, Some(&i), &st).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "Env:     daemon environment (--inherit-env) with code-loading PYTHONPATH\n"
        );
        let mut buf = Vec::new();
        write_inherit_line(&mut buf, None, &st).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn meta_and_env_lines_are_bounded() {
        let render = |req: &ValidatedRequest, st: &Style| {
            let mut buf = Vec::new();
            write_request_header(&mut buf, req, st).expect("write");
            write_request_meta(&mut buf, req, st).expect("write");
            write_env_line(&mut buf, req).expect("write");
            String::from_utf8(buf).expect("utf8")
        };

        let long = "r".repeat(10_000);
        let env = (0..5_000)
            .map(|i| (format!("K{i}"), "v".repeat(300)))
            .collect();
        let mut raw = Request::new(
            long.clone(),
            long.clone(),
            vec![vec!["echo".into(), "A".repeat(900_000)]],
            env,
            long.clone(),
            false,
            true,
        );
        raw.requester = long.clone();
        raw.version = long.clone();
        let req = ValidatedRequest::validate(raw).expect("valid");
        for st in [style_for(false), style_for(true)] {
            let out = render(&req, &st);
            for line in out.lines().map(strip_csi) {
                assert!(
                    line.chars().count() <= META_BOUND,
                    "line of {} chars",
                    line.chars().count()
                );
            }
            assert!(out.contains("Command: ") && out.contains("full command not shown"));
            assert!(out.contains("Env:     ") && out.contains("(agent forwarded)"));
        }

        // Short values: the same bytes as before the bound.
        let mut raw = Request::new(
            "h".into(),
            "s".into(),
            vec![vec!["id".into()]],
            [("K".to_string(), "v".to_string())].into(),
            "why".into(),
            false,
            false,
        );
        raw.requester = "human".into();
        raw.version = "1.0".into();
        raw.id = "id1".into();
        raw.time = "2026-01-01T00:00:00Z".into();
        let req = ValidatedRequest::validate(raw).expect("valid");
        assert_eq!(
            render(&req, &style_for(true)),
            "\n━━━ Privilege Request ━━━\n\
             From:    s @ h\n\
             Requester: human (self-declared, not verified)\n\
             Client:  sudo-proxy 1.0\n\
             Time:    2026-01-01T00:00:00Z\n\
             ID:      id1\n\
             Reason:  why\n\
             Command: id\n\
             Env:     K=v\n"
        );
    }

    /// Make some strings of a plan long: an argv element or a path of up to
    /// 3 000 chars (1 in 4), or a resolvable long absolute `argv[0]` (1 in 8),
    /// so that every clip, including the three-string `Resolves:` row, runs.
    fn lengthen(plan: &mut Plan, rng: &mut crate::prop::Rng) {
        const ALPHA: &[u8] = b"ab z;'$()&|-*";
        match plan {
            Plan::Exec { argv } => {
                if rng.below(8) == 0 {
                    argv[0] = long_echo_path(rng.below(1_500));
                }
                for a in argv.iter_mut() {
                    if rng.below(4) == 0 {
                        *a = rng.string(ALPHA, 3_000);
                    }
                }
            }
            Plan::Shell { .. } => {}
            Plan::Chdir { dir, body } => {
                if rng.below(4) == 0 {
                    *dir = format!("/{}", rng.string(ALPHA, 3_000));
                }
                lengthen(body, rng);
            }
            Plan::Redirect { target, body, .. } => {
                if let RedirTarget::File { path, .. } = target {
                    if rng.below(4) == 0 {
                        *path = format!("/{}", rng.string(ALPHA, 3_000));
                    }
                }
                lengthen(body, rng);
            }
            Plan::WithStdinFrom { path, body } => {
                if rng.below(4) == 0 {
                    *path = format!("/{}", rng.string(ALPHA, 3_000));
                }
                lengthen(body, rng);
            }
            Plan::Setenv { body, .. }
            | Plan::RunAs { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => lengthen(body, rng),
            Plan::Run { steps } | Plan::Alt { steps } | Plan::Seq { steps } => {
                steps.iter_mut().for_each(|s| lengthen(s, rng))
            }
            Plan::Pipe { stages } => stages.iter_mut().for_each(|s| lengthen(s, rng)),
        }
    }

    /// `line` without a trailing `clip` marker, if it has one.
    fn unmark(line: &str) -> &str {
        match line.rfind("… [") {
            Some(i) if line.ends_with(" more chars hidden]") => &line[..i],
            _ => line,
        }
    }

    // Spec clause (Rung 2, G4.3 / Sn4.3): for every plan, every line of the
    // plan block is bounded, the number of lines is bounded, and each `Steps:`
    // line shows a prefix of its unclipped text.
    #[test]
    fn prop_prompt_lines_are_bounded_and_prefix_faithful() {
        let mut rng = crate::prop::Rng::new(0xB0_0D_ED_85_u64);
        for _ in 0..300 {
            let mut plan = random_any(&mut rng, 4);
            lengthen(&mut plan, &mut rng);
            let req = mk_req(plan, rng.below(2) == 0);
            let full = steps_lines(
                &layout(&req.exec_plan(), &ambient_ctx(req.privileged)),
                &style_for(true),
            );
            for st in [style_for(false), style_for(true)] {
                let out = plan_output(&req, &st);
                let lines: Vec<String> = out.lines().map(strip_csi).collect();
                assert!(
                    lines.len() <= 1 + MAX_DISPLAY_RESOLVES + 1 + 1 + MAX_DISPLAY_STAGES + 1,
                    "{out}"
                );
                for l in &lines {
                    assert!(
                        l.chars().count() <= PLAN_BOUND,
                        "line of {} chars",
                        l.chars().count()
                    );
                }
                let (steps, _) = split_plan_output(&out);
                let shown = full.len().min(MAX_DISPLAY_STAGES);
                let numbered = full[..shown].iter().filter(|l| l.numbered).count();
                let width = numbered.saturating_sub(1).to_string().len();
                for (l, f) in steps.iter().zip(&full[..shown]) {
                    assert!(
                        l.chars().count() <= STEPS_BOUND,
                        "Steps line of {} chars",
                        l.chars().count()
                    );
                    let shown_text: String = l.chars().skip(width).collect();
                    let unclipped = format!(
                        "{}{}{}",
                        "  ".repeat(f.depth + 1),
                        f.text,
                        f.comment(&style_for(true))
                    );
                    let head = unmark(&shown_text);
                    assert!(
                        unclipped.starts_with(head),
                        "not a prefix:\n{head}\nof\n{unclipped}"
                    );
                    if head.len() == shown_text.len() {
                        assert_eq!(head, unclipped);
                    }
                }
            }
        }
    }

    /// The longest `Resolves:` line with the `(user-writable)` marker: both
    /// sides of `->` clipped at their maximum, the marker kept. The property
    /// test above resolves real programs, which are never marked.
    #[test]
    fn user_writable_resolves_line_stays_bounded() {
        let long = format!("/{}", "d".repeat(4094));
        let mut r = Resolved::fake(&long);
        r.canonical = Some(std::path::PathBuf::from(format!("/{}", "e".repeat(4094))));
        r.user_writable = true;
        for st in [style_for(false), style_for(true)] {
            let mut buf = Vec::new();
            write_resolves_line(&mut buf, &format!("{}x", "n".repeat(4000)), Some(&r), &st)
                .unwrap();
            let out = String::from_utf8(buf).unwrap();
            let line = strip_csi(out.lines().next().unwrap());
            assert!(line.ends_with("(user-writable)"), "{line}");
            assert!(
                line.chars().count() <= PLAN_BOUND,
                "line of {} chars",
                line.chars().count()
            );
        }
    }

    /// Issue #86: a symlink's target name never goes through validation, so a
    /// same-UID caller can point an absolute symlink at a file named with ESC
    /// and newline. The `Resolves:` text must print it escaped, not raw.
    #[test]
    fn resolves_escapes_dangerous_symlink_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No `/` in the name: a file name cannot hold one.
        let target = dir.path().join("evil\x1b[2J\nExecute? [y|N]");
        std::fs::write(&target, b"").expect("write target");
        let link = dir.path().join("link");
        // Absolute target, so `canonicalize` succeeds and the
        // `resolved -> canonical` arm is exercised.
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let style = style_for(true);

        let check = |text: &str| {
            assert!(text.contains("\\u{1b}"), "ESC not escaped: {text:?}");
            assert!(text.contains("\\u{a}"), "newline not escaped: {text:?}");
            assert!(!text.contains('\x1b'), "raw ESC: {text:?}");
            assert!(text.contains("->"), "canonical arm not taken: {text:?}");
        };

        let pinned =
            crate::executor::resolve_command(link.to_str().unwrap(), "/").expect("resolves");
        let detail = resolve_detail(Some(&pinned), &style);
        check(&detail);
        assert!(!detail.contains('\n'), "raw newline: {detail:?}");

        let mut out = Vec::new();
        write_resolves_line(&mut out, link.to_str().unwrap(), Some(&pinned), &style).unwrap();
        let line = String::from_utf8(out).unwrap();
        check(&line);
        assert_eq!(line.matches('\n').count(), 1, "raw newline: {line:?}");
    }
}
