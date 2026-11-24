use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;

/// Version stamped onto outgoing wire messages. All four binaries live in
/// the same crate, so this resolves to the same value everywhere.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the sender wants the daemon to do. Absent on the wire for old
/// clients, so it defaults to `Exec`; exec requests from new clients skip
/// the field entirely, keeping them byte-identical to the pre-1.1 format.
///
/// Control actions (`Stop`, `Ping`) are sent with an empty `pipeline`. An
/// old daemon (< 1.1) ignores the unknown `action` key, rejects the empty
/// pipeline at `ValidatedRequest::validate` without prompting the human,
/// and its error `Response` still carries its `version` — which is how new
/// clients detect a peer that predates control actions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Exec,
    Stop,
    Ping,
}

impl Action {
    fn is_exec(&self) -> bool {
        matches!(self, Action::Exec)
    }
}

/// Maximum nesting depth of a structured plan tree. Bounds stack use in the
/// recursive validator / compiler and caps pathologically-nested plans a
/// client could submit. The flat `pipeline` model never needed this; a tree
/// does.
pub const MAX_PLAN_DEPTH: usize = 32;

/// Maximum number of nodes in a structured plan tree. A second, independent
/// bound so a wide-but-shallow plan (thousands of siblings) is rejected even
/// though it stays under `MAX_PLAN_DEPTH`.
pub const MAX_PLAN_NODES: usize = 256;

/// Which stream a `Redirect` node retargets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Stdout,
    Stderr,
    /// Both stdout and stderr (the `2>&1` / `with-outputs-to` case).
    Both,
}

/// Truncate (`>`) vs append (`>>`) for a file redirect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    #[default]
    Truncate,
    Append,
}

/// Where a `Redirect` node sends its stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "to", rename_all = "kebab-case")]
pub enum RedirTarget {
    File {
        path: String,
        #[serde(default)]
        mode: WriteMode,
    },
    /// `>/dev/null` — discard (the Dune `ignore-*` case).
    DevNull,
}

/// The privilege / run-as context a `RunAs` node imposes on its subtree.
///
/// This is the security axis Dune's action DSL lacks. Any `RunAs` node makes
/// the whole request "effectively privileged" (see `Request::effective_privileged`),
/// because running as root *or* as another user requires escalation the daemon
/// gates behind the human prompt. It is the structured replacement for the
/// nested `sudo -H -u <user> bash -lc '…'` the approval log showed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "as", rename_all = "lowercase")]
pub enum RunAs {
    Root,
    User { name: String },
}

/// Which interpreter an explicit `Shell` escape-hatch node runs. Named so the
/// prompt can render the stage as "opaque — resolves only the shell". A shell
/// can also be an `Exec`'s program, directly or behind a wrapper; that stage
/// is flagged opaque the same way, so a shell is never hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellProc {
    Sh,
    Bash,
}

/// A structured execution plan: a recursive tree the daemon executes
/// **directly** (fork/exec per stage: pipes, redirections, env, run-as,
/// sequencing) with **no shell on the privileged path**. The load-bearing
/// invariant: *the structure the human approves is literally the structure
/// that runs.*
///
/// JSON-native (serde-tagged on `op`), not an S-expression sub-language: the
/// wire is already JSON, and a single representation that both the validator
/// and the executor walk means there is no second grammar to diverge from the
/// one that runs. A flat `pipeline` desugars into this via
/// `Request::exec_plan`, so every current client keeps working unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Plan {
    /// A single literal command: prog + args (one `execve`). No word-splitting,
    /// globbing, or substitution — the leaf of every tree.
    Exec { argv: Vec<String> },
    /// Run steps in order, stopping at the first non-accepted exit (≈ `&&`).
    /// Status is the last step that ran. Dune `progn` with short-circuit.
    Run { steps: Vec<Plan> },
    /// Run every step in order regardless of exit (≈ `;`). A non-accepted exit
    /// does not stop the rest; a timeout or spawn failure still aborts. Status
    /// is the last step's.
    Seq { steps: Vec<Plan> },
    /// Alternatives; run steps until one succeeds, continuing past a non-accepted
    /// exit and stopping on the first success (≈ `||`). Dual of `run`.
    Alt { steps: Vec<Plan> },
    /// Connect stdout→stdin left-to-right (Dune `pipe-stdout`, = `|`).
    Pipe { stages: Vec<Plan> },
    /// Redirect a stream of the inner plan to a file or /dev/null.
    Redirect {
        stream: Stream,
        target: RedirTarget,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// Feed a file as stdin to the inner plan (Dune `with-stdin-from`, = `<`).
    WithStdinFrom {
        path: String,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// Add an env var to the inner plan's scope (Dune `setenv`). Still subject
    /// to the executor's env allowlist at run time.
    Setenv {
        key: String,
        value: String,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// Change cwd for the inner plan (Dune `chdir`).
    Chdir {
        dir: String,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// Run the inner plan under a specific privilege context — `[ROOT]` or
    /// `[as <user>]`. The axis Dune lacks; see `RunAs`. `who` is flattened, so
    /// the wire form is `{"op":"run-as","as":"root","do":{…}}` /
    /// `{"op":"run-as","as":"user","name":"…","do":{…}}` (matching the MCP docs),
    /// not a nested `"who":{…}` object.
    RunAs {
        #[serde(flatten)]
        who: RunAs,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// Treat these exit codes as success (Dune `with-accepted-exit-codes`).
    WithAcceptedExitCodes {
        codes: Vec<i32>,
        #[serde(rename = "do")]
        body: Box<Plan>,
    },
    /// EXPLICIT opaque escape hatch (Dune `system`/`bash`). Rendered at the
    /// prompt as "opaque — resolves only the shell"; the strict `no_shell`
    /// policy (`policy.no_shell` in hosts.json, or `--no-shell`) rejects it
    /// before prompting. An `Exec` whose program is a shell (`sh -c '…'`,
    /// `bash script.sh`), directly or behind a wrapper (`env sh -c …`,
    /// `timeout 5 bash …`), is treated identically, so the hatch cannot be
    /// taken unflagged; so are inline-code interpreters (`python3 -c`) and
    /// program runners (`sudo`, `ssh`) — see `crate::wrappers`.
    Shell { shell: ShellProc, script: String },
}

impl Plan {
    /// Recursively reject dangerous characters on **every** string leaf and
    /// enforce the depth / node-count bounds. Mirrors the flat-pipeline checks
    /// in `ValidatedRequest::validate` (same `has_dangerous_chars` predicate,
    /// same non-empty rule) so the Rung 2 property test and Rung 3 Kani harness
    /// extend to the tree rather than restarting.
    ///
    /// `nodes` accumulates the total node count across the whole tree so a
    /// wide plan is bounded independently of depth.
    pub(crate) fn validate_tree(&self, depth: usize, nodes: &mut usize) -> Result<(), String> {
        if depth > MAX_PLAN_DEPTH {
            return Err(format!("plan nesting exceeds {MAX_PLAN_DEPTH} levels"));
        }
        *nodes += 1;
        if *nodes > MAX_PLAN_NODES {
            return Err(format!("plan exceeds {MAX_PLAN_NODES} nodes"));
        }
        let check = |s: &str, what: &str| -> Result<(), String> {
            if has_dangerous_chars(s) {
                Err(format!("{what} contains forbidden control/bidi characters"))
            } else {
                Ok(())
            }
        };
        match self {
            Plan::Exec { argv } => {
                if argv.is_empty() {
                    return Err("exec stage must have a command".to_string());
                }
                for a in argv {
                    check(a, "argv element")?;
                }
            }
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                if steps.is_empty() {
                    return Err("run/seq/alt must have at least one step".to_string());
                }
                for s in steps {
                    s.validate_tree(depth + 1, nodes)?;
                }
            }
            Plan::Pipe { stages } => {
                if stages.len() < 2 {
                    return Err("pipe must have at least two stages".to_string());
                }
                for s in stages {
                    s.validate_tree(depth + 1, nodes)?;
                }
            }
            Plan::Redirect { target, body, .. } => {
                if let RedirTarget::File { path, .. } = target {
                    check(path, "redirect path")?;
                    require_absolute(path, "redirect path")?;
                }
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::WithStdinFrom { path, body } => {
                check(path, "stdin path")?;
                require_absolute(path, "stdin path")?;
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::Setenv { key, value, body } => {
                check(key, "env key")?;
                if !is_valid_env_name(key) {
                    return Err(format!("setenv key '{key}' is not a valid variable name"));
                }
                check(value, "env value")?;
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::Chdir { dir, body } => {
                check(dir, "chdir dir")?;
                require_absolute(dir, "chdir dir")?;
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::RunAs { who, body } => {
                if let RunAs::User { name } = who {
                    if name.is_empty() {
                        return Err("run-as user must be named".to_string());
                    }
                    // sudo reads `#<uid>` as a numeric uid, so `#0` is root
                    // under a name the prompt would not recognise as root.
                    if name.starts_with('#') {
                        return Err("run-as user must be a name, not a #uid".to_string());
                    }
                    check(name, "run-as user")?;
                }
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::WithAcceptedExitCodes { body, .. } => {
                body.validate_tree(depth + 1, nodes)?;
            }
            Plan::Shell { script, .. } => {
                check(script, "system script")?;
            }
        }
        Ok(())
    }

    /// Reject stdio shapes whose shell rendering would not mean what the
    /// executor does. In the shell the *last* redirection of a stream wins, so
    /// the prompt's `cmd > G > F` writes to F, while the executor lets the
    /// innermost node win (G). Rather than display a target that is never
    /// opened, a stream may be redirected at most once along any path. Likewise
    /// a later pipe stage reads the previous stage, so a `with-stdin-from` on it
    /// is rejected rather than silently ignored.
    ///
    /// `out` / `err` / `inp`: whether an enclosing node already redirects
    /// stdout / stderr / stdin.
    pub(crate) fn validate_stdio(&self, out: bool, err: bool, inp: bool) -> Result<(), String> {
        match self {
            Plan::Exec { .. } | Plan::Shell { .. } => Ok(()),
            Plan::Redirect { stream, body, .. } => {
                let (o, e) = match stream {
                    Stream::Stdout => (true, false),
                    Stream::Stderr => (false, true),
                    Stream::Both => (true, true),
                };
                if (o && out) || (e && err) {
                    return Err("a stream is redirected twice; keep only one redirect per stream"
                        .to_string());
                }
                body.validate_stdio(out || o, err || e, inp)
            }
            Plan::WithStdinFrom { body, .. } => {
                if inp {
                    return Err("stdin is redirected twice; keep only one with-stdin-from".to_string());
                }
                body.validate_stdio(out, err, true)
            }
            Plan::Pipe { stages } => {
                for (i, s) in stages.iter().enumerate() {
                    if i > 0 && s.contains_stdin_from() {
                        return Err(
                            "with-stdin-from is only allowed on the first pipe stage".to_string()
                        );
                    }
                    s.validate_stdio(out, err, inp)?;
                }
                Ok(())
            }
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter().try_for_each(|s| s.validate_stdio(out, err, inp))
            }
            Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::RunAs { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => body.validate_stdio(out, err, inp),
        }
    }

    fn contains_stdin_from(&self) -> bool {
        match self {
            Plan::Exec { .. } | Plan::Shell { .. } => false,
            Plan::WithStdinFrom { .. } => true,
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter().any(Plan::contains_stdin_from)
            }
            Plan::Pipe { stages } => stages.iter().any(Plan::contains_stdin_from),
            Plan::Redirect { body, .. }
            | Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::RunAs { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => body.contains_stdin_from(),
        }
    }

    /// Canonicalise run-as targets: a `user` named `root` is the root
    /// escalation, so it becomes `RunAs::Root` and gets the root wording and
    /// colouring at the prompt.
    pub(crate) fn normalize_runas(&mut self) {
        match self {
            Plan::Exec { .. } | Plan::Shell { .. } => {}
            Plan::RunAs { who, body } => {
                if matches!(who, RunAs::User { name } if name == "root") {
                    *who = RunAs::Root;
                }
                body.normalize_runas();
            }
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter_mut().for_each(Plan::normalize_runas)
            }
            Plan::Pipe { stages } => stages.iter_mut().for_each(Plan::normalize_runas),
            Plan::Redirect { body, .. }
            | Plan::WithStdinFrom { body, .. }
            | Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => body.normalize_runas(),
        }
    }

    /// True if any subtree imposes a `RunAs` context. Any run-as — root or a
    /// named user — requires escalation the daemon must gate as privileged, so
    /// this drives `Request::effective_privileged`.
    pub fn contains_runas(&self) -> bool {
        match self {
            Plan::Exec { .. } | Plan::Shell { .. } => false,
            Plan::RunAs { .. } => true,
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter().any(Plan::contains_runas)
            }
            Plan::Pipe { stages } => stages.iter().any(Plan::contains_runas),
            Plan::Redirect { body, .. }
            | Plan::WithStdinFrom { body, .. }
            | Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => body.contains_runas(),
        }
    }

    /// True if any subtree is a root `RunAs`. Drives the prompt's "Execute as
    /// root?" wording (vs. a milder "with elevated privileges?" when the only
    /// escalation is to a named non-root user).
    pub fn contains_root(&self) -> bool {
        match self {
            Plan::Exec { .. } | Plan::Shell { .. } => false,
            Plan::RunAs { who: RunAs::Root, .. } => true,
            Plan::RunAs { who: RunAs::User { .. }, body } => body.contains_root(),
            Plan::Run { steps } | Plan::Seq { steps } | Plan::Alt { steps } => {
                steps.iter().any(Plan::contains_root)
            }
            Plan::Pipe { stages } => stages.iter().any(Plan::contains_root),
            Plan::Redirect { body, .. }
            | Plan::WithStdinFrom { body, .. }
            | Plan::Setenv { body, .. }
            | Plan::Chdir { body, .. }
            | Plan::WithAcceptedExitCodes { body, .. } => body.contains_root(),
        }
    }
}

/// Plan paths (`chdir`, redirect targets, `with-stdin-from`) must be absolute:
/// a relative one would resolve against the daemon's own cwd, not the
/// enclosing `chdir` the prompt shows it under.
fn require_absolute(path: &str, what: &str) -> Result<(), String> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(format!("{what} must be an absolute path: {path}"))
    }
}

/// A POSIX shell variable name: `[A-Za-z_][A-Za-z0-9_]*`. Any env key —
/// request-level or `setenv` — must be one, so the prompt's `export K=…` and
/// `sudo K=V …` renderings can never carry shell syntax in the key.
pub(crate) fn is_valid_env_name(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Desugar a flat `pipeline` into an equivalent `Plan` tree. A single stage
/// becomes a bare `Exec`; multiple stages become a `Pipe`. Ambient privilege is
/// **not** encoded here — the executor seeds its run-as context from
/// `Request::privileged`, so a desugared tree and an explicit plan are handled
/// uniformly. An empty pipeline (control actions only) yields an empty `Run`,
/// which never reaches execution.
fn desugar_pipeline(pipeline: &[Vec<String>]) -> Plan {
    let mut stages: Vec<Plan> = pipeline
        .iter()
        .map(|argv| Plan::Exec { argv: argv.clone() })
        .collect();
    match stages.len() {
        0 => Plan::Run { steps: vec![] },
        1 => stages.pop().unwrap(),
        _ => Plan::Pipe { stages },
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_session")]
    pub session: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub pipeline: Vec<Vec<String>>,
    /// Optional structured execution plan. When present it is the canonical
    /// form the daemon validates, executes, and renders; `pipeline` is then a
    /// legacy sugar left empty. Exactly one of `plan` / `pipeline` carries the
    /// command. `skip_serializing_if` keeps exec requests that use `pipeline`
    /// byte-identical to the pre-plan wire format, and an old daemon that drops
    /// this unknown key sees an empty `pipeline` and rejects cleanly at
    /// validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Plan>,
    #[serde(default, skip_serializing_if = "Action::is_exec")]
    pub action: Action,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_true")]
    pub privileged: bool,
    /// Inject the daemon's snapshotted SSH_AUTH_SOCK into the child env
    /// so unprivileged commands (e.g. `git clone`) can reach the user's
    /// agent. Honored only when `privileged` is false; the daemon
    /// rejects the request otherwise.
    #[serde(default)]
    pub forward_agent: bool,
    /// Sender's `CARGO_PKG_VERSION`. Empty when peer predates this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Self-declared identity of the requester (conventionally "human", "ai",
    /// "ai:<model>", "automation"). NOT authenticated: the daemon shows it to
    /// the approver as-is, like `reason`, and never uses it as a trust signal.
    /// Empty when the peer predates this field (rendered as nothing).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub requester: String,
}

pub(crate) fn default_true() -> bool {
    true
}

fn default_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Request {
    /// Build an outgoing request, stamping the fields every sender fills the
    /// same way: a fresh random `id`, the current time, and this binary's
    /// `version`. Callers supply only what actually varies between sites.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: String,
        session: String,
        pipeline: Vec<Vec<String>>,
        env: HashMap<String, String>,
        reason: String,
        privileged: bool,
        forward_agent: bool,
    ) -> Self {
        Self {
            id: default_id(),
            host,
            session,
            time: crate::datetime::now_iso8601(),
            pipeline,
            plan: None,
            action: Action::Exec,
            env,
            reason,
            privileged,
            forward_agent,
            version: VERSION.to_string(),
            requester: String::new(),
        }
    }

    /// Build an outgoing exec request carrying a structured `plan` instead of a
    /// flat `pipeline`. The `pipeline` field is left empty; the daemon reads the
    /// command from `plan`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_plan(
        host: String,
        session: String,
        plan: Plan,
        env: HashMap<String, String>,
        reason: String,
        privileged: bool,
        forward_agent: bool,
    ) -> Self {
        Self {
            id: default_id(),
            host,
            session,
            time: crate::datetime::now_iso8601(),
            pipeline: vec![],
            plan: Some(plan),
            action: Action::Exec,
            env,
            reason,
            privileged,
            forward_agent,
            version: VERSION.to_string(),
            requester: String::new(),
        }
    }

    /// Build a control request (`Stop` / `Ping`). The empty pipeline is
    /// deliberate: it is what makes an old daemon reject the request at
    /// validation — before any prompt — while still stamping its version
    /// on the error response.
    pub fn control(host: String, session: String, action: Action) -> Self {
        Self {
            id: default_id(),
            host,
            session,
            time: crate::datetime::now_iso8601(),
            pipeline: vec![],
            plan: None,
            action,
            env: HashMap::new(),
            reason: String::new(),
            privileged: false,
            forward_agent: false,
            version: VERSION.to_string(),
            requester: String::new(),
        }
    }

    /// The canonical execution plan: the explicit `plan` if present, otherwise
    /// the flat `pipeline` desugared into an equivalent tree. Single source of
    /// truth for validation, execution, and the approval-prompt render, so the
    /// structure the human approves is exactly the structure the executor runs.
    pub fn exec_plan(&self) -> Plan {
        match &self.plan {
            Some(p) => p.clone(),
            None => desugar_pipeline(&self.pipeline),
        }
    }

    /// Whether this request must be gated as privileged. True when the top-level
    /// `privileged` flag is set, *or* the plan contains any `RunAs` node — a
    /// root or named-user escalation an unprivileged request must not smuggle
    /// past the quieter unprivileged gate.
    pub fn effective_privileged(&self) -> bool {
        self.privileged || self.plan.as_ref().is_some_and(Plan::contains_runas)
    }

    /// Whether any part of the request runs as root — the top-level privileged
    /// flag, or an explicit root `RunAs`. Drives the prompt's "as root" wording.
    pub fn runs_as_root(&self) -> bool {
        self.privileged || self.plan.as_ref().is_some_and(Plan::contains_root)
    }

    /// Whether the requester self-identifies as an AI agent (`"ai"` or
    /// `"ai:<identity>"`). A display hint only: the value is client-asserted.
    pub fn requester_is_ai(&self) -> bool {
        self.requester == "ai" || self.requester.starts_with("ai:")
    }
}

fn default_session() -> String {
    "unknown".to_string()
}

/// Every code point forbidden in prompt-rendered text, as sorted,
/// non-overlapping, inclusive `(lo, hi)` ranges. The rule is
///
/// > dangerous(c) ⇔ c ≠ TAB ∧ c ∈ Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point
///
/// i.e. control (C0, DEL, C1 including NEL/CSI/OSC), format (soft hyphen,
/// zero-width, bidi embeddings/overrides/isolates/marks, BOM, invisible
/// operators, interlinear annotation, tag characters), line/paragraph
/// separators, and every default-ignorable code point (variation selectors,
/// Hangul fillers, reserved ignorables such as U+2065 and U+E0000–E0FFF), which
/// render as nothing and so can hide text from the approver.
///
/// Built from the Unicode 16.0.0 UCD (General_Category, and
/// `DerivedCoreProperties.txt` Default_Ignorable_Code_Point), merging adjacent
/// ranges. TAB is in the table (it is Cc) and is exempted by
/// [`is_dangerous_char`]. The table is not trusted by inspection: the unit test
/// `dangerous_class_matches_unicode_oracle` checks it exhaustively, over every
/// `char`, against a General_Category oracle of the same Unicode version plus
/// a verbatim copy of the DICP list.
pub(crate) const DANGEROUS_RANGES: &[(u32, u32)] = &[
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// True if `c` is forbidden in any request-derived string rendered on the
/// approval prompt: a control, format, separator or default-ignorable
/// character other than TAB (see [`DANGEROUS_RANGES`]).
///
/// Also used by `mcp::sanitize_description` (same crate) to strip this class
/// from the MCP `description` before it becomes `reason`.
///
/// The lookup is a binary search (`partition_point`) rather than a linear
/// scan, so the Kani harnesses in `src/proofs.rs` need an unwind bound near
/// log2(table length) rather than the table length + 1.
pub(crate) fn is_dangerous_char(c: char) -> bool {
    if c == '\t' {
        return false;
    }
    let u = c as u32;
    // First range whose upper bound is >= u; it holds u iff its lower bound
    // is <= u.
    let i = DANGEROUS_RANGES.partition_point(|&(_, hi)| hi < u);
    i < DANGEROUS_RANGES.len() && DANGEROUS_RANGES[i].0 <= u
}

/// True if `s` contains a character forbidden in any request-derived string
/// that is rendered on the approval prompt: control, format, separator and
/// default-ignorable characters (Cc/Cf/Zl/Zp/DICP), except tab. The prompt is
/// the security gate, so a field carrying raw ANSI/escape/newline, bidi or
/// invisible characters could redraw the terminal or hide text, and so
/// misrepresent the command being approved. See [`is_dangerous_char`].
///
/// `pub(crate)` so the Rung 2 property test and the Rung 3 Kani harness can
/// drive it directly; the only *enforcement* path is `ValidatedRequest::validate`.
pub(crate) fn has_dangerous_chars(s: &str) -> bool {
    s.chars().any(is_dangerous_char)
}

/// Make text that never went through `ValidatedRequest::validate` (e.g. a
/// filesystem-derived path) safe to print on the approval prompt: every
/// [`is_dangerous_char`] character is written as a `\u{…}` escape; tab and
/// everything else are kept as is.
pub(crate) fn escape_dangerous(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_dangerous_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// A `Request` that has passed `ValidatedRequest::validate`.
///
/// The wrapped `Request` is private to this module, so the *only* way to obtain
/// a `ValidatedRequest` is through the validating constructor below. The
/// privileged execution path (`executor::exec_*`) and the approval prompt
/// (`tui::Prompter`) take `&ValidatedRequest`, which makes "a request reaching
/// dispatch skipped validation" a *compile error* rather than a runtime gap —
/// the Rung 3 closure of the F1-class finding. See docs/formalisation-roadmap.md.
#[derive(Clone, Debug)]
pub struct ValidatedRequest(Request);

impl ValidatedRequest {
    /// Validate every attacker-controlled, prompt-rendered field of `req` and,
    /// on success, consume it into a `ValidatedRequest`. The checks: a non-empty
    /// pipeline of non-empty stages, and no dangerous character in any argv
    /// element, env key/value, or in `reason`/`session`/`host`/`version`/`id`/
    /// `requester`.
    ///
    /// `reason` may arrive from the MCP `description`, and `host`/`session`/
    /// `id`/`version` from a direct same-UID socket client that bypasses the
    /// client-side `validate_host`; all are held to the same sanitization as
    /// argv and env. See `tui::prompt_tty` for the render this protects.
    pub fn validate(mut req: Request) -> Result<Self, String> {
        // Control actions (Stop/Ping) carry no pipeline by design; only an
        // Exec request must have one. An explicit `plan` is the modern form, so
        // an Exec request is "empty" only when it has neither. Every string-
        // field check below stays unconditional, so control requests are
        // sanitized like any other.
        if req.action == Action::Exec && req.pipeline.is_empty() && req.plan.is_none() {
            return Err("pipeline must not be empty".to_string());
        }
        // A request carries at most one command form. Rejecting both-present
        // removes the ambiguity of which one the executor would run.
        if !req.pipeline.is_empty() && req.plan.is_some() {
            return Err("request must not set both pipeline and plan".to_string());
        }
        // Flat-pipeline path: keep the exact per-stage checks (and their error
        // messages) the pre-plan wire format relied on.
        for (stage_idx, argv) in req.pipeline.iter().enumerate() {
            if argv.is_empty() {
                return Err(format!("pipeline stage {stage_idx} must not be empty"));
            }
            for (i, arg) in argv.iter().enumerate() {
                if has_dangerous_chars(arg) {
                    return Err(format!(
                        "pipeline[{stage_idx}][{i}] contains forbidden control/bidi characters"
                    ));
                }
            }
        }
        // Structured-plan path: recursively sanitize every string leaf and
        // enforce the depth / node bounds, using the same `has_dangerous_chars`
        // predicate as the flat path above.
        if let Some(plan) = &mut req.plan {
            let mut nodes = 0usize;
            plan.validate_tree(0, &mut nodes)?;
            plan.validate_stdio(false, false, false)?;
            plan.normalize_runas();
        }
        for key in req.env.keys() {
            if has_dangerous_chars(key) {
                // Do not echo the key: by construction it holds a forbidden char.
                return Err("env key contains forbidden characters".to_string());
            }
            if !is_valid_env_name(key) {
                return Err(format!("env key '{key}' is not a valid variable name"));
            }
        }
        for val in req.env.values() {
            if has_dangerous_chars(val) {
                return Err("env value contains forbidden characters".to_string());
            }
        }
        for (field, value) in [
            ("reason", &req.reason),
            ("session", &req.session),
            ("host", &req.host),
            ("version", &req.version),
            ("id", &req.id),
            ("requester", &req.requester),
        ] {
            if has_dangerous_chars(value) {
                return Err(format!("{field} contains forbidden control/bidi characters"));
            }
        }
        Ok(ValidatedRequest(req))
    }

    /// Borrow the validated request.
    pub fn inner(&self) -> &Request {
        &self.0
    }
}

impl Deref for ValidatedRequest {
    type Target = Request;
    fn deref(&self) -> &Request {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageResult {
    pub exit_code: i32,
    pub stderr: String, // base64
    /// True if the stage's stderr was capped before the child finished
    /// writing. Defaults to false; old peers without this field deserialize
    /// to false transparently.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<StageResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    /// True if the final stdout was capped at MAX_OUTPUT_BYTES before the
    /// child finished writing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stdout_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Daemon's `CARGO_PKG_VERSION`. Empty when peer predates this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Denied,
    Timeout,
    Error,
}

impl Response {
    pub fn ok(id: &str, stages: Vec<StageResult>, stdout: &[u8]) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Ok,
            stages,
            stdout: Some(B64.encode(stdout)),
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn ok_with_truncation(
        id: &str,
        stages: Vec<StageResult>,
        stdout: &[u8],
        stdout_truncated: bool,
    ) -> Self {
        let mut r = Self::ok(id, stages, stdout);
        r.stdout_truncated = stdout_truncated;
        r
    }

    pub fn denied(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Denied,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn timeout(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Timeout,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: None,
            version: VERSION.to_string(),
        }
    }

    pub fn error(id: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            status: Status::Error,
            stages: vec![],
            stdout: None,
            stdout_truncated: false,
            message: Some(message.to_string()),
            version: VERSION.to_string(),
        }
    }

    /// Returns the exit code of the last stage, or 0 if no stages.
    pub fn exit_code(&self) -> i32 {
        self.stages.last().map(|s| s.exit_code).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_request() -> Request {
        Request::new(
            String::new(),
            "test".into(),
            vec![vec!["ls".into()]],
            HashMap::new(),
            String::new(),
            true,
            false,
        )
    }

    /// Wire compat: a request from an old client (no `action` key) must
    /// deserialize to `Action::Exec`.
    #[test]
    fn action_absent_defaults_to_exec() {
        let json = r#"{"id":"a","session":"s","time":"2026-01-01T00:00:00Z","pipeline":[["ls"]]}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, Action::Exec);
    }

    /// Wire compat the other way: an exec request from a new client must be
    /// byte-identical to the pre-1.1 format — no `action` key on the wire.
    #[test]
    fn exec_request_omits_action_on_wire() {
        let json = serde_json::to_string(&exec_request()).unwrap();
        assert!(!json.contains("action"), "exec must not serialize `action`: {json}");
    }

    /// A control request must serialize an explicit empty pipeline (so old
    /// daemons parse it and reject at validate, version-stamping the error)
    /// and must round-trip its action.
    #[test]
    fn control_request_serializes_empty_pipeline_and_action() {
        let req = Request::control(String::new(), "test".into(), Action::Stop);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""pipeline":[]"#), "missing empty pipeline: {json}");
        assert!(json.contains(r#""action":"stop""#), "missing action: {json}");
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, Action::Stop);
    }

    #[test]
    fn validate_allows_empty_pipeline_for_control_only() {
        for action in [Action::Stop, Action::Ping] {
            let req = Request::control(String::new(), "test".into(), action);
            assert!(ValidatedRequest::validate(req).is_ok(), "{action:?} must validate");
        }
        let mut req = Request::control(String::new(), "test".into(), Action::Exec);
        req.pipeline = vec![];
        assert_eq!(
            ValidatedRequest::validate(req).unwrap_err(),
            "pipeline must not be empty"
        );
    }

    /// Control requests go through the same dangerous-character sanitization
    /// as exec requests — every displayed field is still checked.
    #[test]
    fn validate_still_sanitizes_control_fields() {
        let mut req = Request::control(String::new(), "test".into(), Action::Ping);
        req.session.push('\u{1b}');
        assert!(ValidatedRequest::validate(req).is_err());
    }

    // === Requester self-identification (issue #25) ========================

    /// Wire compat: an old client sends no `requester`; it must deserialize to
    /// empty (rendered as nothing), and an empty one must not be serialized.
    #[test]
    fn requester_absent_defaults_to_empty_and_is_not_serialized() {
        let json = r#"{"id":"a","session":"s","time":"2026-01-01T00:00:00Z","pipeline":[["ls"]]}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.requester, "");
        let out = serde_json::to_string(&exec_request()).unwrap();
        assert!(!out.contains("requester"), "empty requester must be omitted: {out}");
    }

    #[test]
    fn requester_round_trips_and_is_sanitized() {
        let mut req = exec_request();
        req.requester = "ai:test".into();
        let back: Request = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.requester, "ai:test");
        req.requester.push('\u{1b}');
        assert_eq!(
            ValidatedRequest::validate(req).unwrap_err(),
            "requester contains forbidden control/bidi characters"
        );
    }

    #[test]
    fn requester_is_ai_matches_ai_and_ai_prefix_only() {
        let mut req = exec_request();
        for (value, expected) in [
            ("ai", true),
            ("ai:claude", true),
            ("", false),
            ("human", false),
            ("automation", false),
            ("aix", false),
            ("AI", false),
        ] {
            req.requester = value.into();
            assert_eq!(req.requester_is_ai(), expected, "{value:?}");
        }
    }

    // === Structured plan schema ===========================================

    fn exec(argv: &[&str]) -> Plan {
        Plan::Exec { argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    /// A single-stage pipeline desugars to a bare `Run`; a multi-stage pipeline
    /// to a `Pipe`. This is the compat shim the whole backward-compatibility
    /// story rests on.
    #[test]
    fn desugar_pipeline_shapes() {
        let single = desugar_pipeline(&[vec!["ls".into(), "-l".into()]]);
        assert_eq!(single, exec(&["ls", "-l"]));

        let multi = desugar_pipeline(&[vec!["ls".into()], vec!["wc".into(), "-l".into()]]);
        assert_eq!(multi, Plan::Pipe { stages: vec![exec(&["ls"]), exec(&["wc", "-l"])] });

        assert_eq!(desugar_pipeline(&[]), Plan::Run { steps: vec![] });
    }

    /// An explicit `plan` round-trips through JSON with the `op`-tagged form,
    /// and a flat-pipeline exec request still omits the `plan` key entirely
    /// (wire compat).
    #[test]
    fn plan_wire_roundtrip_and_omission() {
        let req = Request::new_plan(
            String::new(),
            "s".into(),
            Plan::Run { steps: vec![exec(&["true"]), exec(&["false"])] },
            HashMap::new(),
            String::new(),
            true,
            false,
        );
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"run""#), "tagged form missing: {json}");
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exec_plan(), req.exec_plan());

        // An `alt` plan round-trips with its own `op` tag.
        let alt = Request::new_plan(
            String::new(),
            "s".into(),
            Plan::Alt { steps: vec![exec(&["false"]), exec(&["true"])] },
            HashMap::new(),
            String::new(),
            true,
            false,
        );
        let alt_json = serde_json::to_string(&alt).unwrap();
        assert!(alt_json.contains(r#""op":"alt""#), "tagged form missing: {alt_json}");
        let alt_back: Request = serde_json::from_str(&alt_json).unwrap();
        assert_eq!(alt_back.exec_plan(), alt.exec_plan());

        // A pipeline request must not serialize a `plan` key.
        let flat = exec_request();
        let flat_json = serde_json::to_string(&flat).unwrap();
        assert!(!flat_json.contains("plan"), "flat request leaked plan key: {flat_json}");
    }

    /// `run-as` uses the flattened wire form documented by the MCP tool —
    /// `{"op":"run-as","as":"root","do":{…}}` — not a nested `"who":{…}` object.
    /// Both root and named-user forms round-trip, and the exact JSON the MCP doc
    /// advertises deserializes. (Regression guard for finding F1.)
    #[test]
    fn run_as_wire_form_is_flattened_and_matches_docs() {
        let root = Request::new_plan(
            String::new(),
            "s".into(),
            Plan::RunAs { who: RunAs::Root, body: Box::new(exec(&["id", "-un"])) },
            HashMap::new(),
            String::new(),
            true,
            false,
        );
        let json = serde_json::to_string(&root).unwrap();
        assert!(json.contains(r#""op":"run-as""#), "op tag missing: {json}");
        assert!(json.contains(r#""as":"root""#), "flattened `as` missing: {json}");
        assert!(!json.contains(r#""who""#), "`who` should be flattened away: {json}");
        assert_eq!(
            serde_json::from_str::<Request>(&json).unwrap().exec_plan(),
            root.exec_plan()
        );

        // The exact JSON shapes the MCP `plan` doc advertises must parse.
        let doc_root = r#"{"op":"run-as","as":"root","do":{"op":"exec","argv":["id"]}}"#;
        let doc_user = r#"{"op":"run-as","as":"user","name":"alice","do":{"op":"exec","argv":["id"]}}"#;
        let p_root: Plan = serde_json::from_str(doc_root).unwrap();
        let p_user: Plan = serde_json::from_str(doc_user).unwrap();
        assert_eq!(p_root, Plan::RunAs { who: RunAs::Root, body: Box::new(exec(&["id"])) });
        assert_eq!(
            p_user,
            Plan::RunAs {
                who: RunAs::User { name: "alice".into() },
                body: Box::new(exec(&["id"])),
            }
        );
    }

    /// `effective_privileged` is true for a top-level privileged flag, and also
    /// for an unprivileged request whose plan smuggles any `RunAs` node.
    #[test]
    fn effective_privileged_accounts_for_runas() {
        let mut req = Request::new_plan(
            String::new(),
            "s".into(),
            Plan::RunAs {
                who: RunAs::Root,
                body: Box::new(exec(&["sysctl", "-w", "x=1"])),
            },
            HashMap::new(),
            String::new(),
            false, // unprivileged flag...
            false,
        );
        assert!(req.effective_privileged(), "root RunAs must force privileged");
        assert!(req.runs_as_root());

        // A named-user RunAs still forces the privileged gate, but is not root.
        req.plan = Some(Plan::RunAs {
            who: RunAs::User { name: "alice".into() },
            body: Box::new(exec(&["dune", "build"])),
        });
        assert!(req.effective_privileged());
        assert!(!req.runs_as_root());

        // A plain plan with no RunAs and no flag is unprivileged.
        req.plan = Some(exec(&["ls"]));
        req.privileged = false;
        assert!(!req.effective_privileged());
    }

    #[test]
    fn validate_rejects_dangerous_leaf_in_plan() {
        let req = Request::new_plan(
            String::new(),
            "s".into(),
            Plan::Setenv {
                key: "LANG".into(),
                value: "x\u{1b}y".into(), // ESC in a setenv value
                body: Box::new(exec(&["true"])),
            },
            HashMap::new(),
            String::new(),
            false,
            false,
        );
        let err = ValidatedRequest::validate(req).unwrap_err();
        assert!(err.contains("forbidden"), "got: {err}");
    }

    #[test]
    fn validate_rejects_both_pipeline_and_plan() {
        let mut req = exec_request();
        req.plan = Some(exec(&["ls"]));
        let err = ValidatedRequest::validate(req).unwrap_err();
        assert!(err.contains("both pipeline and plan"), "got: {err}");
    }

    #[test]
    fn validate_rejects_overdeep_plan() {
        // Nest RunAs past MAX_PLAN_DEPTH.
        let mut p = exec(&["true"]);
        for _ in 0..(MAX_PLAN_DEPTH + 2) {
            p = Plan::RunAs { who: RunAs::Root, body: Box::new(p) };
        }
        let req = Request::new_plan(
            String::new(), "s".into(), p, HashMap::new(), String::new(), true, false,
        );
        let err = ValidatedRequest::validate(req).unwrap_err();
        assert!(err.contains("nesting exceeds"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_run_and_short_pipe() {
        let empty_run = Request::new_plan(
            String::new(), "s".into(), Plan::Exec { argv: vec![] },
            HashMap::new(), String::new(), false, false,
        );
        assert!(ValidatedRequest::validate(empty_run).is_err());

        let short_pipe = Request::new_plan(
            String::new(), "s".into(),
            Plan::Pipe { stages: vec![exec(&["ls"])] },
            HashMap::new(), String::new(), false, false,
        );
        assert!(ValidatedRequest::validate(short_pipe).is_err());

        let empty_alt = Request::new_plan(
            String::new(), "s".into(),
            Plan::Alt { steps: vec![] },
            HashMap::new(), String::new(), false, false,
        );
        assert!(ValidatedRequest::validate(empty_alt).is_err());
    }

    fn plan_req(plan: Plan) -> Request {
        Request::new_plan(String::new(), "s".into(), plan, HashMap::new(), String::new(), false, false)
    }

    fn redirect(stream: Stream, path: &str, body: Plan) -> Plan {
        Plan::Redirect {
            stream,
            target: RedirTarget::File { path: path.into(), mode: WriteMode::Truncate },
            body: Box::new(body),
        }
    }

    fn stdin_from(path: &str, body: Plan) -> Plan {
        Plan::WithStdinFrom { path: path.into(), body: Box::new(body) }
    }

    /// The shell lets the last redirection of a stream win, the executor the
    /// innermost: a stream redirected twice cannot be displayed faithfully, so
    /// it is rejected.
    #[test]
    fn validate_rejects_a_stream_redirected_twice() {
        let twice = [
            (Stream::Stdout, Stream::Stdout),
            (Stream::Stderr, Stream::Stderr),
            (Stream::Both, Stream::Stdout),
            (Stream::Both, Stream::Stderr),
            (Stream::Stdout, Stream::Both),
        ];
        for (outer, inner) in twice {
            let p = redirect(outer, "/tmp/f", redirect(inner, "/tmp/g", exec(&["echo"])));
            let err = ValidatedRequest::validate(plan_req(p)).unwrap_err();
            assert!(err.contains("redirected twice"), "{outer:?}/{inner:?}: {err}");
        }
        // Different streams are fine.
        let p = redirect(Stream::Stdout, "/tmp/f", redirect(Stream::Stderr, "/tmp/g", exec(&["echo"])));
        assert!(ValidatedRequest::validate(plan_req(p)).is_ok());
        // So is the same stream on sibling steps.
        let p = Plan::Run {
            steps: vec![
                redirect(Stream::Stdout, "/tmp/f", exec(&["echo"])),
                redirect(Stream::Stdout, "/tmp/g", exec(&["echo"])),
            ],
        };
        assert!(ValidatedRequest::validate(plan_req(p)).is_ok());
        // Stdin twice.
        let p = stdin_from("/dev/null", stdin_from("/dev/zero", exec(&["cat"])));
        assert!(ValidatedRequest::validate(plan_req(p)).unwrap_err().contains("stdin is redirected twice"));
    }

    #[test]
    fn validate_rejects_stdin_on_a_later_pipe_stage() {
        let p = Plan::Pipe { stages: vec![exec(&["echo", "x"]), stdin_from("/etc/hostname", exec(&["cat"]))] };
        let err = ValidatedRequest::validate(plan_req(p)).unwrap_err();
        assert!(err.contains("first pipe stage"), "{err}");
        let p = Plan::Pipe { stages: vec![stdin_from("/etc/hostname", exec(&["cat"])), exec(&["wc"])] };
        assert!(ValidatedRequest::validate(plan_req(p)).is_ok());
    }

    #[test]
    fn validate_requires_absolute_plan_paths() {
        let cases = [
            Plan::Chdir { dir: "bin".into(), body: Box::new(exec(&["pwd"])) },
            redirect(Stream::Stdout, "out.txt", exec(&["echo"])),
            stdin_from("in.txt", exec(&["cat"])),
        ];
        for p in cases {
            let err = ValidatedRequest::validate(plan_req(p)).unwrap_err();
            assert!(err.contains("must be an absolute path"), "{err}");
        }
        let p = Plan::Chdir { dir: "/usr".into(), body: Box::new(exec(&["pwd"])) };
        assert!(ValidatedRequest::validate(plan_req(p)).is_ok());
    }

    #[test]
    fn env_keys_must_be_shell_variable_names() {
        for good in ["LANG", "LC_ALL", "_x", "a1"] {
            assert!(is_valid_env_name(good), "{good}");
        }
        for bad in ["", "1A", "LC_X;echo INJECTED;:", "A-B", "A B", "A=B", "LC_$(id)"] {
            assert!(!is_valid_env_name(bad), "{bad}");
        }
        let p = Plan::Setenv {
            key: "LC_X;echo INJECTED;:".into(),
            value: "v".into(),
            body: Box::new(exec(&["echo", "ok"])),
        };
        assert!(ValidatedRequest::validate(plan_req(p)).unwrap_err().contains("not a valid variable name"));
        let mut req = exec_request();
        req.env.insert("LC_X;echo INJECTED;:".into(), "v".into());
        assert!(ValidatedRequest::validate(req).unwrap_err().contains("not a valid variable name"));
    }

    /// `root` by name is root; `#uid` (which sudo reads as a uid, so `#0` is
    /// root) is refused.
    #[test]
    fn run_as_root_by_name_is_root_and_uid_form_is_refused() {
        let p = Plan::RunAs { who: RunAs::User { name: "root".into() }, body: Box::new(exec(&["id"])) };
        let v = ValidatedRequest::validate(plan_req(p)).unwrap();
        assert!(v.runs_as_root());
        assert!(matches!(v.plan, Some(Plan::RunAs { who: RunAs::Root, .. })));

        let p = Plan::RunAs { who: RunAs::User { name: "#0".into() }, body: Box::new(exec(&["id"])) };
        assert!(ValidatedRequest::validate(plan_req(p)).unwrap_err().contains("#uid"));

        let p = Plan::RunAs { who: RunAs::User { name: "nobody".into() }, body: Box::new(exec(&["id"])) };
        assert!(!ValidatedRequest::validate(plan_req(p)).unwrap().runs_as_root());
    }

    /// Default_Ignorable_Code_Point, copied verbatim (one entry per line, not
    /// merged) from `DerivedCoreProperties.txt` of Unicode 16.0.0 — the
    /// version `unicode-general-category` 1.1.0 implements
    /// (`UNICODE_VERSION`, checked below). Independent of `DANGEROUS_RANGES`:
    /// it is not derived from the table. Bump both together.
    const DICP_16_0: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),   // Cf SOFT HYPHEN
        (0x034F, 0x034F),   // Mn COMBINING GRAPHEME JOINER
        (0x061C, 0x061C),   // Cf ARABIC LETTER MARK
        (0x115F, 0x1160),   // Lo HANGUL CHOSEONG FILLER..HANGUL JUNGSEONG FILLER
        (0x17B4, 0x17B5),   // Mn KHMER VOWEL INHERENT AQ..KHMER VOWEL INHERENT AA
        (0x180B, 0x180D),   // Mn MONGOLIAN FREE VARIATION SELECTOR ONE..THREE
        (0x180E, 0x180E),   // Cf MONGOLIAN VOWEL SEPARATOR
        (0x180F, 0x180F),   // Mn MONGOLIAN FREE VARIATION SELECTOR FOUR
        (0x200B, 0x200F),   // Cf ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
        (0x202A, 0x202E),   // Cf LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE
        (0x2060, 0x2064),   // Cf WORD JOINER..INVISIBLE PLUS
        (0x2065, 0x2065),   // Cn <reserved-2065>
        (0x2066, 0x206F),   // Cf LEFT-TO-RIGHT ISOLATE..NOMINAL DIGIT SHAPES
        (0x3164, 0x3164),   // Lo HANGUL FILLER
        (0xFE00, 0xFE0F),   // Mn VARIATION SELECTOR-1..VARIATION SELECTOR-16
        (0xFEFF, 0xFEFF),   // Cf ZERO WIDTH NO-BREAK SPACE
        (0xFFA0, 0xFFA0),   // Lo HALFWIDTH HANGUL FILLER
        (0xFFF0, 0xFFF8),   // Cn <reserved-FFF0>..<reserved-FFF8>
        (0x1BCA0, 0x1BCA3), // Cf SHORTHAND FORMAT LETTER OVERLAP..SHORTHAND FORMAT UP STEP
        (0x1D173, 0x1D17A), // Cf MUSICAL SYMBOL BEGIN BEAM..MUSICAL SYMBOL END PHRASE
        (0xE0000, 0xE0000), // Cn <reserved-E0000>
        (0xE0001, 0xE0001), // Cf LANGUAGE TAG
        (0xE0002, 0xE001F), // Cn <reserved-E0002>..<reserved-E001F>
        (0xE0020, 0xE007F), // Cf TAG SPACE..CANCEL TAG
        (0xE0080, 0xE00FF), // Cn <reserved-E0080>..<reserved-E00FF>
        (0xE0100, 0xE01EF), // Mn VARIATION SELECTOR-17..VARIATION SELECTOR-256
        (0xE01F0, 0xE0FFF), // Cn <reserved-E01F0>..<reserved-E0FFF>
    ];

    /// Issue #86: `is_dangerous_char` is exactly
    /// `c != TAB && (gc(c) ∈ {Cc, Cf, Zl, Zp} || DICP(c))`, checked over every
    /// `char`. A Unicode bump of the oracle that adds Cf characters fails here.
    #[test]
    fn dangerous_class_matches_unicode_oracle() {
        use unicode_general_category::{get_general_category, GeneralCategory as Gc};
        assert_eq!(
            unicode_general_category::UNICODE_VERSION,
            (16, 0, 0),
            "oracle bumped: refresh DICP_16_0 and DANGEROUS_RANGES from the same UCD"
        );
        let dicp = |u: u32| DICP_16_0.iter().any(|&(lo, hi)| lo <= u && u <= hi);
        let mut mismatches = Vec::new();
        for u in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(u) else { continue };
            let expected = c != '\t'
                && (matches!(
                    get_general_category(c),
                    Gc::Control | Gc::Format | Gc::LineSeparator | Gc::ParagraphSeparator
                ) || dicp(u));
            if is_dangerous_char(c) != expected {
                mismatches.push(format!("U+{u:04X} expected {expected}"));
            }
        }
        assert!(mismatches.is_empty(), "class mismatches: {mismatches:?}");
    }

    #[test]
    fn dangerous_ranges_sorted_and_disjoint() {
        for &(lo, hi) in DANGEROUS_RANGES {
            assert!(lo <= hi, "({lo:#x}, {hi:#x}) inverted");
        }
        for w in DANGEROUS_RANGES.windows(2) {
            assert!(
                w[0].1 < w[1].0,
                "{:#x?} and {:#x?} overlap or are unsorted",
                w[0],
                w[1]
            );
        }
    }

    /// Issue #86 regression table: every code point the issue names, plus a
    /// tag character, an emoji variation selector and reserved U+2065, is
    /// forbidden; ordinary printable text (ASCII, accents, CJK, dashes,
    /// arrows, NBSP, a bare emoji) and TAB are not.
    #[test]
    fn dangerous_char_regression_table() {
        let must_reject = [
            '\u{7f}',
            '\u{85}',
            '\u{9b}',
            '\u{9d}',
            '\u{ad}',
            '\u{61c}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{2061}',
            '\u{2062}',
            '\u{2063}',
            '\u{2064}',
            '\u{feff}',
            '\u{e0041}',
            '\u{fe0f}',
            '\u{2065}',
        ];
        for c in must_reject {
            assert!(is_dangerous_char(c), "U+{:04X} must be dangerous", c as u32);
            assert!(has_dangerous_chars(&format!("ok{c}ok")));
        }
        let mut must_accept: Vec<char> = (0x20u8..=0x7E).map(char::from).collect();
        must_accept.extend(['\t', 'é', '漢', '—', '→', '\u{a0}', '\u{1f642}']);
        for c in must_accept {
            assert!(!is_dangerous_char(c), "U+{:04X} must be accepted", c as u32);
        }
        assert!(!has_dangerous_chars("café 漢字 — → 🙂\tend"));
    }

    #[test]
    fn escape_dangerous_escapes_class_keeps_rest() {
        assert_eq!(
            escape_dangerous("a\u{1b}[2J\nb\tc\u{2065}é"),
            "a\\u{1b}[2J\\u{a}b\tc\\u{2065}é"
        );
        assert_eq!(escape_dangerous("/usr/bin/ls"), "/usr/bin/ls");
    }
}
