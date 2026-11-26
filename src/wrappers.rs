//! Wrapper-aware unwrap of a leaf's argv (issue #87).
//!
//! A leaf whose program is a shell runs a script the prompt cannot show stage
//! by stage, so it is flagged *opaque* and refused under `no_shell`. Looking at
//! `argv[0]` alone misses a shell (or an inline-code interpreter, or a program
//! runner) placed behind a wrapper: `env sh -c …`, `nice bash …`,
//! `timeout 5 sh -c …`. [`unwrap`] walks the chain of known wrappers to the
//! program(s) that actually run and classifies each one:
//!
//! - **Shell** ([`SHELLS`]): opaque.
//! - **Wrapper** ([`WRAPPERS`]): its own options are parsed and the walk
//!   continues with the wrapped program.
//! - **Inline-code interpreter** ([`INTERPRETERS`]): opaque when an inline-code
//!   flag is present, or when no script operand is present (the program is read
//!   from stdin).
//! - **Command-string program** (`ssh`, `scp`, `sftp`, `rsync`, `git`;
//!   [`crate::command_string`]): opaque when an option or word makes it run a
//!   command string remotely or through a shell (`rsync -e`, `git -c`, …);
//!   `ssh` always.
//! - **Runner** ([`RUNNERS`]): always opaque; the prompt does not unwrap it.
//! - anything else: transparent; the walk stops.
//!
//! The walk fails closed: an option a wrapper's table does not list (including
//! GNU long-option abbreviations), a missing option argument or operand, an
//! `env` that changes how the wrapped program is looked up or sets a name the
//! `setenv` policy rejects, a `find -exec` program word containing `{}` or a
//! `find -exec` command containing another action word, an `xargs -I`
//! replacement string in the program word, a `--` or any other option word
//! where a program is expected, a multi-call dispatcher option, an ambiguous
//! name and a chain deeper than [`MAX_DEPTH`] all make the leaf opaque.
//!
//! This module is pure: no filesystem access and no I/O. The only
//! filesystem-dependent input, the canonical name of a hop's resolved binary,
//! is supplied by the caller as a closure.

use crate::command_string::{scan, Prog, Trigger};

/// Shell interpreters. A leaf that runs one of these runs a script the prompt
/// cannot show stage by stage (`sh -c '…'`, `bash script.sh`, a shell reading
/// stdin).
pub const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "yash", "posh",
];

/// Programs that run another program in a way the prompt does not unwrap
/// (another identity, another host, another root, repeatedly). Always opaque.
pub const RUNNERS: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "runuser",
    "pkexec",
    "setpriv",
    "chroot",
    "unshare",
    "nsenter",
    "flock",
    "watch",
    "script",
    "systemd-run",
];

/// Multi-call dispatchers: they pick the applet from `argv[0]` (or, when called
/// by their own name, from `argv[1]`), so their canonical name says nothing
/// about what runs.
const MULTI_CALL: &[&str] = &["busybox", "toybox", "coreutils"];

/// The longest wrapper chain (in hops, `argv[0]` included) that is unwrapped.
pub const MAX_DEPTH: usize = 8;

/// True if the basename of `name` is a shell interpreter.
pub fn is_shell_name(name: &str) -> bool {
    SHELLS.contains(&basename(name))
}

fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// How a wrapper's operands are read once its options are parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Options, then `positionals` operands, then the wrapped program.
    Getopt,
    /// `nice`: `Getopt` plus the legacy `-N` adjustment.
    Nice,
    /// `env`: options, then `NAME=VALUE` assignments, then the program.
    Env,
    /// `busybox` / `toybox` / `coreutils`: `argv[1]` is the applet.
    MultiCall,
    /// `find`: each `-exec`/`-execdir`/`-ok`/`-okdir` starts a program.
    FindExec,
}

/// A wrapper's option table. Every wrapper listed here stops option parsing at
/// the first non-option word (GNU getopt strings starting with `+`), and so
/// does the parser. Short clusters (`-iuNAME`), `-u NAME`, `--long=V`,
/// `--long V` and the `--` terminator are accepted; optional-argument options
/// only in attached (`-eEOF`) or `=` (`--eof=EOF`) form. Anything else is
/// rejected, which makes the leaf opaque.
#[derive(Debug, PartialEq, Eq)]
pub struct WrapperSpec {
    pub name: &'static str,
    short_noarg: &'static str,
    short_arg: &'static str,
    short_optarg: &'static str,
    long_noarg: &'static [&'static str],
    long_arg: &'static [&'static str],
    long_optarg: &'static [&'static str],
    /// Operands before the wrapped program (the `timeout` duration, the `chrt`
    /// priority, the `taskset` mask).
    positionals: usize,
    /// The operands must be decimal digits (the `chrt` priority).
    numeric_positionals: bool,
    /// Options (short letter or long name) after which no program runs.
    no_program: &'static [&'static str],
    pub kind: Kind,
}

const fn spec(name: &'static str, kind: Kind) -> WrapperSpec {
    WrapperSpec {
        name,
        short_noarg: "",
        short_arg: "",
        short_optarg: "",
        long_noarg: &["help", "version"],
        long_arg: &[],
        long_optarg: &[],
        positionals: 0,
        numeric_positionals: false,
        no_program: &["help", "version"],
        kind,
    }
}

/// The wrappers that are unwrapped. Extending the list is a one-entry change.
pub const WRAPPERS: &[WrapperSpec] = &[
    // GNU env `+C:iS:u:v0`. `-a`/`--argv0` is not listed: it changes the
    // argv[0] a multi-call program dispatches on, so it fails closed.
    WrapperSpec {
        short_noarg: "i0v",
        short_arg: "uCS",
        long_noarg: &[
            "ignore-environment",
            "null",
            "debug",
            "list-signal-handling",
            "help",
            "version",
        ],
        long_arg: &["unset", "chdir", "split-string"],
        long_optarg: &["default-signal", "ignore-signal", "block-signal"],
        ..spec("env", Kind::Env)
    },
    WrapperSpec {
        short_arg: "n",
        long_arg: &["adjustment"],
        ..spec("nice", Kind::Nice)
    },
    spec("nohup", Kind::Getopt),
    // util-linux setsid `+Vhcfw`.
    WrapperSpec {
        short_noarg: "cfwVh",
        long_noarg: &["ctty", "fork", "wait", "help", "version"],
        no_program: &["V", "h", "help", "version"],
        ..spec("setsid", Kind::Getopt)
    },
    // GNU stdbuf `+i:o:e:`.
    WrapperSpec {
        short_arg: "ioe",
        long_arg: &["input", "output", "error"],
        ..spec("stdbuf", Kind::Getopt)
    },
    // GNU timeout `+k:s:fpv`, then a duration.
    WrapperSpec {
        short_noarg: "fpv",
        short_arg: "ks",
        long_noarg: &[
            "foreground",
            "preserve-status",
            "verbose",
            "help",
            "version",
        ],
        long_arg: &["kill-after", "signal"],
        positionals: 1,
        ..spec("timeout", Kind::Getopt)
    },
    // util-linux ionice `+n:c:p:P:u:tVh`; `-p`/`-P`/`-u` act on existing
    // processes and run no program.
    WrapperSpec {
        short_noarg: "tVh",
        short_arg: "ncpPu",
        long_noarg: &["ignore", "help", "version"],
        long_arg: &["classdata", "class", "pid", "pgid", "uid"],
        no_program: &[
            "p", "P", "u", "pid", "pgid", "uid", "V", "h", "help", "version",
        ],
        ..spec("ionice", Kind::Getopt)
    },
    // util-linux chrt `+abdD:fiphmoP:T:rRvV`, then a numeric priority; `-p`
    // and `-m` run no program.
    WrapperSpec {
        short_noarg: "abdfiphmorRvV",
        short_arg: "DPT",
        long_noarg: &[
            "all-tasks",
            "batch",
            "deadline",
            "fifo",
            "idle",
            "max",
            "other",
            "pid",
            "rr",
            "reset-on-fork",
            "verbose",
            "help",
            "version",
        ],
        long_arg: &["dl-runtime", "dl-deadline", "dl-period"],
        positionals: 1,
        numeric_positionals: true,
        no_program: &["p", "m", "h", "V", "pid", "max", "help", "version"],
        ..spec("chrt", Kind::Getopt)
    },
    // util-linux taskset `+apchV`, then a mask or list; `-p` runs no program.
    WrapperSpec {
        short_noarg: "apchV",
        long_noarg: &["all-tasks", "pid", "cpu-list", "help", "version"],
        positionals: 1,
        no_program: &["p", "h", "V", "pid", "help", "version"],
        ..spec("taskset", Kind::Getopt)
    },
    // GNU time `+af:o:pqvV`.
    WrapperSpec {
        short_noarg: "apqvV",
        short_arg: "fo",
        long_noarg: &[
            "append",
            "portability",
            "quiet",
            "verbose",
            "help",
            "version",
        ],
        long_arg: &["format", "output"],
        no_program: &["V", "help", "version"],
        ..spec("time", Kind::Getopt)
    },
    // GNU xargs `+0a:E:e::i::I:l::L:n:oprs:txP:d:`. A bare `xargs` runs `echo`.
    WrapperSpec {
        short_noarg: "0oprtx",
        short_arg: "aEILnsPd",
        short_optarg: "eil",
        long_noarg: &[
            "null",
            "open-tty",
            "interactive",
            "no-run-if-empty",
            "verbose",
            "exit",
            "show-limits",
            "help",
            "version",
        ],
        long_arg: &[
            "arg-file",
            "delimiter",
            "max-args",
            "max-chars",
            "max-procs",
            "process-slot-var",
        ],
        long_optarg: &["eof", "replace", "max-lines"],
        ..spec("xargs", Kind::Getopt)
    },
    spec("busybox", Kind::MultiCall),
    spec("toybox", Kind::MultiCall),
    spec("coreutils", Kind::MultiCall),
    spec("find", Kind::FindExec),
];

/// An interpreter that can run code given on its command line or on stdin.
#[derive(Debug, PartialEq, Eq)]
pub struct InterpSpec {
    /// Names matched as `base` followed only by ASCII digits and dots
    /// (`python`, `python3`, `python3.12`; not `python3-config`).
    bases: &'static [&'static str],
    /// Names matched exactly.
    exact: &'static [&'static str],
    /// Short options that take inline code.
    short_flags: &'static str,
    /// Long options that take inline code (`--eval`, `--eval=…`).
    long_flags: &'static [&'static str],
    /// Short options whose argument may be the next word (`python3 -W x`), so
    /// that word is not mistaken for a script operand.
    sep_arg_short: &'static str,
    /// Long options whose argument may be the next word.
    sep_arg_long: &'static [&'static str],
}

impl InterpSpec {
    fn matches(&self, name: &str) -> bool {
        self.exact.contains(&name)
            || self.bases.iter().any(|b| {
                name.strip_prefix(b)
                    .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
            })
    }
}

/// Inline-code interpreters. Extending the list is a one-entry change.
pub const INTERPRETERS: &[InterpSpec] = &[
    InterpSpec {
        bases: &["python"],
        exact: &["pypy", "pypy3"],
        short_flags: "c",
        long_flags: &[],
        sep_arg_short: "WX",
        sep_arg_long: &["--check-hash-based-pycs"],
    },
    InterpSpec {
        bases: &["perl"],
        exact: &[],
        short_flags: "eE",
        long_flags: &[],
        sep_arg_short: "",
        sep_arg_long: &[],
    },
    InterpSpec {
        bases: &["ruby"],
        exact: &[],
        short_flags: "e",
        long_flags: &[],
        sep_arg_short: "ICEr",
        sep_arg_long: &["--encoding", "--external-encoding", "--internal-encoding"],
    },
    InterpSpec {
        bases: &[],
        exact: &["node", "nodejs"],
        short_flags: "ep",
        long_flags: &["--eval", "--print"],
        sep_arg_short: "rC",
        sep_arg_long: &[
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "--conditions",
            "--input-type",
            "--title",
            "--env-file",
        ],
    },
    InterpSpec {
        bases: &["php"],
        exact: &[],
        short_flags: "rBRE",
        long_flags: &[],
        sep_arg_short: "cdz",
        sep_arg_long: &[],
    },
    InterpSpec {
        bases: &["lua"],
        exact: &["luajit"],
        short_flags: "e",
        long_flags: &[],
        sep_arg_short: "l",
        sep_arg_long: &[],
    },
    InterpSpec {
        bases: &[],
        exact: &["Rscript"],
        short_flags: "e",
        long_flags: &[],
        sep_arg_short: "",
        sep_arg_long: &[],
    },
];

/// The class of a program name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Shell,
    Wrapper(&'static WrapperSpec),
    Interpreter(&'static InterpSpec),
    /// A program that can run a command string remotely or through a shell
    /// ([`crate::command_string`], issue #91).
    CommandString(Prog),
    Runner,
    Plain,
}

impl Class {
    fn is_opaque(self) -> bool {
        matches!(
            self,
            Class::Shell | Class::Interpreter(_) | Class::CommandString(_) | Class::Runner
        )
    }
}

/// Classify a program by its basename.
pub fn classify(name: &str) -> Class {
    let base = basename(name);
    if SHELLS.contains(&base) {
        Class::Shell
    } else if let Some(w) = WRAPPERS.iter().find(|w| w.name == base) {
        Class::Wrapper(w)
    } else if let Some(i) = INTERPRETERS.iter().find(|i| i.matches(base)) {
        Class::Interpreter(i)
    } else if let Some(p) = Prog::from_name(base) {
        Class::CommandString(p)
    } else if RUNNERS.contains(&base) {
        Class::Runner
    } else {
        Class::Plain
    }
}

/// Combine the class of the name as written with the class of the canonical
/// basename of its resolved binary (`None` when unresolved or a multi-call
/// dispatcher). `Err(())` means two different wrappers: ambiguous.
fn combine(written: Class, canonical: Option<Class>) -> Result<Class, ()> {
    let Some(canonical) = canonical else {
        return Ok(written);
    };
    if canonical.is_opaque() {
        return Ok(canonical);
    }
    match (written, canonical) {
        (w, _) if w.is_opaque() => Ok(w),
        (Class::Plain, c) => Ok(c),
        (Class::Wrapper(a), Class::Wrapper(b)) if a.name != b.name => Err(()),
        (w, _) => Ok(w),
    }
}

/// One program in a leaf's unwrapped chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// Index of the program word in the leaf's argv.
    pub argv_index: usize,
    /// The hop (index into the hop list) whose wrapper runs this one; `None`
    /// for `argv[0]`.
    pub via: Option<usize>,
    /// The directory `env -C` moved to, accumulated along the chain
    /// (`env -C a env -C b ./x` runs `a/b/x`), relative to the leaf's cwd.
    pub chdir: Option<String>,
    /// An applet of a multi-call dispatcher (`busybox sh`): the dispatcher
    /// runs its built-in applet, not the binary the name resolves to on PATH.
    pub applet: bool,
    /// The names this hop sets or unsets, when it is `env` (`env A=1 -u B x`
    /// touches `A` and `B`). The prompt says when one of them overrides a
    /// variable inherited from the daemon (#101).
    pub touches: Vec<String>,
}

/// Why a leaf is opaque. `hop` indexes the hop list returned by [`unwrap`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpaqueReason {
    /// An explicit `Shell` plan node.
    ShellOp,
    Shell {
        hop: usize,
    },
    /// `flag` is the matching argument, or `"stdin"` when no script operand is
    /// present.
    InlineCode {
        hop: usize,
        flag: String,
    },
    /// A command string run remotely or through a shell (#91).
    CommandString {
        hop: usize,
        trigger: Trigger,
    },
    Runner {
        hop: usize,
    },
    Unparsable {
        hop: usize,
        why: String,
    },
    PathChanged {
        hop: usize,
    },
    EnvRejected {
        hop: usize,
        name: String,
    },
    FindPlaceholder {
        hop: usize,
    },
    /// `xargs -I R` / `-i` / `--replace` with `R` in the program word: the
    /// program is chosen by xargs's input.
    XargsReplace {
        hop: usize,
        replace: String,
    },
    Ambiguous {
        hop: usize,
        canonical: String,
    },
    TooDeep,
}

impl OpaqueReason {
    /// The hop the reason is about (`0` for a `Shell` node or a chain too deep).
    pub fn hop(&self) -> usize {
        match self {
            OpaqueReason::ShellOp | OpaqueReason::TooDeep => 0,
            OpaqueReason::Shell { hop }
            | OpaqueReason::InlineCode { hop, .. }
            | OpaqueReason::CommandString { hop, .. }
            | OpaqueReason::Runner { hop }
            | OpaqueReason::Unparsable { hop, .. }
            | OpaqueReason::PathChanged { hop }
            | OpaqueReason::EnvRejected { hop, .. }
            | OpaqueReason::FindPlaceholder { hop }
            | OpaqueReason::XargsReplace { hop, .. }
            | OpaqueReason::Ambiguous { hop, .. } => *hop,
        }
    }

    /// True if the reason is a shell (the prompt keeps its wording).
    pub fn is_shell(&self) -> bool {
        matches!(self, OpaqueReason::ShellOp | OpaqueReason::Shell { .. })
    }

    /// True if the reason is about the hop's program itself, so the prompt
    /// shows its resolved path; false for a wrapper that could not be parsed.
    pub fn names_program(&self) -> bool {
        matches!(
            self,
            OpaqueReason::ShellOp
                | OpaqueReason::Shell { .. }
                | OpaqueReason::InlineCode { .. }
                | OpaqueReason::CommandString { .. }
                | OpaqueReason::Runner { .. }
                | OpaqueReason::Ambiguous { .. }
        )
    }

    /// The one description shown both at the prompt (after `opaque — `) and
    /// in the `no_shell` rejection.
    pub fn describe(&self, hops: &[Hop], argv: &[String]) -> String {
        let name = hops
            .get(self.hop())
            .and_then(|h| argv.get(h.argv_index))
            .map(|s| basename(s))
            .unwrap_or("");
        match self {
            OpaqueReason::ShellOp | OpaqueReason::Shell { .. } => "resolves only the shell".into(),
            OpaqueReason::InlineCode { flag, .. } if flag == "stdin" => {
                "reads its program from stdin".into()
            }
            OpaqueReason::InlineCode { flag, .. } => format!("inline code ({flag})"),
            OpaqueReason::CommandString { trigger, .. } => trigger.describe(),
            OpaqueReason::Runner { .. } => "runs a program the prompt does not unwrap".into(),
            OpaqueReason::Unparsable { why, .. } => format!("cannot unwrap {name}: {why}"),
            OpaqueReason::PathChanged { .. } => {
                format!("{name} changes PATH; the program it runs is not resolved")
            }
            OpaqueReason::EnvRejected { name: var, .. } => {
                format!("{name} sets a name the policy rejects: {var}")
            }
            OpaqueReason::FindPlaceholder { .. } => {
                format!("{name} runs the files it finds ({{}})")
            }
            OpaqueReason::XargsReplace { replace, .. } => {
                format!("{name} takes the program from its input ({replace})")
            }
            OpaqueReason::Ambiguous { canonical, .. } => {
                format!("ambiguous wrapper: {name} resolves to {canonical}")
            }
            OpaqueReason::TooDeep => format!("wrapper chain deeper than {MAX_DEPTH}"),
        }
    }
}

/// An argv slice still to unwrap: `argv[start..end]`, run by hop `via`.
struct Region {
    start: usize,
    end: usize,
    via: Option<usize>,
    chdir: Option<String>,
    depth: usize,
    applet: bool,
}

/// Unwrap a leaf's argv into the chain of programs that run, and say why the
/// leaf is opaque, if it is.
///
/// `canonical_name(argv_index, chdir)` supplies the canonical basename of the
/// hop's resolved binary (the only filesystem-dependent input; tests pass
/// `|_, _| None`). `hops[0]` is `argv[0]`; a `find` hop can have several
/// children with the same `via`. On an opaque result the hops seen so far are
/// returned. Total: never panics, for any argv.
pub fn unwrap(
    argv: &[String],
    canonical_name: impl Fn(usize, Option<&str>) -> Option<String>,
) -> (Vec<Hop>, Option<OpaqueReason>) {
    let mut hops = Vec::new();
    if argv.is_empty() {
        return (hops, None);
    }
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(Region {
        start: 0,
        end: argv.len(),
        via: None,
        chdir: None,
        depth: 1,
        applet: false,
    });
    while let Some(r) = queue.pop_front() {
        if r.depth > MAX_DEPTH {
            return (hops, Some(OpaqueReason::TooDeep));
        }
        // An option word (`--`, `-v`, `--verbose`, `-s`…) where a wrapper's
        // program is expected: GNU `env` would run a program named `--`, but
        // uutils `timeout` keeps parsing options after its duration (review
        // C8) and uutils `timeout` / util-linux `chrt` skip a `--`, then run
        // the next word. What runs depends on the implementation, so fail
        // closed for every wrapper.
        if let Some(via) = r.via.filter(|_| argv[r.start].starts_with('-')) {
            let word = &argv[r.start];
            let why = if word == "--" || word == "-" {
                format!("{word} where the program is expected")
            } else {
                format!("option {word} where the program is expected")
            };
            return (hops, Some(OpaqueReason::Unparsable { hop: via, why }));
        }
        let hop = hops.len();
        hops.push(Hop {
            argv_index: r.start,
            via: r.via,
            chdir: r.chdir.clone(),
            applet: r.applet,
            touches: Vec::new(),
        });
        let written = classify(&argv[r.start]);
        // An applet's PATH resolution says nothing about what the dispatcher
        // runs, so only its written name classifies it.
        let canonical = if r.applet {
            None
        } else {
            canonical_name(r.start, r.chdir.as_deref())
        };
        let canonical_class = canonical
            .as_deref()
            .filter(|c| !MULTI_CALL.contains(c))
            .map(classify);
        let class = match combine(written, canonical_class) {
            Ok(c) => c,
            Err(()) => {
                let canonical = canonical.unwrap_or_default();
                return (hops, Some(OpaqueReason::Ambiguous { hop, canonical }));
            }
        };
        let next = match class {
            Class::Plain => continue,
            Class::Shell => Err(OpaqueReason::Shell { hop }),
            Class::Runner => Err(OpaqueReason::Runner { hop }),
            Class::Interpreter(spec) => match inline_code(spec, &argv[r.start + 1..r.end]) {
                Some(flag) => Err(OpaqueReason::InlineCode { hop, flag }),
                None => continue,
            },
            Class::CommandString(prog) => match scan(prog, &argv[r.start + 1..r.end]) {
                Some(trigger) => Err(OpaqueReason::CommandString { hop, trigger }),
                None => continue,
            },
            Class::Wrapper(spec) => parse_wrapper(spec, argv, &r, hop, &mut hops[hop].touches),
        };
        match next {
            Err(reason) => return (hops, Some(reason)),
            Ok(children) => {
                let applet = matches!(class, Class::Wrapper(s) if s.kind == Kind::MultiCall);
                for (start, end, chdir) in children {
                    queue.push_back(Region {
                        start,
                        end,
                        via: Some(hop),
                        chdir,
                        depth: r.depth + 1,
                        applet,
                    });
                }
            }
        }
    }
    (hops, None)
}

/// The inline-code flag an interpreter's arguments carry, `"stdin"` if no
/// script operand is present, or `None` if it runs a script or module. The
/// flag scan is deliberately coarse (a script's own `-c` over-flags).
fn inline_code(spec: &InterpSpec, args: &[String]) -> Option<String> {
    for a in args {
        if spec
            .long_flags
            .iter()
            .any(|f| a == f || a.strip_prefix(f).is_some_and(|r| r.starts_with('=')))
        {
            return Some(a.clone());
        }
        let Some(rest) = a.strip_prefix('-') else {
            continue;
        };
        // The leading run of switch letters (digits too: `perl -0777e`,
        // `-l0e`). Code may be attached after it (`-Bcprint(1)`,
        // `-le'print 1'`). A letter that takes a separate argument takes the
        // rest of the word when attached (`ruby -rset`), so the run ends there.
        let mut hit = false;
        for c in rest.chars() {
            if !c.is_ascii_alphanumeric() {
                break;
            }
            if spec.short_flags.contains(c) {
                hit = true;
                break;
            }
            if spec.sep_arg_short.contains(c) {
                break;
            }
        }
        if hit {
            let shown: String = a.chars().take(16).collect();
            return Some(shown);
        }
    }
    // Is there a script operand? Skip the word after an option that takes a
    // separate argument; after `--` the next word is the operand.
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            return if i + 1 < args.len() {
                None
            } else {
                Some("stdin".into())
            };
        }
        if !a.starts_with('-') {
            return None;
        }
        let takes_next = spec.sep_arg_long.contains(&a.as_str())
            || (!a.starts_with("--")
                && a.len() > 1
                && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                && a.chars()
                    .last()
                    .is_some_and(|c| spec.sep_arg_short.contains(c)));
        i += if takes_next { 2 } else { 1 };
    }
    Some("stdin".into())
}

type Children = Vec<(usize, usize, Option<String>)>;

fn parse_wrapper(
    spec: &'static WrapperSpec,
    argv: &[String],
    r: &Region,
    hop: usize,
    touches: &mut Vec<String>,
) -> Result<Children, OpaqueReason> {
    let bad = |why: String| OpaqueReason::Unparsable { hop, why };
    let one = |at: usize, chdir: Option<String>| -> Children {
        if at < r.end {
            vec![(at, r.end, chdir)]
        } else {
            Vec::new()
        }
    };
    match spec.kind {
        Kind::MultiCall => match argv.get(r.start + 1).filter(|_| r.start + 1 < r.end) {
            Some(a) if a.starts_with('-') => Err(bad(format!("unsupported dispatcher option {a}"))),
            Some(_) => Ok(one(r.start + 1, r.chdir.clone())),
            None => Ok(Vec::new()),
        },
        Kind::FindExec => find_exec(argv, r, hop),
        Kind::Getopt | Kind::Nice => {
            // `xargs -I R` / `-i[R]` / `--replace[=R]` substitutes each input
            // item for `R`, in the program word too (`xargs -I{} {}`).
            let mut replace: Option<String> = None;
            let parsed = getopt(spec, argv, r, hop, |opt, arg| {
                if spec.name == "xargs" && matches!(opt, "I" | "i" | "replace") {
                    replace = Some(arg.unwrap_or("{}").to_string());
                }
                Ok(())
            })?;
            let Some(mut i) = parsed else {
                return Ok(Vec::new());
            };
            for _ in 0..spec.positionals {
                let Some(p) = argv.get(i).filter(|_| i < r.end) else {
                    return Err(bad("missing operand".into()));
                };
                if spec.numeric_positionals
                    && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
                {
                    return Err(bad(format!("non-numeric priority {p}")));
                }
                i += 1;
            }
            if let Some(replace) = replace.filter(|p| i < r.end && argv[i].contains(p.as_str())) {
                return Err(OpaqueReason::XargsReplace { hop, replace });
            }
            Ok(one(i, r.chdir.clone()))
        }
        Kind::Env => {
            let mut chdir = r.chdir.clone();
            let touched = std::cell::RefCell::new(Vec::new());
            let check_name = |var: &str| -> Result<(), OpaqueReason> {
                touched.borrow_mut().push(var.to_string());
                if var == "PATH" {
                    Err(OpaqueReason::PathChanged { hop })
                } else if env_rejected(var) {
                    Err(OpaqueReason::EnvRejected {
                        hop,
                        name: var.to_string(),
                    })
                } else {
                    Ok(())
                }
            };
            let parsed = getopt(spec, argv, r, hop, |opt, arg| match (opt, arg) {
                ("i" | "ignore-environment", _) => Err(OpaqueReason::PathChanged { hop }),
                ("S", _) => Err(bad("unsupported option -S".into())),
                ("split-string", _) => Err(bad("unsupported option --split-string".into())),
                ("u" | "unset", Some(var)) => check_name(var),
                ("C" | "chdir", Some(dir)) => {
                    chdir = Some(match &chdir {
                        Some(c) => std::path::Path::new(c)
                            .join(dir)
                            .to_string_lossy()
                            .into_owned(),
                        None => dir.to_string(),
                    });
                    Ok(())
                }
                _ => Ok(()),
            })?;
            let Some(mut i) = parsed else {
                return Ok(Vec::new());
            };
            // A lone `-` after the options is `-i`.
            if i < r.end && argv[i] == "-" {
                return Err(OpaqueReason::PathChanged { hop });
            }
            // After the options every word containing `=` is an assignment;
            // the first one without is the program, even `--`.
            while i < r.end {
                let Some((var, _)) = argv[i].split_once('=') else {
                    break;
                };
                check_name(var)?;
                i += 1;
            }
            *touches = touched.into_inner();
            Ok(one(i, chdir))
        }
    }
}

/// `PATH` is reported as [`OpaqueReason::PathChanged`]; the other names are
/// the code-loading ones ([`is_code_loading`]), which change what code the
/// resolved program runs. None of them is on the `setenv` allowlist (G3.2).
pub fn env_rejected(name: &str) -> bool {
    name == "PATH" || is_code_loading(name)
}

/// Prefixes of names that make a program load code other than its own.
/// `GIT_CONFIG*` covers `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`,
/// `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_KEY_n`/`VALUE_n`, which can set
/// `core.sshCommand` or `core.pager` and so run a command like
/// `GIT_SSH_COMMAND` does.
pub const CODE_LOADING_PREFIXES: &[&str] = &["LD_", "DYLD_", "GIT_CONFIG"];

/// Names that make a program load code other than its own: a dynamic loader,
/// a shell's startup file, or a language runtime's module path or options.
/// A best-effort subset (many variables name a command some tool runs:
/// `EDITOR`, `GIT_ASKPASS`, …). An `env` wrapper setting one is opaque, and
/// `--inherit-env` never matches one with a wildcard (#101).
pub const CODE_LOADING: &[&str] = &[
    "NIX_LD",
    "NIX_LD_LIBRARY_PATH",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "BASH_ENV",
    "ENV",
    "IFS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "PERL5DB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_PROXY_COMMAND",
    "GIT_EXEC_PATH",
    "RSYNC_RSH",
    "RSYNC_CONNECT_PROG",
];

/// Whether `name` is a code-loading variable ([`CODE_LOADING`],
/// [`CODE_LOADING_PREFIXES`]).
pub fn is_code_loading(name: &str) -> bool {
    CODE_LOADING_PREFIXES.iter().any(|p| name.starts_with(p)) || CODE_LOADING.contains(&name)
}

/// Parse a wrapper's options from `argv[r.start + 1..r.end]`, calling `on` for
/// each with its name (short letter or long name) and argument. Returns the
/// index of the first operand, or `None` if an option means no program runs.
fn getopt(
    spec: &WrapperSpec,
    argv: &[String],
    r: &Region,
    hop: usize,
    mut on: impl FnMut(&str, Option<&str>) -> Result<(), OpaqueReason>,
) -> Result<Option<usize>, OpaqueReason> {
    let bad = |why: String| OpaqueReason::Unparsable { hop, why };
    let no_program = |n: &str| spec.no_program.contains(&n);
    let mut i = r.start + 1;
    while i < r.end {
        let w = argv[i].as_str();
        if w == "--" {
            return Ok(Some(i + 1));
        }
        if let Some(body) = w.strip_prefix("--") {
            let (name, val) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (body, None),
            };
            if spec.long_noarg.contains(&name) {
                if val.is_some() {
                    return Err(bad(format!("option --{name} takes no argument")));
                }
                if no_program(name) {
                    return Ok(None);
                }
                on(name, None)?;
            } else if spec.long_arg.contains(&name) {
                if no_program(name) {
                    return Ok(None);
                }
                let arg = match val {
                    Some(v) => v,
                    None if i + 1 < r.end => {
                        i += 1;
                        argv[i].as_str()
                    }
                    None => return Err(bad(format!("option --{name} needs an argument"))),
                };
                on(name, Some(arg))?;
            } else if spec.long_optarg.contains(&name) {
                on(name, val)?;
            } else {
                return Err(bad(format!("unsupported option --{name}")));
            }
            i += 1;
            continue;
        }
        let Some(rest) = w.strip_prefix('-').filter(|r| !r.is_empty()) else {
            return Ok(Some(i));
        };
        if spec.kind == Kind::Nice && rest.bytes().all(|b| b.is_ascii_digit()) {
            i += 1;
            continue;
        }
        let mut consumed_next = false;
        for (k, c) in rest.char_indices() {
            let mut buf = [0u8; 4];
            let name: &str = c.encode_utf8(&mut buf);
            let attached = &rest[k + c.len_utf8()..];
            if spec.short_noarg.contains(c) {
                if no_program(name) {
                    return Ok(None);
                }
                on(name, None)?;
            } else if spec.short_arg.contains(c) {
                if no_program(name) {
                    return Ok(None);
                }
                let arg = if !attached.is_empty() {
                    attached
                } else if i + 1 < r.end {
                    consumed_next = true;
                    argv[i + 1].as_str()
                } else {
                    return Err(bad(format!("option -{c} needs an argument")));
                };
                on(name, Some(arg))?;
                break;
            } else if spec.short_optarg.contains(c) {
                on(name, (!attached.is_empty()).then_some(attached))?;
                break;
            } else {
                return Err(bad(format!("unsupported option -{c}")));
            }
        }
        i += if consumed_next { 2 } else { 1 };
    }
    Ok(Some(i))
}

/// `find`: each `-exec`/`-execdir`/`-ok`/`-okdir` runs the program word after
/// it, up to the terminating `;` (or `+` right after `{}`, for `-exec` and
/// `-execdir`).
fn find_exec(argv: &[String], r: &Region, hop: usize) -> Result<Children, OpaqueReason> {
    let bad = |why: String| OpaqueReason::Unparsable { hop, why };
    let mut out = Vec::new();
    let mut i = r.start + 1;
    while i < r.end {
        let action = argv[i].as_str();
        if !matches!(action, "-exec" | "-execdir" | "-ok" | "-okdir") {
            i += 1;
            continue;
        }
        let prog = i + 1;
        if prog >= r.end || argv[prog] == ";" {
            return Err(bad(format!("{action} with no command")));
        }
        if argv[prog].contains("{}") {
            return Err(OpaqueReason::FindPlaceholder { hop });
        }
        let plus_ok = matches!(action, "-exec" | "-execdir");
        let term = (prog + 1..r.end)
            .find(|&k| argv[k] == ";" || (plus_ok && argv[k] == "+" && argv[k - 1] == "{}"));
        let Some(term) = term else {
            return Err(bad(format!("{action} without a terminating ; or +")));
        };
        // A test that takes an argument (`-printf`, `-name`, …) can absorb an
        // action word, and the real action after it then falls inside this
        // command: `-printf -exec -exec sh -c x ;`. Tests are not parsed, so
        // an action word inside a command fails closed.
        if let Some(k) = (prog..term)
            .find(|&k| matches!(argv[k].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
        {
            return Err(bad(format!("{} inside the command of {action}", argv[k])));
        }
        out.push((prog, term, r.chdir.clone()));
        i = term + 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prop::Rng;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn run(s: &[&str]) -> (Vec<Hop>, Option<OpaqueReason>) {
        unwrap(&v(s), |_, _| None)
    }

    /// The argv words of the hops.
    fn names(s: &[&str]) -> Vec<String> {
        let argv = v(s);
        let (hops, _) = unwrap(&argv, |_, _| None);
        hops.iter().map(|h| argv[h.argv_index].clone()).collect()
    }

    fn opaque(s: &[&str]) -> bool {
        run(s).1.is_some()
    }

    #[test]
    fn wrappers_reach_the_inner_program() {
        let cases: &[(&[&str], &str)] = &[
            (
                &[
                    "env", "-u", "FOO", "-C", "/tmp", "--", "X=1", "sh", "-c", "x",
                ],
                "sh",
            ),
            (&["nice", "-n", "5", "bash"], "bash"),
            (&["nice", "-5", "bash"], "bash"),
            (&["nice", "--adjustment=5", "bash"], "bash"),
            (&["timeout", "-k", "1", "-s", "KILL", "5", "sh"], "sh"),
            (&["timeout", "--preserve-status", "5s", "sh"], "sh"),
            (&["stdbuf", "-oL", "-eL", "sh"], "sh"),
            (&["setsid", "-f", "sh"], "sh"),
            (&["ionice", "-c", "3", "sh"], "sh"),
            (&["chrt", "-o", "0", "sh"], "sh"),
            (&["taskset", "-c", "0", "sh"], "sh"),
            (&["time", "-f", "%e", "sh"], "sh"),
            (&["xargs", "-0", "-n1", "sh", "-c"], "sh"),
            (&["busybox", "sh"], "sh"),
            (&["toybox", "sh"], "sh"),
            (&["coreutils", "env", "X=1", "sh", "-c", "x"], "sh"),
            (
                &[
                    "find", ".", "-name", "x", "-exec", "sh", "-c", "…", "{}", ";",
                ],
                "sh",
            ),
            (&["env", "nice", "timeout", "5", "sh"], "sh"),
            (&["nohup", "sh"], "sh"),
        ];
        for (argv, inner) in cases {
            let (hops, reason) = run(argv);
            assert_eq!(
                reason,
                Some(OpaqueReason::Shell {
                    hop: hops.len() - 1
                }),
                "{argv:?}"
            );
            assert_eq!(
                names(argv).last().map(String::as_str),
                Some(*inner),
                "{argv:?}"
            );
        }
    }

    /// `--` ends `env`'s options only before the first assignment; after it,
    /// `--` stands where the program is expected and fails closed.
    #[test]
    fn env_double_dash_after_an_assignment_fails_closed() {
        assert_eq!(
            unparsable(&["env", "X=1", "--", "true"]),
            "-- where the program is expected"
        );
        assert_eq!(names(&["env", "--", "X=1", "true"]), ["env", "true"]);
        assert!(!opaque(&["env", "--", "X=1", "true"]));
    }

    /// Review C3: uutils `timeout` and util-linux `chrt` skip a `--` placed
    /// after their operand and run the next word; every wrapper fails closed.
    #[test]
    fn double_dash_after_an_operand_fails_closed() {
        for argv in [
            &["timeout", "5", "--", "sh", "-c", "evil"][..],
            &["chrt", "-o", "0", "--", "sh", "-c", "evil"],
            &["taskset", "1", "--", "sh"],
            &["nice", "env", "X=1", "--", "sh"],
            &["busybox", "--"],
            &["find", ".", "-exec", "--", "sh", ";"],
        ] {
            let why = match run(argv).1 {
                Some(OpaqueReason::Unparsable { why, .. }) => why,
                other => panic!("{argv:?}: {other:?}"),
            };
            assert!(
                why == "-- where the program is expected"
                    || why == "unsupported dispatcher option --",
                "{argv:?}: {why}"
            );
        }
        // `--` before the operand still ends the options.
        assert_eq!(names(&["timeout", "--", "5", "true"]), ["timeout", "true"]);
        assert!(!opaque(&["timeout", "--", "5", "true"]));
    }

    /// Review C8: uutils `timeout` keeps parsing options after its duration,
    /// so `timeout 5 -v sh -c evil` runs `sh`. Any option word where a
    /// wrapper's program is expected fails closed.
    #[test]
    fn option_word_where_the_program_is_expected_fails_closed() {
        for (argv, word) in [
            (&["timeout", "5", "-v", "sh", "-c", "evil"][..], "-v"),
            (&["timeout", "5", "--verbose", "sh"], "--verbose"),
            (&["timeout", "5", "-s", "KILL", "sh"], "-s"),
            (&["timeout", "-k", "1", "5", "-v", "sh"], "-v"),
            (&["chrt", "-o", "0", "-v", "sh"], "-v"),
            (&["env", "X=1", "-i", "sh"], "-i"),
        ] {
            let why = match run(argv).1 {
                Some(OpaqueReason::Unparsable { why, .. }) => why,
                other => panic!("{argv:?}: {other:?}"),
            };
            assert_eq!(
                why,
                format!("option {word} where the program is expected"),
                "{argv:?}"
            );
        }
        assert!(matches!(
            run(&["timeout", "5", "-"]).1,
            Some(OpaqueReason::Unparsable { why, .. }) if why == "- where the program is expected"
        ));
        // Options before the operand are still parsed as options.
        assert_eq!(
            names(&["timeout", "-s", "KILL", "5", "true"]),
            ["timeout", "true"]
        );
        assert!(!opaque(&["timeout", "-s", "KILL", "5", "true"]));
    }

    /// Review C2: a find test that takes an argument can absorb an action
    /// word; an action word inside a parsed command fails closed.
    #[test]
    fn find_action_inside_a_command_fails_closed() {
        for argv in [
            &[
                "find",
                ".",
                "-maxdepth",
                "0",
                "-printf",
                "-exec",
                "-exec",
                "sh",
                "-c",
                "evil",
                ";",
            ][..],
            &["find", ".", "-fprintf", "f", "-exec", "-exec", "sh", ";"],
            &["find", ".", "-name", "-exec", "-exec", "sh", ";"],
            &["find", ".", "-name", "-ok", "-execdir", "sh", ";"],
        ] {
            let why = match run(argv).1 {
                Some(OpaqueReason::Unparsable { why, .. }) => why,
                other => panic!("{argv:?}: {other:?}"),
            };
            assert!(why.contains("inside the command of"), "{argv:?}: {why}");
        }
    }

    /// Review C4: `xargs -I R` substitutes its input into the program word.
    #[test]
    fn xargs_replace_in_the_program_word_fails_closed() {
        for (argv, r) in [
            (&["xargs", "-I{}", "{}"][..], "{}"),
            (&["xargs", "-I", "X", "X", "a"], "X"),
            (&["xargs", "-i", "{}"], "{}"),
            (&["xargs", "-iZ", "./Z"], "Z"),
            (&["xargs", "--replace", "{}"], "{}"),
            (&["xargs", "--replace=@", "@"], "@"),
        ] {
            assert_eq!(
                run(argv).1,
                Some(OpaqueReason::XargsReplace {
                    hop: 0,
                    replace: r.into()
                }),
                "{argv:?}"
            );
        }
        // In an argument only: transparent.
        assert_eq!(names(&["xargs", "-I{}", "rm", "{}"]), ["xargs", "rm"]);
        assert!(!opaque(&["xargs", "-I{}", "rm", "{}"]));
        assert!(!opaque(&["xargs", "-I", "X", "echo", "X"]));
    }

    /// Review C5: an applet hop is marked, and its PATH resolution is not
    /// consulted for its class.
    #[test]
    fn multi_call_children_are_applets() {
        let argv = v(&["busybox", "foo", "-c", "x"]);
        // A PATH `foo` that is really bash does not make busybox's `foo` a shell.
        let (hops, r) = unwrap(&argv, |i, _| (i == 1).then(|| "bash".to_string()));
        assert_eq!(r, None);
        assert!(!hops[0].applet && hops[1].applet);
        let (hops, _) = run(&["busybox", "env", "sh"]);
        assert!(hops[1].applet && !hops[2].applet);
    }

    #[test]
    fn env_chdir_accumulates() {
        let (hops, r) = run(&["env", "-C", "a", "env", "-C", "b", "./x"]);
        assert_eq!(r, None);
        assert_eq!(hops[2].chdir.as_deref(), Some("a/b"));
        let (hops, _) = run(&["env", "-C", "a", "env", "--chdir=/abs", "./x"]);
        assert_eq!(hops[2].chdir.as_deref(), Some("/abs"));
    }

    fn unparsable(argv: &[&str]) -> String {
        match run(argv).1 {
            Some(OpaqueReason::Unparsable { why, .. }) => why,
            other => panic!("{argv:?}: expected Unparsable, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_cases() {
        assert_eq!(unparsable(&["env", "-z", "sh"]), "unsupported option -z");
        assert_eq!(
            unparsable(&["env", "--frob", "sh"]),
            "unsupported option --frob"
        );
        assert_eq!(
            unparsable(&["timeout", "--sig=KILL", "5", "true"]),
            "unsupported option --sig"
        );
        assert_eq!(unparsable(&["timeout"]), "missing operand");
        assert_eq!(
            unparsable(&["timeout", "-s"]),
            "option -s needs an argument"
        );
        assert_eq!(
            unparsable(&["chrt", "-f", "high", "true"]),
            "non-numeric priority high"
        );
        assert_eq!(
            unparsable(&["env", "-S", "sh -c x"]),
            "unsupported option -S"
        );
        assert_eq!(
            unparsable(&["env", "-a", "sh", "true"]),
            "unsupported option -a"
        );
        assert_eq!(
            unparsable(&["busybox", "--list"]),
            "unsupported dispatcher option --list"
        );
        assert_eq!(
            unparsable(&["coreutils", "--coreutils-prog=env", "sh"]),
            "unsupported dispatcher option --coreutils-prog=env"
        );
        assert_eq!(unparsable(&["find", ".", "-exec"]), "-exec with no command");
        assert_eq!(
            unparsable(&["find", ".", "-exec", "rm", "x"]),
            "-exec without a terminating ; or +"
        );

        let path = Some(OpaqueReason::PathChanged { hop: 0 });
        assert_eq!(run(&["env", "PATH=/tmp", "foo"]).1, path);
        assert_eq!(run(&["env", "-u", "PATH", "foo"]).1, path);
        assert_eq!(run(&["env", "--unset=PATH", "foo"]).1, path);
        assert_eq!(run(&["env", "-i", "foo"]).1, path);
        assert_eq!(run(&["env", "-", "foo"]).1, path);
        assert_eq!(run(&["env", "--ignore-environment", "foo"]).1, path);

        for (argv, var) in [
            (&["env", "LD_PRELOAD=/x.so", "true"][..], "LD_PRELOAD"),
            (&["env", "LD_LIBRARY_PATH=/x", "true"], "LD_LIBRARY_PATH"),
            (&["env", "BASH_ENV=/x", "bash", "x.sh"], "BASH_ENV"),
            (&["env", "ENV=/x", "true"], "ENV"),
            (&["env", "IFS=x", "true"], "IFS"),
            (&["env", "-u", "LD_PRELOAD", "true"], "LD_PRELOAD"),
        ] {
            assert_eq!(
                run(argv).1,
                Some(OpaqueReason::EnvRejected {
                    hop: 0,
                    name: var.into()
                }),
                "{argv:?}"
            );
        }

        let ph = Some(OpaqueReason::FindPlaceholder { hop: 0 });
        assert_eq!(
            run(&["find", "/srv", "-perm", "-u+x", "-exec", "{}", ";"]).1,
            ph
        );
        assert_eq!(run(&["find", ".", "-exec", "./{}", "+"]).1, ph);

        let nine = ["nice"; 9];
        assert_eq!(run(&nine).1, Some(OpaqueReason::TooDeep));
        assert_eq!(run(&nine[..8]).1, None);
    }

    /// The code-loading list makes an `env` wrapper opaque, beyond the
    /// loader and shell names (#101), and an ordinary name stays transparent.
    #[test]
    fn env_setting_a_code_loading_name_is_opaque() {
        for var in [
            "PYTHONPATH",
            "NODE_OPTIONS",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_KEY_0",
            "GLIBC_TUNABLES",
            "PERLLIB",
            "DYLD_INSERT_LIBRARIES",
            "NIX_LD",
        ] {
            let set = format!("{var}=x");
            assert_eq!(
                run(&["env", &set, "true"]).1,
                Some(OpaqueReason::EnvRejected { hop: 0, name: var.into() }),
                "{var}"
            );
            assert!(opaque(&["env", "-u", var, "true"]), "{var}");
        }
        assert!(!opaque(&["env", "TF_VAR_x=1", "true"]));
    }

    /// `env` records the names it sets or unsets on its own hop.
    #[test]
    fn env_hop_records_the_names_it_touches() {
        let (hops, reason) = run(&["env", "-u", "A", "B=1", "nice", "env", "C=2", "true"]);
        assert_eq!(reason, None);
        let touched: Vec<Vec<String>> = hops.iter().map(|h| h.touches.clone()).collect();
        assert_eq!(touched, vec![vec!["A".to_string(), "B".into()], vec![], vec!["C".into()], vec![]]);
    }

    #[test]
    fn transparent_cases() {
        for argv in [
            &["env"][..],
            &["env", "FOO=1"],
            &["nice"],
            &["env", "FOO=1", "make"],
            &["timeout", "5", "true"],
            &["xargs"],
            &["ionice", "-p", "1"],
            &["busybox"],
            &["find", ".", "-name", "*.o", "-exec", "rm", "{}", "+"],
            &["env", "LANG=C", "true"],
            &["env", "TSAN_OPTIONS=x", "true"],
            &["nohup", "--", "true"],
        ] {
            assert_eq!(run(argv).1, None, "{argv:?}");
        }
        assert_eq!(
            names(&["find", ".", "-name", "*.o", "-exec", "rm", "{}", "+"]),
            ["find", "rm"]
        );
        // A `+` not right after `{}` does not end the -exec.
        assert_eq!(
            names(&["find", ".", "-exec", "echo", "+", ";", "-exec", "sh", ";"]),
            ["find", "echo", "sh"]
        );
        assert!(opaque(&[
            "find", ".", "-exec", "echo", "+", ";", "-exec", "sh", ";"
        ]));
    }

    /// The motivating real-world use (log corpus cases 06 and 22) stays
    /// transparent and now names `opam`.
    #[test]
    fn corpus_env_opam_is_transparent() {
        let c06 = [
            "env",
            "TSAN_OPTIONS=halt_on_error=0 exitcode=0",
            "opam",
            "exec",
            "--switch=ocaml+tsan",
            "--",
            "dune",
            "exec",
            "lib/proj/test_mock/check_mocked.exe",
        ];
        let c22 = [
            "env",
            "PROJ_CONF=/mnt/data/proj.conf",
            "TSAN_OPTIONS=suppressions=/tmp/tsan.supp halt_on_error=0 exitcode=0 history_size=4",
            "opam",
            "exec",
            "--switch=ocaml+tsan",
            "--",
            "dune",
            "exec",
            "lib/proj/test/concurrency.exe",
            "--",
            "test",
            "Multi-domain stress",
            "1",
        ];
        for argv in [&c06[..], &c22[..]] {
            assert_eq!(run(argv).1, None);
            assert_eq!(names(argv), ["env", "opam"]);
        }
    }

    #[test]
    fn interpreters() {
        for argv in [
            &["python3", "-c", "x"][..],
            &["python3", "-Bc", "x"],
            &["python3", "-cx"],
            &["python3.12", "-c", "x"],
            &["python3"],
            &["python3", "-"],
            &["python3", "-W", "ignore"],
            &["perl", "-lne"],
            &["perl", "-E"],
            &["perl5.38.2", "-e", "x"],
            &["ruby", "-e"],
            &["node", "--eval"],
            &["node", "--eval=1"],
            &["node", "-p"],
            &["php", "-r"],
            &["php8.3", "-r", "x"],
            &["lua", "-e"],
            &["Rscript", "-e", "1"],
            &["pypy3", "-c", "x"],
            // Review C1: code attached after a switch cluster.
            &["perl", "-le'print 1'", "/dev/null"],
            &["python3", "-Bcprint(1)", "foo"],
            &["perl", "-0e", "print 1", "x"],
            &["perl", "-0777le", "print 1", "x"],
            &["ruby", "-we", "p 1", "x.rb"],
        ] {
            assert!(
                matches!(run(argv).1, Some(OpaqueReason::InlineCode { .. })),
                "{argv:?}: {:?}",
                run(argv).1
            );
        }
        assert_eq!(
            run(&["python3"]).1,
            Some(OpaqueReason::InlineCode {
                hop: 0,
                flag: "stdin".into()
            })
        );
        for argv in [
            &["python3", "x.py"][..],
            &["python3", "-m", "pip"],
            &["python3", "-W", "ignore", "x.py"],
            &["python3", "--", "x.py"],
            // An attached argument of a separate-argument letter is not
            // scanned for code letters.
            &["ruby", "-rset", "x.rb"],
            &["php", "-dmemory_limit=1G", "x.php"],
            &["rubocop"],
            &["phpunit"],
            &["php-fpm", "-t"],
            &["python3-config", "--cflags"],
            &["perlcritic"],
            &["luarocks", "list"],
            &["nodemon"],
        ] {
            assert_eq!(run(argv).1, None, "{argv:?}");
        }
        assert_eq!(classify("python3-config"), Class::Plain);
    }

    #[test]
    fn runners_are_opaque() {
        for argv in [
            &["sudo", "true"][..],
            &["watch", "ls"],
            &["env", "sudo", "true"],
        ] {
            assert!(
                matches!(run(argv).1, Some(OpaqueReason::Runner { .. })),
                "{argv:?}"
            );
        }
    }

    /// #91: the ssh family is opaque when it carries a command string, also
    /// behind a wrapper; a plain transfer stays transparent.
    #[test]
    fn command_string_programs() {
        for (argv, hop) in [
            (&["ssh", "h"][..], 0),
            (&["ssh", "h", "true"], 0),
            (&["slogin", "h"], 0),
            (&["rsync", "-e", "x", "a", "h:b"], 0),
            (&["scp", "-S", "x", "a", "h:b"], 0),
            (&["sftp", "-D", "x"], 0),
            (&["git", "-c", "core.sshCommand=x", "fetch"], 0),
            (&["env", "rsync", "-e", "x", "a", "b"], 1),
            (&["timeout", "5", "git", "-c", "a=b", "fetch"], 1),
            (&["nice", "ssh", "h", "id"], 1),
            (&["find", ".", "-exec", "rsync", "-e", "x", "{}", "d", ";"], 1),
            (&["xargs", "git", "clone", "ext::x"], 1),
        ] {
            assert!(
                matches!(run(argv).1, Some(OpaqueReason::CommandString { hop: h, .. }) if h == hop),
                "{argv:?}: {:?}",
                run(argv).1
            );
        }
        for argv in [
            &["rsync", "-a", "a", "h:b"][..],
            &["scp", "a", "h:b"],
            &["git", "fetch"],
            &["env", "git", "status"],
            &["timeout", "5", "rsync", "a", "b"],
        ] {
            assert_eq!(run(argv).1, None, "{argv:?}");
        }
        // The env names that pick a transport command are rejected.
        for argv in [
            &["env", "RSYNC_RSH=x", "rsync", "a", "h:b"][..],
            &["env", "GIT_SSH=x", "git", "fetch"],
            &["env", "GIT_PROXY_COMMAND=x", "git", "fetch"],
            &["env", "RSYNC_CONNECT_PROG=x", "rsync", "h::m", "d"],
        ] {
            assert!(
                matches!(run(argv).1, Some(OpaqueReason::EnvRejected { .. })),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn canonical_name_classification() {
        let with = |argv: &[&str], canon: &[(usize, &str)]| {
            let canon: Vec<(usize, String)> =
                canon.iter().map(|(i, s)| (*i, s.to_string())).collect();
            unwrap(&v(argv), move |i, _| {
                canon.iter().find(|(j, _)| *j == i).map(|(_, s)| s.clone())
            })
        };
        // A plain name whose binary is `env` is unwrapped as `env`.
        let (hops, r) = with(&["innocuous", "true"], &[(0, "env")]);
        assert_eq!(r, None);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[1].via, Some(0));
        assert_eq!(
            with(&["innocuous", "sh"], &[(0, "env")]).1,
            Some(OpaqueReason::Shell { hop: 1 })
        );
        assert_eq!(
            with(&["nice", "true"], &[(0, "env")]).1,
            Some(OpaqueReason::Ambiguous {
                hop: 0,
                canonical: "env".into()
            })
        );
        assert_eq!(
            with(&["foo"], &[(0, "bash")]).1,
            Some(OpaqueReason::Shell { hop: 0 })
        );
        // Multi-call canonical names are ignored: the written name decides.
        let (hops, r) = with(&["env", "true"], &[(0, "busybox")]);
        assert_eq!((hops.len(), r), (2, None));
        // A wrapper whose binary is a plain name keeps the written class.
        let (hops, r) = with(&["env", "sh"], &[(0, "env.real")]);
        assert_eq!((hops.len(), r), (2, Some(OpaqueReason::Shell { hop: 1 })));
        // A renamed rsync is scanned as rsync (#91).
        assert!(matches!(
            with(&["innocuous", "-e", "x", "a", "b"], &[(0, "rsync")]).1,
            Some(OpaqueReason::CommandString { hop: 0, .. })
        ));
        assert_eq!(with(&["innocuous", "a", "b"], &[(0, "rsync")]).1, None);
    }

    /// The cases `prop_wrapping_preserves_opacity` excludes by construction:
    /// an `A` starting with an option or an assignment is read by the wrapper.
    #[test]
    fn wrapping_reads_a_leading_option_or_assignment() {
        assert!(opaque(&["env", "-c", "x"]));
        assert!(!opaque(&["-c", "x"]));
        assert!(opaque(&["env", "X=1", "sh"]));
        assert!(!opaque(&["X=1", "sh"]));
    }

    #[test]
    fn describe_texts() {
        let d = |argv: &[&str]| {
            let argv = v(argv);
            let (hops, r) = unwrap(&argv, |_, _| None);
            r.unwrap().describe(&hops, &argv)
        };
        assert_eq!(d(&["env", "sh"]), "resolves only the shell");
        assert_eq!(d(&["python3", "-c", "x"]), "inline code (-c)");
        assert_eq!(
            d(&["env", "-S", "x"]),
            "cannot unwrap env: unsupported option -S"
        );
        assert_eq!(
            d(&["env", "PATH=/x", "y"]),
            "env changes PATH; the program it runs is not resolved"
        );
        assert_eq!(
            d(&["env", "LD_PRELOAD=/x", "y"]),
            "env sets a name the policy rejects: LD_PRELOAD"
        );
        assert_eq!(
            d(&["find", ".", "-exec", "{}", ";"]),
            "find runs the files it finds ({})"
        );
        assert_eq!(
            d(&["sudo", "true"]),
            "runs a program the prompt does not unwrap"
        );
        assert_eq!(
            d(&["ssh", "h", "true"]),
            "runs a command string remotely (true)"
        );
        assert_eq!(d(&["ssh", "h"]), "runs a remote login shell");
        assert_eq!(
            d(&["env", "rsync", "--rsync-path=x", "a", "h:b"]),
            "runs a command string remotely or through a shell (--rsync-path)"
        );
        assert_eq!(
            d(&["xargs", "-I{}", "{}"]),
            "xargs takes the program from its input ({})"
        );
        assert_eq!(
            d(&["timeout", "5", "--", "sh"]),
            "cannot unwrap timeout: -- where the program is expected"
        );
    }

    // === Properties (Rung 2) ===========================================

    const NAMES: &[&str] = &[
        "env",
        "nice",
        "nohup",
        "setsid",
        "stdbuf",
        "timeout",
        "ionice",
        "chrt",
        "taskset",
        "time",
        "xargs",
        "busybox",
        "toybox",
        "coreutils",
        "find",
        "sh",
        "bash",
        "python3",
        "perl",
        "node",
        "sudo",
        "ssh",
        "scp",
        "rsync",
        "git",
        "true",
        "make",
        "opam",
        "ls",
    ];
    const TOKENS: &[&str] = &[
        "-",
        "--",
        "-n",
        "-c",
        "-e",
        "-i",
        "-u",
        "-C",
        "-S",
        "-s",
        "-k",
        "-p",
        "-o",
        "-0",
        "-5",
        "-exec",
        "-ok",
        "{}",
        ";",
        "+",
        "X=1",
        "PATH=/x",
        "LD_PRELOAD=y",
        "=",
        "5",
        "0",
        "x",
        "--signal",
        "--sig=KILL",
        "--chdir=d",
        "-oL",
        "-iu",
        "--help",
        "-e",
        "--rsh=x",
        "ext::x",
        "rebase",
        "--exec",
    ];

    fn token(rng: &mut Rng) -> String {
        if rng.below(2) == 0 {
            NAMES[rng.below(NAMES.len())].to_string()
        } else {
            TOKENS[rng.below(TOKENS.len())].to_string()
        }
    }

    /// Spec clause: `unwrap` is total, and every hop points into argv, after
    /// the hop that runs it.
    fn unwrap_is_total(argv: &[String]) {
        let (hops, _) = unwrap(argv, |_, _| None);
        for h in &hops {
            assert!(h.argv_index < argv.len(), "{argv:?}");
            if let Some(p) = h.via {
                assert!(hops[p].argv_index < h.argv_index, "{argv:?}");
            }
        }
    }

    #[test]
    fn prop_unwrap_is_total() {
        let mut rng = Rng::new(0x87_0001);
        for _ in 0..5000 {
            let n = rng.below(12);
            let argv: Vec<String> = (0..n).map(|_| token(&mut rng)).collect();
            unwrap_is_total(&argv);
        }
    }

    /// Well-formed wrapper prefixes: each is one hop that runs its next word.
    const PREFIXES: &[&[&str]] = &[
        &["env"],
        &["env", "X=1"],
        &["nice", "-n", "5"],
        &["timeout", "5"],
        &["stdbuf", "-oL"],
        &["setsid"],
        &["nohup"],
        &["time"],
        &["ionice", "-c", "3"],
        &["chrt", "-o", "0"],
        &["taskset", "1"],
        &["xargs"],
        &["busybox"],
        &["coreutils"],
    ];

    /// Spec clause (the issue's failure scenario): putting a well-formed wrapper
    /// in front of a command `a` that starts with a program name does not
    /// change whether it is opaque, and when it is transparent the wrapper's
    /// hop runs `a[0]`. Precondition: `a` unwraps in fewer than
    /// `MAX_DEPTH - 1` hops, so the prefix alone never makes it too deep.
    fn wrapping_preserves_opacity(w: &[&str], a: &[String]) -> bool {
        let (hops_a, reason_a) = unwrap(a, |_, _| None);
        if hops_a.len() >= MAX_DEPTH - 1 {
            return false;
        }
        let wa: Vec<String> = w
            .iter()
            .map(|s| s.to_string())
            .chain(a.iter().cloned())
            .collect();
        let (hops, reason) = unwrap(&wa, |_, _| None);
        assert_eq!(
            reason.is_some(),
            reason_a.is_some(),
            "{wa:?}: {reason:?} vs {reason_a:?}"
        );
        if reason.is_none() {
            assert_eq!(hops[1].argv_index, w.len(), "{wa:?}");
            assert_eq!(hops[1].via, Some(0), "{wa:?}");
        }
        true
    }

    #[test]
    fn prop_wrapping_preserves_opacity() {
        let mut rng = Rng::new(0x87_0002);
        let mut checked = 0;
        while checked < 5000 {
            let w = PREFIXES[rng.below(PREFIXES.len())];
            let n = rng.below(10);
            let mut a = vec![NAMES[rng.below(NAMES.len())].to_string()];
            a.extend((0..n).map(|_| token(&mut rng)));
            if wrapping_preserves_opacity(w, &a) {
                checked += 1;
            }
        }
    }
}
