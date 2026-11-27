//! Programs that run a command string remotely or through a shell (issue #91).
//!
//! The prompt shows these programs' argv faithfully, but part of what runs is a
//! string another shell interprets: `ssh host 'cmd'` on the remote side,
//! `rsync -e 'prog …'` and `scp -S prog` locally, `git -c core.sshCommand=…`,
//! an `ext::` remote, `git rebase --exec …`. [`scan`] says whether an
//! invocation carries such a string, and which word does.
//!
//! The scans are deliberately coarse and fail closed: a word that only looks
//! like a trigger (a file named `-e`, a `git bisect start run`) over-flags,
//! which is acceptable; a missed trigger is not. Plain transfers (`rsync src
//! dst`, `scp src dst`, `git fetch`) carry no command string and stay
//! transparent. `ssh` always runs something remotely, and `sftp` the commands
//! of its batch file or stdin (`!cmd` runs a local shell), so both are always
//! flagged.
//! `git` is scanned only for the subcommands of an allowlist; any other
//! subcommand is flagged.
//!
//! Pure: no filesystem access and no I/O.

/// A program that can run a command string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prog {
    Ssh,
    Scp,
    Sftp,
    Rsync,
    Git,
    /// A dashed git program (`git-rebase`, `git-upload-pack`, …): a git
    /// builtin run under its own name, whose argv does not carry the
    /// subcommand word the [`Prog::Git`] scan keys on. Always flagged.
    GitDashed,
}

impl Prog {
    /// The program a basename names, if it is one of these.
    pub fn from_name(base: &str) -> Option<Prog> {
        match base {
            "ssh" | "slogin" => Some(Prog::Ssh),
            "scp" => Some(Prog::Scp),
            "sftp" => Some(Prog::Sftp),
            "rsync" => Some(Prog::Rsync),
            "git" => Some(Prog::Git),
            _ if base.strip_prefix("git-").is_some_and(|s| !s.is_empty()) => Some(Prog::GitDashed),
            _ => None,
        }
    }
}

/// What carries the command string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// `ssh` with command words; the first one.
    RemoteCommand(String),
    /// `ssh` with no command words: the remote login shell runs, reading its
    /// commands from stdin when no tty is attached.
    RemoteShell,
    /// `ssh` with an option that may make it run no command (`-N`, `-O`,
    /// `-G`, `-V`): still flagged.
    Remote(String),
    /// An invocation the scan does not parse (an unknown option, a missing
    /// option argument, a git subcommand off the allowlist): it may run a
    /// command string, so it is flagged.
    Unparsed(String),
    /// Any other program: the option or word that carries the string.
    Option(String),
    /// A local program that runs the string through a shell (`flock FILE -c`,
    /// #92): the option that carries it.
    Shell(String),
    /// `sftp` with no other trigger: it runs the commands of its `-b` batch
    /// file or of stdin, and `!command` runs a local shell.
    SftpCommands,
}

impl Trigger {
    /// The text shown after `opaque — ` at the prompt and in the `no_shell`
    /// rejection.
    pub fn describe(&self) -> String {
        // The quoted word is a request word: quoted like a `Command:` word
        // (G4.6), so it cannot pass for the prompt's own words.
        let q = crate::tui::shquote;
        match self {
            Trigger::RemoteCommand(w) => format!("runs a command string remotely ({})", q(w)),
            Trigger::RemoteShell => "runs a remote login shell".into(),
            Trigger::Remote(w) => format!("may run a command string remotely ({})", q(w)),
            Trigger::Unparsed(w) => format!("not parsed; may run a command string ({})", q(w)),
            Trigger::Option(t) => {
                format!(
                    "runs a command string remotely or through a shell ({})",
                    q(t)
                )
            }
            Trigger::Shell(t) => format!("runs a command string through a shell ({})", q(t)),
            Trigger::SftpCommands => {
                "runs sftp commands from a batch file or stdin (! runs a local shell)".into()
            }
        }
    }
}

/// The longest word quoted in a trigger, in characters.
const SHOWN: usize = 16;

fn clip(s: &str) -> String {
    s.chars().take(SHOWN).collect()
}

/// Whether `prog`, run with arguments `args` (`argv[1..]`), runs a command
/// string, and which word carries it. Total: never panics, for any input.
pub fn scan(prog: Prog, args: &[String]) -> Option<Trigger> {
    match prog {
        Prog::Ssh => Some(ssh(args)),
        Prog::Scp => scp_sftp(false, args).map(Trigger::Option),
        // Always: its commands come from `-b FILE` or stdin, which a request
        // can supply (a pipe, `with-stdin-from`), and `!cmd` runs a shell.
        Prog::Sftp => Some(
            scp_sftp(true, args)
                .map(Trigger::Option)
                .unwrap_or(Trigger::SftpCommands),
        ),
        Prog::Rsync => rsync(args).map(Trigger::Option),
        Prog::Git => git(args),
        Prog::GitDashed => Some(Trigger::Unparsed("git-<command>".into())),
    }
}

/// The first letter of `triggers` in a short-option cluster (`-avze`), or
/// `None`. The scan stops at a letter in `stops` (it takes an argument, which
/// may be attached) and at any non-alphanumeric character. A `--long` word
/// or a non-option word is not a cluster. Only letters that really take an
/// argument may be listed in `stops`: a stop hides the letters after it.
fn cluster_hit(word: &str, triggers: &str, stops: &str) -> Option<char> {
    let rest = word.strip_prefix('-').filter(|r| !r.starts_with('-'))?;
    for c in rest.chars() {
        if triggers.contains(c) {
            return Some(c);
        }
        if stops.contains(c) || !c.is_ascii_alphanumeric() {
            return None;
        }
    }
    None
}

/// `ssh [options] destination [options] [command …]`. OpenSSH parses options
/// again after the destination, so the command is the first non-option word
/// after it.
fn ssh(args: &[String]) -> Trigger {
    const NOARG: &str = "46AaCfGgKkMNnqsTtVvXxYy";
    const ARG: &str = "BbcDEeFIiJLlmOoPpQRSWw";
    const NO_COMMAND: &str = "NOGV";
    let mut dest = false;
    let mut maybe_none: Option<char> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            if !dest {
                if i >= args.len() {
                    return Trigger::Unparsed("no destination".into());
                }
                dest = true;
                i += 1;
            }
            break;
        }
        let Some(rest) = a.strip_prefix('-').filter(|r| !r.is_empty()) else {
            if dest {
                break;
            }
            dest = true;
            i += 1;
            continue;
        };
        let mut consumed_next = false;
        for (k, c) in rest.char_indices() {
            if NO_COMMAND.contains(c) && maybe_none.is_none() {
                maybe_none = Some(c);
            }
            if NOARG.contains(c) {
                continue;
            }
            if ARG.contains(c) {
                if rest[k + c.len_utf8()..].is_empty() {
                    if i + 1 >= args.len() {
                        return Trigger::Unparsed(format!("-{c} without its argument"));
                    }
                    consumed_next = true;
                }
                break;
            }
            return Trigger::Unparsed(clip(a));
        }
        i += if consumed_next { 2 } else { 1 };
    }
    if let Some(c) = maybe_none {
        Trigger::Remote(format!("-{c}"))
    } else if !dest {
        Trigger::Unparsed("no destination".into())
    } else if let Some(w) = args.get(i) {
        Trigger::RemoteCommand(clip(w))
    } else {
        Trigger::RemoteShell
    }
}

/// `scp` / `sftp`: `-S program`, `-D server`, a `-F` config file (it can set
/// `ProxyCommand`), an `-o` that names a program or a library to load (see
/// [`ssh_option_runs`]), `scp -O` (the legacy protocol passes the remote path
/// through the remote shell), and for `sftp` the `-s` subsystem or server
/// program. Options are permuted with operands, so every word up to a `--`
/// is scanned.
fn scp_sftp(sftp: bool, args: &[String]) -> Option<String> {
    let (triggers, stops) = if sftp {
        ("SDFso", "BbciJlPR")
    } else {
        ("SDFOo", "ciJlPX")
    };
    for (i, a) in args.iter().enumerate() {
        if a == "--" {
            break;
        }
        let Some(c) = cluster_hit(a, triggers, stops) else {
            continue;
        };
        if c != 'o' {
            return Some(format!("-{c}"));
        }
        // `-oKey=Value`, `-o Key=Value`, `-o 'Key Value'`.
        let at = a.find('o').map_or(a.len(), |k| k + 1);
        let value = if at < a.len() {
            Some(&a[at..])
        } else {
            args.get(i + 1).map(String::as_str)
        };
        let Some(value) = value else {
            return Some("-o".into());
        };
        match ssh_option_key(value) {
            None => return Some("-o".into()),
            Some(key) if ssh_option_runs(&key) => {
                return Some(format!("-o {}", clip(&key)));
            }
            Some(_) => {}
        }
    }
    None
}

/// The keyword of an ssh `-o` value, as ssh's config tokenizer reads it: it
/// skips leading whitespace and `=`, and strips double quotes. `None` when
/// there is no keyword.
fn ssh_option_key(value: &str) -> Option<String> {
    let unquoted: String = value.chars().filter(|c| *c != '"').collect();
    let key = unquoted
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("");
    (!key.is_empty()).then(|| key.to_string())
}

/// Whether an ssh option keyword names a program to run or a library to load:
/// a key ending in `Command` (`ProxyCommand`, `LocalCommand`,
/// `KnownHostsCommand`, …) or `Provider` (`PKCS11Provider`,
/// `SecurityKeyProvider`), and `XAuthLocation`. Keywords are case-insensitive.
fn ssh_option_runs(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.ends_with("command") || k.ends_with("provider") || k == "xauthlocation"
}

/// `rsync`: `-e` / `--rsh` (the remote shell program), `--rsync-path` (a
/// command run by the remote shell), `-M` / `--remote-option` (options for
/// the remote rsync, which can set those), `--old-args` (the remote path
/// reaches the remote shell unescaped) and `--daemon` / `--dparam` (a daemon
/// runs the `exec` commands of its config). popt accepts no abbreviation;
/// prefixes of these names are flagged anyway, as a precaution.
fn rsync(args: &[String]) -> Option<String> {
    const LONG: &[&str] = &[
        "rsh",
        "rsync-path",
        "remote-option",
        "old-args",
        "daemon",
        "dparam",
    ];
    for a in args {
        if a == "--" {
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let name = body.split('=').next().unwrap_or("");
            if let Some(l) = LONG
                .iter()
                .find(|l| **l == name || (name.len() >= 3 && l.starts_with(name)))
            {
                return Some(format!("--{l}"));
            }
            continue;
        }
        if let Some(c) = cluster_hit(a, "eM", "BfT@") {
            return Some(format!("-{c}"));
        }
    }
    None
}

/// Whether the long option `name` (with its `--`) is `full` or a prefix git
/// would accept as an abbreviation of it.
fn long_hit(name: &str, full: &str) -> bool {
    name.len() > 2 && full.starts_with(name)
}

/// The git subcommands scanned option by option. Any other subcommand is
/// flagged: the rest of git's surface (and an alias, or a `git-<name>` found
/// on PATH) is open-ended.
const GIT_SUBCOMMANDS: &[&str] = &[
    "add",
    "blame",
    "branch",
    "cat-file",
    "checkout",
    "clone",
    "commit",
    "describe",
    "diff",
    "fetch",
    "grep",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge",
    "mv",
    "pull",
    "push",
    "rebase",
    "reflog",
    "remote",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "rm",
    "shortlog",
    "show",
    "show-ref",
    "stash",
    "status",
    "switch",
    "tag",
    "version",
    "worktree",
];

/// The URL schemes git handles without a remote helper found on PATH.
const GIT_SCHEMES: &[&str] = &[
    "ssh", "git", "file", "http", "https", "ftp", "ftps", "git+ssh", "ssh+git",
];

/// A git remote that runs a helper: `<transport>::<address>` (`ext::` runs its
/// address as a command; any other transport runs `git-remote-<transport>`,
/// looked up on PATH), or `<scheme>://` with a scheme git does not handle
/// itself.
fn git_remote_helper(w: &str) -> Option<String> {
    let scheme_ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    };
    if let Some((t, _)) = w.split_once("::") {
        if scheme_ok(t) {
            return Some(format!("{}::", clip(t)));
        }
    }
    if let Some((s, _)) = w.split_once("://") {
        if scheme_ok(s) && !GIT_SCHEMES.contains(&s.to_ascii_lowercase().as_str()) {
            return Some(format!("{}://", clip(s)));
        }
    }
    None
}

/// `git`: config set on the command line (`-c`, `--config-env`; many keys run
/// a command, as `GIT_CONFIG*` in the environment does), `--exec-path`, any
/// unknown global option, a remote run by a helper (`ext::`), the transport
/// program options (`--upload-pack`, `--receive-pack`, `--exec`), the options
/// of allowlisted subcommands that run a command string, and any subcommand
/// off the allowlist ([`GIT_SUBCOMMANDS`]). Long options match abbreviated, as
/// git accepts them.
fn git(args: &[String]) -> Option<Trigger> {
    const NOARG: &[&str] = &[
        "-p",
        "-P",
        "--paginate",
        "--no-pager",
        "--bare",
        "--no-replace-objects",
        "--no-lazy-fetch",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--no-advice",
        "--html-path",
        "--man-path",
        "--info-path",
        "--version",
        "--help",
        "-v",
        "-h",
    ];
    const ARG: &[&str] = &[
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--list-cmds",
        "--attr-source",
    ];
    const CONFIG: &[&str] = &["-c", "--config-env", "--exec-path"];
    let opt = |s: String| Some(Trigger::Option(s));
    let mut i = 0;
    while let Some(a) = args.get(i) {
        if !a.starts_with('-') {
            break;
        }
        if NOARG.contains(&a.as_str()) {
            i += 1;
        } else if ARG.contains(&a.as_str()) {
            i += 2;
        } else if a
            .split_once('=')
            .is_some_and(|(n, _)| n.starts_with("--") && ARG.contains(&n))
        {
            i += 1;
        } else {
            let name = a.split_once('=').map_or(a.as_str(), |(n, _)| n);
            return if CONFIG.contains(&name) {
                opt(name.into())
            } else {
                Some(Trigger::Unparsed(clip(name)))
            };
        }
    }
    let words = args.get(i..).unwrap_or(&[]);
    if let Some(t) = words.iter().find_map(|w| git_remote_helper(w)) {
        return opt(t);
    }
    let (sub, rest) = words.split_first()?;
    let sub = sub.as_str();
    if !GIT_SUBCOMMANDS.contains(&sub) {
        let has = |w: &str| rest.iter().any(|r| r == w);
        return match sub {
            "submodule" if has("foreach") => opt("submodule foreach".into()),
            "bisect" if has("run") => opt("bisect run".into()),
            "filter-branch" | "remote-ext" | "send-email" | "daemon" | "instaweb" | "difftool"
            | "mergetool" => opt(sub.into()),
            _ => Some(Trigger::Unparsed(format!("git {}", clip(sub)))),
        };
    }
    let opts = rest.iter().take_while(|w| *w != "--");
    let long_name = |w: &str| w.split_once('=').map_or(w, |(n, _)| n).to_string();
    const TRANSPORT: &[&str] = &["--upload-pack", "--receive-pack", "--exec"];
    for w in opts.clone() {
        let name = long_name(w);
        if let Some(full) = TRANSPORT.iter().find(|f| long_hit(&name, f)) {
            return opt((*full).into());
        }
    }
    let hit = |triggers: &str, stops: &str, long: &[&str]| -> Option<Trigger> {
        opts.clone().find_map(|w| {
            if w.starts_with("--") {
                let name = long_name(w);
                return long
                    .iter()
                    .find(|f| long_hit(&name, f))
                    .map(|f| Trigger::Option(format!("{sub} {f}")));
            }
            cluster_hit(w, triggers, stops).map(|c| Trigger::Option(format!("{sub} -{c}")))
        })
    };
    match sub {
        // `clone -c` writes config, and `--template` installs hooks, before
        // the fetch runs.
        "clone" => hit("uc", "obj", &["--config", "--template"]),
        "init" => hit("", "", &["--template"]),
        "ls-remote" => hit("u", "o", &[]),
        // `-s`/`--strategy` runs `git-merge-<strategy>`, looked up on PATH.
        "rebase" => hit("xs", "XC", &["--strategy"]),
        "merge" => hit("s", "XmF", &["--strategy"]),
        "pull" => hit("s", "Xoj", &["--strategy"]),
        "grep" => hit("O", "efmABC", &["--open-files-in-pager"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn trig(p: Prog, s: &[&str]) -> Option<String> {
        scan(p, &v(s)).map(|t| match t {
            Trigger::Option(o) => o,
            other => format!("{other:?}"),
        })
    }

    #[test]
    fn ssh_is_always_flagged() {
        let s = |a: &[&str]| scan(Prog::Ssh, &v(a)).unwrap();
        let u = |w: &str| Trigger::Unparsed(w.into());
        assert_eq!(s(&["h", "true"]), Trigger::RemoteCommand("true".into()));
        assert_eq!(s(&["h"]), Trigger::RemoteShell);
        assert_eq!(
            s(&["-p", "22", "h", "ls", "-l"]),
            Trigger::RemoteCommand("ls".into())
        );
        assert_eq!(
            s(&["-p22", "-A", "h", "id"]),
            Trigger::RemoteCommand("id".into())
        );
        // Options are parsed again after the destination.
        assert_eq!(s(&["h", "-t", "top"]), Trigger::RemoteCommand("top".into()));
        assert_eq!(
            s(&["-l", "u", "--", "h", "x"]),
            Trigger::RemoteCommand("x".into())
        );
        assert_eq!(s(&["-N", "h"]), Trigger::Remote("-N".into()));
        assert_eq!(s(&["-O", "check", "h"]), Trigger::Remote("-O".into()));
        assert_eq!(s(&["-G", "h"]), Trigger::Remote("-G".into()));
        assert_eq!(s(&["-V"]), Trigger::Remote("-V".into()));
        assert_eq!(s(&["-Z", "h", "x"]), u("-Z"));
        assert_eq!(s(&["-p"]), u("-p without its argument"));
        assert_eq!(s(&[]), u("no destination"));
        assert_eq!(s(&["--"]), u("no destination"));
        assert_eq!(
            s(&["h", "a-very-long-command-word"]),
            Trigger::RemoteCommand("a-very-long-comm".into())
        );
    }

    #[test]
    fn scp_and_sftp() {
        let flagged: &[(&[&str], &str)] = &[
            (&["-S", "x", "a", "h:b"], "-S"),
            (&["-rS", "x", "a", "h:b"], "-S"),
            (&["a", "h:b", "-Sx"], "-S"),
            (&["-F", "cfg", "a", "h:b"], "-F"),
            (&["-D", "/srv", "a", "h:b"], "-D"),
            (&["-O", "a", "h:b"], "-O"),
            (&["-rO", "a", "h:$(id)"], "-O"),
            (
                &["-o", "ProxyCommand=nc %h %p", "a", "h:b"],
                "-o ProxyCommand",
            ),
            (&["-oProxyCommand=x", "a", "h:b"], "-o ProxyCommand"),
            (&["-o", "proxycommand x", "a", "h:b"], "-o proxycommand"),
            (&["-o", "LocalCommand=x", "a", "h:b"], "-o LocalCommand"),
            (
                &["-o", "KnownHostsCommand=x", "a", "h:b"],
                "-o KnownHostsComman",
            ),
            // ssh's tokenizer skips leading whitespace and `=`, and strips
            // quotes.
            (&["-o", " ProxyCommand=x", "a", "h:b"], "-o ProxyCommand"),
            (&["-o", "\tProxyCommand=x", "a", "h:b"], "-o ProxyCommand"),
            (&["-o", "=ProxyCommand=x", "a", "h:b"], "-o ProxyCommand"),
            (&["-o", "\"ProxyCommand\" x", "a", "h:b"], "-o ProxyCommand"),
            (&["-o", "", "a", "h:b"], "-o"),
            (&["-o", " = ", "a", "h:b"], "-o"),
            // A library loaded into the ssh child.
            (
                &["-o", "PKCS11Provider=/x.so", "a", "h:b"],
                "-o PKCS11Provider",
            ),
            (
                &["-oSecurityKeyProvider=/x.so", "a", "h:b"],
                "-o SecurityKeyProvi",
            ),
            (&["-o", "XAuthLocation=/x", "a", "h:b"], "-o XAuthLocation"),
            (&["a", "h:b", "-o"], "-o"),
        ];
        for (a, t) in flagged {
            assert_eq!(trig(Prog::Scp, a).as_deref(), Some(*t), "scp {a:?}");
        }
        for a in [
            &["a", "h:b"][..],
            &["-r", "-P", "22", "a", "h:b"],
            &["-o", "Port=22", "a", "h:b"],
            &["-o", " Port 22", "a", "h:b"],
            &["-i", "key-S", "a", "h:b"],
            &["-l", "100", "a", "h:b"],
            &["-J", "jump", "a", "h:b"],
            &["-XO", "a", "h:b"],
            &["--", "-S", "h:b"],
        ] {
            assert_eq!(trig(Prog::Scp, a), None, "scp {a:?}");
        }
        assert_eq!(trig(Prog::Sftp, &["-s", "/x", "h"]).as_deref(), Some("-s"));
        assert_eq!(trig(Prog::Sftp, &["-S", "x", "h"]).as_deref(), Some("-S"));
        assert_eq!(
            trig(Prog::Sftp, &["-o", "PKCS11Provider=/x.so", "h"]).as_deref(),
            Some("-o PKCS11Provider")
        );
        // sftp runs the commands of its batch file or stdin, where `!cmd`
        // runs a local shell: always flagged, by its other triggers first.
        for a in [&["-b", "batch", "h"][..], &["h"], &["-O", "h"]] {
            assert_eq!(
                scan(Prog::Sftp, &v(a)),
                Some(Trigger::SftpCommands),
                "sftp {a:?}"
            );
        }
        // `scp -s` selects the sftp protocol; it runs nothing.
        assert_eq!(trig(Prog::Scp, &["-s", "a", "h:b"]), None);
    }

    #[test]
    fn rsync() {
        let flagged: &[(&[&str], &str)] = &[
            (&["-e", "ssh -p 2", "a", "h:b"], "-e"),
            (&["-avze", "x", "a", "h:b"], "-e"),
            (&["-essh", "a", "h:b"], "-e"),
            (&["--rsh=x", "a", "h:b"], "--rsh"),
            (&["--rsh", "x", "a", "h:b"], "--rsh"),
            (&["--rsync-path=sudo rsync", "a", "h:b"], "--rsync-path"),
            // rsync accepts no abbreviation; prefixes are flagged anyway.
            (&["--rsync-p=x", "a", "h:b"], "--rsync-path"),
            (&["-M", "--x", "a", "h:b"], "-M"),
            (&["--remote-option=--x", "a", "h:b"], "--remote-option"),
            (&["--rem=x", "a", "h:b"], "--remote-option"),
            (&["a", "h:b", "-e", "x"], "-e"),
            (&["--old-args", "a", "h:$(id)"], "--old-args"),
            (&["--daemon", "--config=x"], "--daemon"),
            (&["--daemon", "--no-detach"], "--daemon"),
            (&["--dparam=pre-xfer exec=id"], "--dparam"),
        ];
        for (a, t) in flagged {
            assert_eq!(trig(Prog::Rsync, a).as_deref(), Some(*t), "rsync {a:?}");
        }
        for a in [
            &["a", "b"][..],
            &["-avz", "--delete", "a", "h:b"],
            &["--exclude=-e", "a", "b"],
            &["-f", "- e", "a", "b"],
            &["-Tetmp", "a", "b"],
            &["--remove-source-files", "a", "b"],
            &["--no-old-args", "a", "h:b"],
            &["--old-dirs", "h:b", "d"],
            &["--", "-e", "b"],
        ] {
            assert_eq!(trig(Prog::Rsync, a), None, "rsync {a:?}");
        }
    }

    #[test]
    fn git() {
        let flagged: &[(&[&str], &str)] = &[
            (&["-c", "core.sshCommand=x", "fetch"], "-c"),
            (&["-c", "core.pager=x", "log"], "-c"),
            (&["-C", "d", "-c", "a=b", "status"], "-c"),
            (&["--config-env=core.pager=V", "log"], "--config-env"),
            (&["--exec-path=/x", "status"], "--exec-path"),
            (&["clone", "ext::sh -c x", "d"], "ext::"),
            (&["clone", "--", "ext::x", "d"], "ext::"),
            (&["fetch", "ext::x"], "ext::"),
            // Any other transport runs `git-remote-<name>` from PATH.
            (&["fetch", "evil::x"], "evil::"),
            (&["clone", "evil://x", "d"], "evil://"),
            (&["fetch", "--upload-pack=x", "o"], "--upload-pack"),
            (&["ls-remote", "--upload-pack", "x", "o"], "--upload-pack"),
            (&["push", "--receive-pack=x", "o"], "--receive-pack"),
            (&["push", "--exec=x", "o"], "--exec"),
            (&["rebase", "--exec", "make", "main"], "--exec"),
            // git accepts any unambiguous prefix of a long option.
            (&["fetch", "--upload=x", "o"], "--upload-pack"),
            (&["ls-remote", "--u=x", "o"], "--upload-pack"),
            (&["push", "--rec=x", "o"], "--receive-pack"),
            (&["rebase", "--ex=x", "main"], "--exec"),
            (&["clone", "--conf=a=b", "o"], "clone --config"),
            (&["clone", "--template=/t", "o", "d"], "clone --template"),
            (&["clone", "--temp", "/t", "o", "d"], "clone --template"),
            (&["init", "--template=/t", "d"], "init --template"),
            (&["rebase", "-x", "make", "main"], "rebase -x"),
            (&["rebase", "-ix", "make", "main"], "rebase -x"),
            (&["rebase", "-s", "evil", "main"], "rebase -s"),
            (&["rebase", "--strat=evil", "main"], "rebase --strategy"),
            (&["merge", "-s", "evil", "b"], "merge -s"),
            (&["merge", "-nsevil", "b"], "merge -s"),
            (&["pull", "--strategy=evil"], "pull --strategy"),
            (&["clone", "-u", "x", "o", "d"], "clone -u"),
            (&["clone", "-c", "core.sshCommand=x", "o"], "clone -c"),
            (&["clone", "--config=a=b", "o"], "clone --config"),
            (&["ls-remote", "-u", "x", "o"], "ls-remote -u"),
            (&["grep", "-Ox", "p"], "grep -O"),
            (&["grep", "-iO", "p"], "grep -O"),
            (
                &["grep", "--open-files-in-pager=x", "p"],
                "grep --open-files-in-pager",
            ),
            (&["grep", "--open=x", "p"], "grep --open-files-in-pager"),
            (&["difftool", "-x", "x"], "difftool"),
            (&["mergetool"], "mergetool"),
            (&["submodule", "foreach", "x"], "submodule foreach"),
            (
                &["submodule", "--quiet", "foreach", "x"],
                "submodule foreach",
            ),
            (&["bisect", "run", "make"], "bisect run"),
            (&["filter-branch", "--tree-filter", "x"], "filter-branch"),
            (&["remote-ext", "x", "id"], "remote-ext"),
            (&["send-email", "--sendmail-cmd=x"], "send-email"),
            (&["daemon", "--access-hook=x"], "daemon"),
            (&["instaweb", "--httpd=x"], "instaweb"),
        ];
        for (a, t) in flagged {
            assert_eq!(trig(Prog::Git, a).as_deref(), Some(*t), "git {a:?}");
        }
        // Off the allowlist, or an unknown global option: not parsed.
        for (a, w) in [
            (&["--frobnicate", "status"][..], "--frobnicate"),
            (&["bisect", "start"], "git bisect"),
            (&["submodule", "update"], "git submodule"),
            (&["my-alias"], "git my-alias"),
            (&["help", "log"], "git help"),
        ] {
            assert_eq!(
                scan(Prog::Git, &v(a)),
                Some(Trigger::Unparsed(w.into())),
                "git {a:?}"
            );
        }
        for a in [
            &[][..],
            &["status"],
            &["fetch", "origin"],
            &["clone", "https://x/y.git", "d"],
            &["clone", "ssh://h/y.git", "d"],
            &["clone", "git@h:y.git", "d"],
            &["push", "-u", "origin", "main"],
            &["add", "-u"],
            &["commit", "-c", "HEAD"],
            &["commit", "--template=msg"],
            &["grep", "-c", "x"],
            &["grep", "-e", "x"],
            &["grep", "-eO"],
            &["grep", "--only-matching", "x"],
            &["init", "d"],
            &["-C", "d", "--no-pager", "log", "-p"],
            &["--git-dir=/x/.git", "status"],
            &["rebase", "-i", "main"],
            &["rebase", "-Xours", "main"],
            &["merge", "-Xours", "b"],
            &["merge", "-m", "msg s", "b"],
            &["pull", "--rebase"],
            &["log", "--", "--exec"],
            &["--version"],
            &["version"],
        ] {
            assert_eq!(trig(Prog::Git, a), None, "git {a:?}");
        }
    }

    #[test]
    fn dashed_git_programs() {
        assert_eq!(Prog::from_name("git-rebase"), Some(Prog::GitDashed));
        assert_eq!(Prog::from_name("git-upload-pack"), Some(Prog::GitDashed));
        assert_eq!(Prog::from_name("git-"), None);
        assert_eq!(Prog::from_name("legit"), None);
        assert_eq!(
            scan(Prog::GitDashed, &v(&["-x", "id", "main"])),
            Some(Trigger::Unparsed("git-<command>".into()))
        );
        assert!(scan(Prog::GitDashed, &[]).is_some());
    }

    #[test]
    fn describe_texts() {
        assert_eq!(
            Trigger::RemoteCommand("true".into()).describe(),
            "runs a command string remotely (true)"
        );
        assert_eq!(Trigger::RemoteShell.describe(), "runs a remote login shell");
        assert_eq!(
            Trigger::Remote("-N".into()).describe(),
            "may run a command string remotely (-N)"
        );
        assert_eq!(
            Trigger::Unparsed("--frobnicate".into()).describe(),
            "not parsed; may run a command string (--frobnicate)"
        );
        assert_eq!(
            Trigger::Option("-e".into()).describe(),
            "runs a command string remotely or through a shell (-e)"
        );
    }

    #[test]
    fn scan_is_total() {
        const TOKENS: &[&str] = &[
            "-",
            "--",
            "-e",
            "-o",
            "-O",
            "-S",
            "-c",
            "-C",
            "-x",
            "-u",
            "h",
            "ext::",
            "::",
            "://",
            "a::b",
            "=",
            "-oX",
            " ProxyCommand=x",
            "\"",
            "--rsh",
            "--old-args",
            "--daemon",
            "--template=",
            "--x=",
            "run",
            "foreach",
            "clone",
            "rebase",
            "grep",
            "remote-ext",
            "-p",
            "é",
            "-é",
            "é::",
        ];
        let mut rng = crate::prop::Rng::new(0x91_0001);
        for _ in 0..5000 {
            let n = rng.below(8);
            let args: Vec<String> = (0..n)
                .map(|_| TOKENS[rng.below(TOKENS.len())].to_string())
                .collect();
            for p in [
                Prog::Ssh,
                Prog::Scp,
                Prog::Sftp,
                Prog::Rsync,
                Prog::Git,
                Prog::GitDashed,
            ] {
                let _ = scan(p, &args);
            }
        }
    }
}
