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
//! transparent. `ssh` always runs something remotely, so it is always flagged.
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
    /// `ssh` whose options could not be parsed, or that may run no command
    /// (`-N`, `-O`, `-G`, `-V`): still flagged.
    Remote,
    /// Any other program: the option or word that carries the string.
    Option(String),
}

impl Trigger {
    /// The text shown after `opaque — ` at the prompt and in the `no_shell`
    /// rejection.
    pub fn describe(&self) -> String {
        match self {
            Trigger::RemoteCommand(w) => format!("runs a command string remotely ({w})"),
            Trigger::RemoteShell => "runs a remote login shell".into(),
            Trigger::Remote => "runs a command string remotely".into(),
            Trigger::Option(t) => {
                format!("runs a command string remotely or through a shell ({t})")
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
        Prog::Sftp => scp_sftp(true, args).map(Trigger::Option),
        Prog::Rsync => rsync(args).map(Trigger::Option),
        Prog::Git => git(args).map(Trigger::Option),
    }
}

/// The first letter of `triggers` in a short-option cluster (`-avze`), or
/// `None`. The scan stops at a letter in `stops` (it takes an argument, which
/// may be attached) and at any non-alphanumeric character. A `--long` word
/// or a non-option word is not a cluster.
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
    let mut maybe_none = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            if !dest {
                if i >= args.len() {
                    return Trigger::Remote;
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
            if NO_COMMAND.contains(c) {
                maybe_none = true;
            }
            if NOARG.contains(c) {
                continue;
            }
            if ARG.contains(c) {
                if rest[k + c.len_utf8()..].is_empty() {
                    if i + 1 >= args.len() {
                        return Trigger::Remote;
                    }
                    consumed_next = true;
                }
                break;
            }
            return Trigger::Remote;
        }
        i += if consumed_next { 2 } else { 1 };
    }
    if !dest || maybe_none {
        Trigger::Remote
    } else if let Some(w) = args.get(i) {
        Trigger::RemoteCommand(clip(w))
    } else {
        Trigger::RemoteShell
    }
}

/// `scp` / `sftp`: `-S program`, `-D server`, a `-F` config file (it can set
/// `ProxyCommand`), an `-o` whose key ends in `command`, and for `sftp` the
/// `-s` subsystem or server program. Options are permuted with operands, so
/// every word up to a `--` is scanned.
fn scp_sftp(sftp: bool, args: &[String]) -> Option<String> {
    let (triggers, stops) = if sftp {
        ("SDFso", "BbciJlPR")
    } else {
        ("SDFo", "ciJlPX")
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
        let key = value
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if key.to_ascii_lowercase().ends_with("command") {
            return Some(format!("-o {}", clip(key)));
        }
    }
    None
}

/// `rsync`: `-e` / `--rsh` (the remote shell program), `--rsync-path` (a
/// command run by the remote shell) and `-M` / `--remote-option` (options for
/// the remote rsync, which can set those). Abbreviated long names fail closed.
fn rsync(args: &[String]) -> Option<String> {
    const LONG: &[&str] = &["rsh", "rsync-path", "remote-option"];
    for a in args {
        if a == "--" {
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let name = body.split('=').next().unwrap_or("");
            if LONG
                .iter()
                .any(|l| *l == name || (name.len() >= 3 && l.starts_with(name)))
            {
                return Some(format!("--{}", clip(name)));
            }
            continue;
        }
        if let Some(c) = cluster_hit(a, "eM", "BfT@") {
            return Some(format!("-{c}"));
        }
    }
    None
}

/// `git`: config set on the command line (`-c`, `--config-env`; many keys run
/// a command, as `GIT_CONFIG*` in the environment does), `--exec-path`, any
/// unknown global option, an `ext::` remote, the transport program options
/// (`--upload-pack`, `--receive-pack`, `--exec`), and the subcommands that
/// run a command string.
fn git(args: &[String]) -> Option<String> {
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
            // `-c`, `--config-env`, `--exec-path`, or a global option this
            // table does not list.
            let name = a.split_once('=').map_or(a.as_str(), |(n, _)| n);
            return Some(clip(name));
        }
    }
    let words = args.get(i..).unwrap_or(&[]);
    if words.iter().any(|w| w.starts_with("ext::")) {
        return Some("ext::".into());
    }
    let (sub, rest) = words.split_first()?;
    let opts = rest.iter().take_while(|w| *w != "--");
    for w in opts.clone() {
        let name = w.split_once('=').map_or(w.as_str(), |(n, _)| n);
        if matches!(name, "--upload-pack" | "--receive-pack" | "--exec") {
            return Some(name.into());
        }
    }
    let hit = |triggers: &str, stops: &str, long: &[&str]| -> Option<String> {
        opts.clone().find_map(|w| {
            let name = w.split_once('=').map_or(w.as_str(), |(n, _)| n);
            if long.contains(&name) {
                return Some(format!("{sub} {name}"));
            }
            cluster_hit(w, triggers, stops).map(|c| format!("{sub} -{c}"))
        })
    };
    match sub.as_str() {
        // `clone -c` writes config before the fetch runs.
        "clone" => hit("uc", "obj", &["--config"]),
        "ls-remote" => hit("u", "o", &[]),
        "rebase" => hit("x", "sXC", &[]),
        "difftool" => hit("x", "t", &["--extcmd"]),
        "submodule" if rest.iter().any(|w| w == "foreach") => Some("submodule foreach".into()),
        "bisect" if rest.iter().any(|w| w == "run") => Some("bisect run".into()),
        "filter-branch" => Some("filter-branch".into()),
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
        assert_eq!(s(&["-N", "h"]), Trigger::Remote);
        assert_eq!(s(&["-O", "check", "h"]), Trigger::Remote);
        assert_eq!(s(&["-Z", "h", "x"]), Trigger::Remote);
        assert_eq!(s(&["-p"]), Trigger::Remote);
        assert_eq!(s(&[]), Trigger::Remote);
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
            (&["a", "h:b", "-o"], "-o"),
        ];
        for (a, t) in flagged {
            assert_eq!(trig(Prog::Scp, a).as_deref(), Some(*t), "scp {a:?}");
        }
        for a in [
            &["a", "h:b"][..],
            &["-r", "-P", "22", "a", "h:b"],
            &["-o", "Port=22", "a", "h:b"],
            &["-i", "key-S", "a", "h:b"],
            &["-l", "100", "a", "h:b"],
            &["-J", "jump", "a", "h:b"],
            &["--", "-S", "h:b"],
        ] {
            assert_eq!(trig(Prog::Scp, a), None, "scp {a:?}");
        }
        assert_eq!(trig(Prog::Sftp, &["-s", "/x", "h"]).as_deref(), Some("-s"));
        assert_eq!(trig(Prog::Sftp, &["-S", "x", "h"]).as_deref(), Some("-S"));
        assert_eq!(trig(Prog::Sftp, &["-b", "batch", "h"]), None);
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
            (&["--rsync-p=x", "a", "h:b"], "--rsync-p"),
            (&["-M", "--x", "a", "h:b"], "-M"),
            (&["--remote-option=--x", "a", "h:b"], "--remote-option"),
            (&["--rem=x", "a", "h:b"], "--rem"),
            (&["a", "h:b", "-e", "x"], "-e"),
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
            (&["--frobnicate", "status"], "--frobnicate"),
            (&["clone", "ext::sh -c x", "d"], "ext::"),
            (&["fetch", "ext::x"], "ext::"),
            (&["fetch", "--upload-pack=x", "o"], "--upload-pack"),
            (&["ls-remote", "--upload-pack", "x", "o"], "--upload-pack"),
            (&["push", "--receive-pack=x", "o"], "--receive-pack"),
            (&["push", "--exec=x", "o"], "--exec"),
            (&["archive", "--exec", "x", "--remote=o", "HEAD"], "--exec"),
            (&["rebase", "--exec", "make", "main"], "--exec"),
            (&["rebase", "-x", "make", "main"], "rebase -x"),
            (&["rebase", "-ix", "make", "main"], "rebase -x"),
            (&["clone", "-u", "x", "o", "d"], "clone -u"),
            (&["clone", "-c", "core.sshCommand=x", "o"], "clone -c"),
            (&["clone", "--config=a=b", "o"], "clone --config"),
            (&["ls-remote", "-u", "x", "o"], "ls-remote -u"),
            (&["difftool", "-x", "x"], "difftool -x"),
            (&["difftool", "--extcmd=x"], "difftool --extcmd"),
            (&["submodule", "foreach", "x"], "submodule foreach"),
            (
                &["submodule", "--quiet", "foreach", "x"],
                "submodule foreach",
            ),
            (&["bisect", "run", "make"], "bisect run"),
            (&["filter-branch", "--tree-filter", "x"], "filter-branch"),
        ];
        for (a, t) in flagged {
            assert_eq!(trig(Prog::Git, a).as_deref(), Some(*t), "git {a:?}");
        }
        for a in [
            &[][..],
            &["status"],
            &["fetch", "origin"],
            &["clone", "https://x/y.git", "d"],
            &["push", "-u", "origin", "main"],
            &["add", "-u"],
            &["commit", "-c", "HEAD"],
            &["grep", "-c", "x"],
            &["-C", "d", "--no-pager", "log", "-p"],
            &["--git-dir=/x/.git", "status"],
            &["rebase", "-i", "main"],
            &["rebase", "-Xours", "main"],
            &["log", "--", "--exec"],
            &["bisect", "start"],
            &["submodule", "update"],
            &["--version"],
        ] {
            assert_eq!(trig(Prog::Git, a), None, "git {a:?}");
        }
    }

    #[test]
    fn describe_texts() {
        assert_eq!(
            Trigger::RemoteCommand("true".into()).describe(),
            "runs a command string remotely (true)"
        );
        assert_eq!(Trigger::RemoteShell.describe(), "runs a remote login shell");
        assert_eq!(Trigger::Remote.describe(), "runs a command string remotely");
        assert_eq!(
            Trigger::Option("-e".into()).describe(),
            "runs a command string remotely or through a shell (-e)"
        );
    }

    #[test]
    fn scan_is_total() {
        const TOKENS: &[&str] = &[
            "-", "--", "-e", "-o", "-S", "-c", "-C", "-x", "-u", "h", "ext::", "=", "-oX", "--rsh",
            "--x=", "run", "foreach", "clone", "rebase", "-p", "é", "-é",
        ];
        let mut rng = crate::prop::Rng::new(0x91_0001);
        for _ in 0..5000 {
            let n = rng.below(8);
            let args: Vec<String> = (0..n)
                .map(|_| TOKENS[rng.below(TOKENS.len())].to_string())
                .collect();
            for p in [Prog::Ssh, Prog::Scp, Prog::Sftp, Prog::Rsync, Prog::Git] {
                let _ = scan(p, &args);
            }
        }
    }
}
