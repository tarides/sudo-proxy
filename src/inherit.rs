//! `--inherit-path` and `--inherit-env=PATTERN,…` (issue #101).
//!
//! A daemon started by hand inside a dev shell (direnv, Nix) can hand that
//! shell's `PATH`, and the variables it names, to requests that have **no
//! escalated step**. A request any of whose steps runs as root or as another
//! user is handled exactly as without the flags, all of its steps included.
//!
//! Everything here is decided once, at startup, from the daemon's own
//! environment; no request field, `hosts.json` key or environment variable
//! turns it on, and neither `--host` nor `sudo-proxy-mcp` forwards it.
//!
//! The inherited layer is applied only where a step runs as the daemon's own
//! user (the executor's `Direct` arm), never in the shared request
//! environment, so it cannot reach `sudo`'s command line or a root step.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Which flag turned inheritance on (`--inherit-env` implies `--inherit-path`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InheritMode {
    /// `--inherit-path`: only `PATH`.
    Path,
    /// `--inherit-env=…`: `PATH` and the variables the patterns match.
    Env,
}

impl InheritMode {
    /// The flag's name, as the prompt's `Env:` line shows it.
    pub fn flag(self) -> &'static str {
        match self {
            InheritMode::Path => "--inherit-path",
            InheritMode::Env => "--inherit-env",
        }
    }
}

/// One element of `--inherit-env`'s list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// `NAME`: that variable, even one a wildcard never matches.
    Exact(String),
    /// `PREFIX*`: every name starting with `PREFIX`, except the excluded ones.
    Prefix(String),
    /// `*`: every name, except the excluded ones.
    All,
}

impl Pattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Pattern::Exact(n) => n == name,
            Pattern::Prefix(p) => name.starts_with(p.as_str()) && !wildcard_excluded(name),
            Pattern::All => !wildcard_excluded(name),
        }
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Exact(n) => write!(f, "{n}"),
            Pattern::Prefix(p) => write!(f, "{p}*"),
            Pattern::All => write!(f, "*"),
        }
    }
}

/// Terminal and display variables. Today's env-cleared children don't get
/// them, and a wildcard does not change that: they are inherited only when
/// named exactly.
pub const TERMINAL: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// Whether a wildcard (`PREFIX*` or `*`) skips `name`: a code-loading
/// variable, a terminal or display variable, or `SSH_AUTH_SOCK`.
pub fn wildcard_excluded(name: &str) -> bool {
    crate::wrappers::is_code_loading(name)
        || TERMINAL.contains(&name)
        || crate::ttyguard::INHERITED_TERMINAL_VARS.contains(&name)
        || name == "SSH_AUTH_SOCK"
}

/// A shell variable name: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_name(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c == b'_' || c.is_ascii_alphabetic())
        && b.all(|c| c == b'_' || c.is_ascii_alphanumeric())
}

/// Parse `--inherit-env`'s value: a comma-separated list of patterns.
pub fn parse_patterns(value: &str) -> Result<Vec<Pattern>, String> {
    if value.is_empty() {
        return Err("--inherit-env needs a value (NAME, PREFIX* or *)".into());
    }
    value
        .split(',')
        .map(|p| {
            if p.is_empty() {
                return Err(format!("--inherit-env: empty element in {value:?}"));
            }
            if p == "*" {
                return Ok(Pattern::All);
            }
            let (name, prefix) = match p.strip_suffix('*') {
                Some(n) => (n, true),
                None => (p, false),
            };
            if !is_valid_name(name) {
                return Err(format!(
                    "--inherit-env: {p:?} is not a variable name, NAME* or * \
                     (a `*` is allowed only at the end)"
                ));
            }
            if !prefix && name == "SSH_AUTH_SOCK" {
                return Err("--inherit-env: SSH_AUTH_SOCK is never inherited; \
                            use forward_agent instead"
                    .into());
            }
            Ok(if prefix {
                Pattern::Prefix(name.to_string())
            } else {
                Pattern::Exact(name.to_string())
            })
        })
        .collect()
}

/// One `PATH` entry, as checked at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEntry {
    pub dir: String,
    /// The entry does not exist yet (`.venv/bin` before `uv sync`); its
    /// nearest existing directory was checked instead.
    pub missing: bool,
}

/// The environment a daemon started with `--inherit-path` or
/// `--inherit-env` hands to requests with no escalated step. Built once at
/// startup ([`Inherited::from_env`]) and immutable thereafter.
#[derive(Clone, Debug)]
pub struct Inherited {
    pub mode: InheritMode,
    pub patterns: Vec<Pattern>,
    /// The daemon's `PATH`, checked ([`check_path`]).
    pub path: String,
    pub path_entries: Vec<PathEntry>,
    /// The matched variables, `PATH` excluded.
    pub vars: BTreeMap<String, String>,
    /// The code-loading names among `vars` (each named exactly).
    pub code_loading: Vec<String>,
    /// Environment entries never inherited whatever the patterns: names that
    /// are not variable names (`BASH_FUNC_x%%`) or not UTF-8, and values that
    /// are not UTF-8. Escaped for display.
    pub skipped: Vec<String>,
}

impl Inherited {
    /// Build the inherited layer from `env` (the daemon's environment), for
    /// the daemon user `uid`. Fails if `PATH` does not pass [`check_path`].
    pub fn from_env(
        mode: InheritMode,
        patterns: Vec<Pattern>,
        env: impl IntoIterator<Item = (OsString, OsString)>,
        uid: u32,
    ) -> Result<Inherited, String> {
        let env: Vec<(OsString, OsString)> = env.into_iter().collect();
        let path = match env.iter().find(|(k, _)| k == "PATH") {
            None => return Err("PATH is unset".into()),
            Some((_, v)) => v
                .to_str()
                .ok_or_else(|| "PATH is not valid UTF-8".to_string())?
                .to_string(),
        };
        let path_entries = check_path(&path, uid)?;
        let mut vars = BTreeMap::new();
        let mut code_loading = Vec::new();
        let mut skipped = Vec::new();
        if mode == InheritMode::Env {
            for (k, v) in &env {
                let shown = || crate::protocol::escape_dangerous(&k.to_string_lossy());
                let Some(name) = k.to_str() else {
                    skipped.push(format!("{} (name not UTF-8)", shown()));
                    continue;
                };
                if name == "PATH" {
                    continue;
                }
                if !is_valid_name(name) {
                    skipped.push(format!("{} (not a variable name)", shown()));
                    continue;
                }
                if !patterns.iter().any(|p| p.matches(name)) {
                    continue;
                }
                let Some(value) = v.to_str() else {
                    skipped.push(format!("{name} (value not UTF-8)"));
                    continue;
                };
                if crate::wrappers::is_code_loading(name) {
                    code_loading.push(name.to_string());
                }
                vars.insert(name.to_string(), value.to_string());
            }
        }
        code_loading.sort();
        skipped.sort();
        Ok(Inherited {
            mode,
            patterns,
            path,
            path_entries,
            vars,
            code_loading,
            skipped,
        })
    }

    /// Whether `name` is part of the inherited layer (`PATH` included).
    pub fn has(&self, name: &str) -> bool {
        name == "PATH" || self.vars.contains_key(name)
    }

    /// A short fingerprint of the inherited names and the `PATH` entries.
    /// Goes to the terminal and to the audit startup record.
    pub fn names_fingerprint(&self) -> String {
        let mut h = Sha256::new();
        feed(&mut h, &self.path);
        for k in self.vars.keys() {
            feed(&mut h, k);
        }
        short(h)
    }

    /// A short fingerprint of the inherited names *and values* (and `PATH`).
    /// Shown on the daemon's terminal only, never in the audit record: the
    /// audit log also goes to syslog, and a short hash of a low-entropy
    /// secret can be brute-forced offline.
    pub fn values_fingerprint(&self) -> String {
        let mut h = Sha256::new();
        feed(&mut h, &self.path);
        for (k, v) in &self.vars {
            feed(&mut h, k);
            feed(&mut h, v);
        }
        short(h)
    }

    /// The startup report printed to the daemon's terminal: the patterns,
    /// each `PATH` entry (marked user-writable or missing), the inherited
    /// names without their values (code-loading ones flagged), the skipped
    /// entries, and both fingerprints. Everything filesystem- or
    /// environment-derived is escaped.
    pub fn report(&self) -> String {
        use std::fmt::Write;
        let esc = crate::protocol::escape_dangerous;
        let mut out = String::new();
        let flag = self.mode.flag();
        let _ = writeln!(out, "sudo-proxy: {flag}: requests with no escalated step run with:");
        if self.mode == InheritMode::Env {
            let pats: Vec<String> = self.patterns.iter().map(ToString::to_string).collect();
            let _ = writeln!(out, "  patterns: {}", pats.join(","));
        }
        let _ = writeln!(out, "  PATH, in order:");
        for e in &self.path_entries {
            let mut tags = Vec::new();
            if e.missing {
                tags.push("missing");
            } else if dir_writable_by_me(Path::new(&e.dir)) {
                tags.push("user-writable");
            }
            let tags = if tags.is_empty() { String::new() } else { format!(" ({})", tags.join(", ")) };
            let _ = writeln!(out, "    {}{tags}", esc(&e.dir));
        }
        if self.mode == InheritMode::Env {
            if self.vars.is_empty() {
                let _ = writeln!(out, "  variables: none matched");
            } else {
                let names: Vec<String> = self
                    .vars
                    .keys()
                    .map(|k| if self.code_loading.contains(k) { format!("{k} (code-loading)") } else { k.clone() })
                    .collect();
                let _ = writeln!(out, "  variables: {}", names.join(" "));
            }
            if !self.skipped.is_empty() {
                let _ = writeln!(out, "  skipped: {}", self.skipped.join(" "));
            }
        }
        let _ = writeln!(
            out,
            "  fingerprint: names+PATH {}, names+values {} (compare with the last start)",
            self.names_fingerprint(),
            self.values_fingerprint()
        );
        out
    }
}

/// Hash one field, length-prefixed so field boundaries cannot shift.
fn feed(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

/// The first 12 hex digits of the digest.
fn short(h: Sha256) -> String {
    h.finalize().iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Whether the daemon's effective uid may write `dir` (ACLs count).
fn dir_writable_by_me(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

/// Check the daemon's `PATH` for `--inherit-path`, returning its entries.
///
/// Refused: an empty `PATH`; an empty entry (`::`, or a leading or trailing
/// `:`, which mean the current directory) or a relative one; an entry with a
/// character the prompt would reject; an entry any directory of which, up to
/// `/`, is owned by neither root nor `uid`, or is writable by group or others.
/// Two exceptions to the last rule: a root-owned sticky directory
/// (`/nix/store`, where others can add entries but cannot rename or remove
/// existing ones), and a directory owned by `uid` whose group is the daemon
/// user's private group ([`user_private_gid`]). An entry that does not exist
/// yet is checked at its nearest existing directory and reported missing.
///
/// Looser than the helper rules on purpose: a dev shell's `PATH` is made of
/// directories the daemon's user owns, and these entries only govern steps
/// that run as that user anyway. Escalators keep the root-only rules.
pub fn check_path(path: &str, uid: u32) -> Result<Vec<PathEntry>, String> {
    if path.is_empty() {
        return Err("PATH is empty".into());
    }
    let private_gid = user_private_gid(uid);
    path.split(':')
        .map(|dir| {
            if dir.is_empty() {
                return Err("PATH has an empty entry (`::`, or a leading or trailing `:`), \
                            which means the current directory"
                    .to_string());
            }
            let shown = crate::protocol::escape_dangerous(dir);
            if crate::protocol::has_dangerous_chars(dir) {
                return Err(format!("PATH entry {shown} contains a character the prompt rejects"));
            }
            if !dir.starts_with('/') {
                return Err(format!("PATH entry {shown} is relative"));
            }
            check_entry(Path::new(dir), uid, private_gid)
                .map(|missing| PathEntry { dir: dir.to_string(), missing })
                .map_err(|e| format!("PATH entry {shown}: {e}"))
        })
        .collect()
}

/// Check one absolute `PATH` entry; `Ok(true)` if it does not exist yet.
fn check_entry(dir: &Path, uid: u32, private_gid: Option<u32>) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;

    // Every symlink on the path as spelled must be owned by root or the
    // daemon's user, or someone else could repoint it after this check.
    for comp in dir.ancestors() {
        if let Ok(l) = std::fs::symlink_metadata(comp) {
            if l.file_type().is_symlink() && l.uid() != 0 && l.uid() != uid {
                return Err(format!(
                    "symlink {} is owned by uid {}, expected {uid} or root",
                    comp.display(),
                    l.uid()
                ));
            }
        }
    }
    let mut existing = dir;
    let mut missing = false;
    let meta = loop {
        match std::fs::metadata(existing) {
            Ok(m) => break m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing = true;
                existing = existing
                    .parent()
                    .ok_or_else(|| "no existing directory above it".to_string())?;
            }
            Err(e) => return Err(format!("{}: {e}", existing.display())),
        }
    };
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", existing.display()));
    }
    // The directory programs are found in (or, for a missing entry, the one
    // it would be created in) gets no sticky exception: a sticky bit stops
    // others renaming entries that exist, not adding new ones, and a new
    // program there is exactly what a lookup would find. The exception holds
    // only for the directories above it, as with `/nix/store/<hash>/bin`.
    if meta.mode() & 0o1000 != 0 && meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: directory mode {:04o} lets others add programs (sticky does not prevent that)",
            existing.display(),
            meta.mode() & 0o7777
        ));
    }
    let real = std::fs::canonicalize(existing).map_err(|e| format!("{}: {e}", existing.display()))?;
    crate::hosts::check_dir_chain(&real, uid, None, private_gid)?;
    Ok(missing)
}

/// The daemon user's private group: the primary group of `uid`, if it has
/// the user's own name (the user-private-group convention) and no other user
/// belongs to it, either as a listed member or as their own primary group.
/// The name test does not rely on enumeration: `getpwent` lists only local
/// accounts under sssd/LDAP, where a shared primary group such as `users`
/// would otherwise look private. Its group write bit then grants no one else anything, so a
/// directory owned by `uid` with that group (mode 775, the usual default on
/// distributions with user private groups) is as safe as a 755 one.
pub fn user_private_gid(uid: u32) -> Option<u32> {
    // SAFETY: getpwuid/getgrgid/getpwent return pointers into static storage,
    // read before the next call. Called once, at startup, before any thread
    // that could call them is spawned.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let gid = (*pw).pw_gid;
        let name = std::ffi::CStr::from_ptr((*pw).pw_name).to_owned();
        let gr = libc::getgrgid(gid);
        if gr.is_null() || std::ffi::CStr::from_ptr((*gr).gr_name) != name.as_c_str() {
            return None;
        }
        let mut mem = (*gr).gr_mem;
        while !mem.is_null() && !(*mem).is_null() {
            if std::ffi::CStr::from_ptr(*mem) != name.as_c_str() {
                return None;
            }
            mem = mem.add(1);
        }
        let mut shared = false;
        libc::setpwent();
        loop {
            let p = libc::getpwent();
            if p.is_null() {
                break;
            }
            if (*p).pw_gid == gid && (*p).pw_uid != uid {
                shared = true;
                break;
            }
        }
        libc::endpwent();
        (!shared).then_some(gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect()
    }

    #[test]
    fn patterns_parse() {
        assert_eq!(
            parse_patterns("REPO_ROOT,TF_VAR_*,*").unwrap(),
            vec![
                Pattern::Exact("REPO_ROOT".into()),
                Pattern::Prefix("TF_VAR_".into()),
                Pattern::All
            ]
        );
        for bad in ["", "A,,B", ",A", "A,", "*A", "A*B", "A**", "1A", "A-B", "A B", "SSH_AUTH_SOCK"] {
            assert!(parse_patterns(bad).is_err(), "{bad:?} must be refused");
        }
        // A prefix that happens to cover SSH_AUTH_SOCK is fine: wildcards skip it.
        assert!(parse_patterns("SSH_*").is_ok());
    }

    #[test]
    fn wildcards_skip_excluded_names_and_exact_names_reach_them() {
        let all = Pattern::All;
        let ld = Pattern::Prefix("LD_".into());
        for name in ["LD_PRELOAD", "PYTHONPATH", "DISPLAY", "TMUX", "SSH_AUTH_SOCK", "DYLD_X", "BASH_ENV"] {
            assert!(!all.matches(name), "{name}");
        }
        assert!(!ld.matches("LD_PRELOAD"));
        assert!(all.matches("REPO_ROOT"));
        assert!(Pattern::Exact("PYTHONPATH".into()).matches("PYTHONPATH"));
        assert!(Pattern::Exact("DISPLAY".into()).matches("DISPLAY"));
    }

    #[test]
    fn from_env_selects_flags_and_skips() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = d.path().display().to_string();
        let mut e = env(&[
            ("PATH", &path),
            ("REPO_ROOT", "/r"),
            ("TF_VAR_x", "1"),
            ("OTHER", "o"),
            ("PYTHONPATH", "/p"),
            ("LD_PRELOAD", "/x.so"),
            ("SSH_AUTH_SOCK", "/s"),
            ("BASH_FUNC_f%%", "() { :; }"),
        ]);
        {
            use std::os::unix::ffi::OsStringExt;
            e.push((OsString::from("TF_VAR_bin"), OsString::from_vec(vec![0xff])));
        }
        let pats = parse_patterns("REPO_ROOT,TF_VAR_*,PYTHONPATH").unwrap();
        let i = Inherited::from_env(InheritMode::Env, pats, e.clone(), uid()).unwrap();
        assert_eq!(i.path, path);
        let names: Vec<&str> = i.vars.keys().map(String::as_str).collect();
        assert_eq!(names, ["PYTHONPATH", "REPO_ROOT", "TF_VAR_x"]);
        assert_eq!(i.code_loading, ["PYTHONPATH"]);
        assert!(i.skipped.iter().any(|s| s.starts_with("BASH_FUNC_f%%")), "{:?}", i.skipped);
        assert!(i.skipped.iter().any(|s| s.starts_with("TF_VAR_bin")), "{:?}", i.skipped);

        let star = Inherited::from_env(InheritMode::Env, vec![Pattern::All], e.clone(), uid()).unwrap();
        assert!(star.vars.contains_key("OTHER"));
        for n in ["PYTHONPATH", "LD_PRELOAD", "SSH_AUTH_SOCK", "PATH"] {
            assert!(!star.vars.contains_key(n), "{n}");
        }

        let p = Inherited::from_env(InheritMode::Path, vec![], e, uid()).unwrap();
        assert!(p.vars.is_empty() && p.skipped.is_empty());
    }

    #[test]
    fn fingerprints_track_names_and_values_separately() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = d.path().display().to_string();
        let build = |v: &str| {
            let e = env(&[("PATH", &path), ("A", v), ("SECRET", "s")]);
            Inherited::from_env(InheritMode::Env, parse_patterns("A,SECRET").unwrap(), e, uid()).unwrap()
        };
        let (one, two) = (build("1"), build("2"));
        assert_eq!(one.names_fingerprint(), two.names_fingerprint());
        assert_ne!(one.values_fingerprint(), two.values_fingerprint());
        assert_eq!(one.names_fingerprint().len(), 12);
        let r = one.report();
        assert!(r.contains("variables: A SECRET"), "{r}");
        assert!(!r.contains("=1") && !r.contains("=s"), "values never shown: {r}");
        assert!(r.contains(&one.names_fingerprint()) && r.contains(&one.values_fingerprint()), "{r}");
    }

    #[test]
    fn path_must_be_set_and_utf8() {
        assert!(Inherited::from_env(InheritMode::Path, vec![], env(&[]), uid()).is_err());
        use std::os::unix::ffi::OsStringExt;
        let bad = vec![(OsString::from("PATH"), OsString::from_vec(vec![b'/', 0xff]))];
        assert!(Inherited::from_env(InheritMode::Path, vec![], bad, uid()).is_err());
    }

    #[test]
    fn path_entries_are_checked() {
        let me = uid();
        if me == 0 {
            return; // every directory is root's: the owner rules pass trivially
        }
        let d = tempfile::tempdir().unwrap();
        let ok = d.path().join("ok");
        std::fs::create_dir(&ok).unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let okp = ok.display().to_string();

        assert_eq!(check_path(&okp, me).unwrap(), vec![PathEntry { dir: okp.clone(), missing: false }]);
        assert!(check_path("/usr/bin", me).is_ok());
        for bad in ["", ":/usr/bin", "/usr/bin:", "/usr/bin::/bin", ".", "bin", "/usr/bin:."] {
            assert!(check_path(bad, me).is_err(), "{bad:?} must be refused");
        }
        assert!(check_path("/usr/\u{1b}[2Jbin", me).is_err());

        // Missing entry: its nearest existing directory is checked.
        let venv = format!("{okp}/.venv/bin");
        assert_eq!(check_path(&venv, me).unwrap(), vec![PathEntry { dir: venv.clone(), missing: true }]);

        // World-writable (not sticky) is refused, with or without a private group.
        let ww = d.path().join("ww");
        std::fs::create_dir(&ww).unwrap();
        std::fs::set_permissions(&ww, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_path(&ww.display().to_string(), me).is_err());

        // Group-writable: accepted only for the daemon user's private group.
        let gw = d.path().join("gw");
        std::fs::create_dir(&gw).unwrap();
        std::fs::set_permissions(&gw, std::fs::Permissions::from_mode(0o775)).unwrap();
        let gw_ok = check_path(&gw.display().to_string(), me).is_ok();
        use std::os::unix::fs::MetadataExt;
        let gid = std::fs::metadata(&gw).unwrap().gid();
        assert_eq!(gw_ok, user_private_gid(me) == Some(gid), "group {gid}");

        // A symlink in the spelled path owned by the user is fine.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&ok, &link).unwrap();
        assert!(check_path(&link.display().to_string(), me).is_ok());
    }

    #[test]
    fn root_sticky_directory_passes_above_the_entry_only() {
        // /tmp is root-owned and sticky (1777) on any normal host.
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata("/tmp").unwrap();
        if m.uid() != 0 || m.mode() & 0o1000 == 0 || m.mode() & 0o002 == 0 {
            return;
        }
        // As an ancestor: others cannot replace what is below it.
        let d = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_path(&d.path().display().to_string(), uid()).is_ok());
        // As the entry, or as where a missing entry would be created: anyone
        // can add a program there.
        let err = check_path("/tmp", uid()).unwrap_err();
        assert!(err.contains("lets others add programs"), "{err}");
        let missing = format!("/tmp/sp-missing-{}/bin", uuid::Uuid::new_v4());
        let err = check_path(&missing, uid()).unwrap_err();
        assert!(err.contains("lets others add programs"), "{err}");
    }
}
