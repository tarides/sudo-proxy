//! Locating the external programs the daemon itself runs (GHSA-gx9w-4f7x-2gcp).
//!
//! A bare `Command::new("sudo")` is looked up on the daemon's own `PATH`,
//! which commonly starts with directories the daemon's user (and so the agent
//! it gates) can write: `~/.cargo/bin`, `~/.local/bin`, version-manager shims.
//! A `sudo` planted there would run on the next approved privileged request,
//! holding the terminal and sudo's cached credential, while the prompt showed
//! the approved command.
//!
//! So helpers are never looked up on the daemon's `PATH`. They are searched on
//! the fixed [`HELPER_PATH`] and a candidate is accepted only if no principal
//! other than root could have put it there: the file and every directory
//! leading to it, both as found and after resolving symlinks, are owned by
//! root and not group/world-writable. For `sudo` and `pkexec`, which cannot
//! work otherwise, the file must also be setuid. A same-UID, non-root process
//! cannot produce such a file.
//!
//! `--sudo-path` (CLI only) overrides the `sudo` lookup for layouts the
//! search does not cover, and for test stand-ins; it is not trust-checked and
//! the daemon says so at startup.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Directories searched for helpers, in order. `/run/wrappers/bin` holds the
/// setuid wrappers on NixOS (its `sudo` is not elsewhere on this list); the
/// rest is [`crate::executor`]'s default login PATH. Kept separate from that
/// constant on purpose: that one is the *child's* PATH, this one decides which
/// file the daemon runs as an escalator.
pub const HELPER_PATH: &str =
    "/run/wrappers/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

static SUDO_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
static SUDO: OnceLock<Result<PathBuf, String>> = OnceLock::new();
static PKEXEC: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Use `path` as `sudo` instead of searching for it (`--sudo-path`). Must be
/// called before the first [`sudo`]; validates only that `path` is an
/// absolute path to an executable regular file.
pub fn set_sudo_override(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "--sudo-path {}: not an absolute path",
            path.display()
        ));
    }
    let meta =
        std::fs::metadata(path).map_err(|e| format!("--sudo-path {}: {e}", path.display()))?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 {
        return Err(format!(
            "--sudo-path {}: not an executable file",
            path.display()
        ));
    }
    SUDO_OVERRIDE
        .set(path.to_path_buf())
        .map_err(|_| "--sudo-path given twice".to_string())
}

/// The `sudo` the daemon runs: the `--sudo-path` override, else the first
/// trusted `sudo` on [`HELPER_PATH`]. Resolved once.
pub fn sudo() -> Result<&'static Path, String> {
    SUDO.get_or_init(|| match SUDO_OVERRIDE.get() {
        Some(p) => Ok(p.clone()),
        None => find_trusted("sudo", true, HELPER_PATH),
    })
    .as_deref()
    .map_err(Clone::clone)
}

/// The `pkexec` the daemon runs: the first trusted `pkexec` on
/// [`HELPER_PATH`]. Resolved once.
pub fn pkexec() -> Result<&'static Path, String> {
    PKEXEC
        .get_or_init(|| find_trusted("pkexec", true, HELPER_PATH))
        .as_deref()
        .map_err(Clone::clone)
}

/// First `name` in the `:`-separated `search` list that passes
/// [`check_trusted`]. Untrusted candidates are skipped (a planted file must
/// not hide the real one) and listed in the error if none is accepted.
pub fn find_trusted(name: &str, setuid: bool, search: &str) -> Result<PathBuf, String> {
    let mut rejected = Vec::new();
    for dir in search.split(':').filter(|d| d.starts_with('/')) {
        let candidate = Path::new(dir).join(name);
        if std::fs::symlink_metadata(&candidate).is_err() {
            continue;
        }
        match check_trusted(&candidate, setuid) {
            Ok(()) => return Ok(candidate),
            Err(why) => rejected.push(why),
        }
    }
    if rejected.is_empty() {
        Err(format!("no `{name}` found in {search}"))
    } else {
        Err(format!(
            "no trusted `{name}` found ({})",
            rejected.join("; ")
        ))
    }
}

/// Whether `path` could only have been put in place by root: it resolves to a
/// root-owned regular executable file that is not group/world-writable (and,
/// with `setuid`, has the setuid bit), and every directory above it, as
/// spelled and as resolved, is root-owned and not group/world-writable.
pub fn check_trusted(path: &Path, setuid: bool) -> Result<(), String> {
    let shown = path.display();
    let real = std::fs::canonicalize(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = std::fs::metadata(&real).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown}: not a regular file"));
    }
    if meta.uid() != 0 {
        return Err(format!("{shown}: owned by uid {}, not root", meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{shown}: mode {:04o} is group/world-writable",
            meta.mode() & 0o7777
        ));
    }
    if meta.mode() & 0o111 == 0 {
        return Err(format!("{shown}: not executable"));
    }
    if setuid && meta.mode() & 0o4000 == 0 {
        return Err(format!("{shown}: not setuid"));
    }
    if writable_by_me(&real) {
        return Err(format!("{shown}: writable by this user (ACL?)"));
    }
    for start in [path, real.as_path()] {
        for dir in start
            .ancestors()
            .skip(1)
            .filter(|d| !d.as_os_str().is_empty())
        {
            let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if m.uid() != 0 {
                return Err(format!(
                    "{shown}: directory {} owned by uid {}, not root",
                    dir.display(),
                    m.uid()
                ));
            }
            if m.mode() & 0o022 != 0 {
                return Err(format!(
                    "{shown}: directory {} mode {:04o} is group/world-writable",
                    dir.display(),
                    m.mode() & 0o7777
                ));
            }
            if writable_by_me(dir) {
                return Err(format!(
                    "{shown}: directory {} writable by this user (ACL?)",
                    dir.display()
                ));
            }
        }
    }
    Ok(())
}

/// Whether the daemon's effective uid may write `path`, by the kernel's own
/// answer, so a POSIX ACL granting this user write access is seen even when
/// the mode bits look safe. Root may write anything, and owns these files
/// anyway, so the check is skipped there.
fn writable_by_me(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn running_as_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn user_owned_file_is_rejected() {
        if running_as_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let p = fake(d.path(), "sudo");
        let err = check_trusted(&p, false).unwrap_err();
        assert!(err.contains("not root"), "{err}");
    }

    #[test]
    fn missing_everywhere_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let err = find_trusted("sudo", true, d.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("no `sudo` found"), "{err}");
    }

    #[test]
    fn relative_search_entries_are_ignored() {
        let err = find_trusted("sudo", true, ".:bin:").unwrap_err();
        assert!(err.contains("no `sudo` found"), "{err}");
    }

    /// The advisory's scenario: a `sudo` planted in a user-writable directory
    /// ahead of the real one is skipped, and the real one is found. Needs a
    /// real setuid-root `sudo` on the host; skipped otherwise.
    #[test]
    fn planted_sudo_ahead_of_real_one_is_skipped() {
        if running_as_root() {
            return;
        }
        let Ok(real) = find_trusted("sudo", true, HELPER_PATH) else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        fake(d.path(), "sudo");
        let search = format!("{}:{HELPER_PATH}", d.path().display());
        assert_eq!(find_trusted("sudo", true, &search).unwrap(), real);
        // And with nothing trusted after it, the plant is refused, not used.
        let err = find_trusted("sudo", true, d.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("no trusted `sudo`"), "{err}");
    }

    #[test]
    fn root_owned_non_setuid_file_fails_setuid_check() {
        // /bin/sh is root-owned and not setuid on every supported host.
        let Ok(sh) = find_trusted("sh", false, HELPER_PATH) else {
            return;
        };
        let err = check_trusted(&sh, true).unwrap_err();
        assert!(err.contains("not setuid"), "{err}");
    }

    #[test]
    fn helpers_resolve_to_absolute_paths() {
        if let Ok(p) = find_trusted("sudo", true, HELPER_PATH) {
            assert!(p.is_absolute());
        }
    }
}
