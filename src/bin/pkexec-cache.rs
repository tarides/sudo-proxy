use std::fs;
use std::path::Path;
use std::process;

const RULES_PATH: &str = "/etc/polkit-1/rules.d/50-pkexec-cache.rules";

/// Longest login name accepted (the usual `useradd` limit).
const MAX_USERNAME_LEN: usize = 32;

/// Accept only the conventional login-name charset, `^[a-z_][a-z0-9_-]*\$?$`.
///
/// The name ends up inside polkit JavaScript, so anything outside this set
/// (quotes, backslashes, whitespace, control characters) is refused outright
/// rather than escaped.
fn validate_username(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= MAX_USERNAME_LEN
        && matches!(bytes[0], b'a'..=b'z' | b'_')
        && {
            // An optional trailing '$' (machine accounts).
            let body = bytes.strip_suffix(b"$").unwrap_or(bytes);
            body[1..]
                .iter()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
        };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid username {name:?}: expected 1-{MAX_USERNAME_LEN} characters matching ^[a-z_][a-z0-9_-]*\\$?$"
        ))
    }
}

/// Validate `name`, then look it up in the passwd database. Refuse names
/// that do not exist or that map to uid 0. Returns the database's spelling.
fn resolve_user(name: &str) -> Result<String, String> {
    validate_username(name)?;
    let c_name = std::ffi::CString::new(name).map_err(|_| format!("invalid username {name:?}"))?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    // POSIX says "not found" is rc == 0 with a null result, but glibc may
    // also report it as one of these errnos (see getpwnam(3)).
    let not_found = matches!(rc, libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM);
    if rc != 0 && !not_found {
        return Err(format!(
            "cannot look up user {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        ));
    }
    if not_found || result.is_null() {
        return Err(format!("user {name:?} does not exist"));
    }
    if pwd.pw_uid == 0 {
        return Err(format!(
            "user {name:?} has uid 0; refusing to cache root's pkexec"
        ));
    }
    let canonical = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .map_err(|_| format!("user {name:?} has a non-UTF-8 passwd entry"))?
        .to_string();
    validate_username(&canonical)?;
    Ok(canonical)
}

/// The rule file for `username`. The name is validated here, not just by
/// the callers, because it also appears in a `//` comment where a newline
/// would end the comment. In the condition it is emitted as a JSON string
/// literal (also a valid JavaScript one) as a second line of defence; for
/// a valid name this is the same bytes as the plain `"name"` older
/// versions wrote, so existing rules still check as installed.
fn expected_content(username: &str) -> Result<String, String> {
    validate_username(username)?;
    let username_lit = serde_json::to_string(username).expect("serialising a &str cannot fail");
    Ok(format!(
        r#"// Managed by pkexec-cache. Do not edit manually.
// Caches pkexec authentication for ~5 minutes (like sudo).
// Applies to ALL pkexec calls from {username} in an active local session.
polkit.addRule(function(action, subject) {{
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.user == {username_lit} &&
        subject.active == true &&
        subject.local == true) {{
        return polkit.Result.AUTH_ADMIN_KEEP;
    }}
}});
"#
    ))
}

/// Find the non-root user the rule is for. Every candidate goes through
/// `resolve_user`; a candidate that is set but invalid is an error rather
/// than a silent fall-through to the next source.
fn get_login_username() -> Result<String, String> {
    // SUDO_USER is set when running under sudo, giving us the real user
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return resolve_user(&user).map_err(|e| format!("SUDO_USER: {e}"));
        }
    }
    // PKEXEC_UID is set when running under pkexec — resolve to username
    if let Ok(uid_str) = std::env::var("PKEXEC_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            if uid != 0 {
                let pw = unsafe { libc::getpwuid(uid) };
                if !pw.is_null() {
                    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
                    if let Ok(s) = name.to_str() {
                        validate_username(s).map_err(|e| format!("PKEXEC_UID: {e}"))?;
                        return Ok(s.to_string());
                    }
                }
            }
        }
    }
    // Fallback: LOGNAME or USER
    if let Ok(user) = std::env::var("LOGNAME").or_else(|_| std::env::var("USER")) {
        if !user.is_empty() && user != "root" {
            return resolve_user(&user).map_err(|e| format!("LOGNAME/USER: {e}"));
        }
    }
    Err("could not determine non-root username (run with sudo or pkexec)".to_string())
}

enum Action {
    Check,
    Create,
    Delete,
}

fn main() {
    let action = parse_args();

    match action {
        Action::Check => cmd_check(),
        Action::Create => cmd_create(),
        Action::Delete => cmd_delete(),
    }
}

/// Read the rule file in one step, so nothing can change between an
/// existence check and the read. `Ok(None)` means the rule is absent,
/// `Ok(Some(text))` means it is present, and `Err` means we could not tell
/// (unlike `Path::exists`, which reports every error as "absent").
fn read_rule(path: &Path) -> std::io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(c) => Ok(Some(c)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn cmd_check() {
    let content = match read_rule(Path::new(RULES_PATH)) {
        Ok(Some(c)) => c,
        Ok(None) => {
            println!("not installed: {RULES_PATH} does not exist");
            println!("run with --create to install the rule");
            process::exit(1);
        }
        // e.g. rules.d shipped as root:polkitd 0750: we cannot tell whether
        // the rule is there, so do not claim it is absent (#75).
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("unknown: cannot read {RULES_PATH}: permission denied (run with sudo)");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: cannot read {RULES_PATH}: {e}");
            process::exit(1);
        }
    };

    // Check if it contains our marker
    if !content.contains("Managed by pkexec-cache") {
        println!("unknown: {RULES_PATH} exists but was not created by this tool");
        process::exit(1);
    }

    // Extract the username from the file
    let username = match extract_username(&content) {
        Some(u) => u,
        None => {
            println!("corrupt: {RULES_PATH} exists but username could not be parsed");
            process::exit(1);
        }
    };

    // Verify it matches expected content (this also rejects a name outside
    // the login-name charset)
    let expected = match expected_content(&username) {
        Ok(e) => e,
        Err(e) => {
            println!("corrupt: {RULES_PATH}: {e}");
            process::exit(1);
        }
    };
    if content == expected {
        println!("installed: {RULES_PATH}");
        println!("user: {username}");
        println!("effect: pkexec auth cached ~5 min for active local sessions");
        println!("polkitd monitors rules.d and reloads automatically");
    } else {
        println!("modified: {RULES_PATH} exists but differs from expected content");
        println!("run with --delete then --create to reset");
        process::exit(1);
    }
}

fn cmd_create() {
    check_root();

    let path = Path::new(RULES_PATH);
    if path.exists() {
        eprintln!("error: {RULES_PATH} already exists");
        eprintln!("run with --delete first, or use default mode to check it");
        process::exit(1);
    }

    let username = match get_login_username() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    // Verify parent directory exists
    let parent = path.parent().unwrap();
    if !parent.is_dir() {
        eprintln!(
            "error: {} does not exist (is polkit installed?)",
            parent.display()
        );
        process::exit(1);
    }

    let content = match expected_content(&username) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = fs::write(path, &content) {
        eprintln!("error: cannot write {RULES_PATH}: {e}");
        process::exit(1);
    }

    // Set ownership to root:root, mode 644
    set_permissions(path);

    println!("created: {RULES_PATH}");
    println!("user: {username}");
    println!("effect: pkexec auth cached ~5 min for active local sessions");
    println!("polkitd monitors rules.d and reloads automatically");
}

fn cmd_delete() {
    check_root();

    let path = Path::new(RULES_PATH);
    if !path.exists() {
        println!("already absent: {RULES_PATH}");
        return;
    }

    // Safety: only delete if it's ours
    if let Ok(content) = fs::read_to_string(path) {
        if !content.contains("Managed by pkexec-cache") {
            eprintln!("error: {RULES_PATH} was not created by this tool, refusing to delete");
            process::exit(1);
        }
    }

    if let Err(e) = fs::remove_file(path) {
        eprintln!("error: cannot remove {RULES_PATH}: {e}");
        process::exit(1);
    }

    println!("deleted: {RULES_PATH}");
    println!("polkitd monitors rules.d and reloads automatically");
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: this command must be run as root (use sudo)");
        process::exit(1);
    }
}

fn set_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    // chown root:root
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes().to_vec()).unwrap();
    unsafe {
        libc::chown(c_path.as_ptr(), 0, 0);
    }
}

/// Read back the name from `subject.user == "USERNAME"`, decoding it as the
/// JSON string literal `expected_content` writes.
fn extract_username(content: &str) -> Option<String> {
    let marker = "subject.user == ";
    let start = content.find(marker)? + marker.len();
    let rest = &content[start..];
    if !rest.starts_with('"') {
        return None;
    }
    // Find the closing quote, skipping escaped characters.
    let mut escaped = false;
    let mut end = None;
    for (i, c) in rest.char_indices().skip(1) {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => {
                end = Some(i);
                break;
            }
            _ => {}
        }
    }
    serde_json::from_str(&rest[..=end?]).ok()
}

fn parse_args() -> Action {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        return Action::Check;
    }

    if args.len() != 1 {
        usage();
    }

    match args[0].as_str() {
        "--create" => Action::Create,
        "--delete" => Action::Delete,
        "--version" | "-V" => sudo_proxy::cli::print_version("pkexec-cache"),
        "--help" | "-h" => {
            usage();
        }
        other => {
            eprintln!("unknown option: {other}");
            usage();
        }
    }
}

fn usage() -> ! {
    eprintln!("Usage: pkexec-cache [--create | --delete]");
    eprintln!();
    eprintln!("Manage the polkit rule for pkexec authentication caching.");
    eprintln!();
    eprintln!("Modes:");
    eprintln!("  (default)   Check if the rule is installed and valid");
    eprintln!("  --create    Install the rule (requires root)");
    eprintln!("  --delete    Remove the rule (requires root)");
    eprintln!();
    eprintln!("The rule caches pkexec authentication for ~5 minutes (like sudo).");
    eprintln!("It applies to ALL pkexec calls from your user in active local sessions.");
    eprintln!("polkitd detects rule changes automatically; no restart is needed.");
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The issue #64 payload.
    const INJECTION: &str = r#"x" || true || ""#;

    #[test]
    fn validate_username_accepts_login_names() {
        for name in ["alice", "_svc", "a-b_c", "a1", "machine$", "x"] {
            assert!(
                validate_username(name).is_ok(),
                "{name:?} should be accepted"
            );
        }
        assert!(validate_username(&"a".repeat(MAX_USERNAME_LEN)).is_ok());
    }

    #[test]
    fn validate_username_rejects_everything_else() {
        let too_long = "a".repeat(MAX_USERNAME_LEN + 1);
        for name in [
            "", "Alice", "1x", "-x", "$", "a b", "a\"b", "a\\b", "a\nb", "a$b", "a$$", "é",
            &too_long, INJECTION,
        ] {
            assert!(
                validate_username(name).is_err(),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn expected_content_refuses_injection() {
        assert!(expected_content(INJECTION).is_err());
        assert!(expected_content("alice\n}); polkit.addRule(").is_err());
    }

    /// The output for a valid name must stay byte-identical to what earlier
    /// versions wrote, or `--check` would call existing rules "modified".
    #[test]
    fn expected_content_is_unchanged_for_valid_names() {
        let golden = r#"// Managed by pkexec-cache. Do not edit manually.
// Caches pkexec authentication for ~5 minutes (like sudo).
// Applies to ALL pkexec calls from alice in an active local session.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.user == "alice" &&
        subject.active == true &&
        subject.local == true) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
});
"#;
        assert_eq!(expected_content("alice").unwrap(), golden);
    }

    #[test]
    fn extract_username_round_trips() {
        for name in ["alice", "_svc", "a-b_c", "machine$"] {
            let content = expected_content(name).unwrap();
            assert_eq!(extract_username(&content).as_deref(), Some(name));
        }
    }

    #[test]
    fn extract_username_decodes_escapes() {
        let content = r#"subject.user == "a\"b\\c" &&"#;
        assert_eq!(extract_username(content).as_deref(), Some(r#"a"b\c"#));
        assert_eq!(extract_username(r#"subject.user == "unterminated"#), None);
        assert_eq!(extract_username("subject.user == alice"), None);
    }

    /// The rule the issue's repro wrote: `--check` must not report it as
    /// installed.
    #[test]
    fn injected_rule_does_not_check_as_installed() {
        let injected = r#"// Managed by pkexec-cache. Do not edit manually.
// Caches pkexec authentication for ~5 minutes (like sudo).
// Applies to ALL pkexec calls from x" || true || " in an active local session.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.user == "x" || true || "" &&
        subject.active == true &&
        subject.local == true) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
});
"#;
        let name = extract_username(injected).unwrap();
        assert_eq!(name, "x");
        assert_ne!(expected_content(&name).unwrap(), injected);
    }

    #[test]
    fn resolve_user_rejects_root_and_unknown_users() {
        assert!(resolve_user("root").unwrap_err().contains("uid 0"));
        assert!(resolve_user("nosuchuser_pkexec_cache_test")
            .unwrap_err()
            .contains("does not exist"));
        assert!(resolve_user(INJECTION)
            .unwrap_err()
            .contains("invalid username"));
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn read_rule_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("50-pkexec-cache.rules");
        assert!(read_rule(&path).unwrap().is_none());
    }

    #[test]
    fn read_rule_present_returns_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("50-pkexec-cache.rules");
        fs::write(&path, "rule text\n").unwrap();
        assert_eq!(read_rule(&path).unwrap().as_deref(), Some("rule text\n"));
    }

    /// The #75 case: the rule exists but its directory is not searchable
    /// (rules.d shipped as root:polkitd 0750, checked by a non-root user).
    #[test]
    fn read_rule_unreadable_dir_is_permission_denied() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root ignores directory mode bits");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("rules.d");
        fs::create_dir(&sub).unwrap();
        let path = sub.join("50-pkexec-cache.rules");
        fs::write(&path, "rule text\n").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
        let result = read_rule(&path);
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        let err = result.expect_err("unreadable directory must not read as absent");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
