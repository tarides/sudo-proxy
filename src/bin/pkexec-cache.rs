use std::fs;
use std::path::Path;
use std::process;

const RULES_PATH: &str = "/etc/polkit-1/rules.d/50-pkexec-cache.rules";

fn expected_content(username: &str) -> String {
    format!(
        r#"// Managed by pkexec-cache. Do not edit manually.
// Caches pkexec authentication for ~5 minutes (like sudo).
// Applies to ALL pkexec calls from {username} in an active local session.
polkit.addRule(function(action, subject) {{
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.user == "{username}" &&
        subject.active == true &&
        subject.local == true) {{
        return polkit.Result.AUTH_ADMIN_KEEP;
    }}
}});
"#
    )
}

fn get_login_username() -> Result<String, String> {
    // SUDO_USER is set when running under sudo, giving us the real user
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return Ok(user);
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
                        return Ok(s.to_string());
                    }
                }
            }
        }
    }
    // Fallback: LOGNAME or USER
    if let Ok(user) = std::env::var("LOGNAME").or_else(|_| std::env::var("USER")) {
        if !user.is_empty() && user != "root" {
            return Ok(user);
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

fn cmd_check() {
    let path = Path::new(RULES_PATH);
    if !path.exists() {
        println!("not installed: {RULES_PATH} does not exist");
        println!("run with --create to install the rule");
        process::exit(1);
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
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

    // Verify it matches expected content
    let expected = expected_content(&username);
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
        eprintln!("error: {} does not exist (is polkit installed?)", parent.display());
        process::exit(1);
    }

    let content = expected_content(&username);

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

fn extract_username(content: &str) -> Option<String> {
    // Look for: subject.user == "USERNAME"
    let marker = "subject.user == \"";
    let start = content.find(marker)? + marker.len();
    let end = content[start..].find('"')? + start;
    Some(content[start..end].to_string())
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
