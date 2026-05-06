use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostInfo {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub last_connected: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostsConfig {
    pub hosts: HashMap<String, HostInfo>,
}

impl HostsConfig {
    pub fn config_path() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                PathBuf::from(home).join(".config")
            });
        base.join("sudo-proxy").join("hosts.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = Self::config_path();
        let _ = save_to(&path, self);
    }

    pub fn touch(&mut self, host: &str) {
        let now = now_iso8601();
        self.hosts
            .entry(host.to_string())
            .and_modify(|info| info.last_connected = now.clone())
            .or_insert_with(|| HostInfo {
                description: String::new(),
                os: String::new(),
                last_connected: now,
                uid: String::new(),
            });
    }

    /// Return the remote UID for `host`, using the cached value if available,
    /// otherwise resolving via `ssh HOST id -u` and persisting the result.
    ///
    /// The uid string ends up interpolated into a path
    /// (`/run/user/{uid}/sudo-proxy.sock`) and into ssh's `-L` argument,
    /// so a non-numeric value would produce a corrupt tunnel target. We
    /// validate at both the resolve site (in case a malicious or
    /// compromised SSH server returns garbage) AND when reading from
    /// the cache (in case the file was hand-edited or written by an
    /// older unvalidated build).
    pub fn resolve_uid(&mut self, host: &str) -> Result<String, String> {
        if let Some(info) = self.hosts.get(host) {
            if is_valid_uid(&info.uid) {
                return Ok(info.uid.clone());
            }
            // A cached non-numeric uid (e.g. from a pre-fix build, or
            // hand-edited config) is treated as missing and re-resolved.
        }

        let output = std::process::Command::new("ssh")
            .args([host, "id", "-u"])
            .output()
            .map_err(|e| format!("ssh id -u: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "failed to get remote UID via ssh {host} id -u"
            ));
        }
        let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !is_valid_uid(&uid) {
            return Err(format!(
                "ssh {host} id -u returned non-numeric uid: {uid:?}"
            ));
        }

        let info = self
            .hosts
            .entry(host.to_string())
            .or_insert_with(|| HostInfo {
                description: String::new(),
                os: String::new(),
                last_connected: String::new(),
                uid: String::new(),
            });
        info.uid = uid.clone();
        self.save();

        Ok(uid)
    }
}

/// A uid is valid if it's a non-empty ASCII-digit string of at most
/// 10 chars (u32::MAX is `4294967295`, ten digits). The length cap
/// keeps a malicious peer from filling our config with an arbitrarily
/// long string that subsequently gets interpolated into paths and
/// argvs.
fn is_valid_uid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_uid_accepts_typical_uids() {
        assert!(is_valid_uid("0"));
        assert!(is_valid_uid("1000"));
        assert!(is_valid_uid("4294967295")); // u32::MAX
    }

    #[test]
    fn is_valid_uid_rejects_garbage() {
        assert!(!is_valid_uid(""), "empty");
        assert!(!is_valid_uid("0\nfoo"), "embedded newline");
        assert!(!is_valid_uid("0/../etc"), "path traversal");
        assert!(!is_valid_uid("1000 "), "trailing space (caller must trim)");
        assert!(!is_valid_uid("abc"), "letters");
        assert!(!is_valid_uid("12345678901"), "11 digits exceeds cap");
    }
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let tod = secs % 86400;
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }
    let md: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &m) in md.iter().enumerate() {
        if days < m {
            month = i as u64 + 1;
            break;
        }
        days -= m;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Compute the SSH target string from a host and an optional login user.
/// Returns `login@host` if login is provided, otherwise just `host`.
pub fn ssh_target(host: &str, login: Option<&str>) -> String {
    match login {
        Some(l) if !l.is_empty() => format!("{l}@{host}"),
        _ => host.to_string(),
    }
}

/// Atomic save: serialize, write to a per-process tempfile in the same
/// directory, fsync, then rename over the destination. Concurrent writers
/// won't tear the file — every reader sees either the previous valid
/// contents or this writer's complete output.
pub fn save_to(path: &Path, config: &HostsConfig) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("hosts.json");
    // Per-(pid, counter) tmp name so concurrent writers in the same
    // process don't clobber each other's tmpfile before rename.
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{stem}.tmp.{}.{seq}", std::process::id()));

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
