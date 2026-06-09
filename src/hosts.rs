use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostInfo {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub last_connected: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
    /// Last-seen `sudo-proxy` version reported by this host's daemon.
    /// Empty if the daemon predates the protocol version field, or if no
    /// successful exchange has happened yet.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    /// When `true`, unprivileged commands hit the TTY Y/N gate (today's
    /// default). When `false`, they take the banner-only path. The
    /// interactive `a` answer flips this to `false` and persists.
    #[serde(default = "crate::protocol::default_true")]
    pub confirm_unprivileged: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            confirm_unprivileged: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostsConfig {
    #[serde(default)]
    pub hosts: HashMap<String, HostInfo>,
    #[serde(default)]
    pub policy: Policy,
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
        let now = crate::datetime::now_iso8601();
        self.hosts
            .entry(host.to_string())
            .and_modify(|info| info.last_connected = now.clone())
            .or_insert_with(|| HostInfo {
                last_connected: now,
                ..Default::default()
            });
    }

    /// Cache the daemon version reported by `host`. Returns `true` if the
    /// stored value changed (caller may persist accordingly). Empty
    /// `version` is a no-op so we don't overwrite a known value when a
    /// transient response happens to lack the field.
    pub fn record_version(&mut self, host: &str, version: &str) -> bool {
        if version.is_empty() {
            return false;
        }
        let info = self.hosts.entry(host.to_string()).or_default();
        if info.version == version {
            false
        } else {
            info.version = version.to_string();
            true
        }
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

        let info = self.hosts.entry(host.to_string()).or_default();
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

    #[test]
    fn policy_defaults_to_confirm_when_field_absent() {
        // An older hosts.json (no `policy` block) must round-trip with
        // confirm_unprivileged=true so behaviour matches pre-policy builds.
        let cfg: HostsConfig = serde_json::from_str(r#"{"hosts":{}}"#).unwrap();
        assert!(cfg.policy.confirm_unprivileged);
    }

    #[test]
    fn policy_with_confirm_false_loads() {
        let cfg: HostsConfig = serde_json::from_str(
            r#"{"hosts":{},"policy":{"confirm_unprivileged":false}}"#,
        )
        .unwrap();
        assert!(!cfg.policy.confirm_unprivileged);
    }

    #[test]
    fn policy_round_trips_through_serde() {
        let mut cfg = HostsConfig::default();
        assert!(cfg.policy.confirm_unprivileged);
        cfg.policy.confirm_unprivileged = false;
        let s = serde_json::to_string(&cfg).unwrap();
        let back: HostsConfig = serde_json::from_str(&s).unwrap();
        assert!(!back.policy.confirm_unprivileged);
    }

    #[test]
    fn policy_save_load_round_trip_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "sudo-proxy-policy-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.json");

        let mut cfg = HostsConfig::default();
        cfg.policy.confirm_unprivileged = false;
        save_to(&path, &cfg).unwrap();

        let s = std::fs::read_to_string(&path).unwrap();
        let back: HostsConfig = serde_json::from_str(&s).unwrap();
        assert!(!back.policy.confirm_unprivileged);

        let _ = std::fs::remove_dir_all(&dir);
    }
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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // hosts.json holds the host inventory, cached remote UIDs, and the
        // confirm_unprivileged policy — owner-private data. Keep the
        // directory owner-only (0700) so other local users can't enumerate
        // or read it, mirroring the socket-bind hardening in server.rs.
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
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
        // Create the tempfile 0600 up front (mode is applied subject to the
        // umask) so the contents are never momentarily world-readable, then
        // enforce 0600 explicitly to defeat a permissive umask. The mode
        // survives the rename onto `path`.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
