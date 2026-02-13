use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

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
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
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
    pub fn resolve_uid(&mut self, host: &str) -> Result<String, String> {
        if let Some(info) = self.hosts.get(host) {
            if !info.uid.is_empty() {
                return Ok(info.uid.clone());
            }
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
        if uid.is_empty() {
            return Err("ssh id -u returned empty output".to_string());
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
