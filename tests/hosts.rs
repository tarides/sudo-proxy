#![cfg(unix)]

use std::sync::Arc;
use std::thread;

use sudo_proxy::hosts::{save_to, HostInfo, HostsConfig};

/// Concurrent writers must not tear the file. Before the atomic-rename
/// fix, two `save()` calls hitting the same path could interleave bytes
/// or leave a zero-length window where a reader saw invalid JSON.
#[test]
fn concurrent_save_is_atomic_and_loses_no_data() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let path = Arc::new(dir.path().join("hosts.json"));

    let n_writers = 8;
    let writes_per_thread = 50;

    let mut handles = Vec::new();
    for tid in 0..n_writers {
        let path = Arc::clone(&path);
        handles.push(thread::spawn(move || {
            for i in 0..writes_per_thread {
                let mut cfg = HostsConfig::default();
                cfg.hosts.insert(
                    format!("host-{tid}-{i}"),
                    HostInfo {
                        description: String::new(),
                        os: String::new(),
                        last_connected: String::new(),
                        uid: String::new(),
                        version: String::new(),
                    },
                );
                save_to(&path, &cfg).expect("atomic save");

                let bytes = std::fs::read(&*path).expect("read");
                serde_json::from_slice::<HostsConfig>(&bytes)
                    .unwrap_or_else(|e| panic!("torn write: {e}; bytes={:?}", bytes));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

/// Sanity-check: the saved file matches what we wrote.
#[test]
fn save_then_load_roundtrips() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let path = dir.path().join("hosts.json");

    let mut cfg = HostsConfig::default();
    cfg.hosts.insert(
        "alpha".into(),
        HostInfo {
            description: "first".into(),
            os: "Linux".into(),
            last_connected: "2026-04-30T12:00:00Z".into(),
            uid: "1000".into(),
            version: "0.5.0".into(),
        },
    );
    save_to(&path, &cfg).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let loaded: HostsConfig = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(loaded.hosts.len(), 1);
    assert_eq!(loaded.hosts["alpha"].uid, "1000");
    assert_eq!(loaded.hosts["alpha"].version, "0.5.0");
}

/// Forward-compat: a hosts.json written by an older build (no `version`
/// field) loads cleanly, with version defaulting to empty string.
#[test]
fn load_hosts_json_without_version_field() {
    let json = r#"{
        "hosts": {
            "legacy": {
                "description": "old config",
                "os": "Linux",
                "last_connected": "2026-04-30T12:00:00Z",
                "uid": "1000"
            }
        }
    }"#;
    let cfg: HostsConfig = serde_json::from_str(json).expect("parse legacy hosts.json");
    let info = cfg.hosts.get("legacy").expect("host present");
    assert_eq!(info.version, "");
    assert_eq!(info.uid, "1000");
}

/// `record_version` should only persist non-empty values and should
/// report whether the cached value actually changed, so callers can
/// avoid redundant disk writes.
#[test]
fn record_version_signals_change_and_ignores_empty() {
    let mut cfg = HostsConfig::default();
    assert!(cfg.record_version("h1", "0.6.0"), "first set is a change");
    assert!(!cfg.record_version("h1", "0.6.0"), "same value: no change");
    assert!(cfg.record_version("h1", "0.7.0"), "new value: change");
    assert!(
        !cfg.record_version("h1", ""),
        "empty version must not overwrite a known value"
    );
    assert_eq!(cfg.hosts["h1"].version, "0.7.0");
}
