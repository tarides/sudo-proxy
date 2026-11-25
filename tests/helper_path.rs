//! GHSA-gx9w-4f7x-2gcp: the escalator is never looked up on the daemon's own
//! PATH. Its own test binary because it rewrites this process's PATH, and the
//! resolution is cached process-wide.

use std::os::unix::fs::PermissionsExt;

#[test]
fn planted_sudo_on_daemon_path_is_never_chosen() {
    let plant = tempfile::tempdir().unwrap();
    for name in ["sudo", "pkexec"] {
        let p = plant.path().join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let old = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{old}", plant.path().display()));

    for (name, got) in [
        ("sudo", sudo_proxy::helper::sudo()),
        ("pkexec", sudo_proxy::helper::pkexec()),
    ] {
        match got {
            Ok(p) => {
                assert!(p.is_absolute(), "{name}: {p:?}");
                assert!(!p.starts_with(plant.path()), "{name}: planted {p:?} chosen");
            }
            // No trusted one on this host (e.g. a CI container): refusing is
            // the correct outcome; falling back to the plant is not.
            Err(e) => assert!(e.contains(name), "{e}"),
        }
    }
}
