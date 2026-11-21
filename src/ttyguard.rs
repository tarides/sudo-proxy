//! Startup check that the approval terminal does not accept synthetic input
//! (GHSA-cpmp-67wf-gwmx).
//!
//! The human gate reads one keypress from the daemon's controlling terminal.
//! It cannot tell a key typed by the human from one injected by another
//! process running as the same user, and the typical requester (an AI agent)
//! also has a same-UID shell. Terminals that let such a process type into
//! them — multiplexers, emulators with remote control, X11 — therefore defeat
//! the gate, so the daemon refuses to start in one unless whoever starts it
//! explicitly accepts the risk with `--allow-injectable-tty`. There is
//! deliberately no `hosts.json` equivalent: an agent can write that file and
//! then restart the daemon through `sudo-proxy-mcp`.
//!
//! Detection is best effort: it reads environment variables and one sysctl,
//! so it cannot see an XWayland terminal inside a Wayland session, nor an
//! emulator it does not know. [`probe`] does the I/O; [`assess`] is pure so
//! every rule is unit-tested without touching the process environment.

use std::collections::HashMap;

/// Environment variables the rules read. [`probe`] captures exactly these.
const VARS: &[&str] = &[
    "TERM",
    "TERM_PROGRAM",
    "TMUX",
    "STY",
    "ZELLIJ",
    "KITTY_WINDOW_ID",
    "KITTY_LISTEN_ON",
    "WEZTERM_PANE",
    "WEZTERM_UNIX_SOCKET",
    "KONSOLE_DBUS_SERVICE",
    "INSIDE_EMACS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_SESSION_TYPE",
];

/// Variables a freshly spawned terminal window may inherit from the process
/// that launched it, although that window is not a pane of the launcher's
/// multiplexer or emulator. `sudo-proxy-mcp` removes them before spawning the
/// daemon's terminal so they do not cause a false refusal; the daemon still
/// probes everything the new window really exposes (X11, its own emulator).
pub const INHERITED_TERMINAL_VARS: &[&str] = &[
    "TMUX",
    "TMUX_PANE",
    "STY",
    "WINDOW",
    "ZELLIJ",
    "ZELLIJ_PANE_ID",
    "ZELLIJ_SESSION_NAME",
    "KITTY_WINDOW_ID",
    "KITTY_LISTEN_ON",
    "KITTY_PID",
    "KITTY_PUBLIC_KEY",
    "WEZTERM_PANE",
    "WEZTERM_UNIX_SOCKET",
    "WEZTERM_EXECUTABLE",
    "KONSOLE_DBUS_SERVICE",
    "KONSOLE_DBUS_SESSION",
    "KONSOLE_DBUS_WINDOW",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "INSIDE_EMACS",
];

/// Set by `sudo-proxy-mcp` on the daemon it spawns in a new terminal window:
/// on refusal the daemon waits for Enter so the window stays open long enough
/// to read why.
pub const HOLD_ENV: &str = "SUDO_PROXY_HOLD_ON_REFUSAL";

/// Snapshot of what the rules look at.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    /// Non-empty values of [`VARS`].
    pub env: HashMap<String, String>,
    /// Contents of `/proc/sys/dev/tty/legacy_tiocsti`, trimmed; `None` when
    /// the file is absent (kernel < 6.2, where TIOCSTI is always allowed).
    pub legacy_tiocsti: Option<String>,
}

impl Probe {
    fn get(&self, k: &str) -> Option<&str> {
        self.env.get(k).map(String::as_str).filter(|v| !v.is_empty())
    }
}

/// The verdict of [`assess`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// Ways a same-UID process can type into this terminal. Non-empty means
    /// the daemon refuses to start unless overridden. Each entry is one line
    /// naming the mechanism and the signal that revealed it.
    pub injectors: Vec<String>,
    /// Weaker exposures that are reported but do not refuse.
    pub warnings: Vec<String>,
}

/// Read the environment and the TIOCSTI sysctl.
pub fn probe() -> Probe {
    let env = VARS
        .iter()
        .filter_map(|k| {
            std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| (k.to_string(), v))
        })
        .collect();
    let legacy_tiocsti = std::fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti")
        .ok()
        .map(|s| s.trim().to_string());
    Probe { env, legacy_tiocsti }
}

/// Classify a [`Probe`]. Pure.
pub fn assess(p: &Probe) -> Assessment {
    let mut a = Assessment::default();
    let inj = &mut a.injectors;

    // Multiplexers: any same-UID process can type into any pane
    // (`tmux send-keys`, `screen -X stuff`, `zellij action write-chars`) and
    // read it back to time the key. TERM survives ssh and nesting; the
    // socket variables catch a pane whose TERM was overridden.
    if let Some(t) = p.get("TERM").filter(|t| t.starts_with("tmux") || t.starts_with("screen")) {
        inj.push(format!("terminal multiplexer (TERM={t}): `tmux send-keys` / `screen -X stuff` can type into it"));
    } else if p.get("TMUX").is_some() {
        inj.push("tmux pane ($TMUX set): `tmux send-keys` can type into it".into());
    } else if p.get("STY").is_some() {
        inj.push("GNU screen window ($STY set): `screen -X stuff` can type into it".into());
    }
    if p.get("ZELLIJ").is_some() {
        inj.push("zellij pane ($ZELLIJ set): `zellij action write-chars` can type into it".into());
    }

    // Emulators with a remote-control channel open to same-UID processes.
    if p.get("KITTY_LISTEN_ON").is_some() {
        inj.push("kitty with remote control listening ($KITTY_LISTEN_ON): `kitty @ send-text` can type into it".into());
    } else if p.get("KITTY_WINDOW_ID").is_some() {
        inj.push("kitty ($KITTY_WINDOW_ID set): `kitty @ send-text` can type into it when allow_remote_control is on".into());
    }
    if p.get("WEZTERM_PANE").is_some() || p.get("WEZTERM_UNIX_SOCKET").is_some() {
        inj.push("WezTerm ($WEZTERM_PANE set): `wezterm cli send-text` can type into it".into());
    }
    if p.get("KONSOLE_DBUS_SERVICE").is_some() {
        inj.push("Konsole ($KONSOLE_DBUS_SERVICE set): its D-Bus `sendText` can type into it".into());
    }
    if p.get("TERM_PROGRAM") == Some("vscode") {
        inj.push("VS Code integrated terminal (TERM_PROGRAM=vscode): extensions can `sendText` into it".into());
    }
    if p.get("INSIDE_EMACS").is_some() {
        inj.push("Emacs terminal ($INSIDE_EMACS set): `emacsclient --eval` can send input to it".into());
    }

    // X11: any client may synthesise keys (XTEST, e.g. `xdotool key y`).
    let x11 = p.get("DISPLAY").is_some()
        && (p.get("WAYLAND_DISPLAY").is_none() || p.get("XDG_SESSION_TYPE") == Some("x11"));
    if x11 {
        inj.push(format!(
            "X11 session (DISPLAY={}, no Wayland): any X client can synthesise keys (`xdotool key y`)",
            p.get("DISPLAY").unwrap_or("")
        ));
    }

    // TIOCSTI only works on the caller's own controlling terminal. The
    // daemon's unprivileged children run in their own session (no
    // controlling terminal), so what remains is another process that shares
    // this terminal: reported, not refused.
    match p.legacy_tiocsti.as_deref() {
        Some("0") => {}
        other => a.warnings.push(format!(
            "the kernel allows TIOCSTI ({}): a process sharing this terminal could inject keystrokes; \
             set `sysctl dev.tty.legacy_tiocsti=0` where available",
            match other {
                None => "no dev.tty.legacy_tiocsti, kernel < 6.2".to_string(),
                Some(v) => format!("dev.tty.legacy_tiocsti={v}"),
            }
        )),
    }
    a
}

/// The refusal printed to stderr when [`Assessment::injectors`] is non-empty
/// and not overridden.
pub fn refusal_message(a: &Assessment) -> String {
    let mut s = String::from(
        "sudo-proxy: refusing to start: other processes running as you can type into this terminal,\n\
         so they could answer the approval prompt themselves (GHSA-cpmp-67wf-gwmx):\n",
    );
    for i in &a.injectors {
        s.push_str(&format!("  - {i}\n"));
    }
    s.push_str(
        "Run the daemon in a terminal window of its own, outside any multiplexer, on Wayland\n\
         (e.g. GNOME Terminal, foot, Alacritty). Running the agent as a separate Unix user\n\
         removes the risk altogether.\n\
         To accept the risk anyway, start it yourself with --allow-injectable-tty.",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_of(vars: &[(&str, &str)], tiocsti: Option<&str>) -> Probe {
        Probe {
            env: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            legacy_tiocsti: tiocsti.map(str::to_string),
        }
    }

    fn injectors(vars: &[(&str, &str)]) -> Vec<String> {
        assess(&probe_of(vars, Some("0"))).injectors
    }

    #[test]
    fn clean_wayland_terminal_is_accepted() {
        let a = assess(&probe_of(
            &[
                ("TERM", "xterm-256color"),
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("DISPLAY", ":0"),
                ("XDG_SESSION_TYPE", "wayland"),
            ],
            Some("0"),
        ));
        assert_eq!(a, Assessment::default());
    }

    #[test]
    fn headless_ssh_session_is_accepted() {
        assert!(injectors(&[("TERM", "xterm-256color")]).is_empty());
    }

    #[test]
    fn multiplexers_are_detected() {
        for term in ["tmux-256color", "screen", "screen-256color"] {
            let i = injectors(&[("TERM", term)]);
            assert_eq!(i.len(), 1, "{term}: {i:?}");
            assert!(i[0].contains(term));
        }
        // TERM overridden inside the multiplexer: the socket variable still counts.
        assert_eq!(injectors(&[("TERM", "xterm-256color"), ("TMUX", "/tmp/tmux-1/default,1,0")]).len(), 1);
        assert_eq!(injectors(&[("TERM", "xterm-256color"), ("STY", "123.pts-0")]).len(), 1);
        assert_eq!(injectors(&[("TERM", "xterm-256color"), ("ZELLIJ", "0")]).len(), 1);
        // One line for tmux, not one per signal.
        assert_eq!(injectors(&[("TERM", "tmux-256color"), ("TMUX", "x")]).len(), 1);
    }

    #[test]
    fn remote_control_emulators_are_detected() {
        for (k, v, needle) in [
            ("KITTY_LISTEN_ON", "unix:/tmp/kitty", "kitty"),
            ("KITTY_WINDOW_ID", "1", "kitty"),
            ("WEZTERM_PANE", "0", "WezTerm"),
            ("WEZTERM_UNIX_SOCKET", "/run/user/1/wezterm/sock", "WezTerm"),
            ("KONSOLE_DBUS_SERVICE", ":1.42", "Konsole"),
            ("TERM_PROGRAM", "vscode", "VS Code"),
            ("INSIDE_EMACS", "29.1,vterm", "Emacs"),
        ] {
            let i = injectors(&[("TERM", "xterm-256color"), (k, v)]);
            assert_eq!(i.len(), 1, "{k}: {i:?}");
            assert!(i[0].contains(needle), "{k}: {i:?}");
        }
        // Another TERM_PROGRAM is not a remote-control signal.
        assert!(injectors(&[("TERM_PROGRAM", "Apple_Terminal")]).is_empty());
    }

    #[test]
    fn x11_without_wayland_is_detected() {
        let i = injectors(&[("DISPLAY", ":0")]);
        assert_eq!(i.len(), 1);
        assert!(i[0].contains("X11"));
        // Wayland session: DISPLAY alone is XWayland for X clients, not this terminal.
        assert!(injectors(&[("DISPLAY", ":0"), ("WAYLAND_DISPLAY", "wayland-0")]).is_empty());
        // A Wayland socket in an X11 session (nested compositor) does not clear it.
        assert_eq!(
            injectors(&[("DISPLAY", ":0"), ("WAYLAND_DISPLAY", "w"), ("XDG_SESSION_TYPE", "x11")]).len(),
            1
        );
        // ssh -X forwarding exposes the local X server too.
        assert_eq!(injectors(&[("DISPLAY", "localhost:10.0")]).len(), 1);
    }

    #[test]
    fn several_mechanisms_are_all_listed() {
        let i = injectors(&[("TERM", "tmux-256color"), ("DISPLAY", ":0"), ("KITTY_WINDOW_ID", "1")]);
        assert_eq!(i.len(), 3, "{i:?}");
    }

    #[test]
    fn empty_values_are_ignored() {
        assert!(injectors(&[("TMUX", ""), ("DISPLAY", ""), ("KITTY_WINDOW_ID", "")]).is_empty());
    }

    #[test]
    fn legacy_tiocsti_warns_but_does_not_refuse() {
        for v in [None, Some("1")] {
            let a = assess(&probe_of(&[], v));
            assert!(a.injectors.is_empty(), "{v:?}");
            assert_eq!(a.warnings.len(), 1, "{v:?}");
            assert!(a.warnings[0].contains("TIOCSTI"));
        }
        assert!(assess(&probe_of(&[], Some("0"))).warnings.is_empty());
    }

    #[test]
    fn refusal_names_every_reason_and_the_override() {
        let a = assess(&probe_of(&[("TERM", "tmux-256color"), ("DISPLAY", ":0")], Some("0")));
        let m = refusal_message(&a);
        for i in &a.injectors {
            assert!(m.contains(i.as_str()));
        }
        assert!(m.contains("--allow-injectable-tty"));
        assert!(!m.contains("hosts.json"), "no file-based override: {m}");
        assert!(m.contains("GHSA-cpmp-67wf-gwmx"));
    }

    #[test]
    fn inherited_vars_cover_every_rule_var_except_display_and_term() {
        // Everything the rules read about the *launcher's* terminal must be
        // scrubbed by the MCP launcher; DISPLAY/WAYLAND/TERM describe the new
        // window and must stay.
        for v in VARS {
            let keep = ["TERM", "DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE"];
            assert_eq!(
                INHERITED_TERMINAL_VARS.contains(v),
                !keep.contains(v),
                "{v}"
            );
        }
    }
}
