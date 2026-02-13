use std::env;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Local,
    Remote,
}

impl Mode {
    pub fn detect() -> Self {
        let has_display = env::var("DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_wayland = env::var("WAYLAND_DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if has_display || has_wayland {
            Mode::Local
        } else {
            Mode::Remote
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Local => "local (TUI + pkexec)",
            Mode::Remote => "remote (TUI + sudo)",
        }
    }
}
