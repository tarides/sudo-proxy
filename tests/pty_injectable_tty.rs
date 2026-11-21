#![cfg(target_os = "linux")]
//! GHSA-cpmp-67wf-gwmx: drive the real daemon through a pty that looks like a
//! tmux pane. Started with --allow-injectable-tty, every prompt must carry the
//! warning line; without it, the daemon must not come up at all (tests/cli.rs
//! covers the refusal message).
mod common;
use common::pty::{PtyDaemon, PtyOpts};
use sudo_proxy::protocol::Status;

#[test]
fn override_puts_a_warning_line_in_every_prompt() {
    let mut d = PtyDaemon::spawn(PtyOpts {
        args: vec!["--allow-injectable-tty".into()],
        env: vec![("TERM".into(), "tmux-256color".into())],
        ..Default::default()
    });
    for i in 0..2 {
        let r = common::make_req(&format!("inj-{i}"), vec![vec!["true"]]);
        let h = d.request_async(&r);
        d.expect("Privilege Request");
        let head = d.expect("[y/N]");
        assert!(
            head.contains("⚠ Other processes can type into this terminal (terminal multiplexer (TERM=tmux-256color))"),
            "prompt {i} lacks the warning: {head}"
        );
        d.answer_raw(b'n');
        assert_eq!(h.join().unwrap().status, Status::Denied);
    }
    let log = d.daemon_log();
    assert!(log.contains("WARNING: other processes running as you can type"), "{log}");
}
