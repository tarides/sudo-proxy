#![cfg(target_os = "linux")]
//! GHSA-h6r4-gh2r-qr98, end to end against the real daemon through a pty:
//! a future-dated request beyond the skew is rejected before any prompt,
//! a captured future-dated `stop` cannot shut the daemon down, and a request
//! within the skew is still prompted normally.
mod common;
use common::pty::{PtyDaemon, PtyOpts};
use sudo_proxy::protocol::{Action, Status};

fn iso_in(secs: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    sudo_proxy::datetime::epoch_to_iso((now + secs) as u64)
}

#[test]
fn future_dated_requests() {
    let mut d = PtyDaemon::spawn(PtyOpts::default());

    // 1. The advisory's ping, dated one hour ahead: rejected, no prompt.
    let mut ping = common::make_req("fut-ping", vec![]);
    ping.action = Action::Ping;
    ping.time = iso_in(3600);
    let r = common::send_request(&d.socket, &ping);
    eprintln!("ping +1h  -> {:?}: {:?}", r.status, r.message);
    assert_eq!(r.status, Status::Error);
    assert!(r.message.as_deref().unwrap_or("").contains("in the future"), "{r:?}");

    // 2. A future-dated `stop` (no keypress needed): rejected, daemon lives.
    let mut stop = common::make_req("fut-stop", vec![]);
    stop.action = Action::Stop;
    stop.time = iso_in(3600);
    let r = common::send_request(&d.socket, &stop);
    eprintln!("stop +1h  -> {:?}: {:?}", r.status, r.message);
    assert_eq!(r.status, Status::Error);

    // 3. An exec dated one hour ahead: rejected before the prompt is drawn.
    let mut ex = common::make_req("fut-exec", vec![vec!["true"]]);
    ex.time = iso_in(3600);
    let r = common::send_request(&d.socket, &ex);
    eprintln!("exec +1h  -> {:?}: {:?}", r.status, r.message);
    assert_eq!(r.status, Status::Error);
    assert!(!d.capture().contains("fut-exec"), "future-dated exec reached the prompt");

    // 4. Within the skew (+10 s): prompted as usual, and runs when approved.
    let mut ok = common::make_req("fut-skew-ok", vec![vec!["echo", "skew-ok"]]);
    ok.time = iso_in(10);
    let h = d.request_async(&ok);
    let prompt = d.answer(b'y');
    assert!(prompt.contains("fut-skew-ok"), "{prompt}");
    let r = h.join().unwrap();
    eprintln!("exec +10s -> {:?}: stdout {:?}", r.status, common::decode_stdout(&r));
    assert_eq!(r.status, Status::Ok, "{r:?}");

    // 5. The daemon is still up: a fresh ping answers pong.
    let mut alive = common::make_req("fut-alive", vec![]);
    alive.action = Action::Ping;
    let r = common::send_request(&d.socket, &alive);
    eprintln!("ping now  -> {:?}: {:?}", r.status, r.message);
    assert_eq!(r.status, Status::Ok);
}
