#![cfg(unix)]

use sudo_proxy::protocol::Status;

mod common;
use common::*;

#[test]
fn duplicate_id_rejected() {
    let s = start_test_server(TestServerOpts::default());

    let req = make_req("dup-1", vec![vec!["true"]]);
    let first = s.send(&req);
    assert_eq!(first.status, Status::Ok, "first: {:?}", first);

    // Same id again: replay-protection must reject it.
    let mut second = make_req("dup-1", vec![vec!["true"]]);
    second.time = iso_now(); // refresh `time` so freshness passes; only id matters
    let resp = s.send(&second);
    assert_eq!(resp.status, Status::Error);
    assert!(
        resp.message.as_deref().unwrap().contains("duplicate"),
        "got: {:?}",
        resp.message
    );
}

#[test]
fn distinct_ids_both_accepted() {
    let s = start_test_server(TestServerOpts::default());
    let r1 = s.send(&make_req("uniq-a", vec![vec!["true"]]));
    let r2 = s.send(&make_req("uniq-b", vec![vec!["true"]]));
    assert_eq!(r1.status, Status::Ok);
    assert_eq!(r2.status, Status::Ok);
}

#[test]
fn rejected_request_does_not_consume_id() {
    // Failed validation must not poison the replay set: an honest client
    // that retries the same id with a fix must still succeed.
    let s = start_test_server(TestServerOpts::default());

    let mut bad = make_req("retry-1", vec![vec!["echo", "hi\u{202E}"]]);
    bad.privileged = false;
    let r1 = s.send(&bad);
    assert_eq!(r1.status, Status::Error);

    let good = make_req("retry-1", vec![vec!["true"]]);
    let r2 = s.send(&good);
    assert_eq!(r2.status, Status::Ok, "got: {:?}", r2);
}
