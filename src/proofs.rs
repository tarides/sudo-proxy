//! Kani bounded-model-checking harnesses — Rung 3 of the assurance ladder
//! (see `docs/formalisation-roadmap.md`).
//!
//! These re-drive the Rung 2 predicate functions with `kani::any()` instead of
//! the fixed-seed PRNG in `prop.rs`: where Rung 2 *samples* the input space,
//! Kani *proves* the invariant for every input in the harness's domain. The
//! whole module is `#[cfg(kani)]`, so it is compiled only by `cargo kani` and
//! never by a normal/CI `cargo build`.
//!
//! Scope. Kani here covers the parser arithmetic and the display-field scanner
//! that are *our* code:
//!   - `datetime::ymd_hms_to_epoch` — the panic/overflow/wrap-relevant core of
//!     the `parse_age` freshness gate (issues #11/#14).
//!   - `protocol::has_dangerous_chars` — the control/bidi scanner the approval
//!     prompt relies on.
//! It deliberately does *not* attempt the base64 and `serde_json` decode paths:
//! those are upstream crates that return `Result`, and our call sites contain no
//! `.unwrap()` on them (`if let Ok`/`?` throughout — server.rs, tui.rs, mcp.rs,
//! sudo-request.rs), so their panic-freedom is the upstream crates' obligation,
//! not ours. Symbolically model-checking serde/base64 is intractable and out of
//! scope for this rung.

/// Proof: `ymd_hms_to_epoch` is total and panic/overflow/wrap-free over the
/// *entire* `u64^6` input domain. This is the Rung 3 discharge of the Rung 2
/// `parse_age_total_and_panic_free` predicate — strictly stronger, since the
/// PRNG only ever sampled bounded near-valid timestamps.
///
/// Kani's default checks prove: no arithmetic overflow (every step is
/// `checked_*`), no out-of-bounds index into `days_before_month` (the
/// `month` guard makes `(month - 1) as usize < 12`), no `day - 1` underflow
/// (the `day` guard), and no panic on any path.
#[kani::proof]
fn ymd_hms_to_epoch_is_total_and_panic_free() {
    let year: u64 = kani::any();
    let month: u64 = kani::any();
    let day: u64 = kani::any();
    let hour: u64 = kani::any();
    let min: u64 = kani::any();
    let sec: u64 = kani::any();
    // The return value is irrelevant; the obligation is that the call returns
    // (no panic, no overflow) for every input.
    let _ = crate::datetime::ymd_hms_to_epoch(year, month, day, hour, min, sec);
}

/// Proof: `ymd_hms_to_epoch` is **monotone in calendar order** — a later civil
/// datetime never maps to a smaller epoch, so making a request's timestamp
/// earlier can never make it look fresher. This is the Rung 3 discharge of the
/// Rung 2 `freshness_is_monotone` predicate: where that test samples the
/// `epoch_to_iso` round-trip, this proves the order-preservation directly.
///
/// Domain, stated precisely:
///   - Years are bounded to `1970..=2099`, the range where the approximate
///     `(year - 1969) / 4` leap rule agrees with the exact Gregorian one
///     (they diverge only at the 2100 non-leap century — a date this tool
///     never sees; freshness bounds inputs to within a minute of now).
///   - Both inputs are *well-formed* calendar dates: the day is constrained to
///     the actual length of its month (incl. the leap-Feb 29). The function
///     itself only range-checks `day <= 31`, so it would accept e.g. "Feb 31"
///     and map it past Mar 1 — breaking naive lexicographic order. Such dates
///     are not in the `epoch_to_iso` image the freshness path ever produces;
///     constraining to real dates makes lexicographic order *be* chronological
///     order, which is the property that matters.
#[kani::proof]
fn ymd_hms_to_epoch_is_monotone_on_valid_dates() {
    // days in `month` of `year`, or 0 for an out-of-range month.
    fn days_in_month(year: u64, month: u64) -> u64 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if crate::datetime::is_leap(year) {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        }
    }

    let (y1, mo1, d1): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (h1, mi1, s1): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (y2, mo2, d2): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (h2, mi2, s2): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());

    // Well-formed calendar dates within the exact-leap-rule window.
    for (y, mo, d, h, mi, s) in [(y1, mo1, d1, h1, mi1, s1), (y2, mo2, d2, h2, mi2, s2)] {
        kani::assume((1970..=2099).contains(&y));
        kani::assume((1..=12).contains(&mo));
        kani::assume(d >= 1 && d <= days_in_month(y, mo));
        kani::assume(h <= 23 && mi <= 59 && s <= 59);
    }

    // For well-formed dates, lexicographic order on the components IS
    // chronological order.
    kani::assume((y1, mo1, d1, h1, mi1, s1) <= (y2, mo2, d2, h2, mi2, s2));

    match (
        crate::datetime::ymd_hms_to_epoch(y1, mo1, d1, h1, mi1, s1),
        crate::datetime::ymd_hms_to_epoch(y2, mo2, d2, h2, mi2, s2),
    ) {
        (Some(e1), Some(e2)) => assert!(e1 <= e2, "ymd_hms_to_epoch must be monotone"),
        // A well-formed date must parse; Kani proves this arm unreachable.
        _ => unreachable!("well-formed date failed to parse"),
    }
}

/// Proof: `has_dangerous_chars` is panic-free for any character and classifies
/// it *exactly* per its documented danger ranges. The function is a per-char
/// fold with no cross-character state, so single-char coverage of the
/// classification generalises to any string. This is the Rung 3 discharge of
/// the display-field clause behind `ValidatedRequest::validate`.
///
/// Two tractability choices keep CBMC fast without weakening the result:
///   - `encode_utf8` writes into a stack `[u8; 4]` rather than allocating a
///     `String`, so CBMC need not model the heap.
///   - The codepoint is bounded below `0x2100`. Every range the function
///     forbids lies at or below `0x2069`, and for any codepoint `>= 0x2100`
///     *both* the function (no matching arm) and `expected` are `false` by
///     inspection — so the bound excludes only a region where the equality
///     holds trivially. The proof is therefore total in substance.
///
/// `#[kani::unwind(5)]` bounds the `for c in s.chars()` loop: the buffer holds
/// a single (≤3-byte) char, so the loop runs once and the UTF-8 byte decode
/// at most three times — 5 unwindings cover every path and let CBMC discharge
/// the unwinding assertion.
#[kani::proof]
#[kani::unwind(5)]
fn has_dangerous_chars_matches_spec_per_char() {
    let c: char = kani::any();
    kani::assume((c as u32) < 0x2100);

    let mut buf = [0u8; 4];
    let s: &str = c.encode_utf8(&mut buf);
    let got = crate::protocol::has_dangerous_chars(s);

    let u = c as u32;
    let expected = (c != '\t' && u < 0x20)
        || matches!(u, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069);
    assert_eq!(got, expected);
}
