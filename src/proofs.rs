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
//!   - `protocol::has_dangerous_chars` / `is_dangerous_char` — the scanner for
//!     the control, format, separator and default-ignorable characters
//!     (Cc/Cf/Zl/Zp/DICP) the approval prompt relies on (widened in #86).
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

/// Proof: `has_dangerous_chars` is panic-free for any character, agrees with
/// the per-char class `is_dangerous_char` through UTF-8 encode/decode, and
/// that class contains every code point issue #86 names and excludes TAB and
/// printable ASCII. The function is a per-char fold with no cross-character
/// state, so single-char coverage generalises to any string. This is the
/// Rung 3 discharge of the display-field clause behind
/// `ValidatedRequest::validate`.
///
/// The spec has three parts, none of them tautological:
///   (a) no panic, and `has_dangerous_chars(encode(c)) == is_dangerous_char(c)`
///       for every `char` (the string fold agrees with the char class);
///   (b) must-reject: an independently written `matches!` of the ranges the
///       issue names, plus C0/C1/DEL and reserved U+2065, implies dangerous;
///   (c) must-accept: TAB and `0x20..=0x7E` are not dangerous.
/// Exact set membership (every code point in or out of
/// Cc ∪ Cf ∪ Zl ∪ Zp ∪ DICP) is *not* proved here: it is discharged by the
/// exhaustive unit test `protocol::tests::dangerous_class_matches_unicode_oracle`,
/// which checks all 1,114,112 `char`s against a General_Category oracle.
///
/// `encode_utf8` writes into a stack `[u8; 4]` rather than allocating a
/// `String`, so CBMC need not model the heap. The domain is the whole `char`
/// range (the earlier `< 0x2100` bound no longer holds: tag characters sit at
/// U+E0000).
///
/// `#[kani::unwind(8)]`: the buffer holds one (≤4-byte) char, so the
/// `chars()` loop runs once and the UTF-8 decode at most four times; the
/// `is_dangerous_char` lookup is a `partition_point` binary search over the
/// 27-entry `DANGEROUS_RANGES`, which iterates at most ⌈log2 27⌉ + 1 = 6
/// times (a linear scan would need 28). 8 covers both with margin and lets
/// CBMC discharge the unwinding assertion.
#[kani::proof]
#[kani::unwind(8)]
fn has_dangerous_chars_matches_spec_per_char() {
    let c: char = kani::any();

    let mut buf = [0u8; 4];
    let s: &str = c.encode_utf8(&mut buf);
    let got = crate::protocol::has_dangerous_chars(s);
    let class = crate::protocol::is_dangerous_char(c);

    // (a) the string fold agrees with the char class.
    assert_eq!(got, class);

    let u = c as u32;
    // (b) must-reject (written independently of `DANGEROUS_RANGES`).
    let must_reject = (c != '\t' && u < 0x20)
        || matches!(
            u,
            0x7F..=0x9F
                | 0xAD
                | 0x61C
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2069
                | 0xFE0F
                | 0xFEFF
                | 0xE0001
                | 0xE0020..=0xE007F
        );
    if must_reject {
        assert!(class, "a code point named by #86 must be dangerous");
    }
    // (c) must-accept.
    if c == '\t' || (0x20..=0x7E).contains(&u) {
        assert!(!class, "TAB and printable ASCII must be accepted");
    }
}

/// Proof: the structured-plan leaf check is panic-free and agrees with the
/// per-char danger spec. A `Plan::Exec` whose single argv element is one symbolic
/// character validates iff that character is not dangerous — i.e. the recursive
/// `Plan::validate_tree` applies exactly the same `has_dangerous_chars` gate to a
/// plan leaf that the flat-pipeline path applies to an argv element. This is the
/// Rung 3 discharge of the structured-plan leaf clause of the Rung 2
/// `prop_plan_display_is_structurally_identical_to_the_tree` / validation
/// predicates.
///
/// Scope mirrors `has_dangerous_chars_matches_spec_per_char`: one leaf, one
/// character over the whole `char` domain (no bound since #86: tag characters
/// sit at U+E0000), so the single-leaf result generalises — `validate_tree` is
/// a fold applying that same per-char predicate to every string leaf.
/// `unwind(8)` bounds the single ≤4-byte char decode, the one-element argv
/// loop and the ≤6-step binary search of `is_dangerous_char`.
#[kani::proof]
#[kani::unwind(8)]
fn plan_run_leaf_matches_dangerous_char_spec() {
    let c: char = kani::any();

    let mut buf = [0u8; 4];
    let s: &str = c.encode_utf8(&mut buf);

    let plan = crate::protocol::Plan::Exec {
        argv: vec![s.to_string()],
    };
    let mut nodes = 0usize;
    let accepted = plan.validate_tree(0, &mut nodes).is_ok();

    // A single non-dangerous char is accepted; a dangerous one is rejected.
    assert_eq!(accepted, !crate::protocol::has_dangerous_chars(s));
}
