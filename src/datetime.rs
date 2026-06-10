//! Minimal UTC date/time helpers.
//!
//! sudo-proxy stamps wire messages and the host inventory with ISO 8601 UTC
//! timestamps and checks request freshness against them. We deliberately avoid
//! a calendar-crate dependency for this handful of conversions; the logic here
//! is the single home for what used to be copy-pasted across `hosts`, `mcp`,
//! and the `sudo-request` binary.
//!
//! The forward path (`epoch_to_iso` / `days_to_ymd`) uses the exact Gregorian
//! leap rule. The reverse parser in `server::parse_age` uses the approximate
//! `(year - 1969) / 4` form; the two agree for every date in 1970..=2099 (they
//! diverge only at the year-2100 non-leap century), which covers any timestamp
//! this tool will ever see.

use std::time::SystemTime;

/// Current time as an ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_to_iso(secs)
}

/// Format a Unix timestamp (seconds since the epoch) as ISO 8601 UTC.
pub fn epoch_to_iso(secs: u64) -> String {
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

/// Convert a count of days since 1970-01-01 into `(year, month, day)`,
/// where month and day are 1-based.
pub fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
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

/// Gregorian leap-year test.
pub fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Convert a UTC calendar date-time into seconds since the Unix epoch, or
/// `None` if any component is out of range or the arithmetic would overflow.
///
/// This is the pure arithmetic core of `server::parse_age` — the reverse of
/// `epoch_to_iso` for the freshness gate. It is factored out (rather than left
/// inline in `parse_age`) so the Rung 3 Kani harness can prove it total and
/// panic/overflow/wrap-free over the *whole* `u64` domain with `kani::any()`,
/// without modelling the `SystemTime::now()` read that `parse_age` wraps it in.
/// See `docs/formalisation-roadmap.md`.
///
/// Like `parse_age` historically, this uses the approximate `(year - 1969) / 4`
/// leap-day count plus a non-leap `days_before_month` table with a current-year
/// correction; it agrees with the exact forward path for every date in
/// 1970..=2099 (module docs). Every step is `checked_*`, so an out-of-range or
/// overflowing input yields `None` rather than a panic or a wrapped value — the
/// integer-underflow that made a stale request look fresh in issues #11/#14.
pub fn ymd_hms_to_epoch(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    min: u64,
    sec: u64,
) -> Option<u64> {
    // Reject out-of-range components up front. Without these guards,
    // year < 1970 underflows `(year - 1970)`, day == 0 underflows `(day - 1)`,
    // and an out-of-range month would index `days_before_month` out of bounds.
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Allow sec == 60 for ISO 8601 leap-second tolerance.
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    // Days before the 1st of each month (non-leap). Good enough for age checking.
    let days_before_month: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = year
        .checked_sub(1970)?
        .checked_mul(365)?
        .checked_add(year.checked_sub(1969)? / 4)?;
    days = days
        .checked_add(days_before_month[(month - 1) as usize])?
        .checked_add(day - 1)?;
    // Leap-year correction for the current year.
    if month > 2 && is_leap(year) {
        days = days.checked_add(1)?;
    }
    days.checked_mul(86400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)
}
