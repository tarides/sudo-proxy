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
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
