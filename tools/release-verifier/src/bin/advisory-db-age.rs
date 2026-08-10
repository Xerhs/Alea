//! `advisory-db-age` (WP-32, ALEA-2026-008) — the fail-closed max-age
//! enforcement for the vendored, pinned RustSec advisory-db snapshot.
//!
//! ```text
//! advisory-db-age <supply-chain/advisory-db.lock>
//! ```
//!
//! Alea's release gate runs `cargo deny --offline check advisories`
//! against a *pinned* RustSec advisory-db snapshot so the release build
//! stays deterministic and offline (a live DB fetch would make two clean
//! builds of the same tag disagree). A pinned snapshot is, by design,
//! behind the live feed — so it MUST NOT be allowed to drift arbitrarily
//! old and silently stop catching real advisories. This tool reads the
//! lock file recording the snapshot's commit and date, compares that date
//! against today, and exits **nonzero** if the snapshot is older than the
//! recorded `max_age_days` (or if the lock is missing/malformed — fail
//! closed). The scheduled online monitor (`.github/workflows/audit.yml`,
//! WP4) covers the window between snapshot bumps.
//!
//! Honesty (SPEC §31/§36.2): a passing age check proves only that the
//! pinned advisory snapshot is *recent enough to be meaningful*, and the
//! advisory gate it guards proves only "no RustSec-published advisory
//! matches the pinned dependency graph as of the snapshot date." Neither
//! is an audit or a safety attestation, and neither substitutes for
//! `cargo vet`.
//!
//! No date/time crate is vendored: the ISO-8601 `YYYY-MM-DD` date math
//! uses the standard proleptic-Gregorian day-count algorithm below, and
//! "today" comes from `SystemTime`.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Days from the civil date `(y, m, d)` to the Unix epoch (1970-01-01),
/// via Howard Hinnant's well-known constant-time algorithm (valid for the
/// full proleptic Gregorian range; no leap-second/time-zone concerns —
/// these are whole calendar days). `m` is 1..=12, `d` is 1..=31.
#[must_use]
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse an ISO-8601 `YYYY-MM-DD` date into `(year, month, day)`.
#[must_use]
pub fn parse_ymd(s: &str) -> Option<(i64, u32, u32)> {
    let s = s.trim();
    let mut parts = s.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Whole days from `snapshot` to `now` (positive when `now` is later).
/// Returns `None` if either date is malformed.
#[must_use]
pub fn age_days(snapshot_ymd: &str, now_ymd: &str) -> Option<i64> {
    let (sy, sm, sd) = parse_ymd(snapshot_ymd)?;
    let (ny, nm, nd) = parse_ymd(now_ymd)?;
    Some(days_from_civil(ny, nm, nd) - days_from_civil(sy, sm, sd))
}

/// The parsed, relevant fields of an `advisory-db.lock`.
#[derive(Debug, PartialEq, Eq)]
pub struct AdvisoryDbLock {
    pub commit: String,
    pub snapshot_date: String,
    pub max_age_days: i64,
}

/// Parse the small `key = value` lock format (`#` comments and blank
/// lines ignored). Values may be bare or double-quoted. Requires
/// `commit`, `snapshot_date`, and `max_age_days` to all be present.
pub fn parse_lock(contents: &str) -> Result<AdvisoryDbLock, String> {
    let mut commit = None;
    let mut snapshot_date = None;
    let mut max_age_days = None;
    for (i, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = value`, got {line:?}", i + 1))?;
        let k = k.trim();
        let v = v.trim().trim_matches('"').trim().to_string();
        match k {
            "commit" => commit = Some(v),
            "snapshot_date" => snapshot_date = Some(v),
            "max_age_days" => {
                max_age_days = Some(
                    v.parse::<i64>()
                        .map_err(|_| format!("line {}: max_age_days is not an integer: {v:?}", i + 1))?,
                )
            }
            _ => {} // forward-compatible: ignore unknown keys
        }
    }
    Ok(AdvisoryDbLock {
        commit: commit.ok_or("advisory-db.lock is missing `commit`")?,
        snapshot_date: snapshot_date.ok_or("advisory-db.lock is missing `snapshot_date`")?,
        max_age_days: max_age_days.ok_or("advisory-db.lock is missing `max_age_days`")?,
    })
}

/// The verdict for a lock against a given "today". `Ok(())` means the
/// snapshot is recent enough; `Err(msg)` is a fail-closed rejection.
pub fn check_lock(lock: &AdvisoryDbLock, now_ymd: &str) -> Result<i64, String> {
    let age = age_days(&lock.snapshot_date, now_ymd)
        .ok_or_else(|| format!("unparseable date(s): snapshot={:?} now={now_ymd:?}", lock.snapshot_date))?;
    if age < 0 {
        return Err(format!(
            "advisory-db snapshot date {} is in the future relative to {now_ymd} — refusing (clock or lock error)",
            lock.snapshot_date
        ));
    }
    if age > lock.max_age_days {
        return Err(format!(
            "advisory-db snapshot is {age} days old (> max_age_days={}) — bump the pinned snapshot (supply-chain/advisory-db.lock) before releasing",
            lock.max_age_days
        ));
    }
    Ok(age)
}

fn today_ymd() -> String {
    // Days since the Unix epoch -> civil date, inverse of days_from_civil.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let z = secs / 86_400 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: advisory-db-age <supply-chain/advisory-db.lock>");
        return ExitCode::from(64);
    }
    let contents = match std::fs::read_to_string(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            // Fail closed: a missing/unreadable lock must never pass.
            eprintln!("FAIL: could not read {}: {e}", args[1]);
            return ExitCode::from(1);
        }
    };
    let lock = match parse_lock(&contents) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };
    let now = today_ymd();
    match check_lock(&lock, &now) {
        Ok(age) => {
            println!(
                "PASS: advisory-db snapshot {} ({}) is {age} day(s) old (<= {} allowed).",
                lock.commit, lock.snapshot_date, lock.max_age_days
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_matches_known_epoch_anchors() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn age_days_counts_whole_calendar_days() {
        assert_eq!(age_days("2026-08-01", "2026-08-10"), Some(9));
        assert_eq!(age_days("2026-08-10", "2026-08-10"), Some(0));
        assert_eq!(age_days("2026-08-10", "2026-08-09"), Some(-1)); // now before snapshot
    }

    #[test]
    fn parse_lock_reads_quoted_and_bare_values_ignoring_comments() {
        let lock = parse_lock(
            "# advisory-db pin\ncommit = \"abc123\"\nsnapshot_date = 2026-08-10\nmax_age_days = 30\nfuture_key = ignored\n",
        )
        .unwrap();
        assert_eq!(lock.commit, "abc123");
        assert_eq!(lock.snapshot_date, "2026-08-10");
        assert_eq!(lock.max_age_days, 30);
    }

    #[test]
    fn advisory_db_age_accepts_within_max_age() {
        let lock = AdvisoryDbLock {
            commit: "c".into(),
            snapshot_date: "2026-08-01".into(),
            max_age_days: 30,
        };
        assert_eq!(check_lock(&lock, "2026-08-20"), Ok(19));
    }

    #[test]
    fn advisory_db_age_rejects_stale_snapshot() {
        let lock = AdvisoryDbLock {
            commit: "c".into(),
            snapshot_date: "2026-06-01".into(),
            max_age_days: 30,
        };
        let err = check_lock(&lock, "2026-08-10").unwrap_err();
        assert!(err.contains("days old"), "{err}");
    }

    #[test]
    fn advisory_db_age_rejects_future_snapshot() {
        let lock = AdvisoryDbLock {
            commit: "c".into(),
            snapshot_date: "2027-01-01".into(),
            max_age_days: 30,
        };
        assert!(check_lock(&lock, "2026-08-10").unwrap_err().contains("future"));
    }

    #[test]
    fn advisory_db_age_fails_closed_when_lock_missing_fields() {
        assert!(parse_lock("commit = x\n").is_err()); // no snapshot_date / max_age_days
        assert!(parse_lock("not a lock at all").is_err());
    }
}
