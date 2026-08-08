//! `cargo run -p seed-desktop-test -- check` (SPEC §4.3, §29.2): headless,
//! no window, bit-for-bit comparison of this crate's pipeline output
//! against every case in every `tests/vectors/frozen/*.json` file.
//!
//! Exits non-zero on any mismatch (WP-28 DoD). Never opens a `winit`
//! window or a `softbuffer` surface — see `crate::window`'s own doc
//! comment for why that module is never reachable from this path, which
//! is what makes `check` (and every `#[cfg(test)]` test in this crate)
//! runnable on a host with no display server at all.

use crate::pipeline;
use crate::vectors;
use seed_selftest::{run_aggregate_self_test, AggregateSelfTestReport};

/// Summary of one `check` run.
pub struct CheckReport {
    pub total_cases: usize,
    pub failed_cases: usize,
    /// One line per case: `"<file> :: <case name> :: OK"` or `"... ::
    /// MISMATCH(field, field, ...)"`.
    pub lines: Vec<String>,
    /// GAP 3 (desktop rehearsal feature parity): the SPEC §11.6 aggregate
    /// known-answer crypto self-test result (SHA-256/512, HMAC, PBKDF2,
    /// secp256k1, RIPEMD/Base58/Bech32, BIP39, BIP32, transcript, wordlist
    /// integrity, bounds, state-machine). Run verbatim via
    /// [`run_aggregate_self_test`] — exactly as the production
    /// `CryptographicSelfTest` state runs it — and surfaced next to the
    /// frozen-vector reproduction in the `[4]` self-check screen. `None` is
    /// passed for the production-build policy marker: the desktop test
    /// edition never claims to be the verified production build, so that
    /// bullet is vacuously clean (see `run_aggregate_self_test`'s doc).
    pub kat: AggregateSelfTestReport,
}

impl CheckReport {
    /// `true` only if every frozen vector reproduced AND every SPEC §11.6
    /// self-test bullet passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed_cases == 0 && self.kat.all_clean()
    }
}

/// One `"<label> :: PASS"` / `"... :: FAIL"` line per SPEC §11.6 bullet,
/// in the spec's listed order, plus a trailing aggregate line. Shared by
/// the CLI ([`print_report`]) and the in-window `[4]` screen
/// (`launcher::render_check_report`).
#[must_use]
pub fn kat_lines(kat: &AggregateSelfTestReport) -> Vec<String> {
    let mark = |ok: bool| if ok { "PASS" } else { "FAIL" };
    let items: [(&str, bool); 13] = [
        ("SHA-256 KAT", kat.sha256_kat),
        ("SHA-512 + HMAC-SHA512 KAT", kat.sha512_hmac_sha512_kat),
        ("PBKDF2-HMAC-SHA512 KAT", kat.pbkdf2_kat),
        ("secp256k1 KAT", kat.secp256k1_kat),
        ("RIPEMD-160 / Base58Check / Bech32 KAT", kat.ripemd160_base58check_bech32_kat),
        ("BIP39 KAT", kat.bip39_kat),
        ("BIP32 KAT", kat.bip32_kat),
        ("entropy-transcript KAT", kat.entropy_transcript_kat),
        ("dice/coin session KAT", kat.dice_coin_session_kat),
        ("wordlist integrity", kat.wordlist_integrity),
        ("fixed-buffer bounds KAT", kat.fixed_buffer_bounds_kat),
        ("state-machine invariant KAT", kat.state_machine_invariant_kat),
        ("production-build policy marker", kat.production_build_policy_marker),
    ];
    let mut lines = Vec::with_capacity(items.len() + 1);
    for (label, ok) in items {
        lines.push(format!("{label} :: {}", mark(ok)));
    }
    lines.push(format!(
        "aggregate crypto self-test :: {}",
        if kat.all_clean() { "ALL PASS" } else { "FAILED" }
    ));
    lines
}

/// Runs every frozen-vector case under `dir` through [`pipeline::derive_case`]
/// and compares it with [`pipeline::compare`]. Returns a full report; does
/// not print or exit (kept pure/host-testable — see `tests` below and
/// `main`'s thin wrapper for the actual CLI printing/exit-code behavior).
#[must_use]
pub fn run(dir: &std::path::Path) -> CheckReport {
    let cases = vectors::load_all(dir);
    let mut lines = Vec::with_capacity(cases.len());
    let mut failed = 0usize;

    for (file, case) in &cases {
        let derived = pipeline::derive_case(case);
        let mismatches = pipeline::compare(case, &derived);
        if mismatches.is_empty() {
            lines.push(format!("{file} :: {} :: OK", case.name));
        } else {
            failed += 1;
            let fields: Vec<&str> = mismatches.iter().map(|m| m.field).collect();
            lines.push(format!("{file} :: {} :: MISMATCH({})", case.name, fields.join(", ")));
            for m in &mismatches {
                lines.push(format!("    {}: expected {:?}, got {:?}", m.field, m.expected, m.got));
            }
        }
    }

    // GAP 3: run the SPEC §11.6 aggregate crypto self-test verbatim
    // alongside the frozen-vector reproduction (`None` = no production
    // policy-marker claim in the test edition).
    let kat = run_aggregate_self_test(None);

    CheckReport { total_cases: cases.len(), failed_cases: failed, lines, kat }
}

/// Print `report` to stdout in a fixed, greppable format.
pub fn print_report(report: &CheckReport) {
    for line in &report.lines {
        println!("{line}");
    }
    println!(
        "---\n{} case(s) checked, {} passed, {} failed",
        report.total_cases,
        report.total_cases - report.failed_cases,
        report.failed_cases
    );
    println!("--- SPEC §11.6 aggregate crypto self-test ---");
    for line in kat_lines(&report.kat) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frozen_case_reproduces_bit_for_bit() {
        let report = run(&vectors::frozen_dir());
        assert!(report.total_cases >= 20, "expected >= 20 cases, found {}", report.total_cases);
        assert_eq!(report.failed_cases, 0, "mismatches found:\n{}", report.lines.join("\n"));
    }

    /// GAP 3 (desktop rehearsal feature parity): `[4]` now runs the SPEC
    /// §11.6 aggregate crypto known-answer self-test (not only the frozen
    /// vectors). Every bullet must pass on the host, and the rendered
    /// per-item report must reflect that.
    #[test]
    fn aggregate_crypto_self_test_runs_and_every_item_passes() {
        let report = run(&vectors::frozen_dir());
        assert!(report.kat.all_clean(), "aggregate self-test not clean: {:?}", report.kat);
        assert!(report.all_passed(), "vectors + KAT must both pass");

        let lines = kat_lines(&report.kat);
        // 13 SPEC §11.6 bullets + 1 aggregate line.
        assert_eq!(lines.len(), 14);
        assert!(lines.iter().all(|l| !l.contains("FAIL")), "no bullet may FAIL:\n{}", lines.join("\n"));
        assert!(lines.iter().any(|l| l == "SHA-256 KAT :: PASS"));
        assert!(lines.iter().any(|l| l == "aggregate crypto self-test :: ALL PASS"));
    }
}
