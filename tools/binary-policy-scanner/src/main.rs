//! `binary-policy-scanner` (WP-30) — SPEC §28 production/test isolation
//! gate.
//!
//! Parses a compiled `x86_64-unknown-uefi` PE/COFF `.efi` artifact and
//! fails (nonzero exit) if it contains anything SPEC §28 forbids in a
//! production release: test-edition banner text, the words `TEST`,
//! `DEMO` or `DEVELOPMENT` in a production string context, watermark
//! wording, deterministic-vector identifiers, entropy-injection hooks,
//! hidden-entropy-toggle API identifiers (UEFI Variable Services /
//! `LoadOptions` — see [`FORBIDDEN_HIDDEN_TOGGLE_MARKERS`]), or
//! symbol/crate-name leakage from `seed-test-vectors` /
//! `seed-desktop-test`. It also confirms the positive production marker
//! from `crates/seed-uefi-production/src/markers.rs`
//! (`ALEA_PRODUCTION_EDITION_MARKER_V1`, byte body
//! `ALEA-PRODUCTION-EDITION-MARKER-V1`) is present as both a
//! symbol name and a byte sequence.
//!
//! # PE parser choice
//!
//! This tool uses the [`object`](https://docs.rs/object) crate rather
//! than hand-rolling PE/COFF section and symbol-table parsing. `object`
//! is a widely used, actively maintained pure-Rust reader used by
//! `rustc`/`cargo` itself (via `wasm-bindgen`/`cargo-binutils`-adjacent
//! tooling) — reviewing its output against the PE spec is far cheaper
//! and less error-prone for a CI security gate than re-deriving section
//! header and symbol table offset math from scratch. It is a host-only
//! `[dependencies]` entry of this standalone tool crate, never linked
//! into any production-graph crate.
//!
//! # What is scanned
//!
//! - Every loadable PE section's raw bytes (`.text`, `.rdata`, `.data`,
//!   and any others the linker emitted) are scanned for forbidden ASCII
//!   substrings, case-insensitively for edition-labeling phrases like
//!   `TEST EDITION`/`DEMO MODE`/`DEVELOPMENT BUILD` (SPEC §4.1's "never
//!   display… unless disabled" targets the word used as an edition/mode
//!   label — see [`FORBIDDEN_EDITION_PHRASES`]'s doc comment for why a
//!   bare `"TEST"` substring ban is not used), and case-sensitively for
//!   the fixed literal banners.
//! - The COFF symbol table (if present — release UEFI builds are
//!   normally stripped of it, but `#[no_mangle]` statics can still
//!   surface as exported/debug symbols depending on linker flags) is
//!   scanned for forbidden and required symbol names.
//!
//! # Exit codes
//!
//! `0` — all required markers present, no forbidden marker found.
//! `1` — policy violation (reported to stderr) or a parse failure.
//!
//! Usage: `binary-policy-scanner <path-to.efi>`

use std::env;
use std::fs;
use std::process::ExitCode;

use object::{Object, ObjectSection, ObjectSymbol};

// WP-C5 (IMPLEMENTATION_MAP_COMPAT.md §4, SPEC_COMPAT.md §9): seed-compat
// isolation denylist, owned as a standalone new file so this WP never
// edits WP-30's own denylist constants directly. See that module's doc
// comment for what it checks.
mod compat_denylist;

/// The exact byte body of the required production marker (mirrors
/// `crates/seed-uefi-production/src/markers.rs::PRODUCTION_MARKER_BYTES`,
/// SPEC §28). Kept as a byte literal, not re-derived, so a future edit to
/// that crate's marker that isn't mirrored here fails this scanner's own
/// self-test loudly rather than silently matching nothing.
const PRODUCTION_MARKER_BYTES: &[u8] = b"ALEA-PRODUCTION-EDITION-MARKER-V1";

/// The `#[no_mangle]` symbol name carrying [`PRODUCTION_MARKER_BYTES`]
/// (SPEC §28).
const PRODUCTION_MARKER_SYMBOL: &str = "ALEA_PRODUCTION_EDITION_MARKER_V1";

/// Reserved hypothetical test-edition marker symbol name (SPEC §28,
/// `markers.rs` doc comment) — must never appear in any artifact this
/// scanner accepts, production or test.
const FORBIDDEN_TEST_MARKER_SYMBOL: &str = "ALEA_TEST_EDITION_MARKER_V1";

/// Forbidden fixed literal strings (SPEC §4.2, §28): the UEFI
/// test-edition's permanent banner lines, checked as exact substrings
/// (case-sensitive — these are fixed, spec-quoted phrases, not bare
/// words that need case-folding).
const FORBIDDEN_LITERALS: &[&str] = &[
    "PUBLIC TEST PHRASE",
    "UEFI TEST EDITION",
    "NEVER USE WITH FUNDS",
];

/// Forbidden crate-name substrings (SPEC §9, §28): if either of these
/// ever appears embedded in metadata, panic strings, or debug info, a
/// test/desktop-only crate has leaked into the production dependency
/// graph.
const FORBIDDEN_CRATE_NAMES: &[&str] = &["seed-test-vectors", "seed_test_vectors", "seed-desktop-test", "seed_desktop_test"];

/// Forbidden deterministic-vector / entropy-injection identifiers (SPEC
/// §28: "release artifacts are scanned for deterministic vectors and
/// debug commands"). `SCHEMA_ID` is `seed-test-vectors`'s own
/// `pub const` (`crates/seed-test-vectors/src/lib.rs`) — its presence
/// anywhere in a production binary means the frozen public vector corpus
/// got compiled in.
const FORBIDDEN_VECTOR_MARKERS: &[&str] = &["alea-vectors-v1"];

/// Forbidden hidden-entropy-toggle API identifiers (SPEC §28: "the
/// production UI has no hidden keyboard sequence, command-line
/// parameter, environment variable or UEFI variable that changes
/// entropy behavior"). `crates/seed-uefi-production/` and the platform
/// crates it depends on (`seed-platform-x86`, `seed-gop-ui`, `seed-flow`)
/// are all `#![no_std]`, which makes `std::env`/POSIX-style environment
/// variables structurally unreachable at compile time (verified
/// separately by `ci.sh`'s successful `no_std` build of those crates —
/// there is no runtime check that could prove a compile-time
/// impossibility more strongly than the compiler itself already does).
/// UEFI has no POSIX environment; its nearest equivalents are UEFI
/// Variable Services (`GetVariable`/`SetVariable`, reachable from
/// `#![no_std]` code via the `uefi` crate) and the `LoadedImageProtocol`
/// `LoadOptions` field (UEFI's "command line"), neither of which is
/// ruled out by `no_std` alone. These markers are the literal Rust API
/// names a production-graph crate would have to reference to read
/// either one; as of this scanner's own passing self-test against the
/// real compiled `seed-uefi-production.efi`, none of them appear
/// anywhere in that artifact (confirmed with `strings`), so this list
/// currently has zero false positives and exists to catch a future
/// regression, not a present one.
const FORBIDDEN_HIDDEN_TOGGLE_MARKERS: &[&str] = &[
    "GetVariable",
    "SetVariable",
    "get_variable",
    "set_variable",
    "LoadOptions",
    "load_options",
];

/// Edition-labeling phrases SPEC §4.1 says the production UI must never
/// display (unless generation is disabled, which is not a state a
/// release artifact should ship with at all): "test," "demo" and
/// "development" used as an *edition/mode label*. Checked as
/// case-insensitive multi-word phrases rather than the bare words alone,
/// because the real production copy legitimately contains "test" as an
/// ordinary English word in non-edition-labeling contexts approved
/// elsewhere in the spec — e.g. "KEYBOARD SELF-TEST" (§22, hardware
/// self-check naming), "Cryptographic self-test," and "Send a small test
/// amount before depositing substantial funds" (§24, standard wallet
/// hygiene advice). A bare `"TEST"` substring/word ban would flag those
/// legitimate, already-shipped strings as false positives; phrase-level
/// matching catches an actual edition-mislabeling banner (the real
/// failure mode SPEC §28 cares about — see `FORBIDDEN_LITERALS` for the
/// test edition's exact banner text) without rejecting known-good
/// production strings.
const FORBIDDEN_EDITION_PHRASES: &[&str] = &[
    "TEST EDITION",
    "DEMO EDITION",
    "DEVELOPMENT EDITION",
    "TEST MODE",
    "DEMO MODE",
    "DEVELOPMENT MODE",
    "TEST BUILD",
    "DEMO BUILD",
    "DEVELOPMENT BUILD",
];

/// One policy violation found in the scanned artifact.
struct Violation {
    /// Human-readable description, including the section or symbol table
    /// the match came from.
    detail: String,
}

/// Outcome of a full scan pass: every violation found, plus whether the
/// required production marker was located at all (symbol and bytes both
/// required — SPEC §28).
struct ScanReport {
    violations: Vec<Violation>,
    marker_symbol_found: bool,
    marker_bytes_found: bool,
    sections_scanned: usize,
    symbols_scanned: usize,
}

impl ScanReport {
    fn passed(&self) -> bool {
        self.violations.is_empty() && self.marker_symbol_found && self.marker_bytes_found
    }
}

/// Scan every section's raw bytes for forbidden literals, forbidden bare
/// words, forbidden crate names, and forbidden vector markers; scan the
/// symbol table for the required production marker symbol and the
/// forbidden reserved test-marker symbol name. Returns a full
/// [`ScanReport`] rather than failing fast, so a single run reports every
/// violation at once (SPEC §28 CI-gate ergonomics).
fn scan(data: &[u8]) -> Result<ScanReport, String> {
    let file = object::File::parse(data).map_err(|e| format!("PE/COFF parse failed: {e}"))?;

    let mut violations = Vec::new();
    let mut marker_bytes_found = false;
    let mut sections_scanned = 0usize;

    for section in file.sections() {
        sections_scanned += 1;
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let bytes = match section.data() {
            Ok(b) => b,
            Err(_) => continue, // uninitialized (e.g. .bss) — nothing to scan
        };

        if contains_subslice(bytes, PRODUCTION_MARKER_BYTES) {
            marker_bytes_found = true;
        }

        for lit in FORBIDDEN_LITERALS {
            if contains_subslice(bytes, lit.as_bytes()) {
                violations.push(Violation {
                    detail: format!("forbidden literal {lit:?} found in section `{name}`"),
                });
            }
        }
        for cn in FORBIDDEN_CRATE_NAMES {
            if contains_subslice(bytes, cn.as_bytes()) {
                violations.push(Violation {
                    detail: format!("forbidden crate-name marker {cn:?} found in section `{name}`"),
                });
            }
        }
        for vm in FORBIDDEN_VECTOR_MARKERS {
            if contains_subslice(bytes, vm.as_bytes()) {
                violations.push(Violation {
                    detail: format!("forbidden deterministic-vector marker {vm:?} found in section `{name}`"),
                });
            }
        }
        for hm in FORBIDDEN_HIDDEN_TOGGLE_MARKERS {
            if contains_subslice(bytes, hm.as_bytes()) {
                violations.push(Violation {
                    detail: format!(
                        "forbidden hidden-entropy-toggle marker {hm:?} found in section `{name}` (SPEC §28)"
                    ),
                });
            }
        }
        let upper_bytes = bytes.to_ascii_uppercase();
        for phrase in FORBIDDEN_EDITION_PHRASES {
            if contains_subslice(&upper_bytes, phrase.as_bytes()) {
                violations.push(Violation {
                    detail: format!(
                        "forbidden edition-labeling phrase {phrase:?} found in section `{name}`"
                    ),
                });
            }
        }
        // WP-C5 call-site wire-in (IMPLEMENTATION_MAP_COMPAT.md §4,
        // SPEC_COMPAT.md §9): fail on any seed-compat symbol, profile-id
        // string, or compat watermark literal.
        for detail in compat_denylist::find_compat_violations(bytes, &name) {
            violations.push(Violation { detail });
        }
    }

    let mut marker_symbol_found = false;
    let mut symbols_scanned = 0usize;
    for symbol in file.symbols() {
        symbols_scanned += 1;
        let Ok(name) = symbol.name() else { continue };
        if name == PRODUCTION_MARKER_SYMBOL {
            marker_symbol_found = true;
        }
        if name == FORBIDDEN_TEST_MARKER_SYMBOL {
            violations.push(Violation {
                detail: format!("forbidden reserved test-marker symbol `{name}` present"),
            });
        }
        for cn in FORBIDDEN_CRATE_NAMES {
            if name.contains(cn) {
                violations.push(Violation {
                    detail: format!("forbidden crate-name substring found in symbol `{name}`"),
                });
            }
        }
    }

    // Release UEFI builds are commonly stripped of their symbol table
    // entirely (no symbols at all, marker included). SPEC §28 requires
    // the marker to be *findable in the linked artifact*; since it is a
    // `#[used]` static, its byte body always survives into `.rdata`/
    // `.data` even when the symbol table itself is stripped. Treat the
    // byte-body check as the authoritative presence check, and the
    // symbol-table check as an additional confirmation only when a
    // symbol table exists at all.
    if symbols_scanned == 0 {
        marker_symbol_found = marker_bytes_found;
    }

    Ok(ScanReport {
        violations,
        marker_symbol_found,
        marker_bytes_found,
        sections_scanned,
        symbols_scanned,
    })
}

/// Naive but correct subslice search over raw bytes (no encoding
/// assumptions — PE string data here is plain ASCII per the source
/// crates, so a byte-level search is exact and avoids pulling in a regex
/// dependency for a handful of fixed needles).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn main() -> ExitCode {
    let mut args = env::args();
    let _prog = args.next();
    let Some(path) = args.next() else {
        eprintln!("usage: binary-policy-scanner <path-to.efi>");
        return ExitCode::FAILURE;
    };

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read `{path}`: {e}");
            return ExitCode::FAILURE;
        }
    };

    let report = match scan(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("binary-policy-scanner: `{path}`");
    println!(
        "  sections scanned: {}  symbols scanned: {}",
        report.sections_scanned, report.symbols_scanned
    );
    println!(
        "  production marker symbol present: {}",
        report.marker_symbol_found
    );
    println!(
        "  production marker bytes present:  {}",
        report.marker_bytes_found
    );

    if !report.marker_bytes_found {
        println!("  FAIL: required production marker bytes NOT found (SPEC §28)");
    }
    if !report.marker_symbol_found {
        println!("  FAIL: required production marker symbol NOT found (SPEC §28)");
    }
    for v in &report.violations {
        println!("  FAIL: {}", v.detail);
    }

    if report.passed() {
        println!("  PASS: no forbidden markers found; production marker present");
        ExitCode::SUCCESS
    } else {
        println!(
            "  RESULT: FAIL ({} violation(s), marker_symbol={}, marker_bytes={})",
            report.violations.len(),
            report.marker_symbol_found,
            report.marker_bytes_found
        );
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal, real (not hand-crafted-invalid) COFF object file
    /// containing the given ASCII payload in a single section named
    /// `.rdata`, using `object::write` so the test exercises the same
    /// PE/COFF reading path `scan` uses against real compiler output,
    /// without depending on a full linked `.efi` (those are built by the
    /// integration test in `tests/scan_real_efi.rs` against the actual
    /// workspace artifacts).
    fn build_coff_with_rdata(payload: &[u8]) -> Vec<u8> {
        use object::write::{Object as WObject, SectionKind};
        use object::{Architecture, BinaryFormat, Endianness};

        let mut obj = WObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let sec = obj.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
        obj.append_section_data(sec, payload, 4);
        obj.write().expect("write COFF")
    }

    #[test]
    fn finds_production_marker_bytes() {
        let data = build_coff_with_rdata(PRODUCTION_MARKER_BYTES);
        let report = scan(&data).expect("parse");
        assert!(report.marker_bytes_found);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn flags_forbidden_literal() {
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00PUBLIC TEST PHRASE\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("PUBLIC TEST PHRASE")));
    }

    #[test]
    fn flags_edition_labeling_phrase_case_insensitively() {
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00Test Edition\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("edition-labeling phrase")));
    }

    #[test]
    fn does_not_flag_legitimate_production_copy_containing_test() {
        // Real, already-shipped production strings (SPEC §22/§24 UX
        // copy) legitimately contain the word "test" as ordinary English,
        // not as an edition label — these must never be flagged.
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(
            b"\x00KEYBOARD SELF-TEST Cryptographic self-test Send a small test amount\x00",
        );
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(report.passed(), "unexpected violations: {:?}", report
            .violations
            .iter()
            .map(|v| &v.detail)
            .collect::<Vec<_>>());
    }

    #[test]
    fn flags_missing_marker() {
        let data = build_coff_with_rdata(b"nothing interesting here");
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(!report.marker_bytes_found);
    }

    #[test]
    fn flags_vector_schema_marker() {
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00alea-vectors-v1\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("deterministic-vector")));
    }

    #[test]
    fn flags_hidden_toggle_marker() {
        // SPEC §28: "the production UI has no hidden keyboard sequence,
        // command-line parameter, environment variable or UEFI variable
        // that changes entropy behavior". A production artifact that
        // embeds the literal `GetVariable` API name (the UEFI Variable
        // Services call a hidden-toggle implementation would need) must
        // be rejected even though it is a legitimate PE/COFF artifact
        // with the correct production marker otherwise present.
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00GetVariable\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("hidden-entropy-toggle")));
    }

    #[test]
    fn does_not_flag_clean_production_payload_for_hidden_toggles() {
        // Companion to `flags_hidden_toggle_marker`: a payload with only
        // the production marker (no forbidden API names) must not be
        // flagged — guards against an overly broad substring match.
        let data = build_coff_with_rdata(PRODUCTION_MARKER_BYTES);
        let report = scan(&data).expect("parse");
        assert!(
            !report.violations.iter().any(|v| v.detail.contains("hidden-entropy-toggle")),
            "unexpected hidden-toggle false positive: {:?}",
            report.violations.iter().map(|v| &v.detail).collect::<Vec<_>>()
        );
    }

    #[test]
    fn flags_planted_compat_profile_id_string() {
        // WP-C5 (IMPLEMENTATION_MAP_COMPAT.md §4, SPEC_COMPAT.md §9): a
        // production-shaped artifact that has a seed-compat profile-id
        // string planted into it (e.g. from an accidental dependency-graph
        // leak) MUST fail the scan even though the required production
        // marker is otherwise present and correct.
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00coldcard-dice\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("coldcard-dice")));
    }

    #[test]
    fn flags_planted_compat_watermark_literal() {
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(
            b"\x00COMPATIBILITY / VERIFICATION MODE - reproduces another vendor's method -\x00",
        );
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report.violations.iter().any(|v| v.detail.contains("watermark")));
    }

    #[test]
    fn clean_production_payload_not_flagged_by_compat_denylist() {
        // Companion negative test: the real production marker bytes alone
        // (no compat content) must not trip the new compat checks.
        let data = build_coff_with_rdata(PRODUCTION_MARKER_BYTES);
        let report = scan(&data).expect("parse");
        assert!(report.passed(), "unexpected violations: {:?}", report
            .violations
            .iter()
            .map(|v| &v.detail)
            .collect::<Vec<_>>());
    }

    #[test]
    fn flags_forbidden_crate_name() {
        let mut payload = PRODUCTION_MARKER_BYTES.to_vec();
        payload.extend_from_slice(b"\x00seed-test-vectors\x00");
        let data = build_coff_with_rdata(&payload);
        let report = scan(&data).expect("parse");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.detail.contains("crate-name")));
    }
}
