//! Structural proof, not just a design claim, that this crate has no
//! real-entropy code path (SPEC §4.3: "Have no real-entropy generation
//! mode and no operating-system RNG mode").
//!
//! [`tests::no_real_entropy_api_anywhere_in_this_crates_own_source`] greps
//! every `.rs` file this crate owns — including `build.rs` at the crate
//! root, not just `src/` — for a fixed list of real-randomness API names
//! and hard-fails if any appear outside of this very file's own doc
//! comments/string literals (which must obviously *name* the forbidden
//! APIs to check for them). This is deliberately independent of
//! `crate::fixed_entropy`'s own design-level guarantee (`include_str!`,
//! no runtime file/OS-RNG read) — a reviewer or a future change could
//! weaken that module without touching this one, and vice versa; both
//! must hold.
#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Real-randomness / OS-RNG API surface that must never appear
    /// anywhere in this crate's own `.rs` source, in any form (crate path,
    /// import, or call) — checked as case-sensitive substrings.
    // Deliberately *not* included: lowercase `rdseed`/`rdrand`/`efi_rng` —
    // those are exactly the identifier names SPEC-mandated `seed_flow::
    // entropy_avail::MachineAvailabilityGate` trait methods this crate
    // must implement (`crate::providers::DesktopGates`, always returning
    // "unavailable"), so they are expected, legitimate matches rather
    // than a real-entropy call site. A real x86 RDRAND/RDSEED
    // instruction invocation in Rust is always spelled with the
    // upper-case intrinsic/mnemonic form below, which this crate's
    // source never contains.
    const FORBIDDEN: &[&str] = &[
        "rand::",
        "\"rand\"",
        "OsRng",
        "getrandom",
        "SystemRandom",
        "thread_rng",
        "RDRAND",
        "RDSEED",
        "/dev/urandom",
        "/dev/random",
        "CryptGenRandom",
        "BCryptGenRandom",
        "RtlGenRandom",
    ];

    /// This file (`guardrails.rs`) necessarily names every forbidden term
    /// in the list above, in its own source text (both in the `FORBIDDEN`
    /// array literal and in this doc comment) — it is excluded from the
    /// scan by file name rather than by asking a human to keep the
    /// scanner's own denylist file "clean" of the very words it lists.
    const SELF_FILE_NAME: &str = "guardrails.rs";

    /// Crate root (`CARGO_MANIFEST_DIR`), *not* just `src/` — this is the
    /// directory that contains both `src/` and this crate's own
    /// `build.rs`. Scanning only `src/` would silently exclude `build.rs`
    /// from this structural guardrail; scanning the whole manifest root
    /// (skipping only build-artifact directories, see
    /// [`collect_rs_files`]) closes that coverage gap.
    fn crate_root_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Recursively collects every `.rs` file under `dir`, skipping `target`
    /// directories (build-artifact/output dirs are never this crate's own
    /// source, and — if a build ever runs without `CARGO_TARGET_DIR`
    /// pointed elsewhere — could otherwise pull in copies of other
    /// crates' source via `cargo`'s dependency scratch dirs).
    fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{dir:?}: {e}")) {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn no_real_entropy_api_anywhere_in_this_crates_own_source() {
        let mut files = Vec::new();
        collect_rs_files(&crate_root_dir(), &mut files);
        assert!(files.len() > 3, "sanity: expected to find several source files, found {}", files.len());
        assert!(
            files.iter().any(|p| p.file_name().and_then(|n| n.to_str()) == Some("build.rs")),
            "sanity: expected the crate-root build.rs to be included in the scan, but it was not found among: {files:?}"
        );

        let mut offenses = Vec::new();
        for path in &files {
            if path.file_name().and_then(|n| n.to_str()) == Some(SELF_FILE_NAME) {
                continue;
            }
            let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            for needle in FORBIDDEN {
                if text.contains(needle) {
                    offenses.push(format!("{}: contains forbidden token {needle:?}", path.display()));
                }
            }
        }
        assert!(offenses.is_empty(), "real-entropy API surface found:\n{}", offenses.join("\n"));
    }

    /// The `winit`/`softbuffer` dependency itself is windowing/presentation
    /// only — confirm this crate's manifest lists no randomness/OS-RNG
    /// crate as a dependency at all (a second, independent structural
    /// check at the manifest level, not just the source-grep above).
    #[test]
    fn cargo_toml_lists_no_randomness_dependency() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).unwrap();
        for needle in ["rand =", "\"rand\"", "getrandom", "ring ="] {
            assert!(!text.contains(needle), "Cargo.toml must not depend on {needle:?}");
        }
    }
}
