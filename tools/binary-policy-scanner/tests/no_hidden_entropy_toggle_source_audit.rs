//! Regression test (WP-30, SPEC §28) for: "the production UI has no
//! hidden keyboard sequence, command-line parameter, environment
//! variable or UEFI variable that changes entropy behavior."
//!
//! Spec-conformance audit finding (2026-08-04): prior evidence for this
//! clause was "grep across crates/seed-uefi-production/src and
//! crates/seed-platform-x86/src found no std::env, UEFI Variable-service,
//! or hidden-key dispatch code" — a real but ad hoc, one-off, human grep,
//! not a codified, CI-run regression test. This file turns that same
//! check into an executable test with a positive control (it fails
//! loudly against a synthetic fixture that DOES contain a forbidden
//! pattern, proving the check itself works, not just that today's
//! source tree happens to be clean) and a negative control (the real
//! production dependency-graph source trees).
//!
//! # Why source-tree scanning, not only the compiled artifact
//!
//! `tools/binary-policy-scanner`'s own binary scan (`src/main.rs`,
//! `FORBIDDEN_HIDDEN_TOGGLE_MARKERS`) checks the compiled
//! `x86_64-unknown-uefi` artifact for the same forbidden API identifiers
//! as literal byte sequences, and is the authoritative release gate (it
//! inspects what is actually linked into the shipped binary). This test
//! is a complementary, independent check at the source level: it does
//! not depend on a successful UEFI build existing on disk, runs on every
//! `cargo test -p binary-policy-scanner` regardless of target
//! availability, and catches the forbidden pattern even in code paths a
//! given compiler invocation might inline, rename or otherwise obscure
//! before the binary scan gets a chance to look at it.
//!
//! # Why `#![no_std]` alone is not asserted here as sufficient
//!
//! `std::env`/POSIX environment variables are structurally unreachable
//! from any `#![no_std]` crate (a compile error, not a runtime
//! property) — every crate in the production dependency graph
//! (`seed-uefi-production`, `seed-platform-x86`, `seed-gop-ui`,
//! `seed-flow`, `seed-selftest`, `seed-core`, `seed-protocol`,
//! `seed-derive`) is `#![no_std]`, and `ci.sh` already proves they
//! compile as such. That
//! is real evidence, but UEFI has no POSIX environment in the first
//! place — its nearest equivalents, UEFI Variable Services
//! (`GetVariable`/`SetVariable`) and `LoadedImageProtocol::load_options`
//! (UEFI's "command line"), are NOT ruled out by `no_std` and are
//! reachable from `no_std` code via the `uefi` crate. Those two, plus a
//! literal `std::env` reference (in case a future edit relaxes
//! `no_std`), are exactly what this test scans for.

use std::path::{Path, PathBuf};

/// Forbidden identifiers (SPEC §28). Case-sensitive, exact Rust API
/// names/snake_case forms — not bare English words — so this cannot
/// false-positive on ordinary prose the way a bare substring ban would
/// (see `tools/binary-policy-scanner/src/main.rs`'s own
/// `FORBIDDEN_EDITION_PHRASES` doc comment for the same reasoning
/// applied to a different check).
const FORBIDDEN_PATTERNS: &[&str] = &[
    "GetVariable",
    "SetVariable",
    "get_variable",
    "set_variable",
    "LoadOptions",
    "load_options",
    "std::env",
];

/// Production dependency-graph source roots (SPEC §9, §28 — every crate
/// `seed-uefi-production` depends on, directly or transitively, plus
/// itself). Paths are relative to the repository root.
const PRODUCTION_GRAPH_SRC_DIRS: &[&str] = &[
    "crates/seed-uefi-production/src",
    "crates/seed-platform-x86/src",
    "crates/seed-gop-ui/src",
    "crates/seed-flow/src",
    "crates/seed-selftest/src",
    "crates/seed-core/src",
    "crates/seed-protocol/src",
    "crates/seed-derive/src",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// One forbidden-pattern occurrence found while scanning.
struct Hit {
    file: PathBuf,
    line_no: usize,
    pattern: &'static str,
    line: String,
}

/// Recursively scans every `*.rs` file under `dir` for
/// [`FORBIDDEN_PATTERNS`], returning every occurrence found.
fn scan_dir(dir: &Path) -> Vec<Hit> {
    let mut hits = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            hits.extend(scan_dir(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (idx, line) in contents.lines().enumerate() {
                for pattern in FORBIDDEN_PATTERNS {
                    if line.contains(pattern) {
                        hits.push(Hit {
                            file: path.clone(),
                            line_no: idx + 1,
                            pattern,
                            line: line.trim().to_string(),
                        });
                    }
                }
            }
        }
    }
    hits
}

/// SPEC §28: no forbidden hidden-entropy-toggle API identifier anywhere
/// in the real production dependency-graph source trees.
#[test]
fn production_graph_source_has_no_hidden_entropy_toggle_apis() {
    let root = repo_root();
    let mut all_hits = Vec::new();
    for rel in PRODUCTION_GRAPH_SRC_DIRS {
        let dir = root.join(rel);
        assert!(dir.is_dir(), "expected production-graph source dir to exist: {}", dir.display());
        all_hits.extend(scan_dir(&dir));
    }

    if !all_hits.is_empty() {
        let mut msg = String::from(
            "SPEC §28 violation: found hidden-entropy-toggle API identifier(s) in the \
             production dependency graph:\n",
        );
        for hit in &all_hits {
            msg.push_str(&format!(
                "  {}:{}: {:?} in `{}`\n",
                hit.file.display(),
                hit.line_no,
                hit.pattern,
                hit.line
            ));
        }
        panic!("{msg}");
    }
}

/// Positive control: proves `scan_dir` actually detects a forbidden
/// pattern when one is present, so a passing
/// `production_graph_source_has_no_hidden_entropy_toggle_apis` above
/// means "verified absent," not "the scanner is silently inert."
#[test]
fn scan_dir_detects_a_synthetic_forbidden_pattern() {
    let work = std::env::temp_dir().join(format!(
        "sf-hidden-toggle-audit-fixture-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&work).expect("create fixture dir");
    std::fs::write(
        work.join("fixture.rs"),
        "fn maybe_toggle_entropy() {\n    let _ = uefi::runtime::get_variable(\"X\");\n}\n",
    )
    .expect("write fixture");

    let hits = scan_dir(&work);
    std::fs::remove_dir_all(&work).ok();

    assert!(!hits.is_empty(), "scan_dir failed to detect a synthetic forbidden pattern");
    assert!(hits.iter().any(|h| h.pattern == "get_variable"));
}
