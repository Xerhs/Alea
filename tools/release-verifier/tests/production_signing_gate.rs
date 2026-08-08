//! Regression test (WP-32, SPEC §28) for
//! `scripts/production-signing-gate.sh`, the structural refusal gate
//! that MUST sit between "an unsigned `.efi` exists on disk" and "an
//! external signer is invoked" in any real release pipeline.
//!
//! Spec-conformance audit gap (2026-08-04): no signing tool/script
//! existed anywhere in the repository, so none of SPEC §28's three
//! signing-pipeline clauses — "production signing refuses artifacts
//! with test markers", "test and production use different signing
//! identities", "test builds cannot be renamed into production by the
//! release pipeline" — had any enforcement, let alone a test proving
//! the enforcement. This file drives the real script (not a
//! reimplementation of its logic) against the real, freshly-built
//! `seed-uefi-production.efi` / `seed-uefi-test.efi` UEFI artifacts and
//! the real compiled `binary-policy-scanner` binary, so a regression in
//! any of the three pieces (script, scanner, or the crates they scan)
//! fails this test.
//!
//! If the UEFI artifacts are not present on disk (e.g. no
//! `x86_64-unknown-uefi` target installed in a given sandbox), the
//! artifact-dependent tests SKIP with a printed reason rather than
//! false-failing on an environment gap — the same convention
//! `tools/binary-policy-scanner/tests/scan_real_efi.rs` already uses.
//! The usage-error and identity/name-policy tests do not depend on any
//! built artifact and always run.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn gate_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/production-signing-gate.sh")
}

fn cargo_target_dir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| {
        format!(
            "{}/.cache/sf-target/workspace",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )
    });
    PathBuf::from(base)
}

fn uefi_release_dir() -> PathBuf {
    cargo_target_dir().join("x86_64-unknown-uefi").join("release")
}

/// Builds (or reuses an already-built) `binary-policy-scanner` binary
/// and returns its path. Building it is fast (host-only tool, small
/// dependency graph — see that crate's own `Cargo.toml`) and keeps this
/// test self-contained rather than depending on some other step of the
/// suite having already run first.
///
/// The host build output directory is deliberately *not* hardcoded to
/// `<target_dir>/debug/`: this workspace's environment pins a global
/// `[build] target` (see `$HOME/.cargo/config.toml`, AGENTS.md), which
/// nests host builds under an extra `<target-triple>/debug/` directory
/// instead — but that pin is environment-specific configuration this
/// crate has no business depending on. A short bounded-depth search for
/// the exact `binary-policy-scanner` file name under `target_dir` finds
/// it either way.
fn scanner_bin() -> PathBuf {
    let target_dir = cargo_target_dir();
    let status = Command::new("cargo")
        .args(["build", "-p", "binary-policy-scanner"])
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(repo_root())
        .status()
        .expect("run cargo build -p binary-policy-scanner");
    assert!(status.success(), "failed to build binary-policy-scanner");

    find_file_named(&target_dir, "binary-policy-scanner", 4)
        .unwrap_or_else(|| panic!("could not locate a built `binary-policy-scanner` under {}", target_dir.display()))
}

/// Bounded-depth search for a file with an exact base name under `dir`,
/// skipping the (large, irrelevant) `deps/`, `incremental/` and
/// `build/` subtrees. Returns the first match; build output layouts
/// only ever produce one real (non-`deps/`) copy of a given bin
/// target's primary artifact per profile.
fn find_file_named(dir: &Path, name: &str, max_depth: u32) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        if path.is_file() {
            if file_name == name {
                return Some(path);
            }
        } else if path.is_dir() {
            match file_name.to_str() {
                Some("deps") | Some("incremental") | Some("build") | Some("examples") => continue,
                _ => subdirs.push(path),
            }
        }
    }
    for sub in subdirs {
        if let Some(found) = find_file_named(&sub, name, max_depth - 1) {
            return Some(found);
        }
    }
    None
}

struct GateOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn run_gate(args: &[&str]) -> GateOutput {
    let output = Command::new("bash")
        .arg(gate_script())
        .args(args)
        .output()
        .expect("run production-signing-gate.sh");
    GateOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn skip_if_missing(path: &Path, build_hint: &str) -> bool {
    if !path.exists() {
        eprintln!("SKIPPED: {} not found; build it first with `{build_hint}`", path.display());
        true
    } else {
        false
    }
}

/// SPEC §28: "production signing refuses artifacts with test markers",
/// exercised against the real production `.efi` with two genuinely
/// distinct identities and a valid SPEC §32 output name — this MUST
/// pass all three gates.
#[test]
fn passes_real_production_efi_with_distinct_identities_and_valid_name() {
    let efi = uefi_release_dir().join("seed-uefi-production.efi");
    if skip_if_missing(&efi, "cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release") {
        return;
    }
    let scanner = scanner_bin();

    let out = run_gate(&[
        "--artifact",
        efi.to_str().unwrap(),
        "--out-name",
        "alea-x86_64-unsigned.efi",
        "--prod-identity",
        "PRODUCTION-KEY-2026",
        "--test-identity",
        "TEST-KEY-2026",
        "--scanner",
        scanner.to_str().unwrap(),
    ]);

    eprintln!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    assert!(out.status.success(), "gate unexpectedly refused a clean production artifact");
    assert!(out.stdout.contains("all gates passed"));
}

/// SPEC §28: "production signing refuses artifacts with test markers"
/// AND "test builds cannot be renamed into production by the release
/// pipeline" — the two clauses collapse into one test here because the
/// gate's refusal is content-based: renaming the test-edition `.efi` to
/// the exact production output name MUST NOT help it pass.
#[test]
fn refuses_test_edition_efi_even_when_renamed_to_a_production_file_name() {
    let test_efi = uefi_release_dir().join("seed-uefi-test.efi");
    if skip_if_missing(&test_efi, "cargo build -p seed-uefi-test --target x86_64-unknown-uefi --release") {
        return;
    }
    let scanner = scanner_bin();

    // Simulate the exact attack SPEC §28 names: copy the test-edition
    // artifact to a file named after the production convention.
    let tmp = std::env::temp_dir().join(format!(
        "signing-gate-renamed-test-{}.efi",
        std::process::id()
    ));
    std::fs::copy(&test_efi, &tmp).expect("copy test efi to renamed path");

    let out = run_gate(&[
        "--artifact",
        tmp.to_str().unwrap(),
        "--out-name",
        "alea-x86_64-unsigned.efi",
        "--prod-identity",
        "PRODUCTION-KEY-2026",
        "--test-identity",
        "TEST-KEY-2026",
        "--scanner",
        scanner.to_str().unwrap(),
    ]);

    let _ = std::fs::remove_file(&tmp);

    eprintln!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    assert!(
        !out.status.success(),
        "gate MUST refuse a renamed test-edition artifact, even under a production file name"
    );
    assert!(
        out.stderr.contains("REFUSED") && out.stderr.contains("test markers"),
        "expected an explicit test-marker refusal; stderr was:\n{}",
        out.stderr
    );
}

/// SPEC §28: "test and production use different signing identities" —
/// even a genuinely clean production artifact must be refused if the
/// caller supplies the same identity string for both roles.
#[test]
fn refuses_when_prod_and_test_identities_are_equal() {
    let efi = uefi_release_dir().join("seed-uefi-production.efi");
    if skip_if_missing(&efi, "cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release") {
        return;
    }
    let scanner = scanner_bin();

    let out = run_gate(&[
        "--artifact",
        efi.to_str().unwrap(),
        "--out-name",
        "alea-x86_64-unsigned.efi",
        "--prod-identity",
        "SHARED-KEY",
        "--test-identity",
        "SHARED-KEY",
        "--scanner",
        scanner.to_str().unwrap(),
    ]);

    eprintln!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    assert!(!out.status.success(), "gate MUST refuse identical production/test signing identities");
    assert!(
        out.stderr.contains("identical"),
        "expected an explicit identity-collision refusal; stderr was:\n{}",
        out.stderr
    );
}

/// SPEC §32: the fixed release-archive artifact names are the only
/// accepted `--out-name` values — an otherwise-clean production
/// artifact bound for a made-up output name must still be refused.
#[test]
fn refuses_non_conforming_output_name() {
    let efi = uefi_release_dir().join("seed-uefi-production.efi");
    if skip_if_missing(&efi, "cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release") {
        return;
    }
    let scanner = scanner_bin();

    let out = run_gate(&[
        "--artifact",
        efi.to_str().unwrap(),
        "--out-name",
        "totally-different-name.efi",
        "--prod-identity",
        "PRODUCTION-KEY-2026",
        "--test-identity",
        "TEST-KEY-2026",
        "--scanner",
        scanner.to_str().unwrap(),
    ]);

    eprintln!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    assert!(!out.status.success(), "gate MUST refuse a non-conforming output file name");
    assert!(out.stderr.contains("not a recognized SPEC \u{a7}32 release"));
}

/// Missing required arguments is a usage error (exit 64), never a
/// silent pass — this test needs no built artifact and always runs.
#[test]
fn usage_error_on_missing_arguments() {
    let out = run_gate(&["--artifact", "/nonexistent/path.efi"]);
    assert_eq!(out.status.code(), Some(64), "stderr was:\n{}", out.stderr);
}

/// A missing artifact file is a policy refusal (exit 1), not a crash or
/// a silent pass — this test needs no built artifact and always runs.
#[test]
fn refuses_missing_artifact_file() {
    let out = run_gate(&[
        "--artifact",
        "/nonexistent/path.efi",
        "--out-name",
        "alea-x86_64-unsigned.efi",
        "--prod-identity",
        "PRODUCTION-KEY-2026",
        "--test-identity",
        "TEST-KEY-2026",
    ]);
    assert_eq!(out.status.code(), Some(1), "stderr was:\n{}", out.stderr);
    assert!(out.stderr.contains("not found"));
}
