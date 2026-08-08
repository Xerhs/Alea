//! Integration test (WP-30, SPEC §28): runs the real
//! `binary-policy-scanner` binary against the real, freshly-built
//! `x86_64-unknown-uefi` release artifacts of `seed-uefi-production` and
//! `seed-uefi-test`.
//!
//! `seed-uefi-production.efi` MUST pass (exit 0): required production
//! marker present, no forbidden marker found.
//!
//! `seed-uefi-test.efi` MUST fail (nonzero exit): it embeds the
//! `"UEFI TEST EDITION"` banner and the `"PUBLIC TEST PHRASE"` /
//! `"NEVER USE WITH FUNDS"` watermark banner (SPEC §4.2,
//! `crates/seed-uefi-test/src/main.rs`).
//!
//! Both artifacts must already exist on disk (built via `cargo build -p
//! <crate> --target x86_64-unknown-uefi` — with or without `--release`;
//! see [`find_uefi_artifact`] below for why both profiles are accepted)
//! under the shared `$CARGO_TARGET_DIR` before running this test; if the
//! sandbox has no network/toolchain access to build them, the test is
//! skipped (prints `SKIPPED`, exits without failing the suite) rather
//! than hanging or false-failing on an environment gap unrelated to the
//! scanner logic itself.
//!
//! # Why both `release/` and `debug/` are checked (SPEC §28, §36.2)
//!
//! `ci.sh` (WP-00) builds the two UEFI binaries with plain `cargo build
//! -p <crate> --target x86_64-unknown-uefi` — no `--release` flag — so
//! the artifacts CI actually produces land in the `debug/` profile
//! directory, never `release/`. An earlier version of this test only
//! ever looked in `release/`, which meant it silently printed `SKIPPED`
//! and reported `ok` on every real CI run: the scanner binary was never
//! actually invoked against a CI-built artifact, so this check provided
//! zero real enforcement despite appearing to exist (SPEC §28: "A
//! release is rejected if reviewers cannot demonstrate that
//! deterministic entropy is structurally absent" — an always-skipping
//! test cannot demonstrate that). Checking `release/` first (preferring
//! the more representative optimized build when both are present, e.g.
//! for a local release rehearsal) and falling back to `debug/` means
//! `cargo test --workspace` after `ci.sh`'s own build steps exercises
//! the real scanner against the real artifact CI just produced.
//!
//! # Self-building when the artifact is missing
//!
//! `ci.sh`'s existing step order runs `cargo test --workspace` *before*
//! its two `cargo build -p seed-uefi-{test,production} --target
//! x86_64-unknown-uefi` steps, so on a clean checkout the artifact this
//! test needs does not exist yet at the time this test would otherwise
//! run — reordering `ci.sh` is outside this crate's ownership
//! (`IMPLEMENTATION_MAP.md` §6: `ci.sh` is a WP-00 file). To make this
//! check actually run under the *existing*, unmodified `ci.sh` — rather
//! than silently reporting `ok` forever, which is the exact failure mode
//! that let this check go unenforced — [`find_or_build_uefi_artifact`]
//! builds the missing crate itself (the same `cargo build -p <crate>
//! --target x86_64-unknown-uefi` command `ci.sh` runs a few lines later)
//! before falling back to `SKIPPED`. A build failure (e.g. no toolchain
//! available at all) still degrades to `SKIPPED` rather than a false
//! failure unrelated to the scanner's own logic.

use std::path::PathBuf;
use std::process::Command;

/// Locate the shared UEFI target directory (without the profile
/// subdirectory). Honors `CARGO_TARGET_DIR` exactly like every other
/// build in this workspace (see `AGENTS.md`), falling back to the
/// workspace-default `$HOME/.cache/sf-target/workspace` used by
/// `.cargo/config.toml` when unset.
fn uefi_target_dir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| {
        format!(
            "{}/.cache/sf-target/workspace",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )
    });
    PathBuf::from(base).join("x86_64-unknown-uefi")
}

/// Find `<crate>.efi` under either `<base>/release/` or `<base>/debug/`,
/// preferring `release/` when both exist. Returns `None` if neither
/// profile directory contains the artifact. Split out from
/// [`find_uefi_artifact`] (which supplies the real `<base>` from
/// [`uefi_target_dir`]) purely so this profile-preference/fallback logic
/// — the actual fix for the "always SKIPPED" regression described in the
/// module doc — has a unit test independent of any real Cargo build.
fn find_uefi_artifact_under(base: &std::path::Path, crate_efi_name: &str) -> Option<PathBuf> {
    for profile in ["release", "debug"] {
        let candidate = base.join(profile).join(crate_efi_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Find `<crate>.efi` under either the `release/` or `debug/` profile
/// directory of the real shared UEFI target dir, preferring `release/`
/// when both exist. Returns `None` if neither profile has produced the
/// artifact yet.
fn find_uefi_artifact(crate_efi_name: &str) -> Option<PathBuf> {
    find_uefi_artifact_under(&uefi_target_dir(), crate_efi_name)
}

/// [`find_uefi_artifact`], but if the artifact is missing, first tries
/// building `crate_name` for `x86_64-unknown-uefi` (see module doc "Self-
/// building when the artifact is missing") and looks again. Returns
/// `None` only when the artifact is still missing after a build attempt
/// (e.g. no Rust UEFI target installed in this environment) — the caller
/// treats that as SKIPPED, never a failure.
fn find_or_build_uefi_artifact(crate_name: &str, crate_efi_name: &str) -> Option<PathBuf> {
    if let Some(p) = find_uefi_artifact(crate_efi_name) {
        return Some(p);
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", crate_name, "--target", "x86_64-unknown-uefi"])
        .status();
    match status {
        Ok(s) if s.success() => find_uefi_artifact(crate_efi_name),
        _ => None,
    }
}

fn scanner_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_binary-policy-scanner"))
}

#[test]
fn production_efi_passes_policy_scan() {
    let Some(efi) = find_or_build_uefi_artifact("seed-uefi-production", "seed-uefi-production.efi") else {
        eprintln!(
            "SKIPPED: seed-uefi-production.efi not found under {} (release/ or debug/) and could not be built; build it first with `cargo build -p seed-uefi-production --target x86_64-unknown-uefi`",
            uefi_target_dir().display()
        );
        return;
    };

    let output = Command::new(scanner_bin())
        .arg(&efi)
        .output()
        .expect("run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("{stdout}");
    assert!(
        output.status.success(),
        "production .efi must PASS the policy scan; scanner output:\n{stdout}"
    );
    assert!(stdout.contains("production marker symbol present: true"));
    assert!(stdout.contains("production marker bytes present:  true"));
}

#[test]
fn test_edition_efi_fails_policy_scan() {
    let Some(efi) = find_or_build_uefi_artifact("seed-uefi-test", "seed-uefi-test.efi") else {
        eprintln!(
            "SKIPPED: seed-uefi-test.efi not found under {} (release/ or debug/) and could not be built; build it first with `cargo build -p seed-uefi-test --target x86_64-unknown-uefi`",
            uefi_target_dir().display()
        );
        return;
    };

    let output = Command::new(scanner_bin())
        .arg(&efi)
        .output()
        .expect("run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("{stdout}");
    assert!(
        !output.status.success(),
        "seed-uefi-test.efi MUST FAIL the policy scan (contains watermark/test banner); scanner output:\n{stdout}"
    );
    assert!(
        stdout.contains("PUBLIC TEST PHRASE") || stdout.contains("UEFI TEST EDITION"),
        "expected the test-edition banner literals to be flagged; got:\n{stdout}"
    );
}

/// Regression test for the exact bug described in the module doc
/// ("Why both `release/` and `debug/` are checked"): before this fix,
/// this helper only ever looked in `release/`, so a `debug/`-only build
/// tree (what `cargo build -p <crate> --target x86_64-unknown-uefi`
/// without `--release` actually produces) was never found and the
/// integration tests above silently reported `ok` without ever invoking
/// the scanner. Uses real temp directories and empty placeholder files —
/// no real `.efi` payload or cargo invocation needed, since only the
/// path-resolution/profile-preference behavior is under test here.
#[test]
fn find_uefi_artifact_under_prefers_release_but_falls_back_to_debug() {
    let base = std::env::temp_dir().join(format!(
        "scan-real-efi-path-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let debug_dir = base.join("debug");
    let release_dir = base.join("release");
    std::fs::create_dir_all(&debug_dir).unwrap();
    std::fs::create_dir_all(&release_dir).unwrap();

    // Neither profile has the artifact yet: not found.
    assert_eq!(find_uefi_artifact_under(&base, "seed-uefi-production.efi"), None);

    // Only `debug/` has it (the shape `ci.sh`'s non-`--release` build
    // steps actually produce): MUST be found there, not silently missed.
    std::fs::write(debug_dir.join("seed-uefi-production.efi"), b"debug-build-bytes").unwrap();
    let found = find_uefi_artifact_under(&base, "seed-uefi-production.efi")
        .expect("must find the debug-profile artifact when release/ is empty");
    assert_eq!(found, debug_dir.join("seed-uefi-production.efi"));

    // Once `release/` also has it, `release/` must win (more
    // representative of what actually ships).
    std::fs::write(release_dir.join("seed-uefi-production.efi"), b"release-build-bytes").unwrap();
    let found = find_uefi_artifact_under(&base, "seed-uefi-production.efi")
        .expect("must find the artifact once release/ has it too");
    assert_eq!(found, release_dir.join("seed-uefi-production.efi"));

    std::fs::remove_dir_all(&base).ok();
}
