//! Release-archive completeness check (WP-32, SPEC §32, §37).
//!
//! SPEC §32 names an exact, closed list of files every stable release
//! archive must contain (the block immediately following "Every stable
//! release contains:"), and separately requires that "The desktop test
//! edition is released separately and MUST NOT appear in the production
//! release archive or on the production USB image" (§4.3 cross-ref).
//! SPEC §37's "Release integrity" section restates the same two
//! requirements as MUSTs: "SBOM and audit status are published" and
//! "The desktop test edition is distributed separately from the
//! production image".
//!
//! [`check_manifest`] is the automatable half of that: given a candidate
//! release directory, it reports which of the required files are
//! present/missing, and flags any file whose name matches a known
//! desktop-test-edition naming pattern. It does **not** and cannot
//! verify that the *contents* of e.g. `AUDIT-STATUS.md` are accurate, or
//! that `SIGNING-GOVERNANCE.md` describes a real, followed process —
//! those are the human/organizational parts of SPEC §32 this crate's own
//! module doc (`lib.rs`) already documents as out of scope for automated
//! tooling. What it *does* prove mechanically is the thing a spec-
//! conformance audit can otherwise only eyeball: that a release cannot
//! be assembled (per this tool's gate) missing one of the fifteen named
//! files, or carrying the desktop test edition alongside the production
//! artifacts.
#![forbid(unsafe_code)]

use std::path::Path;

/// The exact release-artifact file list SPEC §32 requires ("Every stable
/// release contains:" — the fenced block immediately below that
/// sentence). Order matches the spec text. This is the FULL fifteen-file
/// list (core files + signature files); see [`SIGNATURE_FILES`] for the
/// subset that a legitimately UNSIGNED beta release lacks.
pub const REQUIRED_RELEASE_FILES: &[&str] = &[
    "alea-x86_64-unsigned.efi",
    "alea-x86_64-signed.efi",
    "alea-x86_64-usb.img",
    "alea-source.tar.gz",
    "SHA256SUMS",
    "SHA256SUMS.minisig",
    "SBOM.spdx.json",
    "ENTROPY-POLICY.txt",
    "DENYLIST.txt",
    "DEPENDENCY-AUDIT.txt",
    "REPRODUCING.md",
    "VERIFYING-MEDIA.md",
    "COMPATIBILITY.md",
    "AUDIT-STATUS.md",
    "SIGNING-GOVERNANCE.md",
];

/// The two files in [`REQUIRED_RELEASE_FILES`] that only a *signed*
/// release can legitimately produce. An honest UNSIGNED experimental
/// beta (`scripts/build-release.sh` without `--minisign-key`) cannot
/// contain these — there is no key to sign with — so
/// [`check_manifest`]'s `require_signatures: false` mode treats their
/// absence as OK while still requiring every other file, including the
/// plain `SHA256SUMS` checksums themselves (only the detached
/// `.minisig` signature over them is optional).
pub const SIGNATURE_FILES: &[&str] = &["alea-x86_64-signed.efi", "SHA256SUMS.minisig"];

/// The always-required subset of [`REQUIRED_RELEASE_FILES`]: every named
/// file except the two [`SIGNATURE_FILES`]. Required in both signed and
/// unsigned modes.
#[must_use]
pub fn core_required_files() -> Vec<&'static str> {
    REQUIRED_RELEASE_FILES
        .iter()
        .copied()
        .filter(|f| !SIGNATURE_FILES.contains(f))
        .collect()
}

/// Substrings that, if found (case-insensitively) in a release
/// directory entry's file name, identify it as belonging to the desktop
/// test edition (SPEC §4.3, `crates/seed-desktop-test`) rather than the
/// production release. SPEC §32/§37: the desktop test edition "MUST NOT
/// appear in the production release archive".
///
/// Matches the crate's own package/binary name conventions
/// (`crates/seed-desktop-test/Cargo.toml`: `name = "seed-desktop-test"`,
/// binary name `seed-desktop-test`) under both hyphen and underscore
/// spelling (Cargo emits underscored artifact names on some platforms),
/// plus the on-screen banner text the crate embeds
/// (`crates/seed-desktop-test/src/main.rs`) in case a maintainer renames
/// the shipped file but not its contents.
const FORBIDDEN_DESKTOP_TEST_MARKERS: &[&str] = &[
    "desktop-test",
    "desktop_test",
    "seed-desktop-test",
    "seed_desktop_test",
];

/// One release-manifest requirement's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestEntry {
    /// The required file is present in the release directory.
    Present { filename: &'static str },
    /// The required file is missing.
    Missing { filename: &'static str },
}

impl ManifestEntry {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, ManifestEntry::Present { .. })
    }
}

/// Full result of [`check_manifest`] (SPEC §32, §37).
#[derive(Debug, Clone)]
pub struct ManifestReport {
    /// One entry per [`REQUIRED_RELEASE_FILES`] name, in the same order
    /// — including the two [`SIGNATURE_FILES`], whose presence/absence
    /// is reported here regardless of `require_signatures` (this field
    /// is a structural fact about the directory, not a verdict).
    pub required: Vec<ManifestEntry>,
    /// File names actually present in the release directory that match a
    /// [`FORBIDDEN_DESKTOP_TEST_MARKERS`] pattern — i.e. desktop-test-
    /// edition artifacts that must not ship alongside a production
    /// release. Empty when clean.
    pub forbidden_present: Vec<String>,
    /// Whether this report was produced with `require_signatures: true`
    /// (a signed release; [`SIGNATURE_FILES`] must be present) or
    /// `false` (an honest unsigned beta; their absence is OK). Drives
    /// [`ManifestReport::is_complete`].
    pub require_signatures: bool,
}

impl ManifestReport {
    /// True only when every *required-in-this-mode* file is present AND
    /// no forbidden desktop-test-edition artifact was found.
    ///
    /// The thirteen core files (everything in [`REQUIRED_RELEASE_FILES`]
    /// except [`SIGNATURE_FILES`]) are always required. The two
    /// signature files (`alea-x86_64-signed.efi`,
    /// `SHA256SUMS.minisig`) are required only when this report was
    /// built with `require_signatures: true`; when built with `false`
    /// (unsigned mode) their absence does not fail completeness — but
    /// their presence, if they happen to be there, is still fine.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.forbidden_present.is_empty()
            && self.required.iter().all(|entry| match entry {
                ManifestEntry::Present { .. } => true,
                ManifestEntry::Missing { filename } => {
                    !self.require_signatures && SIGNATURE_FILES.contains(filename)
                }
            })
    }

    /// The subset of [`REQUIRED_RELEASE_FILES`] that are missing, in
    /// spec order. This is a structural fact (which named files are
    /// literally absent) and is reported the same regardless of
    /// `require_signatures` — see [`ManifestReport::is_complete`] for
    /// the mode-aware pass/fail verdict.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        self.required
            .iter()
            .filter_map(|e| match e {
                ManifestEntry::Missing { filename } => Some(*filename),
                ManifestEntry::Present { .. } => None,
            })
            .collect()
    }
}

/// Checks `release_dir` against [`REQUIRED_RELEASE_FILES`] and
/// [`FORBIDDEN_DESKTOP_TEST_MARKERS`] (SPEC §32, §37). Reads only
/// directory entry names — never file contents — so this is a cheap,
/// purely structural check that never needs a real build to run
/// (contrast [`crate::verify_sha256sums`], which needs real file bytes).
///
/// `require_signatures` selects signed vs. unsigned release mode (see
/// [`SIGNATURE_FILES`] and [`ManifestReport::is_complete`]): pass `true`
/// for a release that claims to be signed (a signed release still needs
/// `alea-x86_64-signed.efi` and `SHA256SUMS.minisig`), `false` for a
/// legitimately UNSIGNED beta, where those two files are expected to be
/// absent. Every other file in [`REQUIRED_RELEASE_FILES`] — including
/// the plain `SHA256SUMS` checksums themselves — is required in both
/// modes; only the detached `.minisig` *signature* is optional.
///
/// A release directory that does not exist, or cannot be listed, is
/// treated as containing none of the required files and none of the
/// forbidden ones (every required entry reports [`ManifestEntry::Missing`]).
#[must_use]
pub fn check_manifest(release_dir: &Path, require_signatures: bool) -> ManifestReport {
    let entries: Vec<String> = std::fs::read_dir(release_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();

    let required = REQUIRED_RELEASE_FILES
        .iter()
        .map(|&filename| {
            if entries.iter().any(|e| e == filename) {
                ManifestEntry::Present { filename }
            } else {
                ManifestEntry::Missing { filename }
            }
        })
        .collect();

    let forbidden_present = entries
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            FORBIDDEN_DESKTOP_TEST_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        })
        .cloned()
        .collect();

    ManifestReport {
        required,
        forbidden_present,
        require_signatures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "release-verifier-manifest-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"placeholder").unwrap();
    }

    /// Empty directory: every required file is missing, none present.
    /// Checked in signed mode (require_signatures: true) — the strict
    /// case where all fifteen files are required.
    #[test]
    fn empty_dir_reports_all_fifteen_files_missing() {
        let dir = fresh_dir("empty");
        let report = check_manifest(&dir, true);
        assert!(!report.is_complete());
        assert_eq!(report.missing().len(), REQUIRED_RELEASE_FILES.len());
        assert!(report.forbidden_present.is_empty());
    }

    /// SPEC §32: a release directory containing every named file, and
    /// nothing forbidden, MUST report complete. This is the direct
    /// regression test for the audit finding "no structural check that
    /// the 13 [sic; spec text now lists 15] named release files are all
    /// present" — before this module existed, nothing in-repo checked
    /// this at all. Checked in signed mode: a fully-complete directory
    /// (signature files included) must pass regardless of mode — also
    /// covered by `fully_complete_directory_passes_both_modes` below.
    #[test]
    fn full_release_directory_is_reported_complete() {
        let dir = fresh_dir("full");
        for f in REQUIRED_RELEASE_FILES {
            touch(&dir, f);
        }
        let report = check_manifest(&dir, true);
        assert!(
            report.is_complete(),
            "expected a directory with every required file to be complete, missing: {:?}",
            report.missing()
        );
        assert!(report.missing().is_empty());
    }

    /// Missing exactly one required (non-signature) file must be caught
    /// and named, and must fail completeness in BOTH signed and
    /// unsigned mode — this file is one of the thirteen core files, not a
    /// signature file, so it is never optional.
    #[test]
    fn missing_single_file_is_named_precisely() {
        let dir = fresh_dir("missing-one");
        for f in REQUIRED_RELEASE_FILES {
            if *f != "SIGNING-GOVERNANCE.md" {
                touch(&dir, f);
            }
        }
        let report_signed = check_manifest(&dir, true);
        assert!(!report_signed.is_complete());
        assert_eq!(report_signed.missing(), vec!["SIGNING-GOVERNANCE.md"]);

        let report_unsigned = check_manifest(&dir, false);
        assert!(
            !report_unsigned.is_complete(),
            "a missing core file must still fail completeness in unsigned mode"
        );
        assert_eq!(report_unsigned.missing(), vec!["SIGNING-GOVERNANCE.md"]);
    }

    /// SPEC §32/§37/§4.3: a desktop-test-edition artifact sitting in the
    /// same directory as an otherwise-complete production release MUST
    /// be flagged, even though every required production file is also
    /// present.
    #[test]
    fn desktop_test_edition_artifact_present_fails_even_if_otherwise_complete() {
        let dir = fresh_dir("desktop-test-present");
        for f in REQUIRED_RELEASE_FILES {
            touch(&dir, f);
        }
        touch(&dir, "seed-desktop-test");
        let report = check_manifest(&dir, true);
        assert!(
            !report.is_complete(),
            "a desktop-test-edition artifact in the release dir must fail the manifest check"
        );
        assert_eq!(report.forbidden_present, vec!["seed-desktop-test".to_string()]);
    }

    /// Underscore-spelled and differently-cased desktop-test artifact
    /// names must also be caught (Cargo/platform naming variance).
    #[test]
    fn desktop_test_marker_matching_is_case_insensitive_and_covers_underscore_spelling() {
        let dir = fresh_dir("desktop-test-variants");
        touch(&dir, "SEED_DESKTOP_TEST.exe");
        touch(&dir, "some-Desktop-Test-bundle.tar.gz");
        let report = check_manifest(&dir, true);
        assert_eq!(report.forbidden_present.len(), 2);
    }

    /// A nonexistent release directory must not panic, and is correctly
    /// treated as missing everything.
    #[test]
    fn nonexistent_release_dir_does_not_panic() {
        let dir = std::env::temp_dir().join("release-verifier-manifest-test-does-not-exist-xyz");
        let report = check_manifest(&dir, true);
        assert!(!report.is_complete());
        assert_eq!(report.missing().len(), REQUIRED_RELEASE_FILES.len());
    }

    /// An "unsigned-complete" release directory — the thirteen core files
    /// present, `SHA256SUMS` itself included, but neither
    /// `alea-x86_64-signed.efi` nor `SHA256SUMS.minisig` present — MUST
    /// pass with `require_signatures: false` (an honest unsigned beta)
    /// and MUST FAIL with `require_signatures: true` (a release that
    /// claims to be signed still needs the signature files). This is
    /// the direct regression test for `--unsigned` mode.
    #[test]
    fn unsigned_complete_directory_passes_unsigned_and_fails_signed() {
        let dir = fresh_dir("unsigned-complete");
        for f in core_required_files() {
            touch(&dir, f);
        }

        let unsigned_report = check_manifest(&dir, false);
        assert!(
            unsigned_report.is_complete(),
            "an unsigned release with all 13 core files and no signature files must pass \
             require_signatures: false, missing: {:?}",
            unsigned_report.missing()
        );
        // Still honest about what's structurally absent.
        assert_eq!(unsigned_report.missing(), SIGNATURE_FILES.to_vec());

        let signed_report = check_manifest(&dir, true);
        assert!(
            !signed_report.is_complete(),
            "the same directory must FAIL require_signatures: true — signature files are \
             genuinely missing"
        );
        assert_eq!(signed_report.missing(), SIGNATURE_FILES.to_vec());
    }

    /// A fully-complete directory (all fifteen files, including both
    /// signature files) MUST pass in both modes: unsigned mode never
    /// penalizes signature files that happen to be present.
    #[test]
    fn fully_complete_directory_passes_both_modes() {
        let dir = fresh_dir("fully-complete-both-modes");
        for f in REQUIRED_RELEASE_FILES {
            touch(&dir, f);
        }

        let unsigned_report = check_manifest(&dir, false);
        assert!(
            unsigned_report.is_complete(),
            "a fully-complete directory must pass require_signatures: false too"
        );

        let signed_report = check_manifest(&dir, true);
        assert!(
            signed_report.is_complete(),
            "a fully-complete directory must pass require_signatures: true"
        );
    }

    /// Unsigned mode must still require `SHA256SUMS` itself (the plain
    /// checksums) — only the detached `.minisig` *signature* over them
    /// is optional. A directory missing `SHA256SUMS` but present for
    /// every other core file must fail even with require_signatures:
    /// false.
    #[test]
    fn unsigned_mode_still_requires_plain_sha256sums() {
        let dir = fresh_dir("unsigned-missing-sha256sums");
        for f in core_required_files() {
            if f != "SHA256SUMS" {
                touch(&dir, f);
            }
        }
        let report = check_manifest(&dir, false);
        assert!(
            !report.is_complete(),
            "SHA256SUMS itself must remain required even in unsigned mode"
        );
        assert!(report.missing().contains(&"SHA256SUMS"));
    }
}
