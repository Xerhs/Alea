//! License-inventory generator (WP-29, SPEC §31, §32).
//!
//! SPEC §31: "Every dependency requires: ... license review" and "The
//! release MUST include: `Cargo.lock`; SBOM; license inventory;
//! dependency-audit report; ...". Before this module, no tool anywhere in
//! the repository produced a license inventory at all (spec-conformance
//! audit finding, 2026-08-04, paired with the SBOM finding
//! `sbom.rs`'s own module doc already fixed).
//!
//! # Where license data comes from
//!
//! `Cargo.lock` itself carries no license metadata (verified against
//! this workspace's real lockfile format — only `name`/`version`/
//! `source`/`checksum`/`dependencies` appear per `[[package]]` block).
//! Each registry-sourced crate's own `Cargo.toml` DOES carry a `license`
//! (SPDX expression) or `license-file` field, and `cargo` already
//! extracts every registry dependency's full source, including its
//! `Cargo.toml`, into `$CARGO_HOME/registry/src/<index>/<name>-<version>/`
//! as a normal side effect of building this workspace at all — so
//! [`resolve_license`] reads the *real* declared license directly from
//! that already-present extracted source, rather than hand-maintaining a
//! separate license table that could silently drift from what a
//! dependency actually declares. A package this function cannot find a
//! source directory for is reported [`LicenseSource::Unknown`] — never
//! guessed or defaulted to something reassuring.
//!
//! Path/workspace-member packages (no `source` field in `Cargo.lock` —
//! this project's own crates and tools) are reported under this
//! project's own declared license (root `Cargo.toml`'s `[workspace.
//! package] license = "MIT OR Apache-2.0"`, passed in by the caller as
//! `own_license` rather than hard-coded here, so this module does not
//! need write access to that read-only-to-other-WPs root file to stay in
//! sync with it — [`crate::sbom`]'s own module doc gives the same
//! `IMPLEMENTATION_MAP.md` §6 reasoning for reusing `Cargo.lock` as the
//! single source of truth rather than re-deriving package identity by
//! hand).
//!
//! # Determinism (SPEC §32)
//!
//! Same discipline as `sbom.rs`: entries sorted by `(name, version)`
//! regardless of `Cargo.lock`'s own on-disk order or filesystem
//! directory-listing order, and no wall-clock/random content.

use crate::sbom::{parse_cargo_lock, LockParseError, LockedPackage};
use std::path::PathBuf;

/// Where a package's license information came from, and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseSource {
    /// This project's own path/workspace-member crate — license is this
    /// workspace's own declared `[workspace.package] license`.
    WorkspaceMember(String),
    /// The dependency's own `Cargo.toml` `license` field (an SPDX
    /// expression, e.g. `"MIT OR Apache-2.0"`), found and read directly.
    Declared(String),
    /// The dependency declares a `license-file` (no SPDX `license`
    /// field) — the file's name is recorded; this module does not read
    /// or summarize that file's contents.
    SeeLicenseFile(String),
    /// No extracted source directory for this exact `name`-`version` was
    /// found under any of the searched roots, so no license claim can be
    /// made. Never silently treated as "probably fine".
    Unknown,
}

impl LicenseSource {
    /// Rendered form for the inventory table — never fabricates a
    /// license string for [`LicenseSource::Unknown`].
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            LicenseSource::WorkspaceMember(l) | LicenseSource::Declared(l) => l.clone(),
            LicenseSource::SeeLicenseFile(f) => format!("SEE LICENSE FILE: {f}"),
            LicenseSource::Unknown => "UNKNOWN (source not found locally)".to_string(),
        }
    }
}

/// One row of the generated license inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseEntry {
    pub name: String,
    pub version: String,
    pub license: LicenseSource,
}

/// Extracts a top-level `key = "value"` field from a `Cargo.toml`'s
/// `[package]` table. Deliberately simple (same hand-rolled-reader
/// reasoning as `sbom.rs`'s own module doc): stops at the first `[`
/// table header after `[package]` closes, since `license`/`license-file`
/// are always direct `[package]` fields, never nested.
fn extract_package_field(cargo_toml_contents: &str, key: &str) -> Option<String> {
    let mut in_package = false;
    for raw_line in cargo_toml_contents.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim();
        if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
            return Some(inner.to_string());
        }
    }
    None
}

/// Finds the extracted source directory for `pkg` (`<name>-<version>/`)
/// under any of `registry_src_dirs`, in order, returning the first hit.
fn find_extracted_source_dir(pkg: &LockedPackage, registry_src_dirs: &[PathBuf]) -> Option<PathBuf> {
    let dirname = format!("{}-{}", pkg.name, pkg.version);
    registry_src_dirs.iter().map(|root| root.join(&dirname)).find(|candidate| candidate.is_dir())
}

/// Resolves one package's license (see module doc for the full
/// resolution rule).
#[must_use]
pub fn resolve_license(pkg: &LockedPackage, registry_src_dirs: &[PathBuf], own_license: &str) -> LicenseSource {
    if pkg.source.is_none() {
        // No `source` field: a path/workspace-member crate of this
        // project (see module doc).
        return LicenseSource::WorkspaceMember(own_license.to_string());
    }
    let Some(src_dir) = find_extracted_source_dir(pkg, registry_src_dirs) else {
        return LicenseSource::Unknown;
    };
    let manifest_path = src_dir.join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(&manifest_path) else {
        return LicenseSource::Unknown;
    };
    if let Some(license) = extract_package_field(&contents, "license") {
        return LicenseSource::Declared(license);
    }
    if let Some(file) = extract_package_field(&contents, "license-file") {
        return LicenseSource::SeeLicenseFile(file);
    }
    LicenseSource::Unknown
}

/// Builds the full, sorted license inventory for every package in
/// `cargo_lock_contents`.
///
/// # Errors
///
/// [`LockParseError`] if `cargo_lock_contents` cannot be parsed (see
/// [`crate::sbom::parse_cargo_lock`]).
pub fn build_license_inventory(cargo_lock_contents: &str, registry_src_dirs: &[PathBuf], own_license: &str) -> Result<Vec<LicenseEntry>, LockParseError> {
    let packages = parse_cargo_lock(cargo_lock_contents)?;
    let mut entries: Vec<LicenseEntry> = packages
        .iter()
        .map(|pkg| LicenseEntry {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            license: resolve_license(pkg, registry_src_dirs, own_license),
        })
        .collect();
    entries.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(entries)
}

/// Renders a [`LicenseEntry`] list as a deterministic Markdown table
/// (SPEC §32 determinism: identical input always produces identical
/// output, since [`build_license_inventory`] already sorts by
/// `(name, version)`).
#[must_use]
pub fn render_markdown(entries: &[LicenseEntry]) -> String {
    let mut out = String::new();
    out.push_str("# Alea license inventory (SPEC §31)\n\n");
    out.push_str("| Package | Version | License |\n");
    out.push_str("| --- | --- | --- |\n");
    for e in entries {
        out.push_str("| ");
        out.push_str(&e.name);
        out.push_str(" | ");
        out.push_str(&e.version);
        out.push_str(" | ");
        out.push_str(&e.license.display());
        out.push_str(" |\n");
    }
    out
}

/// The default set of local registry-source roots to search, derived
/// from `CARGO_HOME` (falling back to `~/.cargo` per Cargo's own
/// documented default) — every subdirectory of `registry/src/` (one per
/// registry index, e.g. `index.crates.io-<hash>`) is searched, since the
/// exact hash suffix is not a stable constant.
#[must_use]
pub fn default_registry_src_dirs() -> Vec<PathBuf> {
    let cargo_home = std::env::var("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".cargo")
    });
    let src_root = cargo_home.join("registry").join("src");
    std::fs::read_dir(&src_root)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("license-inventory-test-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fake_crate(root: &Path, name: &str, version: &str, manifest_body: &str) {
        let dir = root.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), manifest_body).unwrap();
    }

    const SAMPLE_LOCK: &str = r#"
[[package]]
name = "declared-license-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "license-file-crate"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "not-locally-extracted-crate"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "seed-core"
version = "0.1.0"
"#;

    fn make_fixture_registry() -> PathBuf {
        let root = fresh_dir("registry");
        write_fake_crate(&root, "declared-license-crate", "1.0.0", "[package]\nname = \"declared-license-crate\"\nversion = \"1.0.0\"\nlicense = \"MIT OR Apache-2.0\"\n");
        write_fake_crate(&root, "license-file-crate", "2.0.0", "[package]\nname = \"license-file-crate\"\nversion = \"2.0.0\"\nlicense-file = \"LICENSE.txt\"\n");
        root
    }

    #[test]
    fn workspace_member_with_no_source_gets_own_license() {
        let entries = build_license_inventory(SAMPLE_LOCK, &[], "MIT OR Apache-2.0").unwrap();
        let seed_core = entries.iter().find(|e| e.name == "seed-core").unwrap();
        assert_eq!(seed_core.license, LicenseSource::WorkspaceMember("MIT OR Apache-2.0".to_string()));
    }

    #[test]
    fn registry_package_with_declared_license_is_read_from_its_own_manifest() {
        let registry = make_fixture_registry();
        let entries = build_license_inventory(SAMPLE_LOCK, &[registry], "MIT OR Apache-2.0").unwrap();
        let e = entries.iter().find(|e| e.name == "declared-license-crate").unwrap();
        assert_eq!(e.license, LicenseSource::Declared("MIT OR Apache-2.0".to_string()));
    }

    #[test]
    fn registry_package_with_license_file_field_is_reported_as_such() {
        let registry = make_fixture_registry();
        let entries = build_license_inventory(SAMPLE_LOCK, &[registry], "MIT OR Apache-2.0").unwrap();
        let e = entries.iter().find(|e| e.name == "license-file-crate").unwrap();
        assert_eq!(e.license, LicenseSource::SeeLicenseFile("LICENSE.txt".to_string()));
    }

    #[test]
    fn registry_package_with_no_locally_extracted_source_is_unknown_never_guessed() {
        let registry = make_fixture_registry();
        let entries = build_license_inventory(SAMPLE_LOCK, &[registry], "MIT OR Apache-2.0").unwrap();
        let e = entries.iter().find(|e| e.name == "not-locally-extracted-crate").unwrap();
        assert_eq!(e.license, LicenseSource::Unknown);
    }

    #[test]
    fn entries_are_sorted_by_name_then_version_regardless_of_lock_order() {
        let entries = build_license_inventory(SAMPLE_LOCK, &[], "MIT").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn markdown_rendering_includes_every_package_and_never_fabricates_unknown() {
        let registry = make_fixture_registry();
        let entries = build_license_inventory(SAMPLE_LOCK, &[registry], "MIT OR Apache-2.0").unwrap();
        let md = render_markdown(&entries);
        assert!(md.contains("declared-license-crate"));
        assert!(md.contains("MIT OR Apache-2.0"));
        assert!(md.contains("SEE LICENSE FILE: LICENSE.txt"));
        assert!(md.contains("UNKNOWN (source not found locally)"));
        assert!(md.contains("seed-core"));
    }

    #[test]
    fn rendering_is_byte_identical_across_two_runs() {
        let registry = make_fixture_registry();
        let a = render_markdown(&build_license_inventory(SAMPLE_LOCK, &[registry.clone()], "MIT").unwrap());
        let b = render_markdown(&build_license_inventory(SAMPLE_LOCK, &[registry], "MIT").unwrap());
        assert_eq!(a, b);
    }

    // ========================================================================
    // Real-environment check: against this workspace's actual Cargo.lock
    // and the real local Cargo registry source cache, a handful of known,
    // stable, well-known dependencies' real declared licenses must be
    // resolved correctly. Skips gracefully (never fails the suite) if the
    // registry source cache is not present in this environment — this
    // check exercises real local data, not a network fetch.
    // ========================================================================

    #[test]
    fn real_workspace_lockfile_resolves_known_dependency_licenses_from_the_real_registry_cache() {
        let dirs = default_registry_src_dirs();
        if dirs.is_empty() {
            eprintln!("SKIPPED: no local Cargo registry source cache found ($CARGO_HOME/registry/src/*)");
            return;
        }
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lock_path = repo_root.join("Cargo.lock");
        let Ok(lock_contents) = std::fs::read_to_string(&lock_path) else {
            eprintln!("SKIPPED: {lock_path:?} not readable");
            return;
        };
        let entries = build_license_inventory(&lock_contents, &dirs, "MIT OR Apache-2.0").unwrap();

        // zeroize and sha2 are both workspace-pinned production
        // dependencies (root Cargo.toml [workspace.dependencies]) with
        // well-known, stable dual MIT/Apache-2.0 licensing; if their
        // source was fetched at all to build this workspace (it must
        // have been, for `cargo build --workspace` to succeed), it
        // should be resolvable here.
        for name in ["zeroize", "sha2"] {
            match entries.iter().find(|e| e.name == name) {
                Some(e) => match &e.license {
                    LicenseSource::Declared(lic) => {
                        assert!(lic.contains("MIT") || lic.contains("Apache"), "{name}: expected an MIT/Apache-family license, got {lic:?}");
                    }
                    other => panic!("{name}: expected a Declared license from its real Cargo.toml, got {other:?}"),
                },
                None => eprintln!("SKIPPED: {name} not present in the real Cargo.lock in this checkout"),
            }
        }
    }
}
