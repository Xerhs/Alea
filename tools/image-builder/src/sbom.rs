//! Deterministic SPDX 2.3 SBOM generator (WP-29, SPEC §31, §32).
//!
//! SPEC §31 requires: "Every dependency requires: ... inclusion in the
//! SBOM" and "The release MUST include: `Cargo.lock`; SBOM; ...". SPEC
//! §32 lists `SBOM.spdx.json` as one of the fixed release-archive files.
//! Before this module, no tool anywhere in the repository produced an
//! SBOM at all (spec-conformance audit finding, 2026-08-04): a release
//! could not actually satisfy this MUST.
//!
//! # Why a hand-rolled `Cargo.lock` reader instead of a TOML crate
//!
//! Same reasoning `lib.rs`'s module doc gives for the hand-rolled FAT16
//! writer: no TOML-parsing crate is in the SPEC §3/workspace-pinned
//! dependency set, and adding a new third-party dependency to a release-
//! engineering tool is exactly the kind of change `IMPLEMENTATION_MAP.md`
//! §8 requires a `shared_file_needs` escalation for (root `Cargo.toml`
//! `[workspace.dependencies]` is out of this WP's ownership). `Cargo.lock`
//! (lockfile format version 4, `cargo`-generated, never hand-edited) has a
//! small, stable, well-documented shape: a flat sequence of `[[package]]`
//! tables, each with `name`/`version`/(optional `source`), and never
//! nested tables or multi-line strings for the three fields this module
//! reads. A full TOML parser is not needed to read that reliably.
//!
//! # Determinism (SPEC §32)
//!
//! Byte-identical output for byte-identical input: packages are sorted
//! by (name, version) regardless of `Cargo.lock`'s own on-disk order (it
//! already sorts alphabetically by convention, but this module does not
//! rely on that), and every timestamp/identifier field is a fixed
//! constant rather than derived from wall-clock time or randomness —
//! the same determinism discipline `lib.rs` applies to the FAT16 image
//! itself.

use std::fmt::Write as _;

/// Fixed SPDX `created` timestamp (SPEC §32 determinism — see `lib.rs`'s
/// `FIXED_FAT_DATE` for the same rationale applied to the image builder).
/// Not the real build wall-clock time; a real release process is
/// expected to override this via [`SbomOptions::created`] with the
/// actual signed-tag date if a wall-clock-accurate `created` field is
/// wanted, but the *default* must never make two builds of the same
/// input produce different bytes.
pub const FIXED_CREATED_TIMESTAMP: &str = "2026-01-01T00:00:00Z";

/// One dependency record extracted from `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    /// Raw `source = "..."` value, if present (absent for path/workspace
    /// members). E.g. `"registry+https://github.com/rust-lang/crates.io-index"`.
    pub source: Option<String>,
}

/// Failure parsing `Cargo.lock`.
#[derive(Debug)]
pub enum LockParseError {
    /// A `[[package]]` block never set a `name` key before the next
    /// `[[package]]` or end of file.
    MissingName { block_index: usize },
    /// A `[[package]]` block never set a `version` key.
    MissingVersion { block_index: usize, name: String },
}

impl std::fmt::Display for LockParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockParseError::MissingName { block_index } => {
                write!(f, "[[package]] block #{block_index} has no `name` key")
            }
            LockParseError::MissingVersion { block_index, name } => {
                write!(f, "[[package]] block #{block_index} ({name}) has no `version` key")
            }
        }
    }
}

impl std::error::Error for LockParseError {}

/// Extracts a `key = "value"` line's string value, if `line` (already
/// trimmed) is exactly of that shape for the given `key`.
fn extract_str_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim();
    let rest = rest.strip_prefix('"')?;
    rest.strip_suffix('"')
}

/// Parses `Cargo.lock`'s textual contents into a sorted, de-duplicated
/// list of [`LockedPackage`] entries (SPEC §31, §32).
///
/// Only the three fields this SBOM needs (`name`, `version`, `source`)
/// are read; `checksum`, `dependencies` and any other key are ignored.
/// Lock-file preamble (`# This file is automatically @generated...`,
/// `version = 4`) before the first `[[package]]` is skipped.
///
/// # Errors
///
/// [`LockParseError`] if any `[[package]]` block is missing a `name` or
/// `version` key — a `Cargo.lock` that parses this incompletely is
/// almost certainly not a real `cargo`-generated lockfile, and silently
/// omitting the package from the SBOM would be worse than refusing.
pub fn parse_cargo_lock(contents: &str) -> Result<Vec<LockedPackage>, LockParseError> {
    #[derive(Default)]
    struct Building {
        name: Option<String>,
        version: Option<String>,
        source: Option<String>,
    }

    let mut packages = Vec::new();
    let mut current: Option<Building> = None;
    let mut block_index = 0usize;

    let finish = |current: Option<Building>,
                  block_index: usize,
                  packages: &mut Vec<LockedPackage>|
     -> Result<(), LockParseError> {
        if let Some(b) = current {
            let name = b.name.ok_or(LockParseError::MissingName { block_index })?;
            let version = b
                .version
                .ok_or_else(|| LockParseError::MissingVersion { block_index, name: name.clone() })?;
            packages.push(LockedPackage {
                name,
                version,
                source: b.source,
            });
        }
        Ok(())
    };

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            finish(current.take(), block_index, &mut packages)?;
            block_index += 1;
            current = Some(Building::default());
            continue;
        }
        if line.starts_with('[') {
            // Any other table header (e.g. `[metadata]`) ends the
            // current [[package]] block.
            finish(current.take(), block_index, &mut packages)?;
            continue;
        }
        if let Some(b) = current.as_mut() {
            if let Some(v) = extract_str_field(line, "name") {
                b.name = Some(v.to_string());
            } else if let Some(v) = extract_str_field(line, "version") {
                b.version = Some(v.to_string());
            } else if let Some(v) = extract_str_field(line, "source") {
                b.source = Some(v.to_string());
            }
        }
    }
    finish(current.take(), block_index, &mut packages)?;

    packages.sort();
    packages.dedup();
    Ok(packages)
}

/// Escapes a string for embedding in a JSON string literal. Minimal
/// (covers the characters that actually occur in crate names/versions/
/// source URLs: quote, backslash, and control characters), matching the
/// scope of the JSON this module ever emits — not a general-purpose JSON
/// writer.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// SPDX package "download location" rendering for a `LockedPackage`
/// (SPDX 2.3 §7.7 `PackageDownloadLocation` — required field, `NOASSERTION`
/// permitted when unknown). Registry-sourced crates render a
/// `crates.io`-shaped download URL; path/workspace-member crates (no
/// `source` field) use `NOASSERTION`.
fn download_location(pkg: &LockedPackage) -> String {
    match pkg.source.as_deref() {
        Some(s) if s.starts_with("registry+https://github.com/rust-lang/crates.io-index") => {
            format!("https://crates.io/crates/{}/{}/download", pkg.name, pkg.version)
        }
        _ => "NOASSERTION".to_string(),
    }
}

/// SPDX identifier for a package: `SPDXRef-Package-<name>-<version>`,
/// with any character outside `[A-Za-z0-9.-]` replaced by `-` (SPDX IDs
/// are restricted to that character set).
fn spdx_ref(pkg: &LockedPackage) -> String {
    let raw = format!("SPDXRef-Package-{}-{}", pkg.name, pkg.version);
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
        .collect()
}

/// Options for [`generate_spdx_sbom`]. All fields have deterministic
/// defaults via [`SbomOptions::default`] so a caller that only wants
/// "the SBOM for this Cargo.lock" can pass `SbomOptions::default()`.
#[derive(Debug, Clone)]
pub struct SbomOptions {
    /// SPDX document name / described root package name (SPEC §32 names
    /// the release binary family `alea`).
    pub document_name: String,
    /// SPDX `created` field. Defaults to [`FIXED_CREATED_TIMESTAMP`] for
    /// determinism; a real release process MAY override with the signed
    /// tag's actual date.
    pub created: String,
}

impl Default for SbomOptions {
    fn default() -> Self {
        SbomOptions {
            document_name: "alea".to_string(),
            created: FIXED_CREATED_TIMESTAMP.to_string(),
        }
    }
}

/// Generates a minimal, valid SPDX 2.3 JSON SBOM document from
/// `Cargo.lock`'s contents (SPEC §31, §32). Deterministic: identical
/// `contents`/`options` always produce byte-identical output.
///
/// # Errors
///
/// [`LockParseError`] if `contents` cannot be parsed as a `Cargo.lock`
/// (see [`parse_cargo_lock`]).
pub fn generate_spdx_sbom(contents: &str, options: &SbomOptions) -> Result<String, LockParseError> {
    let packages = parse_cargo_lock(contents)?;

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"spdxVersion\": \"SPDX-2.3\",\n");
    out.push_str("  \"dataLicense\": \"CC0-1.0\",\n");
    out.push_str("  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n");
    let _ = writeln!(out, "  \"name\": \"{}\",", json_escape(&options.document_name));
    // Deterministic namespace: content is a pure function of the document
    // name, never a random UUID (SPEC §32 determinism).
    let _ = writeln!(
        out,
        "  \"documentNamespace\": \"https://alea.example/spdx/{}\",",
        json_escape(&options.document_name)
    );
    out.push_str("  \"creationInfo\": {\n");
    let _ = writeln!(out, "    \"created\": \"{}\",", json_escape(&options.created));
    out.push_str("    \"creators\": [\"Tool: alea-image-builder-sbom\"]\n");
    out.push_str("  },\n");

    out.push_str("  \"packages\": [\n");
    for (i, pkg) in packages.iter().enumerate() {
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"SPDXID\": \"{}\",", spdx_ref(pkg));
        let _ = writeln!(out, "      \"name\": \"{}\",", json_escape(&pkg.name));
        let _ = writeln!(out, "      \"versionInfo\": \"{}\",", json_escape(&pkg.version));
        let _ = writeln!(
            out,
            "      \"downloadLocation\": \"{}\",",
            json_escape(&download_location(pkg))
        );
        out.push_str("      \"filesAnalyzed\": false\n");
        if i + 1 == packages.len() {
            out.push_str("    }\n");
        } else {
            out.push_str("    },\n");
        }
    }
    out.push_str("  ],\n");

    out.push_str("  \"relationships\": [\n");
    for (i, pkg) in packages.iter().enumerate() {
        let comma = if i + 1 == packages.len() { "" } else { "," };
        let _ = writeln!(
            out,
            "    {{ \"spdxElementId\": \"SPDXRef-DOCUMENT\", \"relationshipType\": \"DESCRIBES\", \"relatedSpdxElement\": \"{}\" }}{comma}",
            spdx_ref(pkg)
        );
    }
    out.push_str("  ]\n");
    out.push_str("}\n");

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOCK: &str = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "zeroize"
version = "1.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "seed-core"
version = "0.1.0"
dependencies = [
 "zeroize",
]

[[package]]
name = "ahash"
version = "0.8.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cafef00d"
dependencies = [
 "cfg-if",
]
"#;

    #[test]
    fn parses_packages_with_and_without_source() {
        let pkgs = parse_cargo_lock(SAMPLE_LOCK).unwrap();
        // Sorted by (name, version): ahash, seed-core, zeroize.
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "ahash");
        assert_eq!(pkgs[1].name, "seed-core");
        assert!(pkgs[1].source.is_none(), "path/workspace member has no `source` line");
        assert_eq!(pkgs[2].name, "zeroize");
        assert_eq!(pkgs[2].version, "1.9.0");
        assert!(pkgs[2].source.as_deref().unwrap().starts_with("registry+"));
    }

    #[test]
    fn missing_name_is_reported_not_panicked() {
        let bad = "[[package]]\nversion = \"1.0.0\"\n";
        let err = parse_cargo_lock(bad).unwrap_err();
        assert!(matches!(err, LockParseError::MissingName { .. }));
    }

    #[test]
    fn missing_version_is_reported_not_panicked() {
        let bad = "[[package]]\nname = \"foo\"\n";
        let err = parse_cargo_lock(bad).unwrap_err();
        assert!(matches!(err, LockParseError::MissingVersion { .. }));
    }

    #[test]
    fn empty_lockfile_yields_zero_packages() {
        let pkgs = parse_cargo_lock("# just a comment\nversion = 4\n").unwrap();
        assert!(pkgs.is_empty());
    }

    /// SPEC §32 determinism gate, applied to the SBOM generator the same
    /// way `lib.rs` applies it to the FAT16 image.
    #[test]
    fn sbom_generation_is_byte_identical_across_two_runs() {
        let opts = SbomOptions::default();
        let a = generate_spdx_sbom(SAMPLE_LOCK, &opts).unwrap();
        let b = generate_spdx_sbom(SAMPLE_LOCK, &opts).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sbom_is_insensitive_to_input_package_order() {
        let reordered = r#"
[[package]]
name = "zeroize"
version = "1.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "ahash"
version = "0.8.12"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "seed-core"
version = "0.1.0"
"#;
        let opts = SbomOptions::default();
        let a = generate_spdx_sbom(SAMPLE_LOCK, &opts).unwrap();
        let b = generate_spdx_sbom(reordered, &opts).unwrap();
        assert_eq!(a, b, "package listing order in Cargo.lock must not affect SBOM bytes");
    }

    /// Every SPEC §31-required dependency ("inclusion in the SBOM") must
    /// actually appear as an SPDX package entry with a name and version.
    #[test]
    fn every_locked_package_appears_in_the_sbom() {
        let opts = SbomOptions::default();
        let sbom = generate_spdx_sbom(SAMPLE_LOCK, &opts).unwrap();
        for name in ["ahash", "seed-core", "zeroize"] {
            assert!(sbom.contains(&format!("\"name\": \"{name}\"")), "missing package {name} in SBOM:\n{sbom}");
        }
    }

    #[test]
    fn output_is_structurally_plausible_json() {
        // No `serde_json` dependency is pinned for this tool (see module
        // doc); a lightweight structural sanity check (balanced braces/
        // brackets) stands in for full JSON-schema validation.
        let opts = SbomOptions::default();
        let sbom = generate_spdx_sbom(SAMPLE_LOCK, &opts).unwrap();
        let opens = sbom.matches('{').count();
        let closes = sbom.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces in generated SBOM:\n{sbom}");
        let bracket_opens = sbom.matches('[').count();
        let bracket_closes = sbom.matches(']').count();
        assert_eq!(bracket_opens, bracket_closes, "unbalanced brackets in generated SBOM:\n{sbom}");
        assert!(sbom.starts_with("{\n"));
        assert!(sbom.trim_end().ends_with('}'));
    }
}
