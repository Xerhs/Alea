//! `ENTROPY-POLICY.txt` release-artifact generator (WP-29, SPEC §31, §32).
//!
//! SPEC §31: "The release MUST include: ... entropy-policy version."
//! SPEC §32 lists `ENTROPY-POLICY.txt` as one of the fixed release-
//! archive files, distinct from the build-time `entropy-policy.toml`
//! that ships as input to the signed build (spec-conformance audit
//! finding, 2026-08-04: "ENTROPY-POLICY.txt (as a release artifact,
//! distinct from the build-time entropy-policy.toml) does not exist").
//!
//! This module does not reinterpret or re-derive the policy's meaning —
//! that is `crates/seed-protocol/src/policy/`'s job (WP-12) at boot
//! time. It produces a distinct, release-facing artifact: the exact
//! policy text the shipped build was compiled against, wrapped with a
//! release-artifact banner and its `policy_version` surfaced up front,
//! so a verifier can confirm which policy version a given release
//! archive corresponds to without parsing the full TOML grammar.

use std::fmt::Write as _;

/// Extracts the top-level `policy_version = N` value from
/// `entropy_policy_toml`'s contents, if present. Deliberately tolerant —
/// this is a display convenience, not a validity check (validity is
/// `seed-protocol::policy`'s job).
fn extract_policy_version(entropy_policy_toml: &str) -> Option<&str> {
    for raw_line in entropy_policy_toml.lines() {
        let line = raw_line.trim();
        let stripped_comment = line.split('#').next().unwrap_or(line).trim();
        if let Some(rest) = stripped_comment.strip_prefix("policy_version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                return Some(rest.trim());
            }
        }
    }
    None
}

/// Renders `ENTROPY-POLICY.txt` (SPEC §31, §32) from the build-time
/// `entropy-policy.toml` contents: a fixed banner naming this as a
/// distinct release artifact, the extracted `policy_version`, and then
/// the verbatim policy text (so anyone can diff it against the
/// `entropy-policy.toml` the signed build actually used). Deterministic:
/// a pure function of `entropy_policy_toml`'s content.
#[must_use]
pub fn generate_entropy_policy_txt(entropy_policy_toml: &str) -> String {
    let version = extract_policy_version(entropy_policy_toml).unwrap_or("unknown");
    let mut out = String::new();
    out.push_str("# Alea ENTROPY-POLICY.txt (SPEC.md §31, §32)\n");
    out.push_str("#\n");
    out.push_str("# Release artifact. Distinct from, but verbatim-derived from, the\n");
    out.push_str("# build-time entropy-policy.toml this release was compiled against\n");
    out.push_str("# (SPEC.md §32: \"entropy-policy version\" is a required release-archive\n");
    out.push_str("# field). Published so a verifier can confirm which entropy policy a\n");
    out.push_str("# given release corresponds to without extracting it from the signed\n");
    out.push_str("# binary. See DENYLIST.txt for a human-readable rendering of this\n");
    out.push_str("# policy's known-bad-platform entries specifically.\n");
    let _ = writeln!(out, "policy_version_summary = {version}");
    out.push_str("#\n");
    out.push_str("# --- verbatim entropy-policy.toml below this line ---\n");
    out.push_str("#\n");
    out.push_str(entropy_policy_toml);
    if !entropy_policy_toml.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "policy_version = 3\n\n[rdseed]\napproved = true\n";

    #[test]
    fn extracts_policy_version() {
        assert_eq!(extract_policy_version(SAMPLE), Some("3"));
    }

    #[test]
    fn missing_version_falls_back_to_unknown_without_panicking() {
        let txt = generate_entropy_policy_txt("[rdseed]\napproved = true\n");
        assert!(txt.contains("policy_version_summary = unknown"));
    }

    #[test]
    fn output_contains_banner_version_and_full_verbatim_policy() {
        let txt = generate_entropy_policy_txt(SAMPLE);
        assert!(txt.contains("Release artifact"));
        assert!(txt.contains("policy_version_summary = 3"));
        assert!(txt.contains(SAMPLE), "verbatim policy text must be embedded unmodified");
    }

    #[test]
    fn is_distinct_from_and_a_strict_superset_of_the_input() {
        let txt = generate_entropy_policy_txt(SAMPLE);
        assert_ne!(txt, SAMPLE, "release artifact must be distinct from the raw build-time file");
        assert!(txt.len() > SAMPLE.len());
    }

    #[test]
    fn generation_is_deterministic() {
        let a = generate_entropy_policy_txt(SAMPLE);
        let b = generate_entropy_policy_txt(SAMPLE);
        assert_eq!(a, b);
    }

    /// Regression pin against the real, shipped `entropy-policy.toml`
    /// (read-only input; this module never writes it).
    #[test]
    fn real_shipped_policy_round_trips_if_reachable() {
        let real = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../entropy-policy.toml"),
        );
        if let Ok(real) = real {
            let txt = generate_entropy_policy_txt(&real);
            assert!(txt.contains("policy_version_summary = 1"));
            assert!(txt.contains(&real));
        }
    }
}
