//! seed-compat isolation denylist (WP-C5, IMPLEMENTATION_MAP_COMPAT.md §4,
//! SPEC_COMPAT.md §9, SPEC.md §28).
//!
//! `seed-compat` (crates/seed-compat/), its profile-id strings, and its
//! permanent watermark banner (SPEC_COMPAT.md §8) MUST NEVER appear in a
//! production `seed-uefi-production.efi` artifact — SPEC_COMPAT §9: "The
//! binary-policy scanner (SPEC §28 / WP-30) MUST additionally fail the
//! production build if any `seed-compat` symbol, profile id string
//! (`"coldcard-dice"`, etc.), or the compat watermark asset appears."
//!
//! This module owns exactly that denylist plus a scan function over raw
//! section bytes, mirroring the shape of `main.rs`'s own
//! `FORBIDDEN_CRATE_NAMES` / `FORBIDDEN_LITERALS` checks (same
//! substring-search technique, same `Result: Vec<String>` reporting
//! style) so the WP-30-owned `scan()` in `main.rs` only needs a single
//! call-site line to wire this in (IMPLEMENTATION_MAP_COMPAT.md §4: "Own
//! a NEW file for the denylist; request the one-line call-site wire-in
//! via `shared_file_needs` if the scanner main is WP-30-owned").
//!
//! This crate (`binary-policy-scanner`) itself has **no** dependency on
//! `seed-compat` — the denylist below is a set of `const` string/byte
//! literals only, never a reference to the real crate's symbols, so this
//! isolation gate cannot itself become the very dependency edge it exists
//! to forbid.

/// Forbidden `seed-compat` crate-name / symbol substrings
/// (SPEC_COMPAT §9). Mirrors `main.rs`'s `FORBIDDEN_CRATE_NAMES` pattern:
/// both the Cargo package-name spelling (hyphen) and the Rust
/// identifier/mangled-symbol spelling (underscore) are checked, since
/// either can end up embedded in panic strings, debug info, or a linked
/// symbol name.
pub const FORBIDDEN_COMPAT_CRATE_NAMES: &[&str] = &[
    "seed-compat",
    "seed_compat",
    "seed-compat-vectors",
    "seed_compat_vectors",
    "compat-verify",
    "compat_verify",
];

/// Forbidden `seed-compat` profile-id strings (SPEC_COMPAT §6,
/// `crates/seed-compat/src/lib.rs`'s `PROFILES` table / review F2/F6).
/// Includes all four `CompatProfile::id` values defined there — the
/// three user-facing profiles (`coldcard-dice`, `seedsigner-dice`,
/// `seedsigner-coin`) plus the internal-oracle-only `iancoleman-hex`,
/// since none of the four should ever be reachable from a production
/// artifact regardless of whether `profile()` exposes it to callers.
pub const FORBIDDEN_COMPAT_PROFILE_IDS: &[&str] = &[
    "coldcard-dice",
    "seedsigner-dice",
    "seedsigner-coin",
    "iancoleman-hex",
];

/// Distinctive Method-C (SPEC_COMPAT_ENTROPY.md) method-identifier tokens.
///
/// SPEC_COMPAT_ENTROPY §2 item 3: the scanner is defense-in-depth (the
/// authoritative isolation is the dependency-graph exclusion, verified by
/// `cargo tree`) and MUST key on the **distinctive** `EntropyEncodingRaw`
/// method identifier — **never** on the generic encoding-id words
/// ("binary", "hex", "card", "base 6", "base 10"), which are ordinary
/// English and would risk false positives against unrelated production
/// symbols. Only the distinctive identifier (both spellings) is listed here.
pub const FORBIDDEN_COMPAT_METHOD_TOKENS: &[&str] = &[
    "EntropyEncodingRaw",
    "entropy_encoding_derive",
];

/// The permanent seed-compat watermark text (SPEC_COMPAT.md §8, §7).
/// Two distinct literal strings carry the watermark in the real CLI
/// output: the persistent mode banner shown on every screen (§8) and the
/// bracketed result-screen banner shown on the final mnemonic screen
/// (§7). Both are denylisted independently since either one appearing in
/// a production binary would mean the compat surface (or at least its
/// rendered strings) leaked into the production build.
pub const FORBIDDEN_COMPAT_WATERMARK_LITERALS: &[&str] = &[
    "COMPATIBILITY / VERIFICATION MODE",
    "[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]",
];

/// Scan raw section bytes for any `seed-compat` isolation-denylist hit
/// (crate/symbol name, profile-id string, or watermark literal — SPEC_COMPAT
/// §9). Returns one human-readable description per hit found, or an empty
/// `Vec` if `haystack` is clean. Pure substring search, same technique as
/// `main.rs::contains_subslice`, deliberately re-implemented here rather
/// than imported so this module has zero dependency on `main.rs`'s
/// private items and can be unit-tested in isolation.
///
/// `section_name` is included in each returned description purely for
/// diagnostic output; it is not otherwise interpreted.
pub fn find_compat_violations(haystack: &[u8], section_name: &str) -> Vec<String> {
    let mut hits = Vec::new();

    for needle in FORBIDDEN_COMPAT_CRATE_NAMES {
        if contains_subslice(haystack, needle.as_bytes()) {
            hits.push(format!(
                "forbidden seed-compat crate/symbol marker {needle:?} found in section `{section_name}` (SPEC_COMPAT §9)"
            ));
        }
    }
    for id in FORBIDDEN_COMPAT_PROFILE_IDS {
        if contains_subslice(haystack, id.as_bytes()) {
            hits.push(format!(
                "forbidden seed-compat profile-id string {id:?} found in section `{section_name}` (SPEC_COMPAT §9)"
            ));
        }
    }
    for lit in FORBIDDEN_COMPAT_WATERMARK_LITERALS {
        if contains_subslice(haystack, lit.as_bytes()) {
            hits.push(format!(
                "forbidden seed-compat watermark literal {lit:?} found in section `{section_name}` (SPEC_COMPAT §8/§9)"
            ));
        }
    }
    for tok in FORBIDDEN_COMPAT_METHOD_TOKENS {
        if contains_subslice(haystack, tok.as_bytes()) {
            hits.push(format!(
                "forbidden Method-C identifier {tok:?} found in section `{section_name}` (SPEC_COMPAT_ENTROPY §2/§9)"
            ));
        }
    }

    hits
}

/// Naive but correct subslice search over raw bytes (no encoding
/// assumptions — compat literals here are plain ASCII/UTF-8, and `—`
/// (em dash) encodes to a fixed 3-byte UTF-8 sequence either way, so a
/// byte-level search is exact). Deliberately a private copy of
/// `main.rs::contains_subslice` rather than a shared import, per this
/// module's own doc comment (zero dependency on `main.rs`'s private
/// items).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_payload_has_no_hits() {
        let hits = find_compat_violations(b"ALEA-PRODUCTION-EDITION-MARKER-V1", ".rdata");
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn flags_crate_name_hyphen_form() {
        let hits = find_compat_violations(b"...seed-compat...", ".rdata");
        assert!(hits.iter().any(|h| h.contains("seed-compat")));
    }

    #[test]
    fn flags_crate_name_underscore_form() {
        let hits = find_compat_violations(b"...seed_compat::compat_derive...", ".rdata");
        assert!(hits.iter().any(|h| h.contains("seed_compat")));
    }

    #[test]
    fn flags_each_profile_id() {
        for id in FORBIDDEN_COMPAT_PROFILE_IDS {
            let payload = format!("noise {id} noise");
            let hits = find_compat_violations(payload.as_bytes(), ".rdata");
            assert!(
                hits.iter().any(|h| h.contains(id)),
                "profile id {id:?} not flagged: {hits:?}"
            );
        }
    }

    #[test]
    fn flags_watermark_mode_banner() {
        let hits = find_compat_violations(
            b"COMPATIBILITY / VERIFICATION MODE - reproduces another vendor's method -",
            ".rdata",
        );
        assert!(hits.iter().any(|h| h.contains("watermark")));
    }

    #[test]
    fn flags_watermark_result_banner() {
        let payload = "[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]"
            .as_bytes()
            .to_vec();
        let hits = find_compat_violations(&payload, ".rdata");
        assert!(hits.iter().any(|h| h.contains("watermark")));
    }

    #[test]
    fn does_not_flag_unrelated_production_copy() {
        let hits = find_compat_violations(
            b"KEYBOARD SELF-TEST Cryptographic self-test Send a small test amount",
            ".rdata",
        );
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn flags_method_c_distinctive_identifier() {
        for tok in FORBIDDEN_COMPAT_METHOD_TOKENS {
            let payload = format!("noise {tok} noise");
            let hits = find_compat_violations(payload.as_bytes(), ".rdata");
            assert!(hits.iter().any(|h| h.contains(tok)), "Method-C token {tok:?} not flagged: {hits:?}");
        }
    }

    /// SPEC_COMPAT_ENTROPY §2 item 3: the scanner MUST NOT key on the generic
    /// per-encoding words — they are ordinary English and appear in unrelated
    /// production copy. A production string full of them must stay clean.
    #[test]
    fn does_not_flag_generic_encoding_words() {
        let hits = find_compat_violations(
            b"Enter the binary or hex value; a standard card uses base 6 or base 10 dice.",
            ".rdata",
        );
        assert!(hits.is_empty(), "generic encoding words must not be denylisted: {hits:?}");
    }
}
