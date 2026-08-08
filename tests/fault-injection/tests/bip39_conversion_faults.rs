//! Category D (SPEC §29.5 "during BIP39 conversion"): malformed inputs to
//! `seed_core::bip39` (WP-05, SPEC §14) must be rejected with a typed
//! `Result`, never a panic and never a silently-wrong word count.

use seed_core::bip39::{entropy_to_indexes, resolve_prefix_into, PrefixOutcome};
use seed_core::contracts::Bip39Error;
use seed_fault_injection::coverage;

/// Every length other than exactly 16 or 32 bytes must be rejected.
#[test]
fn entropy_to_indexes_rejects_every_malformed_length() {
    let bad_lengths = [0usize, 1, 15, 17, 31, 33, 100];
    assert_eq!(bad_lengths.len(), coverage::D_BIP39_BAD_LENGTHS);

    for len in bad_lengths {
        let entropy = vec![0u8; len];
        let mut indexes = [0u16; 24];
        let err = entropy_to_indexes(&entropy, &mut indexes).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidEntropyLength, "len={len}: must be rejected as InvalidEntropyLength");
        // Defense in depth: a rejected call must not have partially
        // written the output buffer with misleading indexes.
        assert!(indexes.iter().all(|&i| i == 0), "len={len}: rejected call must leave the output buffer untouched");
    }
}

/// Valid lengths (16, 32) must still succeed -- a companion sanity check
/// so the malformed-length test above cannot be vacuously true if the
/// function always errors.
#[test]
fn entropy_to_indexes_accepts_the_two_valid_lengths() {
    for len in [16usize, 32] {
        let entropy = vec![0x42u8; len];
        let mut indexes = [0u16; 24];
        assert!(entropy_to_indexes(&entropy, &mut indexes).is_ok(), "len={len} must be accepted");
    }
}

/// `resolve_prefix_into` edge cases: empty input, an overlong prefix (only
/// the first 4 letters are ever meaningful per SPEC §12.3, but nothing
/// should panic on a longer one), a prefix with no matching word, and a
/// non-alphabetic prefix. Uses the SPEC §20.2 secret-safe
/// `resolve_prefix_into`/`PrefixOutcome` pair — the sole implementation of
/// prefix resolution (the former `resolve_prefix`/`PrefixResult::Unique(u16)`,
/// which carried a secret index through ordinary-derived
/// `Debug`/`Clone`/`PartialEq`, was retired per pre-release audit
/// MUST-FIX #1, `docs/PRE-RELEASE-AUDIT.md`) — this is also the exact
/// function the real hidden re-entry path
/// (`crate::flow_secret::reentry::read_and_check_one_word`) calls.
#[test]
fn resolve_prefix_into_edge_cases_never_panic() {
    let cases: [(&[u8], &str); 4] = [
        (b"", "empty"),
        (b"abandonabandon", "overlong"),
        (b"zzzz", "no_match"),
        (b"12", "non_alphabetic"),
    ];
    assert_eq!(cases.len(), coverage::D_BIP39_RESOLVE_PREFIX_EDGE_CASES);

    for (prefix, label) in cases {
        let mut out: u16 = 0xFFFF; // sentinel: must stay untouched unless Unique
        let outcome = resolve_prefix_into(prefix, &mut out);
        match outcome {
            PrefixOutcome::Unique | PrefixOutcome::Ambiguous | PrefixOutcome::Unknown => {}
        }
        let _ = label;
    }
    // The two clearly-nonsensical cases must specifically resolve to
    // Unknown, not spuriously match a real word.
    let mut out = 0u16;
    assert_eq!(resolve_prefix_into(b"", &mut out), PrefixOutcome::Unknown);
    assert_eq!(resolve_prefix_into(b"zzzz", &mut out), PrefixOutcome::Unknown);
}
