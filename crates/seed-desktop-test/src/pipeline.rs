//! Runs a [`crate::vectors::Case`] through the real Rust pipeline (SPEC
//! §19, §14, §24.2) and reports every stage's output, so
//! [`crate::check`] can compare it bit-for-bit against the frozen vector
//! it was parsed from (SPEC §4.3: "Reproduce all published deterministic
//! vectors ... bit-for-bit against the UEFI build and the reference
//! implementation").
//!
//! Uses `seed_test_vectors::{RealTranscript, RealDeriver}` — the exact
//! same production adapters WP-16's own cross-implementation test uses —
//! rather than re-implementing transcript/derivation wiring a second time
//! in this crate.

use seed_core::arena::SecretArena;
use seed_core::bip39;
use seed_core::pipeline::{compute_verification_values, derive_final_entropy, SourceInput};
use seed_test_vectors::{RealDeriver, RealTranscript};

use crate::vectors::Case;

/// Everything [`derive_case`] computes for one case, in the same shape
/// [`crate::vectors::Case`] carries, so the two can be compared
/// field-by-field.
#[derive(Debug)]
pub struct DerivedOutput {
    pub transcript_hex: String,
    pub final_entropy_hex: String,
    pub mnemonic_indexes: Vec<u16>,
    pub mnemonic_words: Vec<String>,
    pub bip39_seed_hex: String,
    pub master_fingerprint_hex: String,
    pub addr_bip44: String,
    pub addr_bip49: String,
    pub addr_bip84: String,
    pub addr_bip86: String,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Runs `case.sources` through `TranscriptBuilder -> derive_final_entropy
/// -> compute_verification_values` (SPEC §19.2-§19.3, §14, §24.2) and
/// returns every stage's output. Panics only on an internal pipeline
/// invariant violation (a case whose fixed source bytes cannot serialize
/// or derive at all) — this crate's `check` subcommand treats that as a
/// hard failure exactly like any other mismatch, never silently skipped.
#[must_use]
pub fn derive_case(case: &Case) -> DerivedOutput {
    let source_inputs: Vec<SourceInput<'_>> =
        case.sources.iter().map(|s| SourceInput { tag: s.tag, algo_id: &s.algo, bytes: &s.bytes }).collect();

    // Stage 0: canonical transcript bytes, built independently of the
    // pipeline facade's own (consuming) sink so both can be reported.
    let mut builder = seed_protocol::transcript::TranscriptBuilder::new();
    for s in &case.sources {
        builder.add_source(s.tag, &s.algo, &s.bytes).unwrap_or_else(|e| panic!("{}: add_source failed: {e:?}", case.name));
    }
    let mut wire = [0u8; seed_core::contracts::TRANSCRIPT_CAPACITY];
    let wire_len = builder.serialize(case.arch, case.bits, case.policy_version, &mut wire);
    let transcript_hex = bytes_to_hex(&wire[..wire_len]);

    // Stage 1: sources -> final entropy -> mnemonic indexes.
    let mut arena = SecretArena::new();
    let word_count =
        derive_final_entropy(&mut arena, RealTranscript::new(), &source_inputs, case.arch, case.bits, case.policy_version)
            .unwrap_or_else(|e| panic!("{}: derive_final_entropy failed: {e:?}", case.name));

    let entropy_len = match case.bits {
        seed_core::contracts::TargetBits::Bits128 => 16,
        seed_core::contracts::TargetBits::Bits256 => 32,
    };
    let final_entropy_hex = bytes_to_hex(&arena.final_entropy()[..entropy_len]);

    let n_words = word_count as usize;
    let mnemonic_indexes: Vec<u16> = arena.mnemonic_indexes()[..n_words].to_vec();
    let mnemonic_words: Vec<String> = mnemonic_indexes.iter().map(|&i| bip39::word(i).to_string()).collect();

    // Stage 2: BIP39 seed, master fingerprint, four first addresses.
    let values = compute_verification_values::<RealDeriver>(&mut arena, word_count)
        .unwrap_or_else(|e| panic!("{}: compute_verification_values failed: {e:?}", case.name));
    let bip39_seed_hex = bytes_to_hex(arena.bip39_seed());
    let master_fingerprint_hex = bytes_to_hex(&values.master_fingerprint);

    let addr_of = |standard: seed_core::contracts::PathStandard| -> String {
        let slot = values.addresses.iter().find(|a| a.standard == standard).expect("every standard is always present");
        slot.address.as_str().unwrap_or("?").to_string()
    };

    DerivedOutput {
        transcript_hex,
        final_entropy_hex,
        mnemonic_indexes,
        mnemonic_words,
        bip39_seed_hex,
        master_fingerprint_hex,
        addr_bip44: addr_of(seed_core::contracts::PathStandard::Bip44),
        addr_bip49: addr_of(seed_core::contracts::PathStandard::Bip49),
        addr_bip84: addr_of(seed_core::contracts::PathStandard::Bip84),
        addr_bip86: addr_of(seed_core::contracts::PathStandard::Bip86),
    }
}

/// One field-level mismatch between a [`DerivedOutput`] and the
/// [`Case`] it was derived from.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub field: &'static str,
    pub expected: String,
    pub got: String,
}

/// Compare every stage of `derived` against `case` field-by-field,
/// returning every mismatch found (empty = bit-for-bit match on every
/// field this pipeline produces).
#[must_use]
pub fn compare(case: &Case, derived: &DerivedOutput) -> Vec<Mismatch> {
    let mut out = Vec::new();
    let mut check = |field: &'static str, expected: &str, got: &str| {
        if expected != got {
            out.push(Mismatch { field, expected: expected.to_string(), got: got.to_string() });
        }
    };
    check("transcript_hex", &case.transcript_hex, &derived.transcript_hex);
    check("final_entropy_hex", &case.final_entropy_hex, &derived.final_entropy_hex);
    check("bip39_seed_hex", &case.bip39_seed_hex, &derived.bip39_seed_hex);
    check("master_fingerprint_hex", &case.master_fingerprint_hex, &derived.master_fingerprint_hex);
    check("addr_bip44", &case.addr_bip44, &derived.addr_bip44);
    check("addr_bip49", &case.addr_bip49, &derived.addr_bip49);
    check("addr_bip84", &case.addr_bip84, &derived.addr_bip84);
    check("addr_bip86", &case.addr_bip86, &derived.addr_bip86);
    if case.mnemonic_indexes != derived.mnemonic_indexes {
        out.push(Mismatch {
            field: "mnemonic_indexes",
            expected: format!("{:?}", case.mnemonic_indexes),
            got: format!("{:?}", derived.mnemonic_indexes),
        });
    }
    if case.mnemonic_words != derived.mnemonic_words {
        out.push(Mismatch {
            field: "mnemonic_words",
            expected: format!("{:?}", case.mnemonic_words),
            got: format!("{:?}", derived.mnemonic_words),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors;

    #[test]
    fn derive_case_reproduces_the_frozen_vector_exactly() {
        let path = vectors::frozen_dir().join("dice_only_12w_min_budget.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let case = &vectors::parse_document(&text, "dice_only_12w_min_budget.json")[0];
        let derived = derive_case(case);
        let mismatches = compare(case, &derived);
        assert!(mismatches.is_empty(), "unexpected mismatches: {mismatches:?}");
    }

    #[test]
    fn compare_flags_a_deliberately_wrong_field() {
        let path = vectors::frozen_dir().join("dice_only_12w_min_budget.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let case = &vectors::parse_document(&text, "dice_only_12w_min_budget.json")[0];
        let mut derived = derive_case(case);
        derived.master_fingerprint_hex = "00000000".to_string();
        let mismatches = compare(case, &derived);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].field, "master_fingerprint_hex");
    }
}
