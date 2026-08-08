//! Category G (SPEC §29.5 "during derivation"): malformed/adversarial
//! source-record combinations at the SPEC §19.1/§19.2 transcript-building
//! seam `derive::derive` sits on top of, plus the fail-closed
//! zero-sources rejection (pre-release audit MUST-FIX #2,
//! `docs/PRE-RELEASE-AUDIT.md`) at the real pipeline entry point.

use seed_core::contracts::{
    ArchId, SourceTag, TargetBits, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES, MAX_SOURCE_RECORDS,
    TRANSCRIPT_CAPACITY,
};
use seed_core::pipeline::{derive_final_entropy, SourceInput};
use seed_fault_injection::{coverage, MAX_PHYSICAL_EVENTS, SecretArena};
use seed_flow::flow_secret::derive::FlowTranscript;
use seed_protocol::transcript::{decode, TranscriptBuilder, TranscriptError};

#[test]
fn add_source_rejects_a_duplicate_tag() {
    let mut b = TranscriptBuilder::new();
    b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3]).unwrap();
    let err = b.add_source(SourceTag::DiceRolls, &[], &[4, 5, 6]).unwrap_err();
    assert_eq!(err, TranscriptError::DuplicateTag);
    assert_eq!(1, coverage::G_DERIVATION_DUPLICATE_TAG);
}

/// `TooManyRecords` cannot be reached via `add_source` with distinct
/// valid tags (there are exactly `MAX_SOURCE_RECORDS` = 5 defined tags —
/// see `seed-protocol/src/transcript/mod.rs`'s own
/// `add_source_all_five_tags_fills_builder` test and doc comment, which
/// already documents this as an intentional forward-compatible guard, not
/// a bug). The genuinely reachable fault-injection point for this error
/// is `decode`'s own defense against a corrupted/adversarial wire-format
/// `record_count` byte claiming more records than the fixed buffer could
/// ever hold — exercised here by building one real, valid transcript,
/// then corrupting exactly that one header byte before decoding.
#[test]
fn decode_rejects_a_corrupted_record_count_byte_claiming_too_many_records() {
    let mut b = TranscriptBuilder::new();
    b.add_source(SourceTag::DiceRolls, &[], &[1, 2, 3]).unwrap();
    let mut buf = [0u8; TRANSCRIPT_CAPACITY];
    let len = b.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut buf);

    // Domain (16 bytes: "Alea/Entropy/v1\0") + 4 u16 header fields
    // (arch, bits, policy_ver, presence_bitmap) = the record_count byte is
    // the 9th and last header byte. Verified below rather than trusted
    // blindly: the domain-prefix assertion pins the offset computation
    // against the real serialized output instead of a bare magic number.
    const DOMAIN: &[u8] = b"Alea/Entropy/v1\0";
    assert_eq!(&buf[..DOMAIN.len()], DOMAIN, "serialized output must start with the expected domain prefix");
    let record_count_offset = DOMAIN.len() + 8; // 4 * u16 header fields = 8 bytes before the record_count byte
    assert_eq!(buf[record_count_offset], 1, "sanity: exactly one record was staged");

    buf[record_count_offset] = (MAX_SOURCE_RECORDS as u8) + 1;
    let err = match decode(&buf[..len]) {
        Err(e) => e,
        Ok(_) => panic!("a corrupted record_count byte must be rejected, never accepted"),
    };
    assert_eq!(err, TranscriptError::TooManyRecords, "a corrupted record_count byte must be rejected, never over-read");
    assert_eq!(1, coverage::G_DERIVATION_TOO_MANY_RECORDS);
}

#[test]
fn add_source_rejects_an_oversized_algorithm_identifier() {
    let mut b = TranscriptBuilder::new();
    let oversized_algo = vec![0u8; MAX_ALGO_ID + 1];
    let err = b.add_source(SourceTag::ApprovedEfiRng, &oversized_algo, &[1, 2, 3, 4]).unwrap_err();
    assert_eq!(err, TranscriptError::AlgoIdTooLong);
    assert_eq!(1, coverage::G_DERIVATION_ALGO_ID_TOO_LONG);
}

#[test]
fn add_source_rejects_an_oversized_single_machine_source() {
    let mut b = TranscriptBuilder::new();
    let oversized_bytes = vec![0u8; MAX_MACHINE_SOURCE_BYTES + 1];
    let err = b.add_source(SourceTag::X86Rdseed64, &[], &oversized_bytes).unwrap_err();
    assert_eq!(err, TranscriptError::SourceTooLong);
    assert_eq!(1, coverage::G_DERIVATION_SOURCE_TOO_LONG);
}

/// SPEC §17.3: the combined `DiceRolls` + `CoinFlips` length must never
/// exceed `MAX_PHYSICAL_EVENTS`, even though each individually could fit —
/// checked at two split ratios (dice-heavy and coin-heavy), each one byte
/// over the shared budget.
#[test]
fn add_source_rejects_combined_physical_over_budget_both_split_ratios() {
    let mut checked = 0usize;

    let mut b1 = TranscriptBuilder::new();
    let dice = vec![3u8; MAX_PHYSICAL_EVENTS];
    b1.add_source(SourceTag::DiceRolls, &[], &dice).unwrap();
    let err1 = b1.add_source(SourceTag::CoinFlips, &[], &[1]).unwrap_err();
    assert_eq!(err1, TranscriptError::SourceTooLong, "dice-heavy split: one flip over the shared budget must be rejected");
    checked += 1;

    let mut b2 = TranscriptBuilder::new();
    let coin = vec![1u8; MAX_PHYSICAL_EVENTS];
    b2.add_source(SourceTag::CoinFlips, &[], &coin).unwrap();
    let err2 = b2.add_source(SourceTag::DiceRolls, &[], &[4]).unwrap_err();
    assert_eq!(err2, TranscriptError::SourceTooLong, "coin-heavy split: one roll over the shared budget must be rejected");
    checked += 1;

    assert_eq!(checked, coverage::G_DERIVATION_COMBINED_OVER_BUDGET);
}

/// Fail-closed entropy floor (pre-release audit MUST-FIX #2,
/// `docs/PRE-RELEASE-AUDIT.md`): zero sources must be rejected by the real
/// pipeline entry point (through the real production `FlowTranscript`
/// sink, not just a test double), never silently accepted into a "valid"
/// (fixed, publicly-computable) result. This test used to assert the
/// opposite -- that zero sources derived cleanly -- which was itself a
/// symptom of the exact defect this fix closes; it now pins the corrected
/// contract instead, still without panicking.
#[test]
fn derive_final_entropy_with_zero_sources_does_not_panic() {
    let mut arena = SecretArena::new();
    let sources: [SourceInput<'_>; 0] = [];
    let result =
        derive_final_entropy(&mut arena, FlowTranscript::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1);
    assert!(result.is_err(), "zero sources must be refused, not silently derived");
    assert!(
        arena.final_entropy().iter().all(|&b| b == 0),
        "a rejected call must not leave a deterministic digest in the arena"
    );
    assert_eq!(1, coverage::G_DERIVATION_ZERO_SOURCES);
}
