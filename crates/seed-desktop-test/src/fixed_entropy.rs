//! SPEC §4.3: "Have no real-entropy generation mode and no operating-
//! system RNG mode." This module is the single place in this crate that
//! decides what bytes the desktop ceremony's mnemonic is derived from —
//! and it is always, unconditionally, one of two `include_str!`-embedded
//! frozen public test vectors, chosen only by word count (12 vs 24).
//!
//! # Why `include_str!`, not a runtime file read
//!
//! The two vector files' *text* is compiled directly into this binary
//! (`include_str!`, resolved at compile time, baked into the executable's
//! read-only data). This is deliberately stronger than "reads a file at
//! startup": there is no code path here that opens a file handle, calls
//! into any OS randomness facility, or accepts a runtime-supplied
//! transcript. Changing what this ceremony produces requires editing this
//! source file and recompiling — exactly the "public fixed entropy" the
//! rehearsal promises on screen (see `crate::ceremony`'s banner text).
//!
//! `tests::fixed_transcripts_reproduce_the_named_frozen_vector_bit_for_bit`
//! below re-derives both embedded transcripts through the exact same
//! pipeline `crate::check` uses and asserts the result equals the named
//! frozen vector's own published fields — i.e. this module's constants
//! are not just "some fixed bytes", they are provably the same bytes as
//! the published, audited `tests/vectors/frozen/` corpus.
//!
//! `crate::guardrails` separately greps this whole crate's own source for
//! any real-randomness or OS-RNG API surface (see that module's own
//! denylist) and asserts none exists, structurally backing up what this
//! module's design already guarantees.

use seed_core::contracts::{SourceTag, TargetBits, WordCount};

use crate::vectors::{self, Case};

/// The exact frozen-vector file this rehearsal's 12-word ceremony always
/// reproduces (SPEC §4.3).
pub const VECTOR_FILE_12W: &str = "dice_only_12w_min_budget.json";
/// The exact frozen-vector file this rehearsal's 24-word ceremony always
/// reproduces (SPEC §4.3).
pub const VECTOR_FILE_24W: &str = "dice_only_24w_min_budget.json";

const VECTOR_TEXT_12W: &str = include_str!("../../../tests/vectors/frozen/dice_only_12w_min_budget.json");
const VECTOR_TEXT_24W: &str = include_str!("../../../tests/vectors/frozen/dice_only_24w_min_budget.json");

/// The one fixed public dice-roll transcript this rehearsal ever derives
/// from, for a given [`WordCount`] (SPEC §4.3, §17.1, §19.1). Nothing the
/// user types on the physical-entry rehearsal screen ever reaches this
/// function's return value — see `crate::ceremony`'s doc comment.
#[must_use]
pub fn fixed_case(word_count: WordCount) -> Case {
    let (text, file_name) = match word_count {
        WordCount::Twelve => (VECTOR_TEXT_12W, VECTOR_FILE_12W),
        WordCount::TwentyFour => (VECTOR_TEXT_24W, VECTOR_FILE_24W),
    };
    let mut cases = vectors::parse_document(text, file_name);
    assert_eq!(cases.len(), 1, "{file_name}: expected exactly one embedded case");
    let case = cases.remove(0);
    assert_eq!(case.sources.len(), 1, "{file_name}: expected exactly one source record");
    assert_eq!(case.sources[0].tag, SourceTag::DiceRolls, "{file_name}: expected a dice-only fixed transcript");
    let expected_bits = match word_count {
        WordCount::Twelve => TargetBits::Bits128,
        WordCount::TwentyFour => TargetBits::Bits256,
    };
    assert_eq!(case.bits, expected_bits);
    case
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline;

    #[test]
    fn fixed_case_12w_matches_the_named_frozen_vector_on_disk() {
        let embedded = fixed_case(WordCount::Twelve);
        let on_disk_path = vectors::frozen_dir().join(VECTOR_FILE_12W);
        let on_disk_text = std::fs::read_to_string(&on_disk_path).unwrap();
        let on_disk = &vectors::parse_document(&on_disk_text, VECTOR_FILE_12W)[0];
        assert_eq!(embedded.mnemonic_words, on_disk.mnemonic_words);
        assert_eq!(embedded.sources[0].bytes, on_disk.sources[0].bytes);
    }

    #[test]
    fn fixed_case_24w_matches_the_named_frozen_vector_on_disk() {
        let embedded = fixed_case(WordCount::TwentyFour);
        let on_disk_path = vectors::frozen_dir().join(VECTOR_FILE_24W);
        let on_disk_text = std::fs::read_to_string(&on_disk_path).unwrap();
        let on_disk = &vectors::parse_document(&on_disk_text, VECTOR_FILE_24W)[0];
        assert_eq!(embedded.mnemonic_words, on_disk.mnemonic_words);
        assert_eq!(embedded.sources[0].bytes, on_disk.sources[0].bytes);
    }

    /// This crate's ceremony must never produce anything other than a
    /// known public test mnemonic: re-derive both embedded transcripts
    /// through the real pipeline and assert every stage matches the
    /// named frozen vector's own published fields, bit-for-bit.
    #[test]
    fn fixed_transcripts_reproduce_the_named_frozen_vector_bit_for_bit() {
        for wc in [WordCount::Twelve, WordCount::TwentyFour] {
            let case = fixed_case(wc);
            let derived = pipeline::derive_case(&case);
            let mismatches = pipeline::compare(&case, &derived);
            assert!(mismatches.is_empty(), "{wc:?}: unexpected mismatches: {mismatches:?}");
        }
    }
}
