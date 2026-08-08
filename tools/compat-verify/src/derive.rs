//! Full derivation pipeline for `compat-verify` (SPEC_COMPAT §7, §12;
//! IMPLEMENTATION_MAP_COMPAT.md §4 WP-C4).
//!
//! Wraps `seed_compat::compat_derive` (the digest + word-count-rule +
//! F1-refusal logic) and, for a successful derivation, walks the exact same
//! `seed-derive` chain the production derivation display uses
//! (`seed_core::bip39::mnemonic_to_seed`, `seed_derive::bip32::{master_from_seed,
//! master_fingerprint}`, `seed_derive::address::first_address`) to produce
//! the verification values SPEC_COMPAT §7's result screen shows: the
//! mnemonic, master fingerprint, and all four first receive addresses
//! (SPEC §24.2). This module never fabricates a mnemonic for an outcome
//! `compat_derive` did not itself report as a success (review F1) -- it is
//! a strict formatting/derivation layer over that call, nothing more.

use seed_compat::entropy_encoding::{
    entropy_encoding_derive, Encoding, EntropyEncodingError, EntropyEncodingOutput,
};
use seed_compat::{compat_derive, CompatError, CompatOutput, CompatProfile, WordCount, WordCountRule};
use seed_core::contracts::{AddressBuf, PathStandard, WordCount as CoreWordCount};
use zeroize::Zeroize;

/// One of the four fixed wallet-verification standards SPEC §24.2 defines,
/// paired with its rendered address (SPEC_COMPAT §7 result screen: "BIP84
/// ... BIP86 ... BIP49 ... BIP44 ...").
pub struct RenderedAddress {
    pub label: &'static str,
    pub address: [u8; 92],
    pub address_len: usize,
}

impl RenderedAddress {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.address[..self.address_len]).expect("address bytes are ASCII")
    }
}

/// A successful derivation: mnemonic + SPEC §24 verification values, plus
/// the digest inputs needed to render entropy hex ONLY when the caller
/// explicitly asks for it (SPEC_COMPAT §7, review F7 -- no default
/// concatenation of entropy hex with the mnemonic).
pub struct Success {
    pub profile: &'static CompatProfile,
    pub word_count: WordCount,
    pub words: [&'static str; 24],
    pub used_len: u16,
    /// `digest[..16]` (12w) or `digest[..32]` (24w) -- the exact entropy
    /// bytes hashed into the mnemonic (SPEC_COMPAT §5.1). Only rendered by
    /// the caller when `--show-entropy` is passed (SPEC_COMPAT §7).
    pub entropy: [u8; 32],
    pub entropy_len: usize,
    pub master_fingerprint: [u8; 4],
    /// BIP44, BIP49, BIP84, BIP86 in that fixed order (matches the frozen
    /// `tests/vectors/compat` schema's `addresses` object, SPEC_COMPAT
    /// §10.1).
    pub addresses: [RenderedAddress; 4],
}

impl Success {
    pub fn word_count_n(&self) -> usize {
        match self.word_count {
            WordCount::W12 => 12,
            WordCount::W24 => 24,
        }
    }

    pub fn words_slice(&self) -> &[&'static str] {
        &self.words[..self.word_count_n()]
    }

    pub fn entropy_hex(&self) -> alloc_free_string::String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    pub fn master_fingerprint_hex(&self) -> alloc_free_string::String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

/// Outcome of a `compat-verify` derivation attempt -- deliberately mirrors
/// `seed_compat::CompatError` one-for-one (SPEC_COMPAT §3, §12) plus the
/// `Success` case; there is no variant that pairs a rendered mnemonic with
/// anything other than `Success` (the F1 fix, structurally preserved here).
pub enum Outcome {
    Success(Success),
    BadAlphabet { at: usize },
    Refused { entered: u16, reason: &'static str },
    Empty,
}

/// Run the full `compat-verify` pipeline: `compat_derive` (SPEC_COMPAT §12),
/// then -- only on success -- the SPEC §24.2 derivation chain via
/// `seed-derive`, exactly as production computes it, over the resulting
/// mnemonic.
pub fn run(profile: &'static CompatProfile, events: &str, requested: Option<WordCount>) -> Outcome {
    match compat_derive(profile, events, requested) {
        Err(CompatError::BadAlphabet { at }) => Outcome::BadAlphabet { at },
        Err(CompatError::Refused { entered, reason }) => Outcome::Refused { entered, reason },
        Err(CompatError::Empty) => Outcome::Empty,
        Ok(out) => Outcome::Success(finish(profile, events, out)),
    }
}

fn finish(profile: &'static CompatProfile, events: &str, out: CompatOutput) -> Success {
    // Recompute the digest independently of `seed_compat::compat_derive`'s
    // internals (that crate does not expose the raw entropy bytes, by
    // design -- SPEC_COMPAT §3 gives `seed-compat` no obligation beyond
    // `mnemonic_indexes`). This mirrors exactly the digest step
    // `compat_derive` itself performs (SPEC_COMPAT §5.1, §12 step 4/5):
    // `entropy = SHA256(ascii events)[..16 or ..32]`.
    let digest = seed_core::hash::sha256(events.as_bytes());
    let entropy_len = match out.word_count {
        WordCount::W12 => 16,
        WordCount::W24 => 32,
    };
    let mut entropy = [0u8; 32];
    entropy[..entropy_len].copy_from_slice(&digest[..entropy_len]);

    let core_count = match out.word_count {
        WordCount::W12 => CoreWordCount::Twelve,
        WordCount::W24 => CoreWordCount::TwentyFour,
    };

    let mut words = [""; 24];
    let n = match out.word_count {
        WordCount::W12 => 12,
        WordCount::W24 => 24,
    };
    for i in 0..n {
        words[i] = seed_core::bip39::word(out.mnemonic_indexes[i]);
    }

    let (master_fingerprint, addresses) = verification_values(&out.mnemonic_indexes, core_count);

    Success {
        profile,
        word_count: out.word_count,
        words,
        used_len: out.used_len,
        entropy,
        entropy_len,
        master_fingerprint,
        addresses,
    }
}

/// Shared SPEC §24.2 verification-values chain used by BOTH Method A
/// (`finish`) and Method C (`finish_entropy`): given resolved mnemonic
/// indexes, walk the exact same `seed-derive` path production computes —
/// `mnemonic_to_seed` → `master_from_seed`/`master_fingerprint` →
/// `first_address` for the four fixed standards — scrubbing the seed/key/
/// chain-code buffers afterward (SPEC §13, §20.3 hygiene).
fn verification_values(
    mnemonic_indexes: &[u16; 24],
    core_count: CoreWordCount,
) -> ([u8; 4], [RenderedAddress; 4]) {
    let mut seed = [0u8; 64];
    seed_core::bip39::mnemonic_to_seed(mnemonic_indexes, core_count, &mut seed);

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    seed_derive::bip32::master_from_seed(&seed, &mut key, &mut cc);
    let master_fingerprint = seed_derive::bip32::master_fingerprint(&key);
    key.zeroize();
    cc.zeroize();

    let standards: [(&'static str, PathStandard); 4] = [
        ("BIP44", PathStandard::Bip44),
        ("BIP49", PathStandard::Bip49),
        ("BIP84", PathStandard::Bip84),
        ("BIP86", PathStandard::Bip86),
    ];
    let addresses = standards.map(|(label, standard)| {
        let mut buf = AddressBuf::empty();
        seed_derive::address::first_address(&seed, standard, &mut buf)
            .expect("SPEC §24.2 fixed paths do not fail on a valid BIP39 seed");
        RenderedAddress {
            label,
            address: *buf.full_bytes(),
            address_len: buf.len(),
        }
    });

    seed.zeroize();
    (master_fingerprint, addresses)
}

// ===========================================================================
// Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md)
// ===========================================================================

/// A successful Method-C derivation: the reproduced mnemonic + SPEC §24
/// verification values, plus the diagnostics SPEC_COMPAT_ENTROPY §9 requires
/// on the result screen (accepted-symbol / ignored-char counts, retained vs
/// total bits). Entropy hex is rendered by the caller ONLY behind
/// `--show-entropy` (review F7).
pub struct EntropySuccess {
    pub encoding: Encoding,
    pub word_count: WordCount,
    pub words: [&'static str; 24],
    pub accepted_symbols: u16,
    pub ignored_chars: u16,
    pub retained_bits: u16,
    pub total_bits: u16,
    pub entropy: [u8; 32],
    pub entropy_len: usize,
    pub master_fingerprint: [u8; 4],
    pub addresses: [RenderedAddress; 4],
}

impl EntropySuccess {
    pub fn word_count_n(&self) -> usize {
        match self.word_count {
            WordCount::W12 => 12,
            WordCount::W24 => 24,
        }
    }

    pub fn words_slice(&self) -> &[&'static str] {
        &self.words[..self.word_count_n()]
    }

    pub fn entropy_hex(&self) -> alloc_free_string::String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    pub fn master_fingerprint_hex(&self) -> alloc_free_string::String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

/// Outcome of a Method-C verification attempt — either a `Success` or a
/// typed refusal (`seed_compat::EntropyEncodingError`), never a mnemonic
/// paired with a refusal (SPEC_COMPAT_ENTROPY §5.5).
pub enum EntropyOutcome {
    Success(EntropySuccess),
    Refused(EntropyEncodingError),
}

/// Run the full Method-C pipeline: `seed_compat::entropy_encoding_derive`
/// (the byte-exact `eventBits` front end + truncation + refusal), then —
/// only on success — the SPEC §24.2 derivation chain via `seed-derive`,
/// exactly as production computes it, over the reproduced mnemonic. Never
/// fabricates a phrase for a refused input.
pub fn run_entropy(encoding: Encoding, input: &str) -> EntropyOutcome {
    match entropy_encoding_derive(encoding, input) {
        Err(e) => EntropyOutcome::Refused(e),
        Ok(out) => EntropyOutcome::Success(finish_entropy(out)),
    }
}

fn finish_entropy(out: EntropyEncodingOutput) -> EntropySuccess {
    let core_count = match out.word_count {
        WordCount::W12 => CoreWordCount::Twelve,
        WordCount::W24 => CoreWordCount::TwentyFour,
    };

    let mut words = [""; 24];
    let n = match out.word_count {
        WordCount::W12 => 12,
        WordCount::W24 => 24,
    };
    for i in 0..n {
        words[i] = seed_core::bip39::word(out.mnemonic_indexes[i]);
    }

    let (master_fingerprint, addresses) = verification_values(&out.mnemonic_indexes, core_count);

    let mut entropy = [0u8; 32];
    entropy[..out.entropy_len].copy_from_slice(&out.entropy[..out.entropy_len]);

    EntropySuccess {
        encoding: out.encoding,
        word_count: out.word_count,
        words,
        accepted_symbols: out.accepted_symbols,
        ignored_chars: out.ignored_chars,
        retained_bits: out.retained_bits,
        total_bits: out.total_bits,
        entropy,
        entropy_len: out.entropy_len,
        master_fingerprint,
        addresses,
    }
}

// A tiny no-alloc-crate hex/string helper. `compat-verify` is a host `std`
// binary/lib (SPEC_COMPAT §9: host CLI only, never in the `no_std`
// production graph), so ordinary `std::string::String` is available; this
// module is named defensively so a reader never mistakes it for a
// `no_std`-compatibility shim.
mod alloc_free_string {
    pub type String = std::string::String;
}

fn bytes_to_hex(bytes: &[u8]) -> alloc_free_string::String {
    use std::fmt::Write;
    let mut s = alloc_free_string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Word-count-rule helper shared by `screens` (SPEC_COMPAT §6/§7): the
/// noun used for this profile's events ("rolls" for dice, "flips" for
/// coins), for building profile-agnostic method/refusal text.
pub fn event_noun(profile: &CompatProfile) -> &'static str {
    match profile.alphabet {
        seed_compat::EventAlphabet::Dice1to6 => "rolls",
        seed_compat::EventAlphabet::Coin01 => "flips",
    }
}

/// `true` if `profile` uses `DerivedFromLength` (SeedSigner-style: word
/// count is a pure function of input length, non-canonical lengths
/// refused -- SPEC_COMPAT §6, review F1).
pub fn is_derived_from_length(profile: &CompatProfile) -> bool {
    matches!(profile.word_count_rule, WordCountRule::DerivedFromLength { .. })
}
