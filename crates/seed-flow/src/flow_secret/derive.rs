//! Transcript build + final-entropy derivation in the arena (SPEC §19),
//! with the immediate SPEC §19.4 scrubs.
//!
//! [`FlowTranscript`]/[`FlowDeriver`] wire the real WP-08
//! `TranscriptBuilder` and WP-13/WP-14 free functions into the WP-15
//! pipeline facade's `TranscriptSink`/`KeyDeriver` slots (mirrors
//! `seed-test-vectors::{RealTranscript, RealDeriver}` byte-for-byte —
//! but lives in this crate's *production* path, unlike that crate,
//! because `seed-test-vectors` MUST NOT be a production-graph dependency
//! (SPEC §9, §28); this module's own host tests use these same
//! production adapters, not `seed-test-vectors`' copies).

use seed_core::arena::SecretArena;
use seed_core::contracts::{ArchId, AddressBuf, DeriveError, MAX_SOURCE_RECORDS, PathStandard, SourceTag, TargetBits, WordCount};
use seed_core::pipeline::{
    compute_extended_verification_values, compute_verification_values, derive_final_entropy, scrub_derivation_stage,
    scrub_transcript_stage, ExtendedVerificationValues, KeyDeriver, PipelineError, SourceInput, TranscriptSink,
    VerificationValues,
};
use seed_protocol::transcript::{TranscriptBuilder, TranscriptError};

use crate::flow_secret::machine::AcquiredSources;
use crate::flow_secret::physical::PhysicalStaging;

/// Production `TranscriptSink` adapter (see module doc comment).
pub struct FlowTranscript(TranscriptBuilder);

impl FlowTranscript {
    #[must_use]
    pub fn new() -> Self {
        Self(TranscriptBuilder::new())
    }
}

impl Default for FlowTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl TranscriptSink for FlowTranscript {
    type Error = TranscriptError;

    fn add_source(&mut self, tag: SourceTag, algo_id: &[u8], bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.add_source(tag, algo_id, bytes)
    }

    fn finalize(self, arch: ArchId, bits: TargetBits, policy_ver: u16, out: &mut [u8; 32]) {
        self.0.finalize(arch, bits, policy_ver, out);
    }
}

/// Production `KeyDeriver` adapter (see module doc comment).
pub struct FlowDeriver;

impl KeyDeriver for FlowDeriver {
    fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
        seed_derive::bip32::master_from_seed(seed, key_out, cc_out);
    }

    fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
        seed_derive::bip32::master_fingerprint(key)
    }

    fn first_address(seed: &[u8; 64], standard: PathStandard, out: &mut AddressBuf) -> Result<(), DeriveError> {
        seed_derive::address::first_address(seed, standard, out)
    }

    fn grid_address(
        seed: &[u8; 64],
        standard: PathStandard,
        account: u32,
        change: u32,
        index: u32,
        out: &mut AddressBuf,
    ) -> Result<(), DeriveError> {
        // Preset purpose fixes the script type (SPEC_DERIVATION_OPTIONS
        // §A.2, no free choice in v1); build the bounded five-level path
        // and render its implied form via the general `address_at`.
        let path = seed_derive::bip32::preset_path(standard, account, change, index);
        let script_type = seed_derive::address::ScriptType::for_standard(standard);
        seed_derive::address::address_at(seed, script_type, &path, out)
    }
}

/// Errors from [`derive`] (SPEC §27.2: fatal once reached — this is only
/// ever called from `AppState::FinalEntropyDerivation`, after final
/// entropy has conceptually begun to exist). Includes
/// [`PipelineError::InsufficientSources`] (pre-release audit MUST-FIX #2,
/// `docs/PRE-RELEASE-AUDIT.md`): [`derive`]'s caller
/// (`flow_secret::driver`'s `AppState::FinalEntropyDerivation` handler)
/// already treats every `Err(_)` from this function identically — routed
/// into the fatal `Event::DerivationFailed` transition per SPEC §27.2 —
/// so the new variant is handled correctly with no caller-side match
/// changes: this is defense-in-depth *underneath* that existing
/// catch-all, not a new case the caller needs to distinguish.
pub type DeriveFlowError = PipelineError<TranscriptError>;

fn empty_input() -> SourceInput<'static> {
    SourceInput { tag: SourceTag::DiceRolls, algo_id: &[], bytes: &[] }
}

/// Build the SPEC §19.1 source records from `staging` (dice/coin) and
/// `machine` (machine sources), run the pipeline
/// (`sources -> canonical transcript -> final entropy -> mnemonic
/// indexes`, SPEC §19, §14) into `arena`, and immediately perform the
/// SPEC §19.4 scrubs: the arena's own transcript-stage fields (harmless
/// no-ops today — this driver keeps the real dice/coin/machine bytes in
/// `staging`/`machine`, not in the arena, see those modules' doc
/// comments) plus `staging`/`machine` themselves.
///
/// On success, `arena.final_entropy()`/`arena.mnemonic_indexes()` hold
/// the SPEC §19.3/§14 results; `staging` and `machine` are fully
/// scrubbed either way.
pub fn derive(
    arena: &mut SecretArena,
    staging: &mut PhysicalStaging,
    machine: &mut AcquiredSources,
    arch: ArchId,
    bits: TargetBits,
    policy_ver: u16,
) -> Result<WordCount, DeriveFlowError> {
    // Staging array sized to the canonical maximum (SPEC §19.1;
    // `MAX_SOURCE_RECORDS`), NOT a hand-counted subset — the previous
    // five-entry array could be indexed out of bounds and PANIC if a future
    // policy expansion assembled more sources (Gemini 3.1 Pro audit
    // ALEA-AUDIT-002). `SourceInput` is not `Copy` (it holds a byte-slice
    // reference), so build the array element-wise.
    let mut inputs: [SourceInput; MAX_SOURCE_RECORDS] = core::array::from_fn(|_| empty_input());
    let mut n = 0usize;

    // Count what will be appended FIRST; if it exceeds the staging capacity,
    // fail into the controlled error path (TooManySources) rather than
    // indexing OOB. With the count checked up front, every append below is
    // provably in bounds.
    let dice = staging.dice_bytes();
    let coin = staging.coin_bytes();
    let want = (!dice.is_empty() as usize) + (!coin.is_empty() as usize) + machine.iter().count();

    let result = if want > MAX_SOURCE_RECORDS {
        Err(PipelineError::TooManySources)
    } else {
        if !dice.is_empty() {
            inputs[n] = SourceInput { tag: SourceTag::DiceRolls, algo_id: &[], bytes: dice };
            n += 1;
        }
        if !coin.is_empty() {
            inputs[n] = SourceInput { tag: SourceTag::CoinFlips, algo_id: &[], bytes: coin };
            n += 1;
        }
        for acquired in machine.iter() {
            inputs[n] = SourceInput { tag: acquired.tag(), algo_id: acquired.algo_id(), bytes: acquired.bytes() };
            n += 1;
        }
        derive_final_entropy(arena, FlowTranscript::new(), &inputs[..n], arch, bits, policy_ver)
    };

    // SPEC §19.4: "Immediately after final entropy is derived" -- run on
    // both outcomes, since a failed derivation must not leave raw source
    // material lying around either (SPEC §27.2 routes a derivation
    // failure straight into the fatal scrub chain regardless).
    scrub_transcript_stage(arena);
    staging.scrub();
    machine.scrub();

    result
}

/// Runs `mnemonic indexes -> BIP39 seed -> master fingerprint + 4 first
/// addresses` (SPEC §24.2-§24.3) on demand for the derivation-
/// verification screen.
pub fn compute_verification(arena: &mut SecretArena, word_count: WordCount) -> Result<VerificationValues, DeriveError> {
    compute_verification_values::<FlowDeriver>(arena, word_count)
}

/// SPEC_DERIVATION_OPTIONS §A.0 (Model A): eagerly derive the **whole**
/// bounded verification grid into `out` for the "more derivation options"
/// menu. The caller MUST follow this with [`scrub_after_verification`]
/// **before** opening the interactive menu, so the seed is scrubbed while
/// the menu navigates only the pre-rendered public strings in `out`.
pub fn compute_extended_verification(
    arena: &mut SecretArena,
    word_count: WordCount,
    out: &mut ExtendedVerificationValues,
) -> Result<(), DeriveError> {
    compute_extended_verification_values::<FlowDeriver>(arena, word_count, out)
}

/// Scrubs the BIP39-seed/BIP32-derivation arena fields once the
/// verification screen has been shown or skipped (SPEC §19.4, §20.1).
pub fn scrub_after_verification(arena: &mut SecretArena) {
    scrub_derivation_stage(arena);
}

/// SPEC_DERIVATION_CUSTOM.md §3.2/§4.2: one committed custom-path leaf —
/// the public master fingerprint plus the single rendered address for the
/// arbitrary `(path, script_type)` the §3 structured builder assembled.
/// Non-secret display payload (both fields are exactly what SPEC §24.3
/// permits on screen), safe to `Copy`.
#[derive(Clone, Copy)]
pub struct CustomAddress {
    /// SPEC §24.3 master-key fingerprint (path-independent).
    pub master_fingerprint: [u8; 4],
    /// The rendered mainnet-BTC address for the committed path + script.
    pub address: AddressBuf,
}

/// SPEC_DERIVATION_CUSTOM.md §4.2 (commit-then-derive, OQ-7): derive the
/// ONE committed custom-path leaf from the **resident** BIP39 mnemonic and
/// render it as `script_type`, then scrub the derived seed IMMEDIATELY.
///
/// This is the deliberate, documented relaxation of the "verification never
/// touches a secret" property (SPEC_DERIVATION_CUSTOM §4/§14): the custom
/// builder's BUILD phase is pure public arithmetic, but COMMIT re-derives
/// the seed for exactly one non-interactive `address_at` call. The
/// reconstructed mnemonic (`arena.mnemonic_indexes()`) stays resident across
/// the whole verification phase — from §23 re-entry until the §26 shutdown
/// chain (or any fatal/panic, covered by the whole-arena/panic scrub) — so a
/// second commit in the same builder session (OQ-7) simply re-derives; but
/// the derived **seed** never outlives this call: `seed_local` is scrubbed
/// with the reviewed volatile+fence+verify primitive and the arena's
/// derivation-stage fields (`bip39_seed`, `master_key`, `master_chain_code`,
/// scratch) are wiped via [`scrub_after_verification`] before this returns.
///
/// `address_at` itself scrubs every intermediate child key / chain code /
/// pubkey on every return path (`seed-derive`), so no BIP32 intermediate
/// survives either.
///
/// # Errors
///
/// Propagates any [`DeriveError`] from `address_at` (cryptographically
/// unreachable for a real seed). Per SPEC_DERIVATION_CUSTOM §4.4 the caller
/// treats a commit-phase error as a production verification failure
/// (§24.4 screen, then the fatal scrub-and-shutdown chain, SPEC §27.2).
pub fn compute_custom_address(
    arena: &mut SecretArena,
    word_count: WordCount,
    script_type: seed_derive::address::ScriptType,
    path: &[u32],
) -> Result<CustomAddress, DeriveError> {
    // Stage the resident mnemonic indexes AND the resident committed
    // passphrase locally (same simultaneous-borrow reason as
    // `compute_verification_values`): the crypto call needs them as
    // read-only slices while `arena.bip39_seed()` needs `&mut self`.
    // SPEC_PASSPHRASE §M2: the custom-path leaf derives from the SAME
    // committed passphrase as the grid/preview — an empty passphrase keeps
    // today's byte-identical result.
    let mut indexes_local = [0u16; 24];
    indexes_local.copy_from_slice(arena.mnemonic_indexes());

    let mut pp_local = [0u8; seed_core::passphrase::MAX_PASSPHRASE_LEN];
    let pp_len = arena.passphrase().len();
    pp_local[..pp_len].copy_from_slice(arena.passphrase().as_bytes());

    seed_core::bip39::mnemonic_to_seed_with_passphrase_bytes(
        &indexes_local,
        word_count,
        &pp_local[..pp_len],
        arena.bip39_seed(),
    );
    scrub_u16_local(&mut indexes_local);
    seed_core::arena::scrub_slice(&mut pp_local);

    let mut seed_local = [0u8; 64];
    seed_local.copy_from_slice(arena.bip39_seed());

    // Master fingerprint (path-independent, §24.3): derive it from the
    // master key, then scrub the key/chain-code copies immediately.
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    seed_derive::bip32::master_from_seed(&seed_local, &mut key, &mut cc);
    let master_fingerprint = seed_derive::bip32::master_fingerprint(&key);
    seed_core::arena::scrub_slice(&mut key);
    seed_core::arena::scrub_slice(&mut cc);

    // The one committed leaf.
    let mut address = AddressBuf::empty();
    let result = seed_derive::address::address_at(&seed_local, script_type, path, &mut address);

    // SPEC_DERIVATION_CUSTOM §4.2 step 4: scrub the derived seed IMMEDIATELY.
    // The local seed copy and the arena's derivation-stage fields are wiped
    // now; the mnemonic indexes stay resident for a possible further commit.
    seed_core::arena::scrub_slice(&mut seed_local);
    scrub_after_verification(arena);

    result.map(|()| CustomAddress { master_fingerprint, address })
}

/// Scrubs a `[u16]` mnemonic-index staging buffer through the arena's
/// reviewed volatile+fence+verify primitive (SPEC §20.3), mirroring
/// `SecretArena::scrub_all`'s own `[u16]` handling.
fn scrub_u16_local(buf: &mut [u16]) {
    // SAFETY: reinterpreting a `[u16]` as `2*len` bytes through a `u8`
    // pointer is always valid (`u8` has no alignment/padding constraint and
    // every byte of a `u16` is part of its object representation); the
    // slice stays within the exclusively-borrowed buffer.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), core::mem::size_of_val(buf))
    };
    seed_core::arena::scrub_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-release audit MUST-FIX #2 (`docs/PRE-RELEASE-AUDIT.md`): with
    /// no dice, no coin flips and no acquired machine sources, `derive`
    /// must propagate `seed_core::pipeline`'s fail-closed
    /// `InsufficientSources` rejection all the way through this caller,
    /// not silently succeed with a fixed/empty-transcript digest. Calls
    /// this crate's real production caller directly, with no upstream
    /// state-machine gate anywhere in the call chain, proving the floor
    /// holds even if a future refactor of the gating logic (e.g.
    /// `PhysicalBudgetMet`, machine-acquire-success) ever let an empty
    /// source set reach this function.
    #[test]
    fn empty_sources_are_refused_not_silently_derived() {
        let mut arena = SecretArena::new();
        let mut staging = PhysicalStaging::new();
        let mut machine = AcquiredSources::new();

        let result = derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, TargetBits::Bits128, 1);

        assert!(result.is_err(), "empty sources must be refused, not silently derived");
        assert!(
            arena.final_entropy().iter().all(|&b| b == 0),
            "a rejected derivation must not leave a deterministic digest in the arena"
        );
        // `staging`/`machine` must still be scrubbed on this path too
        // (SPEC §19.4 applies "on both outcomes", see this function's own
        // doc comment).
        assert!(staging.dice_bytes().is_empty());
        assert!(staging.coin_bytes().is_empty());
    }

    #[test]
    fn dice_only_derivation_populates_arena_and_scrubs_staging() {
        let mut arena = SecretArena::new();
        let mut staging = PhysicalStaging::new();
        for _ in 0..50 {
            // push directly (mirrors what `physical::run_physical_entry` does)
            staging_push_dice_for_test(&mut staging, 3);
        }
        let mut machine = AcquiredSources::new();

        let word_count = derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        assert_eq!(word_count, WordCount::Twelve);
        assert!(!arena.final_entropy()[..16].iter().all(|&b| b == 0));
        assert!(staging.dice_bytes().is_empty(), "staging must be scrubbed after derivation");
        assert!(staging.coin_bytes().is_empty());
    }

    #[test]
    fn mixed_dice_and_coin_and_machine_sources_all_contribute() {
        let mut arena_a = SecretArena::new();
        let mut staging_a = PhysicalStaging::new();
        for _ in 0..20 {
            staging_push_dice_for_test(&mut staging_a, 2);
        }
        let mut machine_a = AcquiredSources::new();
        derive(&mut arena_a, &mut staging_a, &mut machine_a, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        let mut arena_b = SecretArena::new();
        let mut staging_b = PhysicalStaging::new();
        for _ in 0..20 {
            staging_push_dice_for_test(&mut staging_b, 2);
        }
        let mut machine_b = AcquiredSources::new();
        machine_b.push(crate::flow_secret::machine::AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &[9u8; 32]).unwrap());
        derive(&mut arena_b, &mut staging_b, &mut machine_b, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        assert_ne!(
            arena_a.final_entropy(),
            arena_b.final_entropy(),
            "adding a machine source must change the derived entropy"
        );
    }

    #[test]
    fn max_source_set_does_not_panic_and_derives() {
        // ALEA-AUDIT-002 regression (Gemini 3.1 Pro): dice + coin + the full
        // 5-slot machine container is SEVEN source records — more than the old
        // five-entry staging array, which would have indexed out of bounds and
        // PANICKED at `inputs[5]`. With the array sized to MAX_SOURCE_RECORDS
        // (8) and the up-front count guard, the widest assemblable set derives
        // without panicking.
        let mut arena = SecretArena::new();
        let mut staging = PhysicalStaging::new();
        for _ in 0..64 {
            staging_push_dice_for_test(&mut staging, 3);
        }
        for _ in 0..64 {
            staging.push_coin(1);
        }
        let mut machine = AcquiredSources::new();
        for (tag, algo) in [
            (SourceTag::ApprovedEfiRng, &b"EFIRNG"[..]),
            (SourceTag::X86Rdseed64, &b"RDSEED64"[..]),
            (SourceTag::X86RdrandSupplementary, &b"RDRAND64"[..]),
            (SourceTag::ApprovedUsbTrng, &b"USBTRNG"[..]),
            (SourceTag::Tpm2GetRandom, &b"TPM2GET"[..]),
        ] {
            machine.push(
                crate::flow_secret::machine::AcquiredSource::new(tag, algo, &[7u8; 32]).unwrap(),
            );
        }
        // 5 machine + dice + coin = 7 records (<= MAX_SOURCE_RECORDS = 8).
        let r = derive(
            &mut arena,
            &mut staging,
            &mut machine,
            ArchId::X86_64,
            TargetBits::Bits128,
            1,
        );
        assert!(r.is_ok(), "max assemblable source set must derive, not panic: {r:?}");
        assert!(staging.dice_bytes().is_empty(), "staging scrubbed after derivation");
        assert!(machine.iter().next().is_none(), "machine scrubbed after derivation");
    }

    #[test]
    fn verification_round_trip_matches_seed_derive_directly() {
        let mut arena = SecretArena::new();
        let mut staging = PhysicalStaging::new();
        for _ in 0..50 {
            staging_push_dice_for_test(&mut staging, 5);
        }
        let mut machine = AcquiredSources::new();
        let word_count = derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        let values = compute_verification(&mut arena, word_count).unwrap();
        assert_ne!(values.master_fingerprint, [0u8; 4]);
        for a in &values.addresses {
            assert!(a.address.len() > 0);
        }

        scrub_after_verification(&mut arena);
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
    }

    /// SPEC_DERIVATION_OPTIONS §A.0 Model-A round trip: the eagerly
    /// pre-derived grid's (0,0,0) leaves reproduce the default screen's
    /// four addresses, and a non-zero cell matches `seed_derive::address::
    /// address_at` computed directly — proving the pipeline wires the real
    /// derivation, not a stand-in.
    #[test]
    fn extended_grid_matches_default_and_direct_derivation() {
        use seed_core::pipeline::{ExtendedVerificationValues, N_ACCOUNT_MAX, N_INDEX_MAX};

        let mut arena = SecretArena::new();
        let mut staging = PhysicalStaging::new();
        for _ in 0..50 {
            staging.push_dice(4);
        }
        let mut machine = AcquiredSources::new();
        let wc = derive(&mut arena, &mut staging, &mut machine, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        // Snapshot the mnemonic indexes so we can reproduce the same seed
        // independently after the grid derivation scrubs the arena.
        let indexes = *arena.mnemonic_indexes();

        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification(&mut arena, wc, &mut ext).unwrap();

        // (a) base_values == the default-screen derivation on a fresh arena.
        let mut arena2 = SecretArena::new();
        arena2.mnemonic_indexes().copy_from_slice(&indexes);
        let values = compute_verification(&mut arena2, wc).unwrap();
        let base = ext.base_values();
        assert_eq!(base.master_fingerprint, values.master_fingerprint);
        for (b, v) in base.addresses.iter().zip(values.addresses.iter()) {
            assert_eq!(b.address.as_str(), v.address.as_str());
        }
        arena2.scrub_all();

        // (b) a non-zero cell (BIP84, account 2, change 1, index 3) matches
        // address_at computed directly from the reproduced seed.
        let mut seed = [0u8; 64];
        seed_core::bip39::mnemonic_to_seed(&indexes, wc, &mut seed);
        let path = seed_derive::bip32::preset_path(PathStandard::Bip84, 2, 1, 3);
        let mut direct = AddressBuf::empty();
        seed_derive::address::address_at(
            &seed,
            seed_derive::address::ScriptType::for_standard(PathStandard::Bip84),
            &path,
            &mut direct,
        )
        .unwrap();
        let cell = ext.address(PathStandard::Bip84, 2, 1, 3).unwrap();
        assert_eq!(cell.as_str(), direct.as_str());
        assert!(cell.len() > 0);

        // sanity: bounds honored.
        assert!(ext.address(PathStandard::Bip84, N_ACCOUNT_MAX + 1, 0, 0).is_none());
        assert!(ext.address(PathStandard::Bip84, 0, 0, N_INDEX_MAX + 1).is_none());

        // Model A: the seed is gone after the pre-derivation scrub step.
        scrub_after_verification(&mut arena);
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));

        for b in seed.iter_mut() {
            *b = 0;
        }
    }

    // `PhysicalStaging::push_dice` is crate-visible (not private) exactly
    // so this module's own unit tests (which only care that *some* dice
    // bytes exist, not the exact `physical::run_physical_entry` UI loop)
    // can populate one directly.
    fn staging_push_dice_for_test(staging: &mut PhysicalStaging, value: u8) {
        staging.push_dice(value);
    }

    // ------------------------------------------------------------------
    // SPEC_PASSPHRASE §7.2.1/§M2 (production FlowDeriver): a set passphrase
    // changes EVERY grid fingerprint/address AND a custom-builder address,
    // versus the empty-passphrase result; the empty path is byte-identical
    // to the published vector.
    // ------------------------------------------------------------------

    extern crate std;

    fn word_index(target: &str) -> u16 {
        (0..2048u16).find(|&i| seed_core::bip39::word(i) == target).expect("word in list")
    }

    /// Load "abandon abandon ... about" into a fresh arena's mnemonic
    /// indexes (the canonical BIP39/BIP84 test seed), optionally committing
    /// `passphrase` into the arena.
    fn arena_abandon(passphrase: &[u8]) -> SecretArena {
        let abandon = word_index("abandon");
        let about = word_index("about");
        let mut arena = SecretArena::new();
        {
            let idx = arena.mnemonic_indexes();
            for slot in idx.iter_mut().take(11) {
                *slot = abandon;
            }
            idx[11] = about;
        }
        for &b in passphrase {
            arena.passphrase().push_ascii(b).unwrap();
        }
        arena
    }

    #[test]
    fn set_passphrase_changes_every_grid_and_custom_value_vs_empty() {
        use seed_core::pipeline::{ExtendedVerificationValues, N_ACCOUNT_MAX, N_CHANGE, N_INDEX_MAX};

        // Empty-passphrase grid.
        let mut arena_e = arena_abandon(b"");
        let mut ext_e = ExtendedVerificationValues::new();
        compute_extended_verification(&mut arena_e, WordCount::Twelve, &mut ext_e).unwrap();

        // Same mnemonic, committed non-empty passphrase.
        let mut arena_p = arena_abandon(b"Correct Horse 42!");
        let mut ext_p = ExtendedVerificationValues::new();
        compute_extended_verification(&mut arena_p, WordCount::Twelve, &mut ext_p).unwrap();

        assert_ne!(ext_e.master_fingerprint, ext_p.master_fingerprint, "fingerprint must change");
        for standard in [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86] {
            for account in 0..=N_ACCOUNT_MAX {
                for change in 0..N_CHANGE as u32 {
                    for index in 0..=N_INDEX_MAX {
                        let a = ext_e.address(standard, account, change, index).unwrap();
                        let b = ext_p.address(standard, account, change, index).unwrap();
                        assert_ne!(
                            a.as_str(), b.as_str(),
                            "grid cell {standard:?}/{account}/{change}/{index} must differ under a set passphrase"
                        );
                    }
                }
            }
        }

        // Custom-path builder leaf (BIP84 m/84'/0'/0'/0/0) differs too.
        let mut arena_ce = arena_abandon(b"");
        let empty_leaf = compute_custom_address(
            &mut arena_ce,
            WordCount::Twelve,
            seed_derive::address::ScriptType::P2wpkh,
            &seed_derive::bip32::preset_path(PathStandard::Bip84, 0, 0, 0),
        )
        .unwrap();
        let mut arena_cp = arena_abandon(b"Correct Horse 42!");
        let pp_leaf = compute_custom_address(
            &mut arena_cp,
            WordCount::Twelve,
            seed_derive::address::ScriptType::P2wpkh,
            &seed_derive::bip32::preset_path(PathStandard::Bip84, 0, 0, 0),
        )
        .unwrap();
        assert_ne!(
            empty_leaf.address.as_str(), pp_leaf.address.as_str(),
            "custom-path leaf must reflect the committed passphrase"
        );

        // Empty path is byte-identical to the published BIP84 vector.
        assert_eq!(empty_leaf.address.as_str().unwrap(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    /// SPEC_PASSPHRASE §10.3 — Alea end-to-end address vector for the
    /// canonical mnemonic + a sample printable-ASCII passphrase. The SEED
    /// for this pair is independently verified (Python `hashlib`, see
    /// `seed-core`'s `alea_sample_ascii_passphrase_seed_matches_independent_reference`);
    /// this pins the derived BIP84 receive-0 address end-to-end so a
    /// regression in the passphrase→seed→address path is caught. It is, by
    /// construction, DIFFERENT from the empty-passphrase published vector.
    #[test]
    fn alea_sample_passphrase_bip84_address_is_pinned_and_differs_from_empty() {
        let mut arena = arena_abandon(b"Correct Horse 42!");
        let leaf = compute_custom_address(
            &mut arena,
            WordCount::Twelve,
            seed_derive::address::ScriptType::P2wpkh,
            &seed_derive::bip32::preset_path(PathStandard::Bip84, 0, 0, 0),
        )
        .unwrap();
        assert_eq!(leaf.address.as_str().unwrap(), ALEA_SAMPLE_BIP84_RECEIVE_0);
        assert_ne!(leaf.address.as_str().unwrap(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
}

/// SPEC_PASSPHRASE §10.3 pinned Alea sample: BIP84 `m/84'/0'/0'/0/0`
/// receive address for "abandon abandon ... about" + passphrase
/// `"Correct Horse 42!"`. (Its underlying seed is independently verified in
/// `seed-core`.)
#[cfg(test)]
const ALEA_SAMPLE_BIP84_RECEIVE_0: &str = "bc1q5ejpn97xt35es36efwx5a6jg88yfrqev7sf0lv";
