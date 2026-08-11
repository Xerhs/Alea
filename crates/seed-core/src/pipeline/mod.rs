//! Core pipeline facade (WP-15, SPEC §1, §19, §24).
//!
//! This module is the one narrow surface the UIs call to walk the whole
//! generation flow: `sources -> transcript -> final entropy -> mnemonic
//! indexes -> (on demand) fingerprint + 4 first addresses`, entirely
//! inside a [`SecretArena`], with explicit lifecycle scrub methods (SPEC
//! §19.4, §20.1, §20.4). No UI, no UEFI code lives here.
//!
//! ## Crate-boundary design note (read before extending this module)
//!
//! `IMPLEMENTATION_MAP.md` §5 lists this work package's dependencies as
//! WP-05 (BIP39, `seed-core::bip39`), WP-07 (physical session,
//! `seed-protocol::physical`), WP-08 (transcript,
//! `seed-protocol::transcript`), WP-09 (arena, `seed-core::arena`), WP-13
//! (BIP32, `seed-derive::bip32`) and WP-14 (address construction,
//! `seed-derive::address`). WP-05/WP-09 are in this crate and are called
//! directly below. WP-07/WP-08 live in `seed-protocol`, and WP-13/WP-14
//! live in `seed-derive`; both of those crates already depend on
//! `seed-core` (`crates/seed-protocol/Cargo.toml`,
//! `crates/seed-derive/Cargo.toml`), so `seed-core` adding a reverse
//! dependency on either would be a build-breaking dependency cycle.
//! `seed-core`'s own `Cargo.toml` is not a path this work package owns
//! (`IMPLEMENTATION_MAP.md` §6), so the fix (most likely: a small
//! `[dev-dependencies]` addition on `seed-protocol`/`seed-derive` scoped
//! to `#[cfg(test)]` integration tests, which Cargo explicitly permits
//! even when it is cyclic, since dev-dependencies never participate in
//! the production build graph) is out of this work package's reach and is
//! called out in this work package's `shared_file_needs`.
//!
//! Until that lands, this module defines the transcript- and
//! derivation-shaped steps as small local traits ([`TranscriptSink`],
//! [`KeyDeriver`]) whose method signatures mirror the frozen contract
//! function signatures in `crates/seed-core/src/contracts.rs` §4
//! (`TranscriptBuilder::add_source`/`finalize`,
//! `master_from_seed`/`master_fingerprint`/`first_address`) byte-for-byte.
//! `seed-protocol`/`seed-derive` (or a later thin integration crate that
//! depends on all three) can implement these traits for their own
//! concrete types with no adapter glue — Rust's orphan rule permits a
//! foreign trait to be implemented for a local type, and `seed-protocol`
//! / `seed-derive` are exactly "foreign trait, local type" from that
//! implementer's point of view. This keeps the facade real, generic,
//! fully unit-testable today, and trivially wireable once the
//! `dev-dependencies` gap above is closed — no shape change needed on
//! either side.

use core::sync::atomic::{compiler_fence, fence, Ordering};

use crate::arena::SecretArena;
use crate::bip39;
use crate::contracts::{
    AddressBuf, ArchId, Bip39Error, DeriveError, PathStandard, SourceTag, TargetBits, WordCount,
};
use crate::passphrase::MAX_PASSPHRASE_LEN;

// ============================================================================
// Injected steps (SPEC §19: transcript; SPEC §24: BIP32 + address)
// ============================================================================

/// One entropy-source record as the caller assembled it (SPEC §19.1). Not
/// itself secret-bearing storage — it borrows from whatever buffer the
/// caller (arena-backed machine-source staging, or `PhysicalSession`'s
/// event history) already holds; this struct only carries the shape
/// [`TranscriptSink::add_source`] needs.
pub struct SourceInput<'a> {
    /// SPEC §19.1 source tag.
    pub tag: SourceTag,
    /// SPEC §19.1 `algorithm_identifier` (empty for dice/coin sources).
    pub algo_id: &'a [u8],
    /// SPEC §19.1 `source_bytes`.
    pub bytes: &'a [u8],
}

/// Mirrors `TranscriptBuilder::add_source`/`finalize`
/// (`crates/seed-core/src/contracts.rs` §4, WP-08, SPEC §19.1-§19.3).
/// Implemented by the real `seed_protocol::transcript::TranscriptBuilder`
/// in an integration context; implemented by a deterministic test double
/// in this module's unit tests.
pub trait TranscriptSink {
    /// The sink's own source-record rejection error (SPEC §19.1
    /// structural checks: duplicate tag, too many records, oversized
    /// payload, ...). Carries no secret content (SPEC §27.3).
    type Error;

    /// Records one source (SPEC §19.1); canonical ordering at `finalize`
    /// time is the sink's responsibility, independent of call order here.
    fn add_source(&mut self, tag: SourceTag, algo_id: &[u8], bytes: &[u8]) -> Result<(), Self::Error>;

    /// Serializes the canonical transcript (SPEC §19.2) and reduces it
    /// with SHA-256 into `out` (SPEC §19.3). Consumes `self` so a real
    /// implementation can scrub its own staged source bytes as part of
    /// this call (SPEC §19.4).
    fn finalize(self, arch: ArchId, bits: TargetBits, policy_ver: u16, out: &mut [u8; 32]);
}

/// Mirrors `master_from_seed`/`master_fingerprint`/`first_address`
/// (`crates/seed-core/src/contracts.rs` §4, WP-13/WP-14, SPEC §24.2-§24.3).
/// Implemented by real `seed_derive::bip32`/`seed_derive::address` free
/// functions via a thin marker type in an integration context; implemented
/// by a deterministic test double in this module's unit tests.
pub trait KeyDeriver {
    /// SPEC §24.2: BIP32 master key from the BIP39 seed.
    fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]);

    /// SPEC §24.3: first four bytes of `hash160(compressed pubkey)`.
    fn master_fingerprint(key: &[u8; 32]) -> [u8; 4];

    /// SPEC §24.2-§24.3: derives `m/purpose'/0'/0'/0/0` for `standard` and
    /// renders its first address into `out`.
    fn first_address(seed: &[u8; 64], standard: PathStandard, out: &mut AddressBuf) -> Result<(), DeriveError>;

    /// SPEC_DERIVATION_OPTIONS §A.2/§A.7.1: derive one arbitrary bounded
    /// grid cell — `m/purpose'/0'/account'/change/address_index` for
    /// `standard`, rendered as the preset's implied script type — into
    /// `out`. Generalizes [`KeyDeriver::first_address`] over the
    /// account/change/index axes for the Model-A pre-derived grid
    /// ([`compute_extended_verification_values`]). The implementer owns the
    /// path construction and purpose→script-type mapping (the pipeline
    /// stays decoupled from `seed-derive`'s `ScriptType`/`preset_path`),
    /// so `grid_address(seed, s, 0, 0, 0, out)` is byte-identical to
    /// `first_address(seed, s, out)`.
    fn grid_address(
        seed: &[u8; 64],
        standard: PathStandard,
        account: u32,
        change: u32,
        index: u32,
        out: &mut AddressBuf,
    ) -> Result<(), DeriveError>;
}

// ============================================================================
// Errors (SPEC §27.3: no secret content)
// ============================================================================

/// Errors from [`derive_final_entropy`]. Generic over the caller's
/// [`TranscriptSink::Error`] so this stays a thin wrapper rather than a
/// re-declaration of WP-08's own error set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineError<T> {
    /// The injected [`TranscriptSink`] rejected a source record.
    Transcript(T),
    /// [`bip39::entropy_to_indexes`] rejected the derived final-entropy
    /// length. Unreachable in practice — [`derive_final_entropy`] always
    /// truncates to exactly 16 or 32 bytes per `bits` — but propagated
    /// rather than panicking (SPEC §27.2: only self-tests panic).
    Bip39(Bip39Error),
    /// `sources` was empty, or every supplied source record contributed
    /// zero bytes of source material (SPEC §19.1, §19.4, §20.1: a
    /// defense-in-depth fail-closed floor at the crypto boundary itself).
    /// Checked by [`derive_final_entropy`] before any hashing happens, so
    /// this can never silently produce a fixed, publicly-computable seed
    /// (pre-release audit MUST-FIX #2, `docs/PRE-RELEASE-AUDIT.md`).
    /// Independent of, and in addition to, any upstream state-machine
    /// gate (e.g. `PhysicalBudgetMet`, machine-acquire-success) that
    /// today already prevents an empty source set from reaching this
    /// function in production.
    InsufficientSources,
    /// More than [`crate::contracts::MAX_SOURCE_RECORDS`] source records
    /// were assembled for one derivation — the fail-closed *ceiling* dual
    /// of [`InsufficientSources`] (Gemini 3.1 Pro audit ALEA-AUDIT-002).
    /// Today's policy keeps the count within bounds, but a future policy
    /// expansion (approving EFI RNG, wiring USB TRNG, a wider source mix)
    /// could exceed the canonical maximum; the assembler returns this
    /// controlled error instead of indexing a fixed staging array out of
    /// bounds and panicking in the pre-OS ceremony (SPEC §27.2: only
    /// self-tests panic). The caller routes it into the same fatal
    /// scrub-and-halt chain as any other derivation failure.
    TooManySources,
}

// ============================================================================
// Verification values (SPEC §24.3: display-only, public, safe to Copy)
// ============================================================================

/// One derivation standard's rendered first address, paired with which
/// standard produced it (SPEC §24.3). Not secret-bearing: an address is
/// exactly the value the wallet-derivation-verification screen displays.
#[derive(Clone, Copy)]
pub struct StandardAddress {
    /// Which of the four fixed single-sig standards this is (SPEC §24.2).
    pub standard: PathStandard,
    /// Its rendered first address (SPEC §24.3).
    pub address: AddressBuf,
}

/// The full "on demand" verification-display payload (SPEC §24.3): the
/// BIP32 master-key fingerprint plus the first address for each of the
/// four fixed standards, in `PathStandard` declaration order
/// (Bip44, Bip49, Bip84, Bip86).
pub struct VerificationValues {
    /// SPEC §24.3 master-key fingerprint.
    pub master_fingerprint: [u8; 4],
    /// SPEC §24.2-§24.3 first address per standard, fixed order.
    pub addresses: [StandardAddress; 4],
}

impl VerificationValues {
    /// Volatile-zero the fingerprint and the four addresses. This is the
    /// small `base_values()` copy the default verification screen renders
    /// from; like [`ExtendedVerificationValues::scrub`] it must be cleared
    /// before its owner drops it, so the SPEC §26 amendment (2026-08-08)
    /// menu-return path leaves no wallet-identifying artifact resident.
    pub fn scrub(&mut self) {
        scrub_local(&mut self.master_fingerprint);
        for sa in self.addresses.iter_mut() {
            sa.address.scrub();
        }
    }
}

// ============================================================================
// Extended (bounded-grid) verification values
// (SPEC_DERIVATION_OPTIONS §A.0/§A.2/§A.7.1 #5, Model A)
// ============================================================================

/// Number of preset standards (SPEC §24.2: BIP44/49/84/86).
pub const N_STANDARDS: usize = 4;

/// Bound on the selectable hardened `account'` axis: `0 ..= N_ACCOUNT_MAX`
/// (SPEC_DERIVATION_OPTIONS §A.2). Pinned by this implementation to keep
/// the Model-A eager pre-derivation grid finite, cheap and small in RAM
/// (see [`ExtendedVerificationValues`]'s size note). A compile-time
/// constant, as §A.0 requires.
pub const N_ACCOUNT_MAX: u32 = 4;

/// Bound on the selectable `address_index` axis: `0 ..= N_INDEX_MAX`
/// (SPEC_DERIVATION_OPTIONS §A.2). Chosen `9` so the first-N-address table
/// (§A.4.3) can reach its hard cap of 10 rows.
pub const N_INDEX_MAX: u32 = 9;

/// Number of selectable accounts (`0 ..= N_ACCOUNT_MAX`).
pub const N_ACCOUNTS: usize = (N_ACCOUNT_MAX as usize) + 1;

/// Number of selectable indices (`0 ..= N_INDEX_MAX`).
pub const N_INDICES: usize = (N_INDEX_MAX as usize) + 1;

/// The two change chains: external (`0`) and internal-change (`1`)
/// (SPEC_DERIVATION_OPTIONS §A.2).
pub const N_CHANGE: usize = 2;

/// First-N-address table default row count (SPEC_DERIVATION_OPTIONS
/// §A.4.3: "default N = 5").
pub const TABLE_DEFAULT_N: usize = 5;

/// First-N-address table hard cap (SPEC_DERIVATION_OPTIONS §A.4.3:
/// "HARD CAP ≈ 10", deliberately not 20). Equals [`N_INDICES`], so the cap
/// never exceeds the pre-derived index axis.
pub const TABLE_MAX_N: usize = 10;

/// Total number of pre-derived leaf-address cells in the Model-A grid:
/// `standards × accounts × change × indices`
/// (`4 × 5 × 2 × 10 = 400`, SPEC_DERIVATION_OPTIONS §A.0).
pub const GRID_CELLS: usize = N_STANDARDS * N_ACCOUNTS * N_CHANGE * N_INDICES;

/// SPEC_DERIVATION_OPTIONS §A.0/§A.7.1 #5: the **Model-A** extended
/// verification payload — the master fingerprint plus **every** address in
/// the bounded selection grid, all pre-rendered up front so the
/// interactive selection menu (`seed-flow`'s `verification.rs`) navigates
/// only finished public strings and never touches a secret.
///
/// The grid is the full product
/// `{BIP44,BIP49,BIP84,BIP86} × account'(0..=N_ACCOUNT_MAX) ×
///  change(0,1) × address_index(0..=N_INDEX_MAX)` = [`GRID_CELLS`] cells,
/// stored flat in [`Self::index`] order. This is **public, non-secret**
/// data (each cell is exactly a displayable address — SPEC §24.3), held
/// outside the secret arena; it is deliberately **not** `Copy` (it is
/// large and only ever passed by `&mut`/`&`).
///
/// Size note (SPEC_DERIVATION_OPTIONS §A.0/OQ-1): `400 × size_of::<AddressBuf>()`
/// = `400 × 93` = **37,200 bytes (~36.3 KB)**. It is a caller-owned local,
/// not arena-resident, so it does not enter the ~4 KB (one-page) secret
/// arena's budget; ~36 KB sits comfortably within the UEFI ≥128 KB stack.
/// The `4×5×2×10` shape (rather than the spec's illustrative `10×10`) was
/// chosen to keep both this footprint and the eager 400-derivation time
/// modest on the production UEFI derive path (§A.0); the bounds are
/// compile-time constants, so tightening `N_ACCOUNT_MAX` further is a
/// one-line change.
pub struct ExtendedVerificationValues {
    /// SPEC §24.3 master-key fingerprint (path-independent; shown once,
    /// identical across every grid cell — §A.4.2/§A.5 rule 9).
    pub master_fingerprint: [u8; 4],
    /// Flat grid of pre-rendered addresses, indexed by [`Self::index`].
    addresses: [AddressBuf; GRID_CELLS],
}

impl Default for ExtendedVerificationValues {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedVerificationValues {
    /// An all-empty grid, the zeroed target
    /// [`compute_extended_verification_values`] fills in place.
    #[must_use]
    pub fn new() -> Self {
        Self {
            master_fingerprint: [0u8; 4],
            addresses: [AddressBuf::empty(); GRID_CELLS],
        }
    }

    /// The fixed ordinal of a standard in the grid's storage order
    /// (Bip44, Bip49, Bip84, Bip86).
    const fn standard_ord(standard: PathStandard) -> usize {
        match standard {
            PathStandard::Bip44 => 0,
            PathStandard::Bip49 => 1,
            PathStandard::Bip84 => 2,
            PathStandard::Bip86 => 3,
        }
    }

    /// Flat storage index for one `(standard, account, change, index)`
    /// selection, or `None` if any coordinate is out of the pre-derived
    /// bounds.
    fn index(standard: PathStandard, account: u32, change: u32, index: u32) -> Option<usize> {
        if account > N_ACCOUNT_MAX || change >= N_CHANGE as u32 || index > N_INDEX_MAX {
            return None;
        }
        let s = Self::standard_ord(standard);
        let a = account as usize;
        let c = change as usize;
        let i = index as usize;
        Some(((s * N_ACCOUNTS + a) * N_CHANGE + c) * N_INDICES + i)
    }

    /// The pre-rendered address for one selection, or `None` if the
    /// selection is out of bounds (a bounds bug in the caller, never
    /// reachable from the bounded UI selectors).
    #[must_use]
    pub fn address(&self, standard: PathStandard, account: u32, change: u32, index: u32) -> Option<&AddressBuf> {
        Self::index(standard, account, change, index).map(|i| &self.addresses[i])
    }

    /// Volatile-zero the master fingerprint and every pre-derived address.
    ///
    /// The grid holds up to 400 wallet-identifying addresses plus the
    /// master fingerprint — not key material, but a full wallet-surveillance
    /// identity. The SPEC §26 amendment (2026-08-08) menu-return path can
    /// leave the machine powered, so this must be cleared before the
    /// verification screen's owner drops it, rather than relying on the
    /// forced power-off's DRAM decay. Mirrors the arena's scrub discipline
    /// (volatile write + fence + verify, via [`scrub_local`]).
    pub fn scrub(&mut self) {
        scrub_local(&mut self.master_fingerprint);
        for a in self.addresses.iter_mut() {
            a.scrub();
        }
    }

    /// The `(fingerprint, four first addresses)` subset that reproduces the
    /// default SPEC §24.3 screen (account 0, external chain, index 0), so
    /// the unchanged [`VerificationValues`]-based `render` can draw the
    /// default view straight from the pre-derived grid without any second
    /// derivation.
    #[must_use]
    pub fn base_values(&self) -> VerificationValues {
        let pick = |standard: PathStandard| StandardAddress {
            standard,
            address: self
                .address(standard, 0, 0, 0)
                .copied()
                .unwrap_or_else(AddressBuf::empty),
        };
        VerificationValues {
            master_fingerprint: self.master_fingerprint,
            addresses: [
                pick(PathStandard::Bip44),
                pick(PathStandard::Bip49),
                pick(PathStandard::Bip84),
                pick(PathStandard::Bip86),
            ],
        }
    }
}

// ============================================================================
// Stage 1: sources -> transcript -> final entropy -> mnemonic indexes
// ============================================================================

/// Runs `sources -> canonical transcript -> final entropy -> mnemonic
/// indexes` (SPEC §19, §14) entirely against `arena`.
///
/// On success, `arena.final_entropy()` holds the SPEC §19.3 final entropy
/// (16 or 32 bytes, zero-padded to the fixed 32-byte field for the
/// 12-word case) and `arena.mnemonic_indexes()` holds the resolved BIP39
/// word indexes. Callers MUST follow a successful call with
/// [`scrub_transcript_stage`] (SPEC §19.4: "Immediately after final
/// entropy is derived, the application MUST scrub ... the canonical
/// transcript ...").
///
/// `sink` is consumed so a real [`TranscriptSink`] implementation can
/// scrub its own internal staging buffers as part of `finalize` (SPEC
/// §19.4).
///
/// # Fail-closed entropy floor (pre-release audit MUST-FIX #2)
///
/// Before anything is hashed, this function independently rejects an
/// empty `sources` slice, or one whose records collectively contribute
/// zero bytes of source material, with
/// [`PipelineError::InsufficientSources`]. This is defense-in-depth at
/// the crypto boundary itself: SPEC §19.3's `SHA256(canonical_transcript)`
/// step still produces *some* 32-byte digest for an empty transcript — a
/// fixed, publicly-computable value for a given `(arch, bits,
/// policy_ver)` triple — so without this self-check, a caller bug that
/// ever let an empty/zero-content source slice reach this function would
/// silently mint a deterministic, attacker-known seed. This check does
/// not depend on, and is not a substitute for, any upstream state-machine
/// gate (e.g. `PhysicalBudgetMet`, machine-acquire-success) that already
/// prevents this in production today.
pub fn derive_final_entropy<T: TranscriptSink>(
    arena: &mut SecretArena,
    mut sink: T,
    sources: &[SourceInput<'_>],
    arch: ArchId,
    bits: TargetBits,
    policy_ver: u16,
) -> Result<WordCount, PipelineError<T::Error>> {
    let total_source_bytes: usize = sources.iter().map(|s| s.bytes.len()).sum();
    if sources.is_empty() || total_source_bytes == 0 {
        return Err(PipelineError::InsufficientSources);
    }

    for s in sources {
        sink.add_source(s.tag, s.algo_id, s.bytes)
            .map_err(PipelineError::Transcript)?;
    }

    // Local digest buffer: `TranscriptSink::finalize`'s frozen shape
    // writes a full 32-byte SHA-256 digest (SPEC §19.3) regardless of
    // `bits`; only the leading 16 or 32 bytes are final entropy. Scrubbed
    // below once the meaningful prefix has been copied into the arena
    // (same controlled-local-buffer pattern as `bip39::mnemonic_to_seed`).
    let mut digest = [0u8; 32];
    sink.finalize(arch, bits, policy_ver, &mut digest);

    let entropy_len = match bits {
        TargetBits::Bits128 => 16,
        TargetBits::Bits256 => 32,
    };

    {
        let fe = arena.final_entropy();
        fe[..entropy_len].copy_from_slice(&digest[..entropy_len]);
        // Zero any unused tail (only reachable for the 12-word case) so
        // no stale/irrelevant digest bytes linger in the arena field
        // (SPEC §13: every secret-bearing byte accounted for).
        for b in fe[entropy_len..].iter_mut() {
            *b = 0;
        }
    }
    scrub_local(&mut digest);

    // Local copy of the final entropy: `entropy_to_indexes` needs it as
    // `&[u8]` at the same time `arena.mnemonic_indexes()` needs `&mut
    // self` for its output — two live `&mut SecretArena` accessor
    // borrows can't coexist, so (as with WP-05's phrase buffer) the
    // input is staged in a small local copy, used, then scrubbed.
    let mut entropy_local = [0u8; 32];
    entropy_local.copy_from_slice(arena.final_entropy());

    let word_count = convert_entropy_and_scrub(&mut entropy_local, entropy_len, arena.mnemonic_indexes())
        .map_err(PipelineError::Bip39)?;

    Ok(word_count)
}

/// Converts the staged `entropy_local` copy into BIP39 word indexes via
/// [`bip39::entropy_to_indexes`], then unconditionally scrubs
/// `entropy_local` — on both the success path and the `Bip39` error path
/// — before the result is handed back to the caller (should-fix #6/#4,
/// pre-release audit `docs/PRE-RELEASE-AUDIT.md`: [`derive_final_entropy`]
/// used to `?`-return on the error path before its scrub ever ran,
/// leaving an unscrubbed stack copy of the final entropy on that path).
/// The conversion `Result` is captured first, the scrub runs
/// unconditionally, and only then is the result handed back — so the
/// scrub can no longer be skipped by an early return.
///
/// Extracted into its own function so this exact ordering — not just
/// [`derive_final_entropy`]'s overall happy path — can be exercised
/// directly by a unit test: [`derive_final_entropy`] itself always calls
/// this with `entropy_len` fixed to 16 or 32 (always valid), so its own
/// `Bip39` error branch is unreachable through the public API; this
/// helper lets the error branch be reached directly with a deliberately
/// invalid `entropy_len`.
fn convert_entropy_and_scrub(
    entropy_local: &mut [u8; 32],
    entropy_len: usize,
    indexes: &mut [u16; 24],
) -> Result<WordCount, Bip39Error> {
    let conversion = bip39::entropy_to_indexes(&entropy_local[..entropy_len], indexes);
    scrub_local(entropy_local);
    conversion
}

// ============================================================================
// Stage 2 (on demand): mnemonic indexes -> seed -> fingerprint + addresses
// ============================================================================

/// Runs `mnemonic indexes -> BIP39 seed -> master fingerprint + 4 first
/// addresses` (SPEC §14, §24.2-§24.3) on demand, i.e. only when the
/// wallet-derivation-verification screen is about to be shown, not as
/// part of ordinary generation.
///
/// Writes `arena.bip39_seed()`, `arena.master_key()` and
/// `arena.master_chain_code()` as a side effect (SPEC §24.2: these are
/// arena-resident secrets like everything else in this flow). Callers
/// MUST follow a call to this function with [`scrub_derivation_stage`]
/// once the verification screen has been shown (SPEC §19.4, §20.1).
/// SPEC_PASSPHRASE §7.2/§M2: derive the BIP39 seed into `arena.bip39_seed()`
/// from the resident mnemonic indexes AND the resident committed passphrase
/// (empty by default → byte-identical to the pre-passphrase seed).
///
/// The passphrase and mnemonic indexes are both arena-resident, but
/// `arena.bip39_seed()` needs `&mut self` while they are read — two live
/// accessor borrows can't coexist — so both inputs are staged into small
/// locals, used, then scrubbed (the same controlled-local-buffer pattern as
/// `bip39::mnemonic_to_seed`). There is exactly one seed in existence
/// afterward, and it is the passphrase-derived one.
fn derive_seed_with_committed_passphrase(arena: &mut SecretArena, word_count: WordCount) {
    let mut indexes_local = [0u16; 24];
    indexes_local.copy_from_slice(arena.mnemonic_indexes());

    let mut pp_local = [0u8; MAX_PASSPHRASE_LEN];
    let pp_len = arena.passphrase().len();
    pp_local[..pp_len].copy_from_slice(arena.passphrase().as_bytes());

    bip39::mnemonic_to_seed_with_passphrase_bytes(
        &indexes_local,
        word_count,
        &pp_local[..pp_len],
        arena.bip39_seed(),
    );

    scrub_local_u16(&mut indexes_local);
    scrub_local(&mut pp_local);
}

pub fn compute_verification_values<D: KeyDeriver>(
    arena: &mut SecretArena,
    word_count: WordCount,
) -> Result<VerificationValues, DeriveError> {
    // SPEC_PASSPHRASE §7.2/§M2: derive the seed from the mnemonic AND the
    // committed passphrase (empty by default), writing into `arena.bip39_seed()`.
    derive_seed_with_committed_passphrase(arena, word_count);

    // Stage the seed locally: every remaining step below (`master_from_seed`
    // for two more arena fields, then `first_address` four times) needs it
    // as a plain `&[u8; 64]` read, and cannot be threaded through repeated
    // simultaneous arena accessor borrows for the same reason as above.
    let mut seed_local = [0u8; 64];
    seed_local.copy_from_slice(arena.bip39_seed());

    let mut key_local = [0u8; 32];
    let mut cc_local = [0u8; 32];
    D::master_from_seed(&seed_local, &mut key_local, &mut cc_local);
    arena.master_key().copy_from_slice(&key_local);
    arena.master_chain_code().copy_from_slice(&cc_local);

    let master_fingerprint = D::master_fingerprint(&key_local);
    scrub_local(&mut key_local);
    scrub_local(&mut cc_local);

    let standards = [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86];
    let mut addresses = [
        StandardAddress { standard: PathStandard::Bip44, address: empty_address() },
        StandardAddress { standard: PathStandard::Bip49, address: empty_address() },
        StandardAddress { standard: PathStandard::Bip84, address: empty_address() },
        StandardAddress { standard: PathStandard::Bip86, address: empty_address() },
    ];

    let mut result: Result<(), DeriveError> = Ok(());
    for (slot, standard) in addresses.iter_mut().zip(standards.iter()) {
        slot.standard = *standard;
        if let Err(e) = D::first_address(&seed_local, *standard, &mut slot.address) {
            result = Err(e);
            break;
        }
    }

    scrub_local(&mut seed_local);

    result.map(|()| VerificationValues { master_fingerprint, addresses })
}

fn empty_address() -> AddressBuf {
    AddressBuf::empty()
}

/// SPEC_DERIVATION_OPTIONS §A.0 (Model A): the **eager, bounded** grid
/// derivation. Runs `mnemonic indexes -> BIP39 seed -> master fingerprint +
/// every [`GRID_CELLS`] leaf address` on demand, filling `out` in place,
/// with the same arena side effects and scrub discipline as
/// [`compute_verification_values`].
///
/// This is the single Model-A obligation: the **whole** bounded grid is
/// derived up front into the public [`ExtendedVerificationValues`] while
/// the seed is briefly arena-resident; the caller MUST then call
/// [`scrub_derivation_stage`] **before** opening the interactive selection
/// menu, so the menu navigates only pre-rendered public strings and the
/// seed's lifetime never extends across the open-ended UI (§A.0, §20/§26).
///
/// Writes `arena.bip39_seed()`, `arena.master_key()` and
/// `arena.master_chain_code()` as a side effect (SPEC §24.2), identical to
/// [`compute_verification_values`]. Any per-cell derivation error aborts
/// the whole grid and is returned (SPEC §27.2 scrub-and-shutdown at the
/// caller); the local seed copy is scrubbed on every path.
pub fn compute_extended_verification_values<D: KeyDeriver>(
    arena: &mut SecretArena,
    word_count: WordCount,
    out: &mut ExtendedVerificationValues,
) -> Result<(), DeriveError> {
    // SPEC_PASSPHRASE §7.2.1/§M2: the passphrase-derived seed is the SOLE
    // input to this eager grid derivation (which the driver fires only on
    // entry to `DerivationVerificationDisplay`, after the passphrase is
    // committed) — a set passphrase changes every grid cell.
    derive_seed_with_committed_passphrase(arena, word_count);

    let mut seed_local = [0u8; 64];
    seed_local.copy_from_slice(arena.bip39_seed());

    let mut key_local = [0u8; 32];
    let mut cc_local = [0u8; 32];
    D::master_from_seed(&seed_local, &mut key_local, &mut cc_local);
    arena.master_key().copy_from_slice(&key_local);
    arena.master_chain_code().copy_from_slice(&cc_local);

    out.master_fingerprint = D::master_fingerprint(&key_local);
    scrub_local(&mut key_local);
    scrub_local(&mut cc_local);

    let standards = [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86];
    let mut result: Result<(), DeriveError> = Ok(());
    'grid: for standard in standards {
        for account in 0..=N_ACCOUNT_MAX {
            for change in 0..N_CHANGE as u32 {
                for index in 0..=N_INDEX_MAX {
                    // Bounds are exactly the loop bounds, so `index()` is
                    // always `Some`; on the impossible `None` we fail
                    // closed rather than silently skip.
                    let Some(slot) = ExtendedVerificationValues::index(standard, account, change, index) else {
                        result = Err(DeriveError::InvalidIndex);
                        break 'grid;
                    };
                    if let Err(e) = D::grid_address(&seed_local, standard, account, change, index, &mut out.addresses[slot]) {
                        result = Err(e);
                        break 'grid;
                    }
                }
            }
        }
    }

    scrub_local(&mut seed_local);
    result
}

// ============================================================================
// Explicit lifecycle scrub methods (SPEC §19.4, §20.1, §20.4)
// ============================================================================

/// SPEC §19.4: "Immediately after final entropy is derived, the
/// application MUST scrub: raw machine-source records; dice and coin
/// history; the canonical transcript; ... temporary digests not needed
/// for BIP39 conversion." Callers invoke this right after a successful
/// [`derive_final_entropy`] — `final_entropy` and `mnemonic_indexes`
/// (still needed for display, re-entry and derivation) are deliberately
/// left untouched by this call.
///
/// This scrubs the arena-resident §19.4 sources: raw machine-source
/// records and the canonical transcript. §19.4's "dice and coin history"
/// is NOT arena-resident — it lives in the dedicated per-session
/// `seed_protocol::physical::PhysicalSession` /
/// `seed_flow::flow_secret::physical::PhysicalStaging` buffers, which are
/// scrubbed at the same §19.4 point by their own explicit scrub (plus a
/// `Drop` backstop). See the `SecretArena` struct-field note and SPEC
/// §20.1's documented exception.
pub fn scrub_transcript_stage(arena: &mut SecretArena) {
    scrub_local(arena.machine_sources());
    scrub_local(arena.transcript());
}

/// Scrubs the BIP39-seed/BIP32-derivation fields (SPEC §24.2's secret
/// intermediates) once [`compute_verification_values`] has run and its
/// result has been displayed. `final_entropy`/`mnemonic_indexes` are left
/// untouched (re-entry, SPEC §23, may still need them).
pub fn scrub_derivation_stage(arena: &mut SecretArena) {
    scrub_local(arena.bip39_seed());
    scrub_local(arena.master_key());
    scrub_local(arena.master_chain_code());
    scrub_local(arena.derive_scratch());
    scrub_local(arena.scratch());
}

/// Full terminal scrub (SPEC §20.1: "scrubbed as a complete region on
/// success and every fatal path"; §20.4: transition every post-generation
/// error to scrub-and-shutdown). Called once the entire ceremony —
/// generation, display, re-entry, derivation-verification — is over, on
/// both the success path and every fatal path.
pub fn scrub_after_display(arena: &mut SecretArena) {
    arena.scrub_all();
}

/// Scrubs a `[u8]`-shaped local buffer with the same volatile-write +
/// fence + verification-read discipline as `arena::scrub_bytes` (SPEC
/// §20.3). Duplicated here (rather than depending on that private
/// function) because every controlled local secret copy this module
/// stages (digest, entropy, seed, key material) is scrubbed the moment
/// its last use ends, exactly like WP-05's `mnemonic_to_seed` phrase
/// buffer.
fn scrub_local(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed `&mut u8` local for
        // the duration of this write.
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);

    let mut observed = 0u8;
    for b in buf.iter() {
        let byte = unsafe { core::ptr::read_volatile(b as *const u8) };
        observed |= byte;
    }
    let observed = core::hint::black_box(observed);
    debug_assert_eq!(observed, 0, "scrub_local: verification read found a non-zero byte");
}

/// Same as [`scrub_local`] but for `[u16]`-shaped mnemonic-index buffers.
fn scrub_local_u16(buf: &mut [u16]) {
    for w in buf.iter_mut() {
        // SAFETY: same reasoning as `scrub_local`.
        unsafe { core::ptr::write_volatile(w as *mut u16, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);

    let mut observed = 0u16;
    for w in buf.iter() {
        let word = unsafe { core::ptr::read_volatile(w as *const u16) };
        observed |= word;
    }
    let observed = core::hint::black_box(observed);
    debug_assert_eq!(observed, 0, "scrub_local_u16: verification read found a non-zero byte");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // ------------------------------------------------------------------
    // Deterministic test doubles for the injected steps. These are NOT
    // the real SPEC §19/§24 algorithms (those are owned by WP-08 and
    // WP-13/WP-14 in sibling crates this module cannot depend on — see
    // the module-level doc comment); they exist to prove this module's
    // own orchestration, buffer plumbing and scrub lifecycle are correct
    // in isolation, independent of the sibling crates' internals.
    // ------------------------------------------------------------------

    /// A minimal transcript double: concatenates every `(tag, algo_id,
    /// bytes)` triple it sees (in call order — canonical ordering is
    /// WP-08's job, not tested here) and SHA-256-reduces the
    /// concatenation, mixing in `arch`/`bits`/`policy_ver` the same way
    /// the real transcript's header does conceptually. Deterministic and
    /// collision-free enough to prove plumbing, not a SPEC §19.2 encoder.
    struct MockSink {
        buf: Vec<u8>,
        source_count: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockSinkError {
        TooManySources,
    }

    impl MockSink {
        fn new() -> Self {
            MockSink { buf: Vec::new(), source_count: 0 }
        }
    }

    impl TranscriptSink for MockSink {
        type Error = MockSinkError;

        fn add_source(&mut self, tag: SourceTag, algo_id: &[u8], bytes: &[u8]) -> Result<(), Self::Error> {
            if self.source_count >= 5 {
                return Err(MockSinkError::TooManySources);
            }
            self.buf.push(tag as u8);
            self.buf.extend_from_slice(algo_id);
            self.buf.extend_from_slice(bytes);
            self.source_count += 1;
            Ok(())
        }

        fn finalize(mut self, arch: ArchId, bits: TargetBits, policy_ver: u16, out: &mut [u8; 32]) {
            self.buf.push(arch as u8);
            self.buf.extend_from_slice(&(bits as u16).to_be_bytes());
            self.buf.extend_from_slice(&policy_ver.to_be_bytes());
            *out = crate::hash::sha256(&self.buf);
        }
    }

    /// A deterministic key-derivation double: "master key" =
    /// `sha256(seed)`, "chain code" = `sha256(sha256(seed))`,
    /// "fingerprint" = first 4 bytes of `sha256(key)`, "address" = a
    /// fixed tag byte per standard followed by 8 bytes of
    /// `sha256(seed || standard_tag)`. None of this is real
    /// BIP32/Base58/Bech32 — it exists to prove
    /// `compute_verification_values`'s plumbing (which bytes reach which
    /// trait method, in what order, with what arena side effects).
    struct MockDeriver;

    impl KeyDeriver for MockDeriver {
        fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
            *key_out = crate::hash::sha256(seed);
            *cc_out = crate::hash::sha256(key_out);
        }

        fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
            let d = crate::hash::sha256(key);
            [d[0], d[1], d[2], d[3]]
        }

        fn first_address(seed: &[u8; 64], standard: PathStandard, out: &mut AddressBuf) -> Result<(), DeriveError> {
            let tag: u8 = match standard {
                PathStandard::Bip44 => 44,
                PathStandard::Bip49 => 49,
                PathStandard::Bip84 => 84,
                PathStandard::Bip86 => 86,
            };
            let mut input = Vec::from(&seed[..]);
            input.push(tag);
            let d = crate::hash::sha256(&input);
            let mut bytes = [0u8; 92];
            bytes[0] = tag;
            for (i, b) in d.iter().take(8).enumerate() {
                bytes[1 + i] = *b;
            }
            *out = AddressBuf::new(bytes, 9);
            Ok(())
        }

        fn grid_address(
            seed: &[u8; 64],
            standard: PathStandard,
            account: u32,
            change: u32,
            index: u32,
            out: &mut AddressBuf,
        ) -> Result<(), DeriveError> {
            // Deterministic double that (a) agrees with `first_address`
            // exactly at the (0,0,0) leaf, so `base_values()` lines up, and
            // (b) varies with every grid coordinate otherwise.
            if account == 0 && change == 0 && index == 0 {
                return Self::first_address(seed, standard, out);
            }
            let tag: u8 = match standard {
                PathStandard::Bip44 => 44,
                PathStandard::Bip49 => 49,
                PathStandard::Bip84 => 84,
                PathStandard::Bip86 => 86,
            };
            let mut input = Vec::from(&seed[..]);
            input.extend_from_slice(&[tag, account as u8, change as u8, index as u8]);
            let d = crate::hash::sha256(&input);
            let mut bytes = [0u8; 92];
            bytes[0] = tag;
            for (i, b) in d.iter().take(11).enumerate() {
                bytes[1 + i] = *b;
            }
            *out = AddressBuf::new(bytes, 12);
            Ok(())
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // ------------------------------------------------------------------
    // Stage 1: derive_final_entropy
    // ------------------------------------------------------------------

    #[test]
    fn derive_final_entropy_128_bits_writes_16_bytes_and_zero_pads_tail() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];

        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .expect("derive_final_entropy should succeed");

        assert_eq!(word_count, WordCount::Twelve);
        assert!(arena.final_entropy()[16..].iter().all(|&b| b == 0), "tail must be zero-padded");
        assert!(!arena.final_entropy()[..16].iter().all(|&b| b == 0), "prefix must be populated");
        assert!(arena.mnemonic_indexes().iter().take(12).all(|&i| i < 2048));
    }

    #[test]
    fn derive_final_entropy_256_bits_writes_full_32_bytes() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::CoinFlips, algo_id: b"", bytes: &[0, 1, 0, 1] }];

        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits256, 1)
                .expect("derive_final_entropy should succeed");

        assert_eq!(word_count, WordCount::TwentyFour);
        assert!(!arena.final_entropy().iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().take(24).all(|&i| i < 2048));
    }

    #[test]
    fn derive_final_entropy_is_deterministic_given_the_same_sources() {
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[3, 3, 3, 3, 3, 3] }];

        let mut arena_a = SecretArena::new();
        derive_final_entropy(&mut arena_a, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
            .unwrap();

        let mut arena_b = SecretArena::new();
        derive_final_entropy(&mut arena_b, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
            .unwrap();

        assert_eq!(arena_a.final_entropy(), arena_b.final_entropy());
        assert_eq!(arena_a.mnemonic_indexes(), arena_b.mnemonic_indexes());
    }

    #[test]
    fn derive_final_entropy_differs_when_sources_differ() {
        let mut arena_a = SecretArena::new();
        let sources_a = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 1, 1, 1, 1, 1] }];
        derive_final_entropy(&mut arena_a, MockSink::new(), &sources_a, ArchId::X86_64, TargetBits::Bits128, 1)
            .unwrap();

        let mut arena_b = SecretArena::new();
        let sources_b = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[2, 2, 2, 2, 2, 2] }];
        derive_final_entropy(&mut arena_b, MockSink::new(), &sources_b, ArchId::X86_64, TargetBits::Bits128, 1)
            .unwrap();

        assert_ne!(arena_a.final_entropy(), arena_b.final_entropy());
    }

    #[test]
    fn derive_final_entropy_propagates_sink_error() {
        let mut arena = SecretArena::new();
        let sources: Vec<SourceInput> = (0..6)
            .map(|_| SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1] })
            .collect();

        let err =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap_err();

        assert_eq!(err, PipelineError::Transcript(MockSinkError::TooManySources));
    }

    // ------------------------------------------------------------------
    // Fail-closed entropy floor (pre-release audit MUST-FIX #2,
    // `docs/PRE-RELEASE-AUDIT.md`): `derive_final_entropy` itself must
    // refuse an empty/zero-content source set BEFORE any hashing happens,
    // independent of any upstream state-machine gate. These tests call
    // the pipeline function directly with no such gate in the picture at
    // all, proving the floor lives at the crypto boundary itself.
    // ------------------------------------------------------------------

    /// An empty `sources` slice must be rejected with
    /// `InsufficientSources`, never silently hashed into a "valid"
    /// (fixed, publicly-computable) mnemonic.
    #[test]
    fn derive_final_entropy_rejects_empty_sources() {
        let mut arena = SecretArena::new();
        let sources: [SourceInput; 0] = [];

        let err =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap_err();

        assert_eq!(err, PipelineError::InsufficientSources);
        // Defense in depth: a rejected call must not have left a
        // deterministic "success" digest sitting in the arena either.
        assert!(arena.final_entropy().iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().all(|&i| i == 0));
    }

    /// A non-empty `sources` slice whose every record contributed zero
    /// bytes must also be rejected — an empty transcript still hashes to
    /// *some* fixed digest (SPEC §19.3), so record *count* alone is not a
    /// sufficient floor.
    #[test]
    fn derive_final_entropy_rejects_sources_that_contribute_zero_bytes() {
        let mut arena = SecretArena::new();
        let sources = [
            SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[] },
            SourceInput { tag: SourceTag::CoinFlips, algo_id: b"", bytes: &[] },
        ];

        let err =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap_err();

        assert_eq!(err, PipelineError::InsufficientSources);
    }

    /// Sanity companion: a single source with at least one real byte must
    /// still succeed, so the floor above cannot be vacuously true from a
    /// check that rejects everything.
    #[test]
    fn derive_final_entropy_accepts_a_single_nonempty_source() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1] }];

        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();

        assert_eq!(word_count, WordCount::Twelve);
    }

    /// This fail-closed floor fires at the pipeline boundary itself, with
    /// no upstream state-machine gate anywhere in the call chain (the test
    /// calls `derive_final_entropy` directly) -- proving the check is a
    /// genuine independent layer of defense-in-depth, not merely
    /// something an upstream gate happens to also enforce.
    #[test]
    fn derive_final_entropy_insufficient_sources_check_has_no_upstream_gate_dependency() {
        let mut arena = SecretArena::new();
        let empty: [SourceInput; 0] = [];
        // No `PhysicalBudgetMet`/machine-acquire-success gate exists in
        // this test at all -- `derive_final_entropy` is the only thing
        // between this empty slice and a hash.
        assert_eq!(
            derive_final_entropy(&mut arena, MockSink::new(), &empty, ArchId::X86_64, TargetBits::Bits256, 1)
                .unwrap_err(),
            PipelineError::InsufficientSources
        );
    }

    // ------------------------------------------------------------------
    // Stage 2: compute_verification_values
    // ------------------------------------------------------------------

    #[test]
    fn compute_verification_values_populates_arena_and_returns_four_addresses() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();

        let values = compute_verification_values::<MockDeriver>(&mut arena, word_count).unwrap();

        assert!(!arena.bip39_seed().iter().all(|&b| b == 0), "bip39 seed must be populated");
        assert!(!arena.master_key().iter().all(|&b| b == 0), "master key must be populated");
        assert!(!arena.master_chain_code().iter().all(|&b| b == 0), "chain code must be populated");

        let expected_standards = [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86];
        for (slot, expected) in values.addresses.iter().zip(expected_standards.iter()) {
            assert_eq!(slot.standard, *expected);
            assert!(slot.address.len() > 0);
        }

        assert_ne!(values.master_fingerprint, [0u8; 4]);
    }

    #[test]
    fn compute_verification_values_propagates_deriver_error() {
        struct FailingDeriver;
        impl KeyDeriver for FailingDeriver {
            fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
                MockDeriver::master_from_seed(seed, key_out, cc_out);
            }
            fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
                MockDeriver::master_fingerprint(key)
            }
            fn first_address(
                _seed: &[u8; 64],
                _standard: PathStandard,
                _out: &mut AddressBuf,
            ) -> Result<(), DeriveError> {
                Err(DeriveError::InvalidChildKey)
            }
            fn grid_address(
                _seed: &[u8; 64],
                _standard: PathStandard,
                _account: u32,
                _change: u32,
                _index: u32,
                _out: &mut AddressBuf,
            ) -> Result<(), DeriveError> {
                Err(DeriveError::InvalidChildKey)
            }
        }

        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();

        match compute_verification_values::<FailingDeriver>(&mut arena, word_count) {
            Err(e) => assert_eq!(e, DeriveError::InvalidChildKey),
            Ok(_) => panic!("expected an error"),
        }
    }

    // ------------------------------------------------------------------
    // Stage 2 (extended): compute_extended_verification_values (Model A,
    // SPEC_DERIVATION_OPTIONS §A.0)
    // ------------------------------------------------------------------

    fn extended_fixture() -> (SecretArena, WordCount) {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();
        (arena, word_count)
    }

    #[test]
    fn extended_grid_shape_constants_are_consistent() {
        assert_eq!(N_ACCOUNTS, 5);
        assert_eq!(N_INDICES, 10);
        assert_eq!(GRID_CELLS, N_STANDARDS * N_ACCOUNTS * N_CHANGE * N_INDICES);
        assert_eq!(GRID_CELLS, 400);
        assert!(TABLE_DEFAULT_N <= TABLE_MAX_N);
        assert!(TABLE_MAX_N <= N_INDICES);
    }

    #[test]
    fn compute_extended_populates_the_whole_grid_and_arena() {
        let (mut arena, wc) = extended_fixture();
        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena, wc, &mut ext).unwrap();

        assert!(!arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(!arena.master_key().iter().all(|&b| b == 0));
        assert_ne!(ext.master_fingerprint, [0u8; 4]);

        // Every in-bounds cell is populated.
        for standard in [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86] {
            for account in 0..=N_ACCOUNT_MAX {
                for change in 0..N_CHANGE as u32 {
                    for index in 0..=N_INDEX_MAX {
                        let a = ext.address(standard, account, change, index).expect("in-bounds cell");
                        assert!(a.len() > 0, "cell {standard:?}/{account}/{change}/{index} must be rendered");
                    }
                }
            }
        }
    }

    #[test]
    fn compute_extended_base_values_match_the_default_screen_derivation() {
        let (mut arena_a, wc) = extended_fixture();
        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena_a, wc, &mut ext).unwrap();

        // A second arena from the same sources, run through the *original*
        // default-screen derivation, must produce identical fingerprint +
        // four base addresses (the (0,0,0) leaf per standard).
        let (mut arena_b, wc_b) = extended_fixture();
        let values = compute_verification_values::<MockDeriver>(&mut arena_b, wc_b).unwrap();

        let base = ext.base_values();
        assert_eq!(base.master_fingerprint, values.master_fingerprint);
        for (b, v) in base.addresses.iter().zip(values.addresses.iter()) {
            assert_eq!(b.standard, v.standard);
            assert_eq!(b.address.as_bytes(), v.address.as_bytes());
        }
    }

    #[test]
    fn compute_extended_distinct_cells_differ() {
        let (mut arena, wc) = extended_fixture();
        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena, wc, &mut ext).unwrap();

        // Compare raw bytes, not `as_str`: the MockDeriver emits arbitrary
        // (non-UTF-8) address bytes, so `as_str()` would be `None` for all.
        let a = Vec::from(ext.address(PathStandard::Bip84, 0, 0, 0).unwrap().as_bytes());
        let b = Vec::from(ext.address(PathStandard::Bip84, 0, 0, 1).unwrap().as_bytes());
        let c = Vec::from(ext.address(PathStandard::Bip84, 1, 0, 0).unwrap().as_bytes());
        let d = Vec::from(ext.address(PathStandard::Bip84, 0, 1, 0).unwrap().as_bytes());
        assert_ne!(a, b, "different index must give a different cell");
        assert_ne!(a, c, "different account must give a different cell");
        assert_ne!(a, d, "different change chain must give a different cell");
    }

    #[test]
    fn extended_address_out_of_bounds_is_none() {
        let ext = ExtendedVerificationValues::new();
        assert!(ext.address(PathStandard::Bip44, N_ACCOUNT_MAX + 1, 0, 0).is_none());
        assert!(ext.address(PathStandard::Bip44, 0, 2, 0).is_none());
        assert!(ext.address(PathStandard::Bip44, 0, 0, N_INDEX_MAX + 1).is_none());
    }

    #[test]
    fn compute_extended_propagates_deriver_error() {
        struct FailingGridDeriver;
        impl KeyDeriver for FailingGridDeriver {
            fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
                MockDeriver::master_from_seed(seed, key_out, cc_out);
            }
            fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
                MockDeriver::master_fingerprint(key)
            }
            fn first_address(seed: &[u8; 64], standard: PathStandard, out: &mut AddressBuf) -> Result<(), DeriveError> {
                MockDeriver::first_address(seed, standard, out)
            }
            fn grid_address(
                _seed: &[u8; 64],
                _standard: PathStandard,
                _account: u32,
                _change: u32,
                _index: u32,
                _out: &mut AddressBuf,
            ) -> Result<(), DeriveError> {
                Err(DeriveError::InvalidChildKey)
            }
        }

        let (mut arena, wc) = extended_fixture();
        let mut ext = ExtendedVerificationValues::new();
        assert_eq!(
            compute_extended_verification_values::<FailingGridDeriver>(&mut arena, wc, &mut ext),
            Err(DeriveError::InvalidChildKey)
        );
    }

    /// SPEC_PASSPHRASE §7.2.1/§M2 (pipeline level): a set (non-empty)
    /// passphrase changes the master fingerprint AND **every** grid cell
    /// versus the empty-passphrase grid — no cell is left equal. This
    /// mechanically catches an eager derivation that ever ignored the
    /// committed passphrase (its grid would still equal the empty one).
    #[test]
    fn set_passphrase_changes_every_grid_fingerprint_and_address() {
        // Empty-passphrase grid.
        let (mut arena_empty, wc) = extended_fixture();
        let mut ext_empty = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena_empty, wc, &mut ext_empty).unwrap();

        // Same mnemonic, but a committed non-empty passphrase.
        let (mut arena_pp, wc2) = extended_fixture();
        for &b in b"Correct Horse 42!" {
            arena_pp.passphrase().push_ascii(b).unwrap();
        }
        let mut ext_pp = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena_pp, wc2, &mut ext_pp).unwrap();

        assert_ne!(
            ext_empty.master_fingerprint, ext_pp.master_fingerprint,
            "a set passphrase must change the master fingerprint"
        );
        for standard in [PathStandard::Bip44, PathStandard::Bip49, PathStandard::Bip84, PathStandard::Bip86] {
            for account in 0..=N_ACCOUNT_MAX {
                for change in 0..N_CHANGE as u32 {
                    for index in 0..=N_INDEX_MAX {
                        let a = ext_empty.address(standard, account, change, index).unwrap();
                        let b = ext_pp.address(standard, account, change, index).unwrap();
                        assert_ne!(
                            a.as_bytes(),
                            b.as_bytes(),
                            "cell {standard:?}/{account}/{change}/{index} must differ under a set passphrase"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scrub_derivation_stage_clears_seed_after_extended_grid() {
        // Model A: the caller scrubs the seed before the menu; prove the
        // existing scrub covers the fields the extended path populates.
        let (mut arena, wc) = extended_fixture();
        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification_values::<MockDeriver>(&mut arena, wc, &mut ext).unwrap();

        scrub_derivation_stage(&mut arena);
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
        assert!(arena.master_chain_code().iter().all(|&b| b == 0));
    }

    // ------------------------------------------------------------------
    // Lifecycle scrub methods
    // ------------------------------------------------------------------

    #[test]
    fn scrub_transcript_stage_clears_only_transcript_fields() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1).unwrap();

        arena.machine_sources().fill(0xAA);

        scrub_transcript_stage(&mut arena);

        assert!(arena.machine_sources().iter().all(|&b| b == 0));
        assert!(arena.transcript().iter().all(|&b| b == 0));
        // Final entropy / mnemonic indexes are deliberately untouched.
        assert!(!arena.final_entropy()[..16].iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().take(12).any(|&i| i != 0));
    }

    #[test]
    fn scrub_derivation_stage_clears_seed_and_key_material_only() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();
        compute_verification_values::<MockDeriver>(&mut arena, word_count).unwrap();

        scrub_derivation_stage(&mut arena);

        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
        assert!(arena.master_chain_code().iter().all(|&b| b == 0));
        assert!(arena.derive_scratch().iter().all(|&b| b == 0));
        assert!(arena.scratch().iter().all(|&b| b == 0));
        // Mnemonic material is deliberately untouched (still needed for
        // display/re-entry).
        assert!(!arena.final_entropy()[..16].iter().all(|&b| b == 0));
    }

    #[test]
    fn scrub_after_display_clears_everything() {
        let mut arena = SecretArena::new();
        let sources = [SourceInput { tag: SourceTag::DiceRolls, algo_id: b"", bytes: &[1, 2, 3, 4, 5, 6] }];
        let word_count =
            derive_final_entropy(&mut arena, MockSink::new(), &sources, ArchId::X86_64, TargetBits::Bits128, 1)
                .unwrap();
        compute_verification_values::<MockDeriver>(&mut arena, word_count).unwrap();

        scrub_after_display(&mut arena);

        assert!(arena.final_entropy().iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().all(|&i| i == 0));
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
    }

    // ------------------------------------------------------------------
    // Local scrub-buffer primitives
    // ------------------------------------------------------------------

    #[test]
    fn scrub_local_zeroes_a_byte_buffer() {
        let mut buf = [0x7Au8; 40];
        scrub_local(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn extended_verification_values_scrub_zeroes_fingerprint_and_every_address() {
        let mut ext = ExtendedVerificationValues::new();
        ext.master_fingerprint = [0xAB; 4];
        for a in ext.addresses.iter_mut() {
            a.set(b"bc1qexampleaddress000000000000000000000000");
        }
        // Sanity: non-zero before the scrub.
        assert!(ext.addresses.iter().any(|a| a.full_bytes().iter().any(|&b| b != 0)));
        ext.scrub();
        assert_eq!(ext.master_fingerprint, [0u8; 4], "fingerprint not scrubbed");
        for a in ext.addresses.iter() {
            assert!(a.full_bytes().iter().all(|&b| b == 0), "address bytes not scrubbed");
            assert!(a.as_bytes().is_empty(), "address len not reset");
        }
    }

    #[test]
    fn verification_values_base_copy_scrub_zeroes_everything() {
        let mut ext = ExtendedVerificationValues::new();
        ext.master_fingerprint = [0xCD; 4];
        for a in ext.addresses.iter_mut() {
            a.set(b"bc1qexampleaddress000000000000000000000000");
        }
        let mut v = ext.base_values();
        assert!(v.addresses.iter().any(|sa| sa.address.full_bytes().iter().any(|&b| b != 0)));
        v.scrub();
        assert_eq!(v.master_fingerprint, [0u8; 4]);
        for sa in v.addresses.iter() {
            assert!(sa.address.full_bytes().iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn scrub_local_u16_zeroes_a_u16_buffer() {
        let mut buf = [0x1234u16; 24];
        scrub_local_u16(&mut buf);
        assert!(buf.iter().all(|&w| w == 0));
    }

    // ------------------------------------------------------------------
    // Scrub-on-error ordering (should-fix #6/#4, pre-release audit
    // `docs/PRE-RELEASE-AUDIT.md`): `derive_final_entropy`'s `Bip39` error
    // branch previously returned via `?` before `entropy_local` was
    // scrubbed. `derive_final_entropy` itself always calls
    // `convert_entropy_and_scrub` with `entropy_len` fixed to 16 or 32
    // (always valid), so this exact branch is unreachable through the
    // public pipeline API -- these tests exercise `convert_entropy_and_scrub`
    // directly with a deliberately invalid length to reach it.
    // ------------------------------------------------------------------

    /// On the `Bip39` error path, `entropy_local` must still be fully
    /// scrubbed before the error is returned.
    #[test]
    fn convert_entropy_and_scrub_zeroes_entropy_local_on_bip39_error() {
        let mut entropy_local = [0x42u8; 32];
        let mut indexes = [0u16; 24];

        // 20 is neither 16 nor 32 -- entropy_to_indexes always rejects it
        // with Bip39Error::InvalidEntropyLength.
        let result = convert_entropy_and_scrub(&mut entropy_local, 20, &mut indexes);

        assert_eq!(result, Err(Bip39Error::InvalidEntropyLength));
        assert!(
            entropy_local.iter().all(|&b| b == 0),
            "entropy_local must be scrubbed even when entropy_to_indexes errors"
        );
    }

    /// Companion sanity check: the success path still scrubs too (so the
    /// regression test above cannot pass merely because scrubbing always
    /// happened to run on some unrelated path).
    #[test]
    fn convert_entropy_and_scrub_zeroes_entropy_local_on_success() {
        let mut entropy_local = [0x42u8; 32];
        let mut indexes = [0u16; 24];

        let result = convert_entropy_and_scrub(&mut entropy_local, 16, &mut indexes);

        assert!(result.is_ok());
        assert!(entropy_local.iter().all(|&b| b == 0));
    }

    // ------------------------------------------------------------------
    // Candidate-vector integration checks (WP-15 DoD /
    // IMPLEMENTATION_MAP.md §5's "integration tests running full
    // candidate-vector cases if reference/python candidates exist"):
    // exercises exactly the seed-core-resident segment of the pipeline
    // (final_entropy -> mnemonic_indexes -> bip39_seed) with the real
    // `bip39` module this facade actually calls, against every published
    // candidate vector. It intentionally cannot exercise the
    // transcript-assembly or BIP32/address-derivation segments, since
    // those live in `seed-protocol`/`seed-derive`, which this crate
    // cannot depend on (module-level doc comment above) — that portion
    // is exactly what WP-16's golden-vector freeze covers once the
    // dev-dependency gap in `shared_file_needs` is closed and a real
    // `TranscriptSink`/`KeyDeriver` pair can be wired in.
    // ------------------------------------------------------------------

    /// Minimal, schema-specific extraction of the handful of top-level
    /// string/array fields this test needs from one `tests/vectors/
    /// candidates/*.json` case object. Not a general JSON parser — no
    /// JSON dependency is available (`IMPLEMENTATION_MAP.md` §3), and a
    /// general parser is unnecessary for this fixed, WP-00-frozen schema
    /// (`tests/vectors/SCHEMA.md`).
    fn extract_hex_field(json: &str, key: &str) -> Option<Vec<u8>> {
        let needle = std::format!("\"{}\": \"", key);
        let start = json.find(&needle)? + needle.len();
        let end = start + json[start..].find('"')?;
        Some(hex_to_bytes(&json[start..end]))
    }

    fn extract_u16_array(json: &str, key: &str) -> Option<Vec<u16>> {
        let needle = std::format!("\"{}\": [", key);
        let start = json.find(&needle)? + needle.len();
        let end = start + json[start..].find(']')?;
        Some(
            json[start..end]
                .split(',')
                .map(|s| s.trim().parse::<u16>().expect("well-formed candidate vector"))
                .collect(),
        )
    }

    #[test]
    fn candidate_vectors_final_entropy_to_mnemonic_and_seed_matches() {
        let dir = std::format!("{}/../../tests/vectors/candidates", env!("CARGO_MANIFEST_DIR"));
        let entries = std::fs::read_dir(&dir).expect("candidate vector directory must exist");

        let mut checked = 0usize;
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let contents = std::fs::read_to_string(&path).expect("readable candidate vector file");

            let final_entropy = extract_hex_field(&contents, "final_entropy_hex")
                .unwrap_or_else(|| panic!("{path:?}: missing final_entropy_hex"));
            let expected_indexes = extract_u16_array(&contents, "mnemonic_indexes")
                .unwrap_or_else(|| panic!("{path:?}: missing mnemonic_indexes"));
            let expected_seed = extract_hex_field(&contents, "bip39_seed_hex")
                .unwrap_or_else(|| panic!("{path:?}: missing bip39_seed_hex"));

            let word_count = match final_entropy.len() {
                16 => WordCount::Twelve,
                32 => WordCount::TwentyFour,
                n => panic!("{path:?}: unexpected final_entropy length {n}"),
            };

            let mut indexes = [0u16; 24];
            let got_word_count = bip39::entropy_to_indexes(&final_entropy, &mut indexes)
                .unwrap_or_else(|e| panic!("{path:?}: entropy_to_indexes failed: {e:?}"));
            assert_eq!(got_word_count, word_count, "{path:?}: word count mismatch");
            assert_eq!(
                &indexes[..expected_indexes.len()],
                expected_indexes.as_slice(),
                "{path:?}: mnemonic_indexes mismatch"
            );

            let mut seed_out = [0u8; 64];
            bip39::mnemonic_to_seed(&indexes, word_count, &mut seed_out);
            assert_eq!(seed_out.as_slice(), expected_seed.as_slice(), "{path:?}: bip39_seed mismatch");

            checked += 1;
        }

        assert!(checked >= 20, "expected at least 20 candidate vectors, checked {checked}");
    }
}
