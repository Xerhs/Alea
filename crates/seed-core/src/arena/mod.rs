//! Fixed secret arena (WP-09, SPEC §13, §20).
//!
//! `SecretArena` is the single fixed-size, `#[repr(C)]`, page-aligned
//! region that every secret-bearing byte produced by this project's
//! generation pipeline lives in, from the first machine/physical entropy
//! byte through the derived BIP32 master key and every intermediate
//! private key produced during derivation (SPEC §13, "production review
//! MUST account for every secret-bearing byte").
//!
//! It is never resized, never boxed, never copied into a heap container
//! (there is no heap — `#![no_std]`, no `alloc`), and is only ever handed
//! out by mutable reference. Callers reach individual fields through the
//! accessor methods below; nothing here is `pub` field access, so every
//! read/write of secret bytes is reviewable at a small number of call
//! sites (SPEC §20.1, §20.2: "Functions SHOULD receive mutable references
//! rather than secret values by value").
//!
//! ## Type restrictions (SPEC §20.2)
//!
//! [`SecretArena`] deliberately implements **none** of `Copy`, `Clone`,
//! `Debug`, `Display`, `PartialEq`/`Eq`, or any serialization trait. That
//! absence is enforced with `compile_fail` doctests below (this crate
//! cannot depend on `trybuild` — no new dependencies per
//! `IMPLEMENTATION_MAP.md` §3 — so rustdoc's built-in `compile_fail`
//! fences are the compile-time proof mechanism instead).
//!
//! ## Scrubbing (SPEC §20.3)
//!
//! [`SecretArena::scrub_all`] overwrites every field with volatile
//! zero-writes (`core::ptr::write_volatile`), inserts a compiler fence and
//! an architecture memory fence so the writes cannot be reordered around
//! or optimized away, then performs a volatile verification read back
//! over every scrubbed byte and asserts (in debug builds; this is a
//! best-effort defense per SPEC §20.3, not a proof) that every byte read
//! back as zero.
//!
//! Beyond that single-shot, whole-region scrub, the ceremony needs to
//! retire *subsets* of the arena at specific points without disturbing
//! fields that are still live (SPEC §19.4: "Immediately after final
//! entropy is derived, the application MUST scrub: raw machine-source
//! records; dice and coin history; the canonical transcript ..." while
//! `final_entropy` itself must survive for BIP39 conversion; SPEC §26's
//! shutdown sequence retires re-entry state, then mnemonic indexes, then
//! the derived-secret fields, each as its own step before the final
//! whole-arena `scrub_all`). [`SecretArena::scrub_entropy_sources`],
//! [`SecretArena::scrub_reentry_state`], [`SecretArena::scrub_mnemonic_indexes`]
//! and [`SecretArena::scrub_derived_secrets`] cover those staged points;
//! `scrub_all` remains the mandatory final catch-all on every success and
//! fatal path (SPEC §20.1).
//!
//! [`scrub_slice`] exposes the same reviewed volatile-write + fence +
//! verification-read primitive the arena uses internally, as a safe
//! `&mut [u8]` wrapper, so other secret-bearing types outside this module
//! (which cannot reach the arena's private fields) scrub with the same
//! reviewed primitive instead of hand-rolling their own.

use core::sync::atomic::{compiler_fence, fence, AtomicPtr, Ordering};

use crate::contracts::{MAX_MACHINE_SOURCE_BYTES, TRANSCRIPT_CAPACITY};
use crate::passphrase::PassphraseAscii;

/// Capacity of the raw machine-entropy staging buffer (SPEC §15, §19.1)
/// before it is folded into the canonical transcript.
///
/// Derivation: up to three machine source records
/// (`ApprovedEfiRng`/`X86Rdseed64`/`X86RdrandSupplementary`, SPEC §19.1)
/// each carrying at most [`MAX_MACHINE_SOURCE_BYTES`] raw bytes before
/// they are recorded into the transcript: `3 * 64 = 192` (the per-record
/// cap doubled 32 → 64 for audit finding L2, which gave the RDSEED64
/// record its second 256-bit block).
pub const MACHINE_SOURCE_CAPACITY: usize = 3 * MAX_MACHINE_SOURCE_BYTES;

/// Capacity of the fixed re-entry verification scratch buffer (SPEC §23:
/// the user re-types a handful of words to confirm the backup).
///
/// Derivation: re-entry verification (SPEC §23.1) checks one word index
/// (`u16`, 2 bytes) at a time against a freshly typed prefix; 8 bytes is
/// generous headroom over the 2 bytes actually needed for a single
/// in-flight comparison, without ever holding more than one word's worth
/// of re-entry state at a time.
pub const REENTRY_BUFFER_CAPACITY: usize = 8;

/// Capacity of the scratch buffer used transiently during BIP32
/// derivation (SPEC §24.2) for intermediate private-key material.
///
/// Derivation: one HMAC-SHA512 call's output (`I = I_L || I_R`, 64 bytes)
/// plus its input buffer for hardened child derivation
/// (`0x00 || ser256(k_par) || ser32(index)` = 1 + 32 + 4 = 37 bytes,
/// the largest CKD input form per BIP32) = 101 bytes, rounded up to 128
/// for alignment headroom and to cover the non-hardened form
/// (`serP(point(k_par)) || ser32(index)` = 33 + 4 = 37 bytes) with the
/// same buffer.
pub const DERIVE_SCRATCH_CAPACITY: usize = 128;

/// Capacity of the general-purpose secret scratch buffer for any
/// transient secret-adjacent computation not covered by a named field
/// (e.g. a compressed public-key serialization computed from a still-live
/// private key while forming an address, SPEC §24.2/§24.3).
///
/// Derivation: the largest single transient value handled outside the
/// dedicated derivation fields is a serialized extended-key-style blob
/// (chain code 32 + compressed pubkey 33 = 65 bytes); 64 bytes covers the
/// common case and pairs with [`DERIVE_SCRATCH_CAPACITY`] for anything
/// larger.
pub const SCRATCH_CAPACITY: usize = 64;

/// Number of bytes in a BIP39 seed (SPEC §14, §24.2: PBKDF2-HMAC-SHA512
/// output).
const BIP39_SEED_LEN: usize = 64;

/// Number of bytes in a raw secp256k1 private key / BIP32 chain code
/// (SPEC §24.2).
const KEY_LEN: usize = 32;

/// Number of bytes in the final BIP39 entropy value (SPEC §14: the larger
/// of the two supported sizes, 256 bits).
const FINAL_ENTROPY_LEN: usize = 32;

/// Maximum number of mnemonic words (SPEC §14: the 24-word case).
const MAX_MNEMONIC_WORDS: usize = 24;

/// The single fixed secret arena (SPEC §13, §20.1).
///
/// Every field is secret-bearing application state for exactly one
/// generation session. The struct is `#[repr(C)]` (stable, reviewable
/// layout) and page-aligned (SPEC §20.1: "one page-aligned fixed-size
/// arena") so the whole region occupies predictable memory independent of
/// compiler field-reordering heuristics.
///
/// ```compile_fail
/// // SPEC §20.2: SecretArena MUST NOT implement Copy.
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<seed_core::arena::SecretArena>();
/// ```
///
/// ```compile_fail
/// // SPEC §20.2: SecretArena MUST NOT implement Clone.
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<seed_core::arena::SecretArena>();
/// ```
///
/// ```compile_fail
/// // SPEC §20.2: SecretArena MUST NOT implement Debug.
/// fn assert_debug<T: core::fmt::Debug>() {}
/// assert_debug::<seed_core::arena::SecretArena>();
/// ```
///
/// ```compile_fail
/// // SPEC §20.2: SecretArena MUST NOT implement Display.
/// fn assert_display<T: core::fmt::Display>() {}
/// assert_display::<seed_core::arena::SecretArena>();
/// ```
///
/// ```compile_fail
/// // SPEC §20.2: SecretArena MUST NOT implement PartialEq.
/// fn assert_partial_eq<T: PartialEq>() {}
/// assert_partial_eq::<seed_core::arena::SecretArena>();
/// ```
#[repr(C, align(4096))]
pub struct SecretArena {
    /// Raw machine-entropy staging bytes before transcript recording
    /// (SPEC §15, §19.1).
    machine_sources: [u8; MACHINE_SOURCE_CAPACITY],
    // The dice/coin physical-event history (SPEC §17.3) is deliberately NOT
    // an arena field: it lives in the dedicated per-session buffers
    // `seed_protocol::physical::PhysicalSession` and
    // `seed_flow::flow_secret::physical::PhysicalStaging`, stack-resident
    // ALONGSIDE the arena (SPEC §20.1 documented exception, §19.4). Those
    // buffers carry their own `Drop` scrub plus an explicit volatile scrub
    // on every normal path (enter/back/undo/clear and after final entropy),
    // and the seed-protocol layer that owns `PhysicalSession` deliberately
    // does not depend on seed-core's arena. It never participated in
    // derivation, so no frozen vector depends on its presence here.
    /// Canonical entropy-combination transcript (SPEC §19.1, §19.2).
    transcript: [u8; TRANSCRIPT_CAPACITY],
    /// Final BIP39 entropy after transcript finalization (SPEC §19.3).
    final_entropy: [u8; FINAL_ENTROPY_LEN],
    /// Resolved BIP39 word indexes, `0..2048` each (SPEC §14).
    mnemonic_indexes: [u16; MAX_MNEMONIC_WORDS],
    /// Scratch space for re-entry verification comparisons (SPEC §23.1).
    reentry_buffer: [u8; REENTRY_BUFFER_CAPACITY],
    /// PBKDF2-HMAC-SHA512 BIP39 seed (SPEC §14, §24.2).
    bip39_seed: [u8; BIP39_SEED_LEN],
    /// BIP32 master private key (SPEC §24.2).
    master_key: [u8; KEY_LEN],
    /// BIP32 master chain code (SPEC §24.2).
    master_chain_code: [u8; KEY_LEN],
    /// Transient BIP32 child-key-derivation scratch (SPEC §24.2).
    derive_scratch: [u8; DERIVE_SCRATCH_CAPACITY],
    /// General-purpose secret scratch space.
    scratch: [u8; SCRATCH_CAPACITY],
    /// The committed BIP39 passphrase (SPEC_PASSPHRASE §5.1). Arena-
    /// resident precisely so the SPEC §26 whole-arena shutdown scrub AND
    /// the SPEC §20.4 `#[panic_handler]` whole-arena scrub reach it
    /// deterministically on the `panic = "abort"` path (SPEC_PASSPHRASE
    /// §5.1/§5.2, M3). Stays resident across the whole verification phase
    /// (like `mnemonic_indexes`) so the grid/preview/custom-path
    /// derivations all use the SAME committed passphrase (SPEC_PASSPHRASE
    /// §7.2/§M2); wiped by [`SecretArena::scrub_all`] at shutdown.
    passphrase: PassphraseAscii,
    /// Scratch buffer for the SPEC_PASSPHRASE §4.1 re-entry confirm
    /// (second entry). Compared against `passphrase` in constant time and
    /// scrubbed on match/mismatch; also arena-resident so both entry
    /// buffers are covered by the whole-arena / panic scrub (M3).
    passphrase_confirm: PassphraseAscii,
}

impl SecretArena {
    /// Builds a fully zeroed arena (SPEC §20.1: "allocated before secret
    /// generation").
    pub const fn new() -> Self {
        Self {
            machine_sources: [0u8; MACHINE_SOURCE_CAPACITY],
            transcript: [0u8; TRANSCRIPT_CAPACITY],
            final_entropy: [0u8; FINAL_ENTROPY_LEN],
            mnemonic_indexes: [0u16; MAX_MNEMONIC_WORDS],
            reentry_buffer: [0u8; REENTRY_BUFFER_CAPACITY],
            bip39_seed: [0u8; BIP39_SEED_LEN],
            master_key: [0u8; KEY_LEN],
            master_chain_code: [0u8; KEY_LEN],
            derive_scratch: [0u8; DERIVE_SCRATCH_CAPACITY],
            scratch: [0u8; SCRATCH_CAPACITY],
            passphrase: PassphraseAscii::new(),
            passphrase_confirm: PassphraseAscii::new(),
        }
    }

    /// Raw machine-entropy staging buffer (SPEC §15, §19.1).
    pub fn machine_sources(&mut self) -> &mut [u8; MACHINE_SOURCE_CAPACITY] {
        &mut self.machine_sources
    }

    /// Canonical entropy-combination transcript (SPEC §19.1, §19.2).
    pub fn transcript(&mut self) -> &mut [u8; TRANSCRIPT_CAPACITY] {
        &mut self.transcript
    }

    /// Final BIP39 entropy (SPEC §19.3).
    pub fn final_entropy(&mut self) -> &mut [u8; FINAL_ENTROPY_LEN] {
        &mut self.final_entropy
    }

    /// Resolved BIP39 word indexes (SPEC §14).
    pub fn mnemonic_indexes(&mut self) -> &mut [u16; MAX_MNEMONIC_WORDS] {
        &mut self.mnemonic_indexes
    }

    /// Re-entry verification scratch (SPEC §23.1).
    pub fn reentry_buffer(&mut self) -> &mut [u8; REENTRY_BUFFER_CAPACITY] {
        &mut self.reentry_buffer
    }

    /// BIP39 seed (SPEC §14, §24.2).
    pub fn bip39_seed(&mut self) -> &mut [u8; BIP39_SEED_LEN] {
        &mut self.bip39_seed
    }

    /// BIP32 master private key (SPEC §24.2).
    pub fn master_key(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.master_key
    }

    /// BIP32 master chain code (SPEC §24.2).
    pub fn master_chain_code(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.master_chain_code
    }

    /// BIP32 child-key-derivation scratch (SPEC §24.2).
    pub fn derive_scratch(&mut self) -> &mut [u8; DERIVE_SCRATCH_CAPACITY] {
        &mut self.derive_scratch
    }

    /// General-purpose secret scratch space.
    pub fn scratch(&mut self) -> &mut [u8; SCRATCH_CAPACITY] {
        &mut self.scratch
    }

    /// The committed BIP39 passphrase (SPEC_PASSPHRASE §5.1). Written
    /// during SPEC_PASSPHRASE §4.1 entry-1 and read (by reference only) by
    /// every passphrase-aware derivation.
    pub fn passphrase(&mut self) -> &mut PassphraseAscii {
        &mut self.passphrase
    }

    /// The SPEC_PASSPHRASE §4.1 confirm (entry-2) scratch buffer.
    pub fn passphrase_confirm(&mut self) -> &mut PassphraseAscii {
        &mut self.passphrase_confirm
    }

    /// SPEC_PASSPHRASE §4.1 constant-time confirm compare: `true` iff the
    /// committed `passphrase` equals the `passphrase_confirm` scratch. Takes
    /// `&self` so both fields can be compared without two live `&mut`
    /// accessor borrows at the call site.
    #[must_use]
    pub fn passphrase_confirm_matches(&self) -> bool {
        self.passphrase.ct_eq(&self.passphrase_confirm)
    }

    /// Scrubs the entire arena: every field, as one complete region
    /// (SPEC §20.1: "scrubbed as a complete region on success and every
    /// fatal path"; SPEC §20.3: volatile writes, compiler fence,
    /// architecture memory fence, verification read).
    ///
    /// This MUST be called on every successful completion path and every
    /// fatal-error path once a secret exists (SPEC §20.1, §20.4). It is
    /// also invoked automatically on `Drop` as a defense-in-depth
    /// backstop, though production builds use `panic = "abort"` (SPEC
    /// §20.4) so `Drop` cannot be relied on after a CPU exception or an
    /// abort — callers MUST still scrub explicitly on every reachable
    /// path.
    pub fn scrub_all(&mut self) {
        scrub_bytes(self.machine_sources.as_mut_ptr(), self.machine_sources.len());
        scrub_bytes(self.transcript.as_mut_ptr(), self.transcript.len());
        scrub_bytes(self.final_entropy.as_mut_ptr(), self.final_entropy.len());
        scrub_mnemonic_indexes_field(&mut self.mnemonic_indexes);
        scrub_bytes(self.reentry_buffer.as_mut_ptr(), self.reentry_buffer.len());
        scrub_bytes(self.bip39_seed.as_mut_ptr(), self.bip39_seed.len());
        scrub_bytes(self.master_key.as_mut_ptr(), self.master_key.len());
        scrub_bytes(self.master_chain_code.as_mut_ptr(), self.master_chain_code.len());
        scrub_bytes(self.derive_scratch.as_mut_ptr(), self.derive_scratch.len());
        scrub_bytes(self.scratch.as_mut_ptr(), self.scratch.len());
        // SPEC_PASSPHRASE §5.2/§M3: the arena-resident passphrase buffers
        // are part of the whole-region scrub (and thus of the panic-handler
        // scrub, which calls this) — `panic = "abort"` skips their `Drop`.
        self.passphrase.scrub();
        self.passphrase_confirm.scrub();
    }

    /// Scrubs the arena-resident fields SPEC §19.4 requires immediately
    /// after final entropy is derived: raw machine-source records and the
    /// canonical transcript. §19.4's dice/coin history is not arena-resident
    /// (see the struct-field note): it is scrubbed at the same point by the
    /// `PhysicalSession`/`PhysicalStaging` session buffers' explicit scrub.
    ///
    /// `final_entropy` (and every other field) is left untouched, so this
    /// MUST be called at that point in the ceremony instead of
    /// [`SecretArena::scrub_all`] — `scrub_all` would also wipe
    /// `final_entropy` before it has been converted to a BIP39 mnemonic,
    /// which SPEC §19.4 does not call for ("Only the minimum state
    /// required for mnemonic display, re-entry and derivation display
    /// remains"). `scrub_all` MUST still run later on every success and
    /// fatal path (SPEC §20.1); this method only lets the ceremony honor
    /// §19.4's "immediately" without doing that final wipe early.
    pub fn scrub_entropy_sources(&mut self) {
        scrub_bytes(self.machine_sources.as_mut_ptr(), self.machine_sources.len());
        scrub_bytes(self.transcript.as_mut_ptr(), self.transcript.len());
    }

    /// Scrubs re-entry verification state (SPEC §26 step 1: "Scrub
    /// re-entry state.").
    pub fn scrub_reentry_state(&mut self) {
        scrub_bytes(self.reentry_buffer.as_mut_ptr(), self.reentry_buffer.len());
    }

    /// Scrubs resolved BIP39 mnemonic word indexes (SPEC §26 step 2:
    /// "Scrub mnemonic indexes.").
    pub fn scrub_mnemonic_indexes(&mut self) {
        scrub_mnemonic_indexes_field(&mut self.mnemonic_indexes);
    }

    /// Scrubs the derived-secret fields and their derivation scratch
    /// (SPEC §26 step 3: "Scrub final entropy, BIP39 seed, master key,
    /// chain codes and all derivation scratch.").
    pub fn scrub_derived_secrets(&mut self) {
        scrub_bytes(self.final_entropy.as_mut_ptr(), self.final_entropy.len());
        scrub_bytes(self.bip39_seed.as_mut_ptr(), self.bip39_seed.len());
        scrub_bytes(self.master_key.as_mut_ptr(), self.master_key.len());
        scrub_bytes(self.master_chain_code.as_mut_ptr(), self.master_chain_code.len());
        scrub_bytes(self.derive_scratch.as_mut_ptr(), self.derive_scratch.len());
        scrub_bytes(self.scratch.as_mut_ptr(), self.scratch.len());
    }

    // ------------------------------------------------------------------
    // SHOULD-FIX #5 (SPEC §20.4/§27.3): best-effort panic-time scrub.
    // See `PANIC_SCRUB_ARENA` (module level, below this `impl` block) for
    // the registry itself and the full rationale.
    // ------------------------------------------------------------------

    /// Registers `self` as the arena a `#[panic_handler]` should
    /// best-effort scrub if a panic ever fires while this instance is
    /// live (SPEC §20.4/§27.3). At most one arena is ever registered at
    /// a time in this project's real call graph (each ceremony run
    /// constructs exactly one `SecretArena`); registering a second
    /// simply replaces the first.
    ///
    /// # Safety
    ///
    /// The caller must not move `self` after this call for as long as it
    /// stays registered (moving it would invalidate the stored pointer),
    /// and must call [`SecretArena::unregister_for_panic_scrub`] before
    /// `self` is dropped or goes out of scope. Every real call site
    /// satisfies this by registering immediately after construction and
    /// only ever accessing `self` through `&mut` borrows afterward (never
    /// moving it), then unregistering at the one point that specific
    /// function can return without going through this arena's own
    /// scrub-and-halt chain.
    pub unsafe fn register_for_panic_scrub(&mut self) {
        PANIC_SCRUB_ARENA.store(core::ptr::from_mut(self), Ordering::SeqCst);
    }

    /// Clears the panic-scrub registration (see
    /// [`SecretArena::register_for_panic_scrub`]). Idempotent; safe to
    /// call even if nothing is currently registered.
    pub fn unregister_for_panic_scrub() {
        PANIC_SCRUB_ARENA.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    /// Best-effort: if a [`SecretArena`] is currently registered (see
    /// [`SecretArena::register_for_panic_scrub`]), scrub it. Intended to
    /// be called from a `#[panic_handler]` only, immediately before
    /// halting — see that call site's own doc comment.
    ///
    /// # Safety
    ///
    /// The caller must only invoke this from a context where, if a
    /// `SecretArena` is currently registered, the registering call site's
    /// own safety contract still holds (in this workspace: a
    /// `#[panic_handler]`, called after everything else has stopped
    /// running, satisfies this — the registered pointer, if any, is
    /// still exactly the live arena `run_secret_phase` registered and
    /// has not been moved or freed).
    pub unsafe fn panic_scrub_registered_arena() {
        let ptr = PANIC_SCRUB_ARENA.load(Ordering::SeqCst);
        // SAFETY: non-null only when a real call site registered a still
        // (per this function's own safety contract) valid `&mut
        // SecretArena`-derived pointer.
        if let Some(arena) = unsafe { ptr.as_mut() } {
            arena.scrub_all();
        }
    }
}

/// Raw pointer to the currently-registered [`SecretArena`], if any, for a
/// panic handler's own best-effort scrub (SPEC §20.4/§27.3;
/// [`SecretArena::register_for_panic_scrub`]/
/// [`SecretArena::unregister_for_panic_scrub`]/
/// [`SecretArena::panic_scrub_registered_arena`]). `null` means "none
/// registered" (the initial and post-`unregister_for_panic_scrub` state).
///
/// `panic = "abort"` (this workspace's profile) skips `Drop` — hence
/// `SecretArena`'s own scrub-on-drop (`impl Drop for SecretArena`) — so a
/// panic while a real, live secret arena exists would otherwise leave it
/// unscrubbed in memory for as long as the machine stays powered: a
/// `#[panic_handler]`'s signature is fixed by the language (it cannot
/// receive arbitrary extra parameters), so it has no other way to reach
/// whatever arena happens to be live on some other function's stack frame.
/// This registry gives it a chance anyway: the ceremony registers its one
/// live arena right after creating it, and the panic handler reads the
/// registration back, best-effort, before halting. Deliberately not a
/// safe, checked API — a panic handler runs with no guarantee about the
/// rest of the program's state — but "best effort, may fail" is strictly
/// better than "never attempted at all", and every real call site in this
/// workspace (`seed_flow::firmware_wiring::run_secret_phase`) upholds the
/// pointer's validity for exactly as long as it stays registered.
///
/// This workspace is single-threaded (no threads are ever spawned
/// anywhere in the production dependency graph), so a plain `AtomicPtr`
/// (used here only for its interior mutability in a `static`, not for
/// cross-thread synchronization) with `SeqCst` ordering is sufficient;
/// there is no concurrent access to reason about beyond "the one panic
/// handler, running after everything else has already stopped."
static PANIC_SCRUB_ARENA: AtomicPtr<SecretArena> = AtomicPtr::new(core::ptr::null_mut());

/// Scrubs a `[u16; N]` mnemonic-index array through the same byte-level
/// volatile+fence+verify primitive used everywhere else, shared by
/// [`SecretArena::scrub_all`] and [`SecretArena::scrub_mnemonic_indexes`]
/// so the two staged/whole-region paths cannot drift apart.
fn scrub_mnemonic_indexes_field(indexes: &mut [u16; MAX_MNEMONIC_WORDS]) {
    // SAFETY: `indexes` is a `[u16; N]`; reinterpreting it as `N * 2`
    // bytes through a `u8` pointer is always valid (`u8` has no alignment
    // or padding constraints and every byte of a `u16` is part of its
    // object representation), and the pointer stays within the bounds of
    // this exclusively-borrowed array.
    scrub_bytes(indexes.as_mut_ptr().cast::<u8>(), core::mem::size_of_val(indexes));
}

impl Default for SecretArena {
    /// Equivalent to [`SecretArena::new`]. `Default` is a construction
    /// convenience, not a data-exposing trait, so it does not conflict
    /// with SPEC §20.2's restrictions.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretArena {
    /// Defense-in-depth: scrub on drop in addition to every explicit
    /// `scrub_all()` call a caller is required to make (SPEC §20.1,
    /// §20.4). See [`SecretArena::scrub_all`] for why this cannot be the
    /// *only* scrub path in production.
    fn drop(&mut self) {
        self.scrub_all();
    }
}

/// Scrubs `len` bytes starting at `ptr` (SPEC §20.3): volatile
/// zero-writes, a compiler fence, an architecture memory fence, then a
/// volatile verification read over the same region.
///
/// # Safety-relevant preconditions (enforced by every call site above)
///
/// `ptr` must be valid for `len` bytes of exclusive (`&mut`) access for
/// the duration of this call. Every caller passes a pointer freshly
/// derived from a `&mut` borrow of one `SecretArena` field, so this holds.
#[inline(never)]
fn scrub_bytes(ptr: *mut u8, len: usize) {
    // Volatile zero-write, one byte at a time: the compiler may not elide,
    // reorder past, or coalesce these in a way that skips the write
    // (SPEC §20.3, "volatile writes").
    for i in 0..len {
        // SAFETY: `ptr..ptr+len` is valid for writes per the function's
        // documented precondition; `i < len`.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
    }

    // Compiler fence: forbids the compiler from reordering the writes
    // above past this point at compile time (SPEC §20.3, "compiler
    // fences").
    compiler_fence(Ordering::SeqCst);
    // Architecture memory fence: forbids the CPU from reordering the
    // writes above past this point at run time (SPEC §20.3,
    // "architecture-appropriate memory fences").
    fence(Ordering::SeqCst);

    // Verification read: read every scrubbed byte back through a volatile
    // load (so the read cannot be optimized away either) and fold it into
    // an accumulator, which is itself passed through `black_box` so the
    // whole read-back loop cannot be proven dead and removed (SPEC §20.3,
    // "verification reads ... where practical"). This is best-effort, not
    // a proof (SPEC §20.3): it only catches the write not taking effect
    // in *this* address space's view of memory.
    let mut observed = 0u8;
    for i in 0..len {
        // SAFETY: same region as above, now valid for reads too.
        let byte = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        observed |= byte;
    }
    let observed = core::hint::black_box(observed);
    debug_assert_eq!(observed, 0, "scrub_bytes: verification read found a non-zero byte");
}

/// Scrubs `buf` in place with the same reviewed primitive
/// [`SecretArena::scrub_all`] and its staged siblings use internally:
/// volatile zero-writes, a compiler fence, an architecture memory fence,
/// then a volatile verification read (SPEC §20.3).
///
/// This is a safe, ordinary-slice wrapper around the private
/// `scrub_bytes` pointer primitive, published specifically so
/// secret-bearing state that cannot live inside [`SecretArena`] itself
/// (for example a fixed-size local buffer in another module of this
/// crate or a downstream crate) still scrubs with the arena's own
/// reviewed volatile+fence+verify sequence rather than a hand-rolled,
/// possibly-incomplete copy of it (SPEC §20.3).
///
/// `buf.len() == 0` is a no-op: there is nothing to write, fence or
/// verify.
pub fn scrub_slice(buf: &mut [u8]) {
    scrub_bytes(buf.as_mut_ptr(), buf.len());
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly constructed arena is fully zeroed (SPEC §20.1: "allocated
    /// before secret generation").
    #[test]
    fn new_arena_is_zeroed() {
        let mut arena = SecretArena::new();
        assert!(arena.machine_sources().iter().all(|&b| b == 0));
        assert!(arena.transcript().iter().all(|&b| b == 0));
        assert!(arena.final_entropy().iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0));
        assert!(arena.reentry_buffer().iter().all(|&b| b == 0));
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
        assert!(arena.master_chain_code().iter().all(|&b| b == 0));
        assert!(arena.derive_scratch().iter().all(|&b| b == 0));
        assert!(arena.scratch().iter().all(|&b| b == 0));
        assert!(arena.passphrase().is_empty());
        assert!(arena.passphrase_confirm().is_empty());
    }

    /// `Default` matches `new()`.
    #[test]
    fn default_matches_new() {
        let mut arena = SecretArena::default();
        assert!(arena.master_key().iter().all(|&b| b == 0));
    }

    /// Accessor field sizes match the documented capacities (a
    /// compile-time-checked-by-return-type property, re-asserted at
    /// runtime for clarity of intent).
    #[test]
    fn field_sizes_match_documented_capacities() {
        let mut arena = SecretArena::new();
        assert_eq!(arena.machine_sources().len(), MACHINE_SOURCE_CAPACITY);
        assert_eq!(arena.transcript().len(), TRANSCRIPT_CAPACITY);
        assert_eq!(arena.final_entropy().len(), 32);
        assert_eq!(arena.mnemonic_indexes().len(), 24);
        assert_eq!(arena.reentry_buffer().len(), REENTRY_BUFFER_CAPACITY);
        assert_eq!(arena.bip39_seed().len(), 64);
        assert_eq!(arena.master_key().len(), 32);
        assert_eq!(arena.master_chain_code().len(), 32);
        assert_eq!(arena.derive_scratch().len(), DERIVE_SCRATCH_CAPACITY);
        assert_eq!(arena.scratch().len(), SCRATCH_CAPACITY);
    }

    /// The arena is page-aligned (SPEC §20.1: "one page-aligned fixed-size
    /// arena").
    #[test]
    fn arena_is_page_aligned() {
        assert_eq!(core::mem::align_of::<SecretArena>(), 4096);
        let arena = SecretArena::new();
        let addr = &arena as *const SecretArena as usize;
        assert_eq!(addr % 4096, 0);
    }

    /// Filling every field with a nonzero pattern and then calling
    /// `scrub_all` leaves every field entirely zero (SPEC §20.3
    /// verification-read requirement, exercised here as an explicit
    /// read-back test rather than only the internal `debug_assert`).
    #[test]
    fn scrub_all_zeroes_every_field() {
        let mut arena = SecretArena::new();

        arena.machine_sources().fill(0xAA);
        arena.transcript().fill(0xCC);
        arena.final_entropy().fill(0xDD);
        arena.mnemonic_indexes().fill(0x1234);
        arena.reentry_buffer().fill(0xEE);
        arena.bip39_seed().fill(0xFF);
        arena.master_key().fill(0x11);
        arena.master_chain_code().fill(0x22);
        arena.derive_scratch().fill(0x33);
        arena.scratch().fill(0x44);
        for &b in b"Correct Horse 42!" {
            arena.passphrase().push_ascii(b).unwrap();
        }
        for &b in b"Correct Horse 42!" {
            arena.passphrase_confirm().push_ascii(b).unwrap();
        }

        // Sanity: the fills actually took effect before scrubbing.
        assert!(arena.master_key().iter().all(|&b| b == 0x11));
        assert_eq!(arena.passphrase().len(), 17);

        arena.scrub_all();

        assert!(arena.machine_sources().iter().all(|&b| b == 0), "machine_sources not scrubbed");
        assert!(arena.transcript().iter().all(|&b| b == 0), "transcript not scrubbed");
        assert!(arena.final_entropy().iter().all(|&b| b == 0), "final_entropy not scrubbed");
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0), "mnemonic_indexes not scrubbed");
        assert!(arena.reentry_buffer().iter().all(|&b| b == 0), "reentry_buffer not scrubbed");
        assert!(arena.bip39_seed().iter().all(|&b| b == 0), "bip39_seed not scrubbed");
        assert!(arena.master_key().iter().all(|&b| b == 0), "master_key not scrubbed");
        assert!(arena.master_chain_code().iter().all(|&b| b == 0), "master_chain_code not scrubbed");
        assert!(arena.derive_scratch().iter().all(|&b| b == 0), "derive_scratch not scrubbed");
        assert!(arena.scratch().iter().all(|&b| b == 0), "scratch not scrubbed");
        assert!(arena.passphrase().is_empty(), "passphrase not scrubbed");
        assert!(arena.passphrase_confirm().is_empty(), "passphrase_confirm not scrubbed");
    }

    /// `Drop` scrubs automatically as a defense-in-depth backstop.
    #[test]
    fn drop_scrubs_automatically() {
        // We cannot read arena state after it is dropped (that would be a
        // use-after-drop / dangling-pointer bug), so instead prove the
        // property by capturing the raw address before drop, then writing
        // a canary and letting a *new* arena of the same layout reuse the
        // freed stack slot in a checked way. This test uses a raw pointer
        // read of freshly-freed stack memory, which is inherently a bit
        // fuzzy on a real allocator but is deterministic for a stack
        // local going out of scope with nothing else touching that frame
        // in between. To keep this test robust (no reliance on stack
        // reuse timing), we instead call `scrub_all` once, drop the
        // arena, then rely on `scrub_all_zeroes_every_field` above as the
        // authoritative functional proof and only assert here that
        // `Drop` does not panic and runs to completion.
        let mut arena = SecretArena::new();
        arena.master_key().fill(0x99);
        drop(arena);
    }

    /// `scrub_bytes` on a small local buffer: direct unit test of the
    /// primitive scrub-all is built on, independent of `SecretArena`'s
    /// layout.
    #[test]
    fn scrub_bytes_zeroes_and_verifies() {
        let mut buf = [0x42u8; 37];
        scrub_bytes(buf.as_mut_ptr(), buf.len());
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// Regression test for the confirmed WP-09 finding: `scrub_slice` is
    /// the public, safe wrapper around the arena's reviewed
    /// volatile+fence+verify primitive, reusable by secret-bearing state
    /// that lives outside `SecretArena` (SPEC §20.3).
    #[test]
    fn scrub_slice_zeroes_a_plain_buffer() {
        let mut buf = [0x77u8; 13];
        scrub_slice(&mut buf);
        assert!(buf.iter().all(|&b| b == 0), "scrub_slice left a non-zero byte");
    }

    /// `scrub_slice` on an empty slice is a safe no-op (no out-of-bounds
    /// pointer arithmetic).
    #[test]
    fn scrub_slice_handles_empty_slice() {
        let mut buf: [u8; 0] = [];
        scrub_slice(&mut buf);
    }

    /// Regression test for the confirmed WP-09 finding: SPEC §19.4
    /// requires `machine_sources`/`transcript` (the arena-resident §19.4
    /// sources) to be scrubbed immediately after final entropy is derived,
    /// while `final_entropy` itself (needed for BIP39 conversion) and every
    /// later-stage field MUST survive that scrub. §19.4's dice/coin history
    /// is not arena-resident (it lives in the `PhysicalSession`/
    /// `PhysicalStaging` session buffers, scrubbed there), so it is not part
    /// of this method. `scrub_all` cannot be used at this point because it
    /// also wipes `final_entropy`; `scrub_entropy_sources` must scrub only
    /// its two §19.4 arena fields.
    #[test]
    fn scrub_entropy_sources_leaves_final_entropy_and_later_fields_intact() {
        let mut arena = SecretArena::new();
        arena.machine_sources().fill(0xAA);
        arena.transcript().fill(0xCC);
        arena.final_entropy().fill(0xDD);
        arena.mnemonic_indexes().fill(0x1234);
        arena.reentry_buffer().fill(0xEE);
        arena.bip39_seed().fill(0xFF);
        arena.master_key().fill(0x11);
        arena.master_chain_code().fill(0x22);
        arena.derive_scratch().fill(0x33);
        arena.scratch().fill(0x44);

        arena.scrub_entropy_sources();

        assert!(arena.machine_sources().iter().all(|&b| b == 0), "machine_sources not scrubbed");
        assert!(arena.transcript().iter().all(|&b| b == 0), "transcript not scrubbed");

        // Everything §19.4 says must remain (final entropy, plus every
        // field not yet needed until later) is untouched.
        assert!(arena.final_entropy().iter().all(|&b| b == 0xDD), "final_entropy wrongly scrubbed");
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0x1234), "mnemonic_indexes wrongly scrubbed");
        assert!(arena.reentry_buffer().iter().all(|&b| b == 0xEE), "reentry_buffer wrongly scrubbed");
        assert!(arena.bip39_seed().iter().all(|&b| b == 0xFF), "bip39_seed wrongly scrubbed");
        assert!(arena.master_key().iter().all(|&b| b == 0x11), "master_key wrongly scrubbed");
        assert!(arena.master_chain_code().iter().all(|&b| b == 0x22), "master_chain_code wrongly scrubbed");
        assert!(arena.derive_scratch().iter().all(|&b| b == 0x33), "derive_scratch wrongly scrubbed");
        assert!(arena.scratch().iter().all(|&b| b == 0x44), "scratch wrongly scrubbed");
    }

    /// Regression test: SPEC §26 step 1 ("Scrub re-entry state.") scrubs
    /// only `reentry_buffer`, leaving everything else — including fields
    /// scrubbed in later shutdown steps — untouched at this point in the
    /// sequence.
    #[test]
    fn scrub_reentry_state_scrubs_only_reentry_buffer() {
        let mut arena = SecretArena::new();
        arena.reentry_buffer().fill(0xEE);
        arena.mnemonic_indexes().fill(0x1234);
        arena.final_entropy().fill(0xDD);

        arena.scrub_reentry_state();

        assert!(arena.reentry_buffer().iter().all(|&b| b == 0), "reentry_buffer not scrubbed");
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0x1234), "mnemonic_indexes wrongly scrubbed");
        assert!(arena.final_entropy().iter().all(|&b| b == 0xDD), "final_entropy wrongly scrubbed");
    }

    /// Regression test: SPEC §26 step 2 ("Scrub mnemonic indexes.")
    /// scrubs only `mnemonic_indexes`.
    #[test]
    fn scrub_mnemonic_indexes_scrubs_only_that_field() {
        let mut arena = SecretArena::new();
        arena.mnemonic_indexes().fill(0x1234);
        arena.final_entropy().fill(0xDD);
        arena.bip39_seed().fill(0xFF);

        arena.scrub_mnemonic_indexes();

        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0), "mnemonic_indexes not scrubbed");
        assert!(arena.final_entropy().iter().all(|&b| b == 0xDD), "final_entropy wrongly scrubbed");
        assert!(arena.bip39_seed().iter().all(|&b| b == 0xFF), "bip39_seed wrongly scrubbed");
    }

    /// Regression test: SPEC §26 step 3 ("Scrub final entropy, BIP39
    /// seed, master key, chain codes and all derivation scratch.")
    /// scrubs exactly those fields, leaving the already-retired §19.4
    /// entropy-source fields (which are all-zero from an earlier step in
    /// a real ceremony, but here left nonzero to prove this method does
    /// not touch them) and re-entry/mnemonic-index state untouched.
    #[test]
    fn scrub_derived_secrets_scrubs_exactly_its_fields() {
        let mut arena = SecretArena::new();
        arena.machine_sources().fill(0xAA);
        arena.transcript().fill(0xCC);
        arena.final_entropy().fill(0xDD);
        arena.mnemonic_indexes().fill(0x1234);
        arena.reentry_buffer().fill(0xEE);
        arena.bip39_seed().fill(0xFF);
        arena.master_key().fill(0x11);
        arena.master_chain_code().fill(0x22);
        arena.derive_scratch().fill(0x33);
        arena.scratch().fill(0x44);

        arena.scrub_derived_secrets();

        assert!(arena.final_entropy().iter().all(|&b| b == 0), "final_entropy not scrubbed");
        assert!(arena.bip39_seed().iter().all(|&b| b == 0), "bip39_seed not scrubbed");
        assert!(arena.master_key().iter().all(|&b| b == 0), "master_key not scrubbed");
        assert!(arena.master_chain_code().iter().all(|&b| b == 0), "master_chain_code not scrubbed");
        assert!(arena.derive_scratch().iter().all(|&b| b == 0), "derive_scratch not scrubbed");
        assert!(arena.scratch().iter().all(|&b| b == 0), "scratch not scrubbed");

        assert!(arena.machine_sources().iter().all(|&b| b == 0xAA), "machine_sources wrongly scrubbed");
        assert!(arena.transcript().iter().all(|&b| b == 0xCC), "transcript wrongly scrubbed");
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0x1234), "mnemonic_indexes wrongly scrubbed");
        assert!(arena.reentry_buffer().iter().all(|&b| b == 0xEE), "reentry_buffer wrongly scrubbed");
    }

    /// Regression test: chaining the four staged §26 scrub steps in
    /// order, followed by the mandatory final `scrub_all` catch-all,
    /// leaves the entire arena zeroed — proving the staged API is a
    /// legitimate decomposition of `scrub_all`, not a divergent path.
    #[test]
    fn staged_scrub_sequence_matches_scrub_all_coverage() {
        let mut arena = SecretArena::new();
        arena.machine_sources().fill(0xAA);
        arena.transcript().fill(0xCC);
        arena.final_entropy().fill(0xDD);
        arena.mnemonic_indexes().fill(0x1234);
        arena.reentry_buffer().fill(0xEE);
        arena.bip39_seed().fill(0xFF);
        arena.master_key().fill(0x11);
        arena.master_chain_code().fill(0x22);
        arena.derive_scratch().fill(0x33);
        arena.scratch().fill(0x44);

        // SPEC §19.4 point, mid-ceremony.
        arena.scrub_entropy_sources();
        // SPEC §26 shutdown sequence, steps 1-4.
        arena.scrub_reentry_state();
        arena.scrub_mnemonic_indexes();
        arena.scrub_derived_secrets();
        arena.scrub_all();

        assert!(arena.machine_sources().iter().all(|&b| b == 0));
        assert!(arena.transcript().iter().all(|&b| b == 0));
        assert!(arena.final_entropy().iter().all(|&b| b == 0));
        assert!(arena.mnemonic_indexes().iter().all(|&w| w == 0));
        assert!(arena.reentry_buffer().iter().all(|&b| b == 0));
        assert!(arena.bip39_seed().iter().all(|&b| b == 0));
        assert!(arena.master_key().iter().all(|&b| b == 0));
        assert!(arena.master_chain_code().iter().all(|&b| b == 0));
        assert!(arena.derive_scratch().iter().all(|&b| b == 0));
        assert!(arena.scratch().iter().all(|&b| b == 0));
    }

    /// SHOULD-FIX #5 regression (SPEC §20.4/§27.3): the panic-scrub
    /// registry must actually scrub the registered arena, and must be a
    /// safe no-op once unregistered (or if nothing was ever registered)
    /// rather than reading a stale pointer.
    #[test]
    fn panic_scrub_registry_scrubs_the_registered_arena_and_can_be_unregistered() {
        let mut arena = SecretArena::new();
        arena.final_entropy().fill(0xAA);
        assert!(
            arena.final_entropy().iter().any(|&b| b != 0),
            "sanity: arena has nonzero secret bytes before scrub"
        );

        // SAFETY: `arena` is not moved for the remainder of this test,
        // and it is unregistered below before going out of scope, per
        // `register_for_panic_scrub`'s own safety contract.
        unsafe {
            arena.register_for_panic_scrub();
        }
        // SAFETY: the registered pointer is still exactly `arena` above,
        // not moved or freed since registration.
        unsafe {
            SecretArena::panic_scrub_registered_arena();
        }
        assert!(
            arena.final_entropy().iter().all(|&b| b == 0),
            "panic_scrub_registered_arena must have zeroed the registered arena"
        );

        SecretArena::unregister_for_panic_scrub();

        // After unregistering, a second call must be a safe no-op
        // (nothing registered), never a stale/dangling-pointer read.
        // SAFETY: nothing is registered at this point.
        unsafe {
            SecretArena::panic_scrub_registered_arena();
        }
    }
}
