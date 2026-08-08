//! Category H companion (SPEC §20.4/§27.3, "best-effort panic-time
//! scrub"): proves the exact function both UEFI `#[panic_handler]`s now
//! call — `seed_core::arena::SecretArena::panic_scrub_registered_arena()`
//! — actually zeroes a *registered live* arena's resident secret buffers.
//!
//! # Why this test exists (the fault it guards against)
//!
//! The production and test UEFI editions build under `panic = "abort"`
//! (root `Cargo.toml` `[profile.release]`), which skips `Drop`. A panic
//! while a funds-bearing mnemonic/seed/passphrase is resident in the one
//! live [`SecretArena`] therefore has exactly one remaining chance to wipe
//! those bytes before the machine halts: the `#[panic_handler]` itself,
//! which runs *before* the abort. Both handlers
//! (`crates/seed-uefi-{production,test}/src/main.rs`) call
//! `panic_scrub_registered_arena()` immediately before `halt_forever()`;
//! the ceremony registers its arena in
//! `seed_flow::firmware_wiring::run_secret_phase` via
//! `SecretArena::register_for_panic_scrub`.
//!
//! A host test cannot invoke the real `#[no_std]`/`#[no_main]` UEFI
//! `#[panic_handler]` (the host uses the std panic runtime), so — exactly
//! as SPEC §29.5 fault injection does elsewhere in this suite — this test
//! drives the *same* real, production function the handler calls, against
//! the *same* real [`SecretArena`] type, and asserts the whole-region
//! scrub took effect. It complements the arena crate's own
//! `panic_scrub_registry_scrubs_the_registered_arena_and_can_be_unregistered`
//! unit test by loading every category of resident secret (mnemonic
//! indexes, BIP39 seed, master key + chain code, and the committed
//! passphrase / confirm buffers), not just `final_entropy`.
//!
//! This is a correctness proof of the panic-scrub *wiring*, not a new
//! SPEC §29.5 injection-point category, so it deliberately does not add a
//! `coverage::*` ledger constant (which would have to be itemized in
//! `coverage_report.rs` too); the existing category-H constants already
//! count the `scrub_and_shutdown` fault points.

use seed_fault_injection::SecretArena;
use std::sync::Mutex;

/// Every test in this file touches the single process-global
/// `PANIC_SCRUB_ARENA` registration slot (via
/// register/unregister/`panic_scrub_registered_arena`). Cargo runs the
/// tests in one binary across multiple threads, so they MUST be serialized
/// — otherwise one test's `unregister`/`register` could race another's
/// scrub and turn it into a no-op (a false failure). This lock makes each
/// test's register→scrub→assert→unregister sequence atomic with respect to
/// the others. Poisoning (from an assertion failure in another test) is
/// deliberately ignored: that test already reported the real failure, and
/// the registry itself is just a raw pointer with no invariant a panic
/// could have left half-updated.
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

fn registry_guard() -> std::sync::MutexGuard<'static, ()> {
    REGISTRY_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Fill every secret-bearing field of `arena` with a distinct nonzero
/// pattern (so a "wrongly left untouched" and a "wrongly zero to begin
/// with" bug are both caught), and return once every field is confirmed
/// nonzero.
fn load_arena_with_secrets(arena: &mut SecretArena) {
    arena.machine_sources().fill(0xA1);
    // `physical_history` was removed from `SecretArena` (fe7740f): it was a
    // dead, never-populated buffer; real dice/coin history lives in the
    // stack-resident `PhysicalSession`/`PhysicalStaging`, each with its own
    // Drop scrub (see SPEC §17.3/§19.4 as amended by that commit).
    arena.transcript().fill(0xC3);
    arena.final_entropy().fill(0xD4);
    arena.mnemonic_indexes().fill(0x1234);
    arena.reentry_buffer().fill(0xE5);
    arena.bip39_seed().fill(0xF6);
    arena.master_key().fill(0x17);
    arena.master_chain_code().fill(0x28);
    arena.derive_scratch().fill(0x39);
    arena.scratch().fill(0x4A);
    for &b in b"Correct Horse Battery Staple 42!" {
        arena.passphrase().push_ascii(b).unwrap();
    }
    for &b in b"Correct Horse Battery Staple 42!" {
        arena.passphrase_confirm().push_ascii(b).unwrap();
    }

    // Sanity: the load actually took effect for the buffers the finding
    // named specifically (mnemonic / seed / passphrase), so the post-scrub
    // assertions below cannot pass vacuously.
    assert!(arena.mnemonic_indexes().iter().any(|&w| w != 0), "sanity: mnemonic indexes loaded");
    assert!(arena.bip39_seed().iter().any(|&b| b != 0), "sanity: BIP39 seed loaded");
    assert!(arena.master_key().iter().any(|&b| b != 0), "sanity: master key loaded");
    assert!(!arena.passphrase().is_empty(), "sanity: passphrase loaded");
    assert!(!arena.passphrase_confirm().is_empty(), "sanity: passphrase confirm loaded");
}

/// Assert every secret-bearing field of `arena` is fully zeroed.
fn assert_arena_fully_scrubbed(arena: &mut SecretArena) {
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

/// The core proof: registering a live arena full of secrets and then
/// invoking the panic handler's scrub entry point
/// (`panic_scrub_registered_arena`) zeroes the mnemonic indexes, the BIP39
/// seed, the master key/chain code and the committed passphrase buffers —
/// i.e. the panic path the two UEFI `#[panic_handler]`s wire really does
/// wipe resident secrets before halting.
#[test]
fn panic_scrub_zeroes_registered_arena_mnemonic_seed_and_passphrase() {
    let _guard = registry_guard();
    let mut arena = SecretArena::new();
    load_arena_with_secrets(&mut arena);

    // SAFETY: `arena` is not moved for the rest of this test and is
    // unregistered below before it goes out of scope, upholding
    // `register_for_panic_scrub`'s safety contract.
    unsafe {
        arena.register_for_panic_scrub();
    }

    // Exactly what both UEFI `#[panic_handler]`s call before halting.
    // SAFETY: nothing else is running; the registered pointer is still the
    // live `arena` above, not moved or freed.
    unsafe {
        SecretArena::panic_scrub_registered_arena();
    }

    assert_arena_fully_scrubbed(&mut arena);

    SecretArena::unregister_for_panic_scrub();
}

/// Fault-injection framing: simulate a panic firing while the ceremony's
/// arena is live by running the load-register-scrub sequence *inside* a
/// `catch_unwind` whose closure then panics (as a real fault would),
/// mirroring how the rest of this suite drives the shutdown/scrub paths.
/// The scrub must have already zeroed the resident secrets by the time the
/// simulated fault unwinds — proving the ordering the real handler relies
/// on (scrub first, then halt) holds even when a panic is in flight.
#[test]
fn panic_scrub_runs_before_the_simulated_fault_unwinds() {
    let _guard = registry_guard();
    // The arena must outlive the unwinding closure so we can inspect it
    // afterwards; a raw pointer lets the closure reach it without moving it
    // across the unwind boundary.
    let mut arena = SecretArena::new();
    load_arena_with_secrets(&mut arena);
    // SAFETY: `arena` is pinned on this stack frame for the remainder of
    // the test and unregistered before it drops.
    unsafe {
        arena.register_for_panic_scrub();
    }

    let result = std::panic::catch_unwind(|| {
        // The panic handler's scrub entry point, invoked in the instant a
        // fault fires.
        // SAFETY: single-threaded; the registered arena is still live.
        unsafe {
            SecretArena::panic_scrub_registered_arena();
        }
        panic!("simulated hardware/platform fault after the panic-time scrub ran");
    });
    assert!(result.is_err(), "the simulated fault must unwind, not be swallowed");

    // After the (simulated) panic path ran its scrub, the resident secrets
    // are gone.
    assert_arena_fully_scrubbed(&mut arena);

    SecretArena::unregister_for_panic_scrub();
}

/// Once unregistered (or if nothing was ever registered), the panic-time
/// scrub entry point must be a safe no-op — never a stale/dangling-pointer
/// read — so a panic *before* the secret phase (no arena registered) is
/// harmless. This guards the "no-op when nothing is registered" branch the
/// handlers rely on for pre-secret panics.
#[test]
fn panic_scrub_is_a_safe_no_op_when_nothing_is_registered() {
    let _guard = registry_guard();
    // Establish a known-clear registration state, then confirm a call does
    // nothing observable and does not fault.
    SecretArena::unregister_for_panic_scrub();
    // SAFETY: nothing is registered at this point.
    unsafe {
        SecretArena::panic_scrub_registered_arena();
    }
}
