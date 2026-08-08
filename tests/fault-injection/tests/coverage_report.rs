//! Human-facing coverage report (SPEC §29.5, WP-33 DoD: "a coverage count
//! of injection points"). Sums every per-category constant from
//! `seed_fault_injection::coverage` (the single source of truth each
//! `tests/*.rs` file's loop bounds are pinned to) and prints the
//! breakdown. Run with `cargo test --test coverage_report -- --nocapture`
//! to see the printed table.

use seed_fault_injection::coverage as c;

#[test]
fn print_and_pin_the_injection_point_coverage_total() {
    let rows: [(&str, usize); 32] = [
        ("A: before-transition watchdog fault (every reachable state)", c::A_BEFORE_TRANSITION_WATCHDOG_FAULT),
        ("A: after-transition illegal-event battery", c::A_AFTER_TRANSITION_ILLEGAL_EVENTS),
        ("B: acquisition assemble_acquired_sources combinations", c::B_ACQUISITION_ASSEMBLE_COMBINATIONS),
        ("B: acquisition gate-failure ceremony (per mode)", c::B_ACQUISITION_GATE_FAILURE_CEREMONY),
        ("B: acquisition gate panic mid-call", c::B_ACQUISITION_GATE_PANIC),
        ("C: physical over-budget split ratios", c::C_PHYSICAL_OVER_BUDGET_COMBOS),
        ("C: physical session exact-capacity boundary", c::C_PHYSICAL_SESSION_CAPACITY),
        ("C: physical undo underflow", c::C_PHYSICAL_UNDO_UNDERFLOW),
        ("D: bip39 malformed entropy lengths", c::D_BIP39_BAD_LENGTHS),
        ("D: bip39 resolve_prefix_into edge cases", c::D_BIP39_RESOLVE_PREFIX_EDGE_CASES),
        ("E: display framebuffer-panic thresholds", c::E_DISPLAY_PANIC_THRESHOLDS),
        ("E: display-bearing states fault-event battery", c::E_DISPLAY_STATE_FAULT_EVENTS),
        ("F: re-entry 12w mismatch-destroy (every position)", c::F_REENTRY_12W_MISMATCH_DESTROY),
        ("F: re-entry 12w mismatch-retry (every position)", c::F_REENTRY_12W_MISMATCH_RETRY),
        ("F: re-entry 24w mismatch-destroy (every position)", c::F_REENTRY_24W_MISMATCH_DESTROY),
        ("F: re-entry 24w mismatch-retry (every position)", c::F_REENTRY_24W_MISMATCH_RETRY),
        ("F: re-entry reveal-again at several positions", c::F_REENTRY_REVEAL_AT_POSITIONS),
        ("G: derivation duplicate tag", c::G_DERIVATION_DUPLICATE_TAG),
        ("G: derivation corrupted record_count (decode)", c::G_DERIVATION_TOO_MANY_RECORDS),
        ("G: derivation oversized algorithm id", c::G_DERIVATION_ALGO_ID_TOO_LONG),
        ("G: derivation oversized single source", c::G_DERIVATION_SOURCE_TOO_LONG),
        ("G: derivation combined physical over-budget (split ratios)", c::G_DERIVATION_COMBINED_OVER_BUDGET),
        ("G: derivation zero sources (defensive, non-fault)", c::G_DERIVATION_ZERO_SOURCES),
        ("H: scrub FaultHook panic per SPEC §26 step", c::H_SCRUB_FAULT_HOOK_PANIC_PER_STEP),
        ("H: scrub ArenaScrubSteps panic per arena step", c::H_SCRUB_ARENA_PANIC_PER_STEP),
        ("I: shutdown always fails", c::I_SHUTDOWN_ALWAYS_FAILS),
        ("I: shutdown fails once then succeeds", c::I_SHUTDOWN_FAILS_ONCE_THEN_OK),
        ("I: shutdown always succeeds", c::I_SHUTDOWN_ALWAYS_OK),
        ("I: shutdown provider panics", c::I_SHUTDOWN_PROVIDER_PANICS),
        ("J: passphrase confirm-mismatch scrubs both buffers (ceremony)", c::J_PASSPHRASE_CONFIRM_MISMATCH_SCRUB),
        ("J: passphrase committed+matched then scrubbed (ceremony)", c::J_PASSPHRASE_COMMITTED_THEN_SCRUBBED),
        ("J: passphrase mid-entry cancel scrubs the buffer (primitive)", c::J_PASSPHRASE_ENTRY_CANCEL_SCRUB),
    ];
    // I_SHUTDOWN_STATE_ABSORBS_EVENTS is checked with a `>=` bound in
    // `shutdown_faults.rs` (`Shutdown` itself is not fully terminal, so
    // its own probe count is data-dependent) rather than an exact count;
    // included in the printed table and the pinned total via `c::total()`
    // below, just not itemized in this fixed-size array.

    let mut sum = 0usize;
    println!("\nSPEC §29.5 fault-injection coverage (WP-33):");
    println!("{:-<78}", "");
    for (label, count) in rows {
        println!("{label:<62} {count:>5}");
        sum += count;
    }
    println!(
        "{:<62} {:>5}",
        "I: shutdown-state absorbs fault-event battery (>=)",
        c::I_SHUTDOWN_STATE_ABSORBS_EVENTS
    );
    sum += c::I_SHUTDOWN_STATE_ABSORBS_EVENTS;
    println!("{:-<78}", "");
    println!("{:<62} {:>5}", "TOTAL injection points covered", sum);
    println!();

    assert_eq!(sum, c::total(), "the itemized table above must sum to exactly coverage::total()");
}
