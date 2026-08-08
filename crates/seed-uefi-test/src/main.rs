//! `seed-uefi-test` — the UEFI test edition (SPEC §4.2, §5, §20.4).
//!
//! Distinct executable name and package identifier from the production
//! edition; MUST display a permanent full-screen watermark and the
//! **PUBLIC TEST PHRASE — NEVER USE WITH FUNDS** banner once WP-25/26
//! implement the real flow.
//!
//! This file (WP-17 scope) is intentionally thin: it wires the UEFI
//! `#[entry]`/`#[panic_handler]` attributes to the shared, host-testable
//! helpers in `seed_platform_x86::boot`, prints a pre-secret banner via
//! the firmware text console, and leaves a clean seam (`flow_pre` /
//! `flow_secret`) for the later state-machine work packages to hang off.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use seed_platform_x86::boot;
use uefi::prelude::*;

/// Pre-secret UI flow (opening warning, acknowledgements, diagnostics,
/// mode selection) — WP-25. All testable logic lives in the `seed-flow`
/// library crate (`crates/seed-flow/`); this module only wires
/// real-firmware providers (see its own doc comment).
mod flow_pre;

/// Secret-phase UI flow (physical/machine entropy, final confirmation,
/// display, re-entry, derivation display, completion education,
/// scrub-and-shutdown) — WP-26. All testable logic lives in the
/// `seed-flow` library crate (`crates/seed-flow/`,
/// `flow_secret` module tree); this module only wires real-firmware
/// providers (see its own doc comment).
mod flow_secret;

// Pre-wired so cross-compilation to `x86_64-unknown-uefi` works from day
// one (IMPLEMENTATION_MAP.md WP-00 DoD). WP-25 is the first real
// consumer (via `flow_pre`/`seed_flow`); `seed_derive` and
// `seed_test_vectors` are still only used starting with WP-26.
#[allow(unused_imports)]
use {seed_derive as _, seed_test_vectors as _};

/// Test-edition banner text. Public, deterministic, non-secret (SPEC
/// §4.2) — safe to print at any phase, but emitted here only during the
/// pre-secret entry banner (SPEC §5).
const BANNER_LINE_1: &str = "Alea -- UEFI TEST EDITION";
const BANNER_LINE_2: &str = "PUBLIC TEST PHRASE -- NEVER USE WITH FUNDS";

/// SPEC §4.1 immutable build identifier for this edition, drawn
/// permanently in every ceremony screen's chrome header band (2026-08-07
/// ceremony redesign, design doc §3.3/§4 Stage 1 — the fix for the
/// "banner cleared before it could be read" defect). Same
/// `ALEA_BUILD_ID`-or-placeholder shape the production edition's
/// `release::BUILD_ID` uses; deliberately marked as the TEST edition so a
/// photograph of any screen is unambiguous.
const BUILD_ID: &str = match option_env!("ALEA_BUILD_ID") {
    Some(id) => id,
    None => "TEST-UNSET-LOCAL-BUILD",
};

/// UEFI application entry point.
///
/// SPEC.md amendment (2026-08-06): the ENTIRE ceremony -- the test-edition
/// banner, every pre-secret screen and every secret-phase screen -- now
/// renders through the GOP linear framebuffer via the application
/// bitmap-font path ([`seed_flow::output::FbTextOutput`]), not the
/// firmware text console. [`run_pre_secret`] does all of it: opens the
/// session GOP once at process start, prints the banner through it, then
/// runs the shared pre-secret flow and, on handoff, the shared
/// secret-phase flow. No secret-bearing state exists until handoff; the
/// real state machine (WP-25/26) drives `flow_pre`/`flow_secret` from
/// there.
#[entry]
fn main() -> Status {
    run_pre_secret();

    // WP-26 (`flow_secret`) is not yet implemented: `run_pre_secret`
    // returns after handing off (or exiting) rather than continuing into
    // secret-bearing state itself.
    Status::SUCCESS
}

/// WP-25: wire the real firmware providers and run the complete
/// pre-secret flow (SPEC §22.1-§22.5, §11, §8.4). All the actual screen/
/// branch logic lives in `seed_flow::run_pre_secret_flow`, driven by the
/// WP-23 state machine; this function only constructs the real-firmware
/// provider values `flow_pre` defines and hands them over.
///
/// # Ordering (SPEC.md amendment 2026-08-06)
///
/// Byte-for-byte parallel to `crates/seed-uefi-production/src/main.rs`'s
/// `run_pre_secret` (see that function's own doc comment for the full
/// five-step rationale): (1) best-effort watchdog disable before any
/// other work; (2) [`flow_pre::open_session_gop`] exactly once, with the
/// one surviving firmware-text-output refusal on failure; (3) the banner
/// through [`seed_flow::output::FbTextOutput`] over the session
/// framebuffer; (4) [`seed_flow::run_pre_secret_flow`] with
/// [`flow_pre::HeldGopGraphicsGate`]; (5) on handoff,
/// [`flow_secret::run_secret_phase`] over the SAME session framebuffer.
#[cfg(target_os = "uefi")]
fn run_pre_secret() {
    let mut watchdog = flow_pre::production_watchdog();
    let _ = watchdog.disable();

    let mut session = match flow_pre::open_session_gop() {
        Ok(session) => session,
        Err(reason) => {
            // No framebuffer exists yet -- the one surviving firmware-
            // text-output use on the normal boot path (see this
            // function's own doc comment).
            let _ = boot::uefi_backend::print_banner_to_stdout("GRAPHICS OUTPUT REFUSED");
            let _ = boot::uefi_backend::print_banner_to_stdout(reason);
            // Best-effort: hold the refusal on screen until the operator
            // acknowledges it, rather than returning to firmware
            // immediately. Many firmwares clear the text console the
            // instant a boot option returns control, which would
            // otherwise make this named SPEC §11.4 reason unreadable in
            // practice. Pre-framebuffer, pre-secret -- cannot violate any
            // gate ordering.
            uefi::system::with_stdin(|stdin| {
                use seed_platform_x86::input::KeySource as _;
                let _ = seed_platform_x86::input::uefi_backend::FirmwareKeySource::new(stdin).read_key_blocking();
            });
            return;
        }
    };

    uefi::system::with_stdin(|stdin| {
        // SPEC §26 amendment (2026-08-08): one pass = one full ceremony.
        // The test edition has no landing menu, so the operator's [M]
        // "wipe and return to the menu" choice (which the shared secret-
        // phase screens now offer) restarts the ceremony from the top —
        // re-running every §11 gate — rather than silently dropping to
        // firmware after the scrub. Every other exit still returns to
        // firmware. The GOP session and watchdog are opened once, above.
        'session: loop {
            let mut output = seed_flow::output::FbTextOutput::new(&mut session.fb);
            print_banner(&mut output);

            // STEP D dedup: `seed_flow::keys::MenuKeySource` has a
            // blanket impl for any real `seed_platform_x86::input::
            // KeySource`, so the real firmware keystroke reader needs no
            // second, edition-owned wrapper type.
            let mut keys = seed_platform_x86::input::uefi_backend::FirmwareKeySource::new(stdin);

            let mut platform_gate = flow_pre::ProdPlatformGate;
            let mut console_gate = flow_pre::ProdConsoleGate;
            let mut graphics_gate = flow_pre::HeldGopGraphicsGate::new(&session.gop, session.info);
            let mut crypto_gate = flow_pre::crypto_self_test_gate();
            // `PlatformInfoGate` and `MachineAvailabilityGate` both live
            // on `ProdPolicyGates`, but `seed_flow::Gates` needs two
            // independent `&mut dyn Trait` borrows; a second instance
            // (cheap: it only holds a `Copy` `Option<Policy>` plus the
            // `production_marker` fn pointer) avoids an aliased-mutable-
            // borrow conflict without any unsafe cell.
            let mut platform_info_gate = flow_pre::policy_gates();
            let mut machine_avail_gate = flow_pre::policy_gates();

            let mut gates = seed_flow::Gates {
                platform: &mut platform_gate,
                console: &mut console_gate,
                graphics: &mut graphics_gate,
                crypto: &mut crypto_gate,
                platform_info: &mut platform_info_gate,
                machine_availability: &mut machine_avail_gate,
                // SPEC.md §11.5 amendment (2026-08-04): this edition runs
                // on real UEFI firmware with the same hidden-re-entry
                // keyboard mechanics as production (only the entropy is
                // public/test), so it gets the same recommended-but-
                // skippable-with-acknowledgement treatment as production,
                // not the desktop rehearsal edition's plain optional
                // skip. See `seed_flow::keys::KeyboardSelfTestSkipPolicy`.
                keyboard_self_test_skip:
                    seed_flow::keys::KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
                // 2026-08-07 ceremony redesign (design doc §4 Stage 1 + §3.3):
                // the SPEC §4.1 immutable build identifier now lives
                // permanently in every ceremony screen's chrome header band,
                // so it survives the startup banner being cleared.
                build_id: BUILD_ID,
            };

            let result =
                seed_flow::run_pre_secret_flow(&mut output, &mut keys, &mut watchdog, &mut gates);

            // `output`/`keys` (and every WP-25 gate above) have no further
            // use past this point in either branch below, so their
            // borrows of `session.fb`/`stdin` end here -- freeing
            // `session.fb` for `flow_secret::run_secret_phase` to borrow
            // directly.
            let handoff = result.outcome == seed_flow::PreSecretOutcome::HandoffToSecretPhase;
            let machine = result.machine;
            // SPEC_DICE_COIN_VISUAL.md §22.5a: presentation-only instrument
            // sub-selection, threaded into the secret phase.
            let instrument = result.instrument;
            // SPEC_TPM_ENTROPY.md §11a: the §22.5b extras opt-ins, threaded
            // into the secret phase alongside the instrument.
            let extras = result.extras;
            // 2026-08-07 ceremony redesign: the SPEC §22.3 recap the Stage-3
            // Setup screen showed, so the secret phase can re-render that same
            // screen if the user backs into `AppState::SetupSelection`.
            let recap = result.recap;
            drop(gates);
            drop(keys);
            drop(output);

            if !handoff {
                // Pre-secret Back/Exit -- return to firmware (SPEC §27.1).
                return;
            }

            // WP-26 (`flow_secret`): SPEC §17.4 physical-entry screen onward,
            // driven by the still-live state machine `run_pre_secret_flow`
            // handed off. Takes the SAME session framebuffer -- no second GOP
            // open, no second `set_mode`. Every post-secret path is
            // non-returning (scrub-and-shutdown) EXCEPT the deliberate
            // menu-return.
            match flow_secret::run_secret_phase(
                machine,
                stdin,
                &mut session.fb,
                instrument,
                extras,
                BUILD_ID,
                recap,
            ) {
                // SPEC §26 amendment (2026-08-08): secrets already wiped —
                // restart the ceremony from the top.
                seed_flow::flow_secret::SecretFlowOutcome::DestroyedReturnToMenu => continue 'session,
                // The pre-secret refusal variants: end at firmware, as before.
                _ => return,
            }
        }
    });
}

#[cfg(not(target_os = "uefi"))]
fn run_pre_secret() {}

/// Print the pre-secret startup banner (the test-edition watermark
/// lines) through `output` -- the GOP framebuffer (SPEC.md amendment
/// 2026-08-06), never firmware text output, on the normal boot path.
#[cfg(target_os = "uefi")]
fn print_banner(output: &mut dyn seed_flow::output::TextOutput) {
    output.write_line(BANNER_LINE_1);
    output.write_line(BANNER_LINE_2);
}

/// Custom panic handler (SPEC §20.4).
///
/// MUST NOT emit any secret-bearing text — and does not: the message
/// carried by `PanicInfo` is deliberately never read or printed here,
/// only discarded, so no formatted panic payload (which could in
/// principle be built from a caller's data) ever reaches firmware
/// output.
///
/// Before halting, it performs the SPEC §20.4/§27.3 best-effort
/// whole-arena scrub of the one live [`seed_core::arena::SecretArena`]
/// the ceremony registered
/// ([`seed_core::arena::SecretArena::register_for_panic_scrub`], wired in
/// `seed_flow::firmware_wiring::run_secret_phase`). Under the workspace's
/// `panic = "abort"` profile this handler runs *before* the abort and
/// `Drop` is skipped, so this is the only remaining chance to zero a live
/// arena's resident secrets after a panic. (The test edition's entropy is
/// public/deterministic, but its arena residency and scrub discipline are
/// identical to production, so it wires the same panic scrub.)
///
/// Halts forever afterwards rather than returning to firmware or
/// unwinding, matching `panic = "abort"` semantics from the workspace
/// profile.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // SPEC §20.4/§27.3 best-effort panic-time scrub of the registered live
    // arena (mnemonic indexes, BIP39 seed, master key/chain code, committed
    // passphrase, ...). A no-op when nothing is registered (e.g. a panic
    // before the secret phase ever ran).
    //
    // SAFETY: a `#[panic_handler]` runs after everything else has stopped;
    // the registered pointer, if any, is still exactly the live arena
    // `run_secret_phase` registered and has not been moved or freed —
    // satisfying `panic_scrub_registered_arena`'s own safety contract.
    unsafe {
        seed_core::arena::SecretArena::panic_scrub_registered_arena();
    }
    boot::halt_forever()
}
