//! `seed-uefi-production` — the production UEFI edition (SPEC §4.1). The
//! only edition intended to generate an unwatermarked, funds-bearing
//! mnemonic.
//!
//! Owned entirely by WP-27 (SPEC §4.1-4.2, §28), which implements the
//! production/test split described in `IMPLEMENTATION_MAP.md`. This
//! crate reuses the same host-testable flow logic every edition shares
//! ([`seed_flow`], `crates/seed-flow/`, owned by WP-25/26) and
//! supplies its own thin real-firmware provider wiring
//! ([`flow_pre`]/[`flow_secret`], this crate's own files — see their doc
//! comments), differing from the test edition in exactly the ways SPEC
//! §4.1/§4.2 require:
//!
//! - No `seed-uefi-test`, `seed-desktop-test` or `seed-test-vectors`
//!   dependency anywhere in this crate's dependency graph, direct or
//!   transitive (SPEC §9, §28) — verify with `cargo tree
//!   -p seed-uefi-production --target x86_64-unknown-uefi` (`ci.sh`
//!   enforces this).
//! - No permanent watermark, no `"PUBLIC TEST PHRASE"` prefix, no `"test"`/
//!   `"demo"`/`"development"` wording anywhere (SPEC §4.1) — this crate's
//!   own source tree simply never defines any such text (a structural
//!   absence, not a runtime flag guarding a hardcoded `true`/`false`).
//! - Displays the SPEC §2 experimental-security-software banner plus the
//!   SPEC §4.1 release version and immutable build identifier
//!   ([`release`]) before any generation gate runs.
//! - Carries the SPEC §28 production policy marker for a future WP-30
//!   binary-policy scanner ([`markers`]).
//! - Refuses execution whenever a SPEC §11 mandatory check fails: this is
//!   inherited for free from [`seed_flow::run_pre_secret_flow`], which
//!   this binary drives with exactly the same `Gates` bundle the test
//!   edition uses — every one of the four mandatory gates
//!   (platform/virtualization, console topology, graphics, cryptographic
//!   self-test) already routes `Failed`/`Inconclusive` to
//!   `AppState::PreSecretError` and, on repeated failure or Escape, to
//!   `AppState::ExitToFirmware`, never past the gate. This crate adds no
//!   separate refusal logic of its own — see `seed-flow`'s own
//!   `diagnostics` module doc comment for the shared gate logic every
//!   edition relies on.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use seed_platform_x86::boot;
use uefi::prelude::*;

/// Production release identification and the SPEC §2 experimental-
/// security-software banner.
mod release;

/// SPEC_MAIN_MENU.md §17: the production landing launcher (pre-secret).
mod launcher;

/// SPEC §28 production policy markers for a future WP-30 binary-policy
/// scanner.
mod markers;

/// Pre-secret UI flow real-firmware wiring (opening warning,
/// acknowledgements, diagnostics, mode selection) — the production
/// edition's own provider implementations for [`seed_flow`]'s traits.
/// All testable logic lives in the `seed-flow` library crate
/// (`crates/seed-flow/`); see this module's own doc comment.
mod flow_pre;

/// Secret-phase UI flow real-firmware wiring (physical/machine entropy,
/// final confirmation, display, re-entry, derivation display, completion
/// education, scrub-and-shutdown) — the production edition's own
/// provider implementations for [`seed_flow::flow_secret`]'s traits. All
/// testable logic lives in the `seed-flow` library crate; see this
/// module's own doc comment.
mod flow_secret;

// Pre-wired so cross-compilation to `x86_64-unknown-uefi` works from day
// one (matching `IMPLEMENTATION_MAP.md` WP-00's original DoD for this
// crate). `seed_derive` is not referenced directly by name anywhere in
// this crate's own source (it is exercised through `seed_flow`'s own
// dependency on it and through `seed_core`'s pipeline internals); this
// keeps it present in `Cargo.toml` — as SPEC §31/§9 expect a production
// build to genuinely link the real derivation code, not merely reuse it
// transitively by accident — without an unused-import complaint.
#[allow(unused_imports)]
use seed_derive as _;

/// UEFI application entry point.
///
/// SPEC.md amendment (2026-08-06): the ENTIRE ceremony -- the SPEC §2
/// experimental-security-software banner, the SPEC §4.1 release
/// version/build identifier, every pre-secret screen and every
/// secret-phase screen -- now renders through the GOP linear framebuffer
/// via the application bitmap-font path
/// ([`seed_flow::output::FbTextOutput`]), not the firmware text console.
/// [`run_pre_secret`] does all of it: opens the session GOP once at
/// process start, prints the banner through it, then runs the shared
/// pre-secret flow ([`seed_flow::run_pre_secret_flow`]) and, on handoff,
/// the shared secret-phase flow
/// ([`seed_flow::flow_secret::run_secret_flow`]) through this crate's own
/// real-firmware provider wiring. Every mandatory-gate refusal and every
/// fatal path is handled inside those shared flows (see the crate doc
/// comment).
#[entry]
fn main() -> Status {
    run_pre_secret();

    Status::SUCCESS
}

/// Wire the real firmware providers and run the complete pre-secret flow
/// (SPEC §22.1-§22.5, §11, §8.4), handing off into the secret-phase flow
/// (SPEC §17.4 onward) on success. All the actual screen/branch logic
/// lives in `seed_flow::run_pre_secret_flow` / `seed_flow::flow_secret::
/// run_secret_flow`, both driven by the WP-23 state machine; this
/// function only constructs the real-firmware provider values
/// `flow_pre`/`flow_secret` define and hands them over — see
/// `crates/seed-uefi-test/src/main.rs`'s `run_pre_secret`, whose
/// structure this mirrors byte-for-byte (without depending on that
/// crate; see the crate doc comment).
///
/// # Ordering (SPEC.md amendment 2026-08-06)
///
/// 1. Best-effort watchdog disable, before any other work (SPEC §11.1:
///    "immediately after startup") -- best-effort only, since
///    [`seed_flow::run_pre_secret_flow`] performs the SPEC-authoritative
///    disable-and-refuse-on-failure immediately below, before its first
///    state-machine transition; a second `SetWatchdogTimer(0)` call is
///    idempotent.
/// 2. [`flow_pre::open_session_gop`] -- the GOP is opened exactly once
///    here, for the whole process. On failure, there is no framebuffer to
///    draw a refusal onto yet, so this is the ONE surviving firmware-
///    text-output use on the normal (non-refusal) boot path (SPEC
///    §12.1's amended scope).
/// 3. The SPEC §2/§4.1 banner renders through
///    [`seed_flow::output::FbTextOutput`] over the session framebuffer.
/// 4. [`seed_flow::run_pre_secret_flow`] runs with
///    [`flow_pre::HeldGopGraphicsGate`] as the SPEC §11.4 gate (re-checks
///    the already-held session mode rather than opening the GOP again).
/// 5. On handoff, [`flow_secret::run_secret_phase`] takes the SAME
///    session framebuffer -- never a second open, never a second
///    `set_mode`.
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
            // 2026-08-07 ceremony redesign (design doc §2 finding 5): every
            // ceremony screen now carries the SPEC §4.1 release version and
            // build identifier permanently in its chrome header band — but
            // THIS path never reaches a ceremony screen, because no
            // framebuffer exists to draw one on. So the pre-GOP refusal is
            // the one place that still has to state them itself; without
            // this, an operator whose machine refuses at the graphics gate
            // has no way to report which build refused.
            let _ = boot::uefi_backend::print_banner_to_stdout(release::RELEASE_VERSION);
            let _ = boot::uefi_backend::print_banner_to_stdout(release::BUILD_ID);
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
        {
            // Scoped so this banner-only `FbTextOutput`'s borrow of
            // `session.fb` ends before the landing launcher below, which
            // draws its own chrome directly on `session.fb` (Task 19:
            // launcher restyle -- `launcher::render_*` now take
            // `&mut dyn Framebuffer`, not a long-lived `TextOutput`).
            let mut banner_output = seed_flow::output::FbTextOutput::new(&mut session.fb);
            print_banner(&mut banner_output);
        }

        // SPEC §26 amendment (2026-08-08): one pass through this loop is
        // one full ceremony, from the landing menu to a terminal. The body
        // returns to firmware (`return`) on every exit EXCEPT when the
        // operator deliberately chose "wipe and return to the menu" at the
        // destroy/finish screen -- there `run_secret_phase` returns
        // `DestroyedReturnToMenu` (all secrets already scrubbed) and this
        // loop re-runs from the landing menu, re-running every mandatory
        // gate from the top so no gate is ever skipped on the second
        // ceremony. The GOP session and watchdog are opened once, outside
        // the loop -- no second `set_mode`.
        'session: loop {
            // STEP D dedup: `seed_flow::keys::MenuKeySource` has a
            // blanket impl for any real `seed_platform_x86::input::
            // KeySource`, so the real firmware keystroke reader needs no
            // second, edition-owned wrapper type. Re-borrowed from `stdin`
            // each pass (dropped before the secret phase reborrows it).
            let mut keys = seed_platform_x86::input::uefi_backend::FirmwareKeySource::new(stdin);

            // SPEC_MAIN_MENU.md §17: the production landing launcher. Strictly
            // pre-secret. Only `Generate` falls through into the unchanged SPEC
            // §11/§21/§22 flow below; `Exit`/Esc returns to firmware (§22.1);
            // the other items render and return to this menu. (Learn/Self-check/
            // About are wired to their real read-only screens; Verify chain-loads
            // the separate \EFI\ALEA\VERIFY.EFI via firmware, returning here on
            // its exit -- SPEC_MAIN_MENU.md §17.4.)
            let proceed_to_generate = loop {
                match launcher::read_landing_choice(&mut session.fb, &mut keys) {
                    launcher::LandingChoice::Generate => break true,
                    launcher::LandingChoice::Exit => break false,
                    launcher::LandingChoice::Verify => {
                        launcher::chain_load_verify(&mut session.fb, &mut keys)
                    }
                    launcher::LandingChoice::Learn => {
                        launcher::render_learn(&mut session.fb, &mut keys)
                    }
                    launcher::LandingChoice::SelfCheck => {
                        launcher::render_selfcheck(&mut session.fb, &mut keys)
                    }
                    launcher::LandingChoice::About => {
                        launcher::render_about(&mut session.fb, &mut keys)
                    }
                }
            };
            if !proceed_to_generate {
                // Exit to firmware -- pre-secret, before any mandatory gate has
                // run (SPEC §22.1: "Exit before generation" is always legal).
                return;
            }

            let mut output = seed_flow::output::FbTextOutput::new(&mut session.fb);

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
                // SPEC.md §11.5 amendment (2026-08-04): production UEFI
                // edition -- the keyboard self-test is offered by default
                // and recommended, skippable only via an explicit
                // acknowledgement of the hidden-re-entry consequence. See
                // `seed_flow::keys::KeyboardSelfTestSkipPolicy`.
                keyboard_self_test_skip:
                    seed_flow::keys::KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
                // 2026-08-07 ceremony redesign (design doc §3.3/§4 Stage 1):
                // the SPEC §4.1 immutable build identifier now lives
                // permanently in every ceremony screen's chrome header band,
                // so [`print_banner`]'s transient copy is no longer the only
                // in-ceremony source of it (design doc §2 finding 5).
                build_id: release::BUILD_ID,
            };

            let result =
                seed_flow::run_pre_secret_flow(&mut output, &mut keys, &mut watchdog, &mut gates);

            // `output`/`keys` (and every gate above) have no further use
            // past this point in either branch below, so their borrows of
            // `session.fb`/`stdin` end here -- freeing `session.fb` for
            // `flow_secret::run_secret_phase` to borrow directly.
            let handoff = result.outcome == seed_flow::PreSecretOutcome::HandoffToSecretPhase;
            let machine = result.machine;
            // SPEC_DICE_COIN_VISUAL.md §22.5a: presentation-only instrument
            // sub-selection, threaded into the secret phase.
            let instrument = result.instrument;
            // 2026-08-07 ceremony redesign: the SPEC §22.3 recap the Stage-3
            // Setup screen showed, so the secret phase can re-render that same
            // screen if the user backs into `AppState::SetupSelection`.
            let recap = result.recap;
            drop(gates);
            drop(keys);
            drop(output);

            if !handoff {
                // Pre-secret Back/Exit out of the gate flow -- return to
                // firmware (SPEC §27.1). Restarting re-runs every gate.
                return;
            }

            // SPEC §17.4 physical-entry screen onward, driven by the
            // still-live state machine `run_pre_secret_flow` handed off.
            // Takes the SAME session framebuffer -- no second GOP open, no
            // second `set_mode`. Every post-secret path is non-returning
            // (scrub-and-shutdown) EXCEPT the deliberate menu-return.
            match flow_secret::run_secret_phase(
                machine,
                stdin,
                &mut session.fb,
                instrument,
                release::BUILD_ID,
                recap,
            ) {
                // SPEC §26 amendment (2026-08-08): secrets already wiped
                // (scrub-and-return ran inside the secret phase) -- start a
                // fresh ceremony from the landing menu.
                seed_flow::flow_secret::SecretFlowOutcome::DestroyedReturnToMenu => continue 'session,
                // The two pre-secret refusal variants `run_secret_phase`
                // documents: end the session at firmware, exactly as before.
                _ => return,
            }
        }
    });
}

#[cfg(not(target_os = "uefi"))]
fn run_pre_secret() {}

/// Print the pre-secret startup banner (SPEC §2 experimental-security-
/// software notice, then the SPEC §4.1 release version and immutable
/// build identifier) through `output` -- the GOP framebuffer (SPEC.md
/// amendment 2026-08-06), never firmware text output, on the normal boot
/// path.
///
/// # Why this survives the 2026-08-07 ceremony redesign
///
/// Design doc §2 finding 5 was that this banner (and with it the build
/// identifier) was cleared before any key could be read. That is fixed
/// elsewhere and permanently: the launcher's `[5] About` exposes
/// `release::BUILD_ID` durably, and every redesigned ceremony screen draws
/// it in its `seed_flow::chrome` header band, so the transient banner is
/// no longer the only in-ceremony source of it. What this function still
/// does is state the SPEC §2 experimental-security-software notice once at
/// startup, before the landing launcher — a display SPEC §2 requires and
/// the chrome header has no room for. It is kept, unchanged, for that.
/// (The genuinely irreplaceable case is the pre-GOP refusal path in
/// [`run_pre_secret`], which reaches no chrome header at all and therefore
/// prints the version/build identifier itself.)
#[cfg(target_os = "uefi")]
fn print_banner(output: &mut dyn seed_flow::output::TextOutput) {
    output.write_line(release::EXPERIMENTAL_BANNER_TITLE);
    // Word-wrap the banner body: on the GOP framebuffer a single over-long
    // line clips at the right edge (the firmware text console used to wrap
    // it). PROSE_WRAP_COLS matches every other wrapped pre-secret prose line.
    for line in seed_flow::text::wrap_words(release::EXPERIMENTAL_BANNER_BODY, seed_flow::text::PROSE_WRAP_COLS) {
        output.write_line(line);
    }
    output.write_line("");
    output.write_line(release::RELEASE_VERSION);
    output.write_line(release::BUILD_ID);
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
/// arena's resident secrets after a panic — without it, a panic while a
/// funds-bearing mnemonic/seed/passphrase is resident would leave those
/// bytes in memory for as long as the machine stayed powered.
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
