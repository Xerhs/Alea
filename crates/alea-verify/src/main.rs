//! `alea-verify` — the standalone cross-device VERIFICATION UEFI binary
//! (SPEC_MAIN_MENU.md §17.4 landing item 2; SPEC_COMPAT.md /
//! SPEC_COMPAT_ENTROPY.md).
//!
//! # Why this is a separate binary (SPEC_COMPAT §9, Option B slice 5)
//!
//! The production UEFI edition (`seed-uefi-production`) MUST NEVER link
//! `seed-compat`: the cross-device verification code reproduces *foreign*
//! wallets' preimage math over unwitnessed/typed symbols, so it must be
//! impossible for that construction to appear in the one edition that mints
//! funds-bearing seeds. The authoritative isolation is the dependency graph
//! (`cargo tree -p seed-uefi-production` shows no `seed-compat`), and the
//! way this slice preserves it while still shipping the feature is to put
//! the whole verification surface in THIS binary, which the production
//! landing launcher chain-loads (item 2) rather than links.
//!
//! # Boot/GOP/key wiring — copied from `seed-uefi-production`
//!
//! This mirrors `crates/seed-uefi-production/src/main.rs`'s
//! `run_pre_secret` shape exactly (SPEC.md amendment 2026-08-06): best-
//! effort watchdog disable, open the GOP session once at process start
//! ([`seed_flow::firmware_wiring::open_session_gop`]), render everything
//! through [`seed_flow::output::FbTextOutput`] over that framebuffer, read
//! keystrokes through
//! `seed_platform_x86::input::uefi_backend::FirmwareKeySource`. Input is
//! number-key + Esc only (SPEC_MAIN_MENU.md §17.2) — no arrows.
//!
//! Unlike production this crate has NO secret phase: it only ever operates
//! on declared-public/throwaway reproduced seeds (SPEC_COMPAT §7/§8), so
//! there is no `SecretArena` to register/scrub and the panic handler simply
//! halts.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use seed_platform_x86::boot;
use uefi::prelude::*;

// The screen-rendering/dispatch logic (`verify`, `custom_path`, `markers`)
// lives in this crate's OWN library target (`src/lib.rs`) instead of a
// `mod` here, so it is exercised by `cargo test -p alea-verify` on the host
// (Task 19 review fix) -- see `lib.rs`'s doc comment for why `#![no_std]
// #![no_main]` binary code itself cannot be host-tested. This file keeps
// only the UEFI-only `#[entry]`/`#[panic_handler]` wiring.
use alea_verify::verify;

/// UEFI application entry point.
#[entry]
fn main() -> Status {
    run_verify();
    Status::SUCCESS
}

/// Wire the real firmware providers and run the verification flow. Mirrors
/// `seed-uefi-production`'s `run_pre_secret` boot sequence (SPEC.md
/// amendment 2026-08-06); see that function's own doc comment for the
/// ordering rationale.
#[cfg(target_os = "uefi")]
fn run_verify() {
    // Best-effort watchdog disable: a user typing 50-256 dice/coin events
    // can easily exceed the firmware's default 5-minute watchdog, which
    // would otherwise reset the machine mid-entry (the same real-hardware
    // hazard the secret ceremony fixed). No secret exists here, so this is
    // purely a usability fix.
    let mut watchdog = seed_flow::firmware_wiring::production_watchdog();
    let _ = watchdog.disable();

    // Open the GOP exactly once for the whole process (SPEC §11.4, §12.1).
    // On failure there is no framebuffer to draw a refusal onto yet, so
    // this is the one surviving firmware-text-output use on the normal
    // path — mirrors `seed-uefi-production`'s own pre-framebuffer refusal.
    let mut session = match seed_flow::firmware_wiring::open_session_gop() {
        Ok(session) => session,
        Err(reason) => {
            let _ = boot::uefi_backend::print_banner_to_stdout("ALEA VERIFY -- GRAPHICS OUTPUT REFUSED");
            let _ = boot::uefi_backend::print_banner_to_stdout(reason);
            uefi::system::with_stdin(|stdin| {
                use seed_platform_x86::input::KeySource as _;
                let _ = seed_platform_x86::input::uefi_backend::FirmwareKeySource::new(stdin)
                    .read_key_blocking();
            });
            return;
        }
    };

    uefi::system::with_stdin(|stdin| {
        use seed_platform_x86::input::KeySource as _;
        let mut output = seed_flow::output::FbTextOutput::new(&mut session.fb);
        let mut keys =
            seed_platform_x86::input::uefi_backend::FirmwareKeySource::new(stdin);

        // Run the whole verification flow. Returns when the user backs all
        // the way out of the profile menu with Esc (SPEC_MAIN_MENU.md
        // §17.2), at which point `main` returns `Status::SUCCESS` and
        // control goes back to whatever loaded this image (the production
        // launcher's chain-load, or the firmware boot manager).
        verify::run_over(&mut output, || keys.read_key_blocking());
    });
}

#[cfg(not(target_os = "uefi"))]
fn run_verify() {}

/// Custom panic handler (SPEC §20.4). This binary holds no secret arena
/// (verification-only, public/throwaway reproduced seeds), so — unlike
/// `seed-uefi-production`'s handler — there is nothing to scrub; it simply
/// halts forever under the workspace `panic = "abort"` profile.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    boot::halt_forever()
}
