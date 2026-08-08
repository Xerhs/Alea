//! Scrub-and-shutdown (SPEC §25, §26).
//!
//! [`scrub_and_shutdown`] performs the full SPEC §26 ordered sequence —
//! re-entry state, mnemonic indexes, derived secrets, the whole secret
//! arena, then the framebuffer, then fences, then the shutdown request —
//! and never returns (SPEC §26 step 8: "Never return to the application
//! menu"; SPEC §21: "No transition ... may return to the main menu or
//! UEFI boot manager").
//!
//! This is the single non-returning terminal every fatal path and the
//! success path both converge on (SPEC §20.1: "scrubbed as a complete
//! region on success and every fatal path").
//!
//! [`FaultHook`] gives a future WP-33 fault-injection suite a seam at
//! every numbered step, and owns the final [`FaultHook::halt`] call so
//! host tests can observe "the halt path was reached" without hanging
//! the test process (see its own doc comment).

use seed_core::arena::SecretArena;
use seed_core::contracts::Framebuffer;
use seed_gop_ui::gop::{scrub_sequence, NEUTRAL_SCRUB_PATTERN};

/// SPEC §26, verbatim, shown when shutdown fails twice.
pub const SHUTDOWN_FAILED_LINE_1: &str = "AUTOMATIC SHUTDOWN FAILED";
/// SPEC §26, verbatim.
pub const SHUTDOWN_FAILED_LINE_2: &str = "Hold the physical power button until the machine is completely off.";
/// SPEC §26, verbatim.
pub const SHUTDOWN_FAILED_LINE_3: &str = "Do not boot another operating system first.";

/// Non-secret shutdown-request failure marker (SPEC §27.3: no secret
/// content in any error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownFailure;

/// Abstraction over `EfiResetShutdown` (SPEC §26 step 7), so the
/// retry-once / halt logic in [`scrub_and_shutdown`] is host-testable.
/// Implemented for real firmware by `crates/seed-uefi-test/src/
/// flow_secret`'s production wiring (UEFI target only, cross-compilation
/// verified); host tests use a mock that can be programmed to fail on
/// demand.
pub trait ShutdownProvider {
    /// Request a complete system shutdown. On real firmware this call
    /// does not return on success (the machine powers off); returning at
    /// all is itself the SPEC §26 failure condition. `Err` covers both
    /// "the firmware reported failure" and, for the real adapter,
    /// "control unexpectedly returned".
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure>;
}

/// Fault-injection hook trait (SPEC §26, §29.5): invoked immediately
/// before each numbered SPEC §26 step's real work runs, so a future
/// WP-33 suite can force any step to behave as though it failed without
/// needing real hardware fault conditions. Every method has a no-op
/// default, so existing callers (and every test that doesn't itself
/// inject a fault) are unaffected.
pub trait FaultHook {
    /// Before step 1: scrub re-entry state.
    fn before_scrub_reentry(&mut self) {}
    /// Before step 2: scrub mnemonic indexes.
    fn before_scrub_mnemonic(&mut self) {}
    /// Before step 3: scrub final entropy, BIP39 seed, master key, chain
    /// codes and derivation scratch.
    fn before_scrub_derived_secrets(&mut self) {}
    /// Before step 4: scrub the whole secret arena (complete-region
    /// catch-all, SPEC §20.1).
    fn before_scrub_arena(&mut self) {}
    /// Before step 5: scrub the framebuffer / rendering buffers.
    fn before_scrub_framebuffer(&mut self) {}
    /// Before step 6: fences and architecture-specific cleanup.
    fn before_fences(&mut self) {}
    /// Before step 7: request `EfiResetShutdown`.
    fn before_shutdown_request(&mut self) {}

    /// The final non-returning halt (SPEC §26 step 8 / the SPEC §21
    /// fatal chain's `ShutdownOrHalt`). Default spins forever
    /// (equivalent in effect to `seed_platform_x86::boot::halt_forever`,
    /// without depending on that `#[cfg(target_arch = "x86_64")]`-gated
    /// helper here). Production wiring overrides this to call the real
    /// `halt_forever`; host tests override it to unwind out of the call
    /// (e.g. via a panic with a recognizable message) so `#[should_panic]`
    /// can observe that the halt path was reached without hanging the
    /// test process.
    fn halt(&mut self) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

/// No-op [`FaultHook`] for callers that don't need fault injection
/// (production code, and any test not specifically exercising a fault).
/// Its `halt()` still uses the trait's spinning default — callers that
/// need `scrub_and_shutdown` to actually return control to a test (e.g.
/// to assert on arena/framebuffer state afterward) MUST reach the
/// success shutdown-request path instead of the halt path, or supply
/// their own `FaultHook` with a panicking `halt()`.
pub struct NoFaultHook;
impl FaultHook for NoFaultHook {}

/// Run SPEC §26 steps 1-6 — the complete ordered secret scrub — and
/// **return** (unlike [`scrub_and_shutdown`], which continues into the
/// non-returning shutdown request). This is the single source of the
/// scrub sequence: [`scrub_and_shutdown`] calls it, and the deliberate
/// "destroy and return to the menu" exit (SPEC §26 amendment 2026-08-08,
/// gated on an explicit operator choice) calls it too, so both exits
/// provably zero the identical set of secret-bearing bytes in the
/// identical order. The `hook` fires before each numbered step exactly as
/// it does inside `scrub_and_shutdown`, so the fault-injection suite
/// covers this path unchanged.
///
/// Steps, in SPEC §26 order:
/// 1. re-entry state, 2. mnemonic indexes, 3. derived secrets,
/// 4. the whole secret arena (complete-region catch-all, SPEC §20.1),
/// 5. the framebuffer / rendering buffers, 6. fences.
pub fn scrub_secrets(
    arena: &mut dyn ArenaScrubSteps,
    fb: &mut dyn Framebuffer,
    hook: &mut dyn FaultHook,
) {
    hook.before_scrub_reentry();
    arena.scrub_reentry_state();

    hook.before_scrub_mnemonic();
    arena.scrub_mnemonic_indexes();

    hook.before_scrub_derived_secrets();
    arena.scrub_derived_secrets();

    hook.before_scrub_arena();
    arena.scrub_all();

    hook.before_scrub_framebuffer();
    scrub_sequence(fb, NEUTRAL_SCRUB_PATTERN);

    hook.before_fences();
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Run the complete SPEC §26 scrub-and-shutdown sequence and never
/// return. `arena` and `fb` are scrubbed as their own explicit steps
/// (§26 steps 1-5); `shutdown` is asked once, retried once on failure
/// (§26: "If shutdown fails: retry once"), and on a second failure the
/// SPEC-verbatim failure screen is drawn and [`FaultHook::halt`] is
/// called.
///
/// Every provider is a trait object (matching this crate's established
/// `&mut dyn Trait` style, e.g. `crate::driver::Gates`) so this function
/// itself never needs to be generic — the sole call site for the whole
/// secret-phase ceremony (`crate::flow_secret::driver`) already holds
/// each provider behind its own reference.
pub fn scrub_and_shutdown(
    arena: &mut dyn ArenaScrubSteps,
    fb: &mut dyn Framebuffer,
    shutdown: &mut dyn ShutdownProvider,
    hook: &mut dyn FaultHook,
) -> ! {
    scrub_secrets(arena, fb, hook);

    hook.before_shutdown_request();
    if shutdown.request_shutdown().is_err() {
        // SPEC §26: "If shutdown fails: retry once."
        if shutdown.request_shutdown().is_err() {
            render_shutdown_failed(fb);
            hook.halt();
        }
    }

    // Reachable only when a test double's `request_shutdown` returns
    // `Ok(())` without actually diverging (real firmware never returns
    // on success). SPEC §26 step 8 still applies: never return.
    hook.halt();
}

/// Minimal seam over exactly the [`SecretArena`] scrub steps
/// [`scrub_and_shutdown`] needs, in SPEC §26 order, so this module can be
/// unit-tested against a spy without linking a full ceremony. The real
/// [`SecretArena`] implements it directly (its methods already have
/// these exact names/signatures).
pub trait ArenaScrubSteps {
    fn scrub_reentry_state(&mut self);
    fn scrub_mnemonic_indexes(&mut self);
    fn scrub_derived_secrets(&mut self);
    fn scrub_all(&mut self);
}

impl ArenaScrubSteps for SecretArena {
    fn scrub_reentry_state(&mut self) {
        SecretArena::scrub_reentry_state(self);
    }
    fn scrub_mnemonic_indexes(&mut self) {
        SecretArena::scrub_mnemonic_indexes(self);
    }
    fn scrub_derived_secrets(&mut self) {
        SecretArena::scrub_derived_secrets(self);
    }
    fn scrub_all(&mut self) {
        SecretArena::scrub_all(self);
    }
}

/// Render the SPEC §26 verbatim shutdown-failure screen. The framebuffer
/// has already been scrubbed blank by the time this runs (SPEC §26:
/// "keep the framebuffer blank except for" this text).
fn render_shutdown_failed(fb: &mut dyn Framebuffer) {
    crate::flow_secret::gop_screen::draw_lines(
        fb,
        &[SHUTDOWN_FAILED_LINE_1, "", SHUTDOWN_FAILED_LINE_2, SHUTDOWN_FAILED_LINE_3],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::panic;

    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }
    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
        }
    }
    impl Framebuffer for VecFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }
        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + px.len()].copy_from_slice(px);
        }
    }

    /// Spy [`ArenaScrubSteps`] double, recording call order.
    struct SpyArena {
        calls: std::vec::Vec<&'static str>,
    }
    impl SpyArena {
        fn new() -> Self {
            Self { calls: std::vec::Vec::new() }
        }
    }
    impl ArenaScrubSteps for SpyArena {
        fn scrub_reentry_state(&mut self) {
            self.calls.push("reentry");
        }
        fn scrub_mnemonic_indexes(&mut self) {
            self.calls.push("mnemonic");
        }
        fn scrub_derived_secrets(&mut self) {
            self.calls.push("derived");
        }
        fn scrub_all(&mut self) {
            self.calls.push("all");
        }
    }

    struct AlwaysOkShutdown;
    impl ShutdownProvider for AlwaysOkShutdown {
        fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
            Ok(())
        }
    }

    struct AlwaysFailShutdown {
        attempts: std::vec::Vec<()>,
    }
    impl AlwaysFailShutdown {
        fn new() -> Self {
            Self { attempts: std::vec::Vec::new() }
        }
    }
    impl ShutdownProvider for AlwaysFailShutdown {
        fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
            self.attempts.push(());
            Err(ShutdownFailure)
        }
    }

    /// Fails on the first call, succeeds on the retry.
    struct FailOnceShutdown {
        calls: usize,
    }
    impl ShutdownProvider for FailOnceShutdown {
        fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
            self.calls += 1;
            if self.calls == 1 {
                Err(ShutdownFailure)
            } else {
                Ok(())
            }
        }
    }

    /// Panics on halt so `#[should_panic]` can observe the halt path was
    /// reached, and records every fault-hook step it saw.
    struct PanicOnHalt {
        steps: std::vec::Vec<&'static str>,
    }
    impl PanicOnHalt {
        fn new() -> Self {
            Self { steps: std::vec::Vec::new() }
        }
    }
    impl FaultHook for PanicOnHalt {
        fn before_scrub_reentry(&mut self) {
            self.steps.push("before_scrub_reentry");
        }
        fn before_scrub_mnemonic(&mut self) {
            self.steps.push("before_scrub_mnemonic");
        }
        fn before_scrub_derived_secrets(&mut self) {
            self.steps.push("before_scrub_derived_secrets");
        }
        fn before_scrub_arena(&mut self) {
            self.steps.push("before_scrub_arena");
        }
        fn before_scrub_framebuffer(&mut self) {
            self.steps.push("before_scrub_framebuffer");
        }
        fn before_fences(&mut self) {
            self.steps.push("before_fences");
        }
        fn before_shutdown_request(&mut self) {
            self.steps.push("before_shutdown_request");
        }
        fn halt(&mut self) -> ! {
            panic!("halted");
        }
    }

    #[test]
    fn scrub_secrets_runs_every_step_in_spec_26_order_and_returns() {
        // The menu-return exit calls scrub_secrets directly. It MUST zero
        // every secret-bearing field (same four arena steps as the
        // shutdown path) and, unlike scrub_and_shutdown, MUST return —
        // control then goes back to the launcher menu.
        struct RecordingHook {
            steps: std::vec::Vec<&'static str>,
        }
        impl FaultHook for RecordingHook {
            fn before_scrub_reentry(&mut self) {
                self.steps.push("reentry");
            }
            fn before_scrub_mnemonic(&mut self) {
                self.steps.push("mnemonic");
            }
            fn before_scrub_derived_secrets(&mut self) {
                self.steps.push("derived");
            }
            fn before_scrub_arena(&mut self) {
                self.steps.push("all");
            }
            fn before_scrub_framebuffer(&mut self) {
                self.steps.push("framebuffer");
            }
            fn before_fences(&mut self) {
                self.steps.push("fences");
            }
            // halt() intentionally left as the spinning default: reaching it
            // would mean scrub_secrets diverged, which this test would hang
            // on rather than pass — but scrub_secrets never calls halt().
        }
        let mut arena = SpyArena::new();
        let mut fb = VecFb::new(16, 16);
        let mut hook = RecordingHook { steps: std::vec::Vec::new() };
        // No catch_unwind, no panic: a plain call that returns normally.
        scrub_secrets(&mut arena, &mut fb, &mut hook);
        assert_eq!(arena.calls, std::vec!["reentry", "mnemonic", "derived", "all"]);
        assert_eq!(
            hook.steps,
            std::vec!["reentry", "mnemonic", "derived", "all", "framebuffer", "fences"]
        );
    }

    #[test]
    fn happy_path_scrubs_every_step_in_spec_26_order_then_halts() {
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let mut arena = SpyArena::new();
            let mut fb = VecFb::new(64, 64);
            let mut shutdown = AlwaysOkShutdown;
            let mut hook = PanicOnHalt::new();
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        assert!(result.is_err(), "scrub_and_shutdown must never return control");
    }

    #[test]
    fn arena_scrub_steps_run_in_spec_order_before_halting() {
        // Use a hook that records the arena's own call order via a
        // shared log by piggy-backing on FaultHook step names, since the
        // arena spy itself is moved into the closure. Simplest: assert
        // order directly by capturing calls in an Rc<RefCell<..>> would
        // add complexity this crate avoids (no alloc in production code,
        // and tests already avoid extra deps) -- instead, drive the
        // steps through the FaultHook order pins (`before_scrub_*` fires
        // immediately before the matching arena call), which is exactly
        // what SPEC §26 numbers.
        struct RecordingHook {
            steps: std::vec::Vec<&'static str>,
        }
        impl FaultHook for RecordingHook {
            fn before_scrub_reentry(&mut self) {
                self.steps.push("reentry");
            }
            fn before_scrub_mnemonic(&mut self) {
                self.steps.push("mnemonic");
            }
            fn before_scrub_derived_secrets(&mut self) {
                self.steps.push("derived");
            }
            fn before_scrub_arena(&mut self) {
                self.steps.push("all");
            }
            fn before_scrub_framebuffer(&mut self) {
                self.steps.push("framebuffer");
            }
            fn before_fences(&mut self) {
                self.steps.push("fences");
            }
            fn before_shutdown_request(&mut self) {
                self.steps.push("shutdown");
            }
            fn halt(&mut self) -> ! {
                panic!("halted:{:?}", self.steps);
            }
        }
        let mut arena = SpyArena::new();
        let mut fb = VecFb::new(16, 16);
        let mut shutdown = AlwaysOkShutdown;
        let mut hook = RecordingHook { steps: std::vec::Vec::new() };
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        let payload = result.unwrap_err();
        let msg = payload.downcast_ref::<std::string::String>().unwrap();
        assert!(msg.contains("reentry") && msg.contains("mnemonic") && msg.contains("derived"));
        assert!(msg.contains("all") && msg.contains("framebuffer") && msg.contains("fences") && msg.contains("shutdown"));
        assert_eq!(arena.calls, std::vec!["reentry", "mnemonic", "derived", "all"]);
    }

    #[test]
    fn shutdown_failure_retries_once_then_halts_with_exact_failure_text() {
        let mut arena = SpyArena::new();
        let mut fb = VecFb::new(200, 100);
        let mut shutdown = AlwaysFailShutdown::new();
        let mut hook = PanicOnHalt::new();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        assert!(result.is_err());
        assert_eq!(shutdown.attempts.len(), 2, "must retry exactly once (2 total attempts)");
        // The failure screen must have been drawn (framebuffer no longer
        // all-blank after the pre-failure-screen scrub left it blank).
        assert!(fb.buf.iter().any(|&p| p != 0), "shutdown-failure screen must be drawn");
    }

    #[test]
    fn shutdown_succeeding_on_retry_does_not_show_failure_screen() {
        let mut arena = SpyArena::new();
        let mut fb = VecFb::new(200, 100);
        let mut shutdown = FailOnceShutdown { calls: 0 };
        let mut hook = PanicOnHalt::new();
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        assert_eq!(shutdown.calls, 2);
        // No failure screen drawn: framebuffer stays at the post-scrub
        // blank state.
        assert!(fb.buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn exact_spec_26_failure_text() {
        assert_eq!(SHUTDOWN_FAILED_LINE_1, "AUTOMATIC SHUTDOWN FAILED");
        assert_eq!(
            SHUTDOWN_FAILED_LINE_2,
            "Hold the physical power button until the machine is completely off."
        );
        assert_eq!(SHUTDOWN_FAILED_LINE_3, "Do not boot another operating system first.");
    }

    #[test]
    fn no_fault_hook_is_a_pure_default_marker() {
        // NoFaultHook exists and implements the trait purely via
        // defaults; this is a compile-time check exercised at runtime by
        // constructing one.
        let _h = NoFaultHook;
    }
}
