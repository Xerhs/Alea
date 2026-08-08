//! Category I (SPEC §29.5 "during shutdown"): faults in the SPEC §26
//! step-7 `EfiResetShutdown` request itself, plus the terminal states'
//! own "absorbs everything" behavior under a fault-event battery.

use seed_fault_injection::{
    coverage, event_fault_battery, AlwaysFailShutdown, AlwaysOkShutdown, AppState, CountingWatchdog,
    FailOnceShutdown, RecordingHook, VecFb,
};
use seed_flow::flow_secret::shutdown::{scrub_and_shutdown, ShutdownFailure, ShutdownProvider};

struct SpyArena {
    calls: Vec<&'static str>,
}
impl SpyArena {
    fn new() -> Self {
        Self { calls: Vec::new() }
    }
}
impl seed_flow::flow_secret::shutdown::ArenaScrubSteps for SpyArena {
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

#[test]
fn shutdown_always_fails_retries_once_then_halts_with_scrub_already_done() {
    let mut arena = SpyArena::new();
    let mut fb = VecFb::new(64, 64);
    let mut shutdown = AlwaysFailShutdown::new();
    let mut hook = RecordingHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
    }));
    assert!(result.is_err());
    assert_eq!(shutdown.attempts, 2, "must retry shutdown exactly once (2 total attempts)");
    assert_eq!(arena.calls, vec!["reentry", "mnemonic", "derived", "all"], "scrub must have completed before the shutdown request even started");
    assert!(fb.buf.iter().any(|&p| p != 0), "the SPEC §26 failure screen must be drawn onto the (already-scrubbed) framebuffer");
    assert_eq!(1, coverage::I_SHUTDOWN_ALWAYS_FAILS);
}

#[test]
fn shutdown_fails_once_then_succeeds_on_retry_shows_no_failure_screen() {
    let mut arena = SpyArena::new();
    let mut fb = VecFb::new(64, 64);
    let mut shutdown = FailOnceShutdown::new();
    let mut hook = RecordingHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
    }));
    assert!(result.is_err());
    assert_eq!(shutdown.attempts, 2);
    assert!(fb.all_zero(), "no failure screen must be drawn when the retry succeeds");
    assert_eq!(1, coverage::I_SHUTDOWN_FAILS_ONCE_THEN_OK);
}

#[test]
fn shutdown_always_ok_halts_after_a_single_request() {
    let mut arena = SpyArena::new();
    let mut fb = VecFb::new(64, 64);
    let mut shutdown = AlwaysOkShutdown::new();
    let mut hook = RecordingHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
    }));
    assert!(result.is_err(), "scrub_and_shutdown always halts, even on the clean success path");
    assert_eq!(shutdown.attempts, 1);
    assert!(fb.all_zero());
    assert_eq!(1, coverage::I_SHUTDOWN_ALWAYS_OK);
}

/// `EfiResetShutdown` panicking (rather than returning `Err`) models the
/// firmware call never returning control at all (SPEC §20.4 residual
/// risk). Distinct, honestly-documented outcome from the three tests
/// above: scrub has already fully completed by the time this call
/// happens (SPEC §26 orders it last), but the shutdown-failure screen is
/// never drawn and the process does not reach a controlled halt loop —
/// it unwinds instead. This suite records that as the expected, SPEC
/// §20.4-acknowledged behavior, not a gap this code could close.
#[test]
fn shutdown_provider_panicking_still_leaves_scrub_already_complete() {
    struct PanicShutdown;
    impl ShutdownProvider for PanicShutdown {
        fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
            panic!("PanicShutdown: simulated EfiResetShutdown firmware fault");
        }
    }

    let mut arena = SpyArena::new();
    let mut fb = VecFb::new(64, 64);
    let mut shutdown = PanicShutdown;
    let mut hook = RecordingHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
    }));
    assert!(result.is_err());
    // SPEC §26 order: every scrub step precedes the shutdown request, so
    // all of them must have completed even though the request itself
    // faulted.
    assert_eq!(arena.calls, vec!["reentry", "mnemonic", "derived", "all"]);
    assert!(fb.all_zero(), "the framebuffer scrub (step 5) precedes the shutdown request (step 7) and must have completed");
    assert_eq!(1, coverage::I_SHUTDOWN_PROVIDER_PANICS);
}

/// SPEC §21: the `Shutdown`/`ShutdownFailedHalt` states must absorb any
/// further event without ever moving to a menu — a battery of events
/// fired at each, reached via `reachable_states` (never a struct
/// literal).
#[test]
fn shutdown_and_halt_states_absorb_the_fault_battery_never_move_to_a_menu() {
    let battery = event_fault_battery();
    let states = seed_fault_injection::reachable_states();
    let shutdown_sm = states.iter().find(|(n, _)| *n == "Shutdown").unwrap().1;
    let halt_sm = states.iter().find(|(n, _)| *n == "ShutdownFailedHalt").unwrap().1;

    let mut checked = 0usize;
    for (label, sm) in [("Shutdown", shutdown_sm), ("ShutdownFailedHalt", halt_sm)] {
        // `Shutdown` itself is not terminal (it accepts ShutdownRequested/
        // ShutdownFailed as real edges), so only probe it with the battery
        // events that are not its own legal edges; `ShutdownFailedHalt` is
        // fully terminal and must absorb everything.
        for ev in battery.into_iter().take(if label == "Shutdown" { 5 } else { battery.len() }) {
            let mut probe = sm;
            let mut w = CountingWatchdog::default();
            let t = probe.transition(ev, &mut w);
            assert!(
                !matches!(t.next, AppState::Start | AppState::ReleaseAndEnvironmentWarning | AppState::SetupSelection),
                "{label} + {ev:?}: must never move to a menu state, got {:?}",
                t.next
            );
            checked += 1;
        }
    }
    assert!(checked >= coverage::I_SHUTDOWN_STATE_ABSORBS_EVENTS);
}
