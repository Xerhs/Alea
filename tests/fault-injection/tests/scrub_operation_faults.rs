//! Category H (SPEC §29.5 "during scrub operations"): drives
//! `seed_flow::flow_secret::shutdown::scrub_and_shutdown` (the single
//! non-returning terminal every fatal path and the success path converge
//! on, SPEC §26) with a fault injected at each of its numbered steps in
//! turn, two different ways:
//!
//! 1. A [`RecordingHook`] whose `before_*` method panics — simulating a
//!    hardware/platform fault occurring *before* that step's real work
//!    runs.
//! 2. A [`SpyArena`] whose scrub method itself panics — simulating a
//!    fault occurring *during* that step's real work.
//!
//! Both document, for each fault point, exactly how much of the ordered
//! SPEC §26 scrub sequence had already completed before the interruption
//! — this is the SPEC §20.4 residual-risk boundary made concrete and
//! measured, not papered over: a fault that prevents application code
//! from continuing to run at all cannot be guaranteed to have scrubbed
//! everything, and these tests pin exactly where that boundary falls for
//! each of the 11 fault points.

use seed_fault_injection::{coverage, RecordingHook, SpyArena, VecFb, ALL_SCRUB_STEPS};
use seed_flow::flow_secret::shutdown::scrub_and_shutdown;

struct AlwaysOkShutdown;
impl seed_flow::flow_secret::shutdown::ShutdownProvider for AlwaysOkShutdown {
    fn request_shutdown(&mut self) -> Result<(), seed_flow::flow_secret::shutdown::ShutdownFailure> {
        Ok(())
    }
}

/// A [`FaultHook`] panicking at `step` must have already seen every
/// step strictly before it in [`ALL_SCRUB_STEPS`] order, and none after.
fn steps_before(step: &str) -> &'static [&'static str] {
    let idx = ALL_SCRUB_STEPS.iter().position(|&s| s == step).unwrap();
    &ALL_SCRUB_STEPS[..idx]
}

#[test]
fn fault_hook_panic_at_every_spec_26_step_leaves_exactly_the_prior_steps_recorded() {
    let mut checked = 0usize;
    for &step in &ALL_SCRUB_STEPS {
        let mut arena = SpyArena::new();
        let mut fb = VecFb::new(32, 32);
        let mut shutdown = AlwaysOkShutdown;
        let mut hook = RecordingHook::panicking_at(step);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        assert!(result.is_err(), "a hook panic must propagate as an unwind, never be swallowed");

        let expected_before = steps_before(step);
        assert_eq!(
            hook.steps,
            expected_before.iter().copied().chain(std::iter::once(step)).collect::<Vec<_>>(),
            "step={step}: the hook must have recorded every prior step plus this one (where it panicked), and nothing after"
        );

        // Cross-check against the real arena spy: the hook's own step name
        // for step 4 is "arena" (`before_scrub_arena`), but the matching
        // `ArenaScrubSteps` method it guards is `scrub_all`, which
        // `SpyArena` records as `"all"` (see `RecordingHook`/`SpyArena`'s
        // own doc comments — the two spies intentionally use their own
        // real method names, which differ at this one step). A fault at
        // or before "reentry" means the arena spy saw nothing yet, and a
        // fault at "framebuffer" or later means all four arena steps had
        // already completed.
        let hook_to_arena_name = |s: &'static str| if s == "arena" { "all" } else { s };
        let arena_step_names = ["reentry", "mnemonic", "derived", "arena"];
        let arena_steps_expected_done: Vec<&str> = arena_step_names
            .iter()
            .copied()
            .filter(|s| expected_before.contains(s))
            .map(hook_to_arena_name)
            .collect();
        assert_eq!(
            arena.calls, arena_steps_expected_done,
            "step={step}: arena scrub calls completed before this fault point did not match the expected prefix"
        );

        checked += 1;
    }
    assert_eq!(checked, coverage::H_SCRUB_FAULT_HOOK_PANIC_PER_STEP);
    assert_eq!(ALL_SCRUB_STEPS.len(), coverage::H_SCRUB_FAULT_HOOK_PANIC_PER_STEP);
}

#[test]
fn arena_scrub_panic_at_each_of_its_four_steps_leaves_exactly_the_prior_arena_steps_done() {
    let arena_steps = ["reentry", "mnemonic", "derived", "all"];
    let mut checked = 0usize;
    for &step in &arena_steps {
        let mut arena = SpyArena::panicking_at(step);
        let mut fb = VecFb::new(32, 32);
        let mut shutdown = AlwaysOkShutdown;
        let mut hook = RecordingHook::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
        }));
        assert!(result.is_err(), "an arena-scrub-step panic must propagate as an unwind");

        let idx = arena_steps.iter().position(|&s| s == step).unwrap();
        let expected: Vec<&str> = arena_steps[..idx].iter().copied().chain(std::iter::once(step)).collect();
        assert_eq!(
            arena.calls, expected,
            "step={step}: arena spy must have recorded every prior arena step plus this one, nothing after"
        );

        // The framebuffer scrub, fences and shutdown-request steps are
        // strictly after every arena step in SPEC §26 order, so a fault
        // during any arena step must mean the framebuffer was never
        // touched by `scrub_and_shutdown`'s own framebuffer-scrub call.
        assert!(!hook.steps.contains(&"framebuffer"), "step={step}: an arena-scrub-stage fault must precede the framebuffer scrub step");

        checked += 1;
    }
    assert_eq!(checked, coverage::H_SCRUB_ARENA_PANIC_PER_STEP);
}

/// Companion positive control: with no fault injected anywhere, every
/// step must run in the exact SPEC §26 order and the arena must show all
/// four of its own steps too — proves the two tests above are not
/// vacuously passing because the harness itself never reaches later
/// steps.
#[test]
fn no_fault_baseline_runs_every_step_in_order() {
    let mut arena = SpyArena::new();
    let mut fb = VecFb::new(32, 32);
    let mut shutdown = AlwaysOkShutdown;
    let mut hook = RecordingHook::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrub_and_shutdown(&mut arena, &mut fb, &mut shutdown, &mut hook);
    }));
    assert!(result.is_err(), "scrub_and_shutdown never returns, even on the happy path (it always halts)");
    assert_eq!(hook.steps, ALL_SCRUB_STEPS.to_vec());
    assert_eq!(arena.calls, vec!["reentry", "mnemonic", "derived", "all"]);
}
