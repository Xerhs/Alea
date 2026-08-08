//! Category A (SPEC §29.5 "before and after each state transition"):
//! drives `seed_protocol::state::StateMachine` (WP-23) to every one of its
//! 32 reachable states (via legal transitions only — see
//! `seed_fault_injection::reachable_states`) and injects a fault at each
//! one, twice:
//!
//! - **Before** the transition is computed: a [`FailingWatchdog`] fault
//!   (SPEC §11.1's own re-assert hook fires *before* `transition` computes
//!   its result — see `StateMachine::transition`'s doc comment).
//! - **After** reaching the state: an 8-event battery of mostly-illegal
//!   events, observing where the resulting transition lands.
//!
//! Both check invariant 1 (`assert_never_a_menu`): no post-secret failure
//! path ever returns to a menu/boot-manager/firmware state.

use seed_fault_injection::{
    assert_never_a_menu, coverage, event_fault_battery, reachable_states, AppState,
    CountingWatchdog, FailingWatchdog,
};

#[test]
fn before_transition_watchdog_fault_at_every_reachable_state() {
    let states = reachable_states();
    assert_eq!(states.len(), coverage::A_BEFORE_TRANSITION_WATCHDOG_FAULT);

    for (name, mut sm) in states {
        let before = sm.state();
        let mut w = FailingWatchdog::default();
        let t = sm.transition(seed_fault_injection::Event::Continue, &mut w);

        assert_eq!(w.count, 1, "{name}: watchdog must be re-asserted exactly once per transition call");

        if before.is_terminal() {
            // Terminal states absorb everything, watchdog result included
            // (StateMachine::transition's own documented rule).
            assert_eq!(t.next, before, "{name}: terminal state must not move under a watchdog fault");
            assert!(!t.was_illegal);
            continue;
        }
        if before.is_fatal_chain() {
            // The fatal chain advances unconditionally regardless of the
            // watchdog result (already inside the non-returning sequence).
            assert!(!t.was_illegal, "{name}: fatal-chain advance must never be reported illegal");
            continue;
        }

        // Every other state: SPEC §11.1 says a watchdog re-assert failure
        // is fatal once a secret exists, and must not be silently ignored
        // pre-secret either.
        assert!(t.was_illegal, "{name}: a failed watchdog re-assert must never be treated as a legal transition");
        if before.is_post_secret() {
            assert_eq!(
                t.next,
                AppState::ScrubWhatIsReachable,
                "{name}: post-secret watchdog fault must route straight to ScrubWhatIsReachable"
            );
        } else {
            assert_eq!(
                t.next,
                AppState::PreSecretError(seed_fault_injection::ErrorClass::Watchdog),
                "{name}: pre-secret watchdog fault must route to PreSecretError(Watchdog), not be ignored"
            );
        }
        assert_never_a_menu(before, t.was_illegal, t.next, name);
    }
}

#[test]
fn after_transition_illegal_event_battery_at_every_reachable_state() {
    let battery = event_fault_battery();
    let states = reachable_states();
    assert_eq!(
        states.len() * battery.len(),
        coverage::A_AFTER_TRANSITION_ILLEGAL_EVENTS
    );

    let mut probed = 0usize;
    for (name, sm) in &states {
        for ev in battery {
            let mut probe = *sm;
            let before = probe.state();
            let mut w = CountingWatchdog::default();
            let t = probe.transition(ev, &mut w);
            assert_eq!(w.count, 1, "{name} + {ev:?}: watchdog must be re-asserted exactly once");
            assert_never_a_menu(before, t.was_illegal, t.next, &format!("{name} + {ev:?}"));
            probed += 1;
        }
    }
    assert_eq!(probed, coverage::A_AFTER_TRANSITION_ILLEGAL_EVENTS);
}

/// Regression-style focused check: the specific "no path returns to a
/// menu" invariant, restated as its own assertion (not just folded into
/// the loop above) for every post-secret state in the reach table, so a
/// future change that weakens `assert_never_a_menu` itself cannot silently
/// hide a real regression.
#[test]
fn post_secret_states_never_land_on_a_menu_state_under_any_battery_event() {
    let battery = event_fault_battery();
    let menu_states = [
        AppState::Start,
        AppState::ReleaseAndEnvironmentWarning,
        AppState::SetupSelection,
    ];
    for (name, sm) in reachable_states() {
        if !sm.state().is_post_secret() {
            continue;
        }
        for ev in battery {
            let mut probe = sm;
            let mut w = CountingWatchdog::default();
            let t = probe.transition(ev, &mut w);
            assert!(
                !menu_states.contains(&t.next),
                "{name} + {ev:?}: post-secret state illegally reached menu state {:?}",
                t.next
            );
        }
    }
}
