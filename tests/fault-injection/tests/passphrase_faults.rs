//! Category J (SPEC §29.5 "during passphrase entry", SPEC_PASSPHRASE
//! §4.1/§6.1/§6.2): faults injected at the post-secret optional-passphrase
//! step, proving that a fault there scrubs the passphrase buffer(s) — the
//! same scrub-on-fault invariant this suite already pins for the re-entry
//! positions (`reentry_position_faults.rs`) and the SPEC §26 scrub steps
//! (`scrub_operation_faults.rs`), extended to the newest secret step.
//!
//! Two of the three tests drive the REAL ceremony
//! (`seed_flow::flow_secret::run_secret_flow`) end-to-end through a frozen
//! vector, so the passphrase states are reached exactly the way production
//! reaches them (a desync in the scripted keystream would fail the test,
//! never pass vacuously). The third drives the REAL entry primitive
//! (`seed_flow::flow_secret::passphrase::run_entry`) against a live
//! arena-resident buffer, so the mid-entry cancel scrub is asserted at the
//! fault point itself — before any later ceremony-end scrub could mask it.

use seed_fault_injection::{
    coverage, reentry_keystream, ArchId, CountingWatchdog, MockOut, RecordingHook, ScriptedKeys,
    ScriptedMenuKeys, SecretArena, TestTimer, VecFb, ALL_SCRUB_STEPS,
};
use seed_flow::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use seed_flow::flow_secret::machine::{AcquiredSources, MachineAcquisitionError, MachineSourceGate};
use seed_flow::flow_secret::{passphrase, run_secret_flow, SecretProviders};
use seed_flow::keys::MenuKey;
use seed_platform_x86::input::InputEvent;
use seed_platform_x86::watchdog::Watchdog;
use seed_protocol::state::{AppState, EntropyMode, Event, StateMachine};

struct UnusedMachineGate;
impl MachineSourceGate for UnusedMachineGate {
    fn acquire(
        &mut self,
        _into: &mut AcquiredSources,
        _observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        panic!("machine gate must not be called on a dice-only path");
    }
}
struct NoMachineAvailability;
impl MachineAvailabilityGate for NoMachineAvailability {
    fn efi_rng(&mut self) -> SourceAvailability {
        SourceAvailability::default()
    }
    fn rdseed(&mut self) -> SourceAvailability {
        SourceAvailability::default()
    }
}

/// Types `text` as a masked passphrase entry, then commits with `[Enter]`.
fn typed(text: &str) -> Vec<InputEvent> {
    let mut v: Vec<InputEvent> = text.chars().map(InputEvent::Char).collect();
    v.push(InputEvent::Enter);
    v
}

struct CeremonyResult {
    reached_normal_shutdown: bool,
    hook_steps: Vec<&'static str>,
    arena_scrubbed: bool,
    passphrase_scrubbed: bool,
    fb_scrubbed: bool,
}

/// Runs the real dice-only 12-word ceremony to completion with `secret_events`
/// as the post-secret keystream, returning the observed scrub state.
fn run_ceremony(case: &seed_fault_injection::FrozenCase, secret_events: Vec<InputEvent>) -> CeremonyResult {
    use seed_fault_injection::WordCount;

    let mut term = MockOut::new();
    let mut menu = Vec::new();
    for &v in &case.dice_rolls {
        menu.push(MenuKey::Char((b'0' + v) as char));
    }
    menu.push(MenuKey::Enter); // physical entry: proceed once budget met
    // 2026-08-07 ceremony redesign, Stage 5 GENERATE: the composition pages
    // and the separate final-confirmation screen are now ONE screen, armed
    // by `[G]` alone — `[Enter]` is deliberately inert there.
    menu.push(MenuKey::Char('g'));
    let mut menu_keys = ScriptedMenuKeys::new(menu);
    let mut fb = VecFb::new(4096, 2048);
    let mut secret_keys = ScriptedKeys::new(secret_events);
    let mut avail = NoMachineAvailability;
    let mut mgate = UnusedMachineGate;
    let mut shutdown = seed_fault_injection::AlwaysOkShutdown::new();
    let mut hook = RecordingHook::new();

    let mut sm = StateMachine::new();
    let mut w = CountingWatchdog::default();
    for _ in 0..3 {
        sm.transition(Event::Continue, &mut w);
    }
    for _ in 0..4 {
        sm.transition(Event::CheckPassed, &mut w);
    }
    sm.transition(
        Event::SetupCommitted {
            word_count: WordCount::Twelve,
            mode: EntropyMode::DiceOnly,
            instrument: seed_fault_injection::Instrument::Both,
        },
        &mut w,
    );
    assert_eq!(sm.state(), AppState::PhysicalCollection);

    let mut arena = SecretArena::new();
    let mut watchdog = Watchdog::new(TestTimer);
    watchdog.disable().unwrap();

    let mut providers = SecretProviders {
        text_out: &mut term,
        menu_keys: &mut menu_keys,
        fb: &mut fb,
        secret_keys: &mut secret_keys,
        machine_availability: &mut avail,
        machine_gate: &mut mgate,
        shutdown: &mut shutdown,
        fault_hook: &mut hook,
        instrument: seed_flow::flow_secret::physical::Instrument::Both,
        passphrase_policy: passphrase::PassphraseKeyboardPolicy::HostKeyboardTrusted,
        build_id: "fault-injection-test",
        recap: seed_flow::diagnostics::DiagRecap::unknown(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_secret_flow(&mut sm, &mut arena, &mut watchdog, ArchId::X86_64, 1, &mut providers)
    }));

    CeremonyResult {
        reached_normal_shutdown: result.is_err() && shutdown.attempts == 1,
        hook_steps: hook.steps,
        arena_scrubbed: arena.final_entropy().iter().all(|&b| b == 0)
            && arena.mnemonic_indexes().iter().all(|&i| i == 0),
        passphrase_scrubbed: arena.passphrase().is_empty() && arena.passphrase_confirm().is_empty(),
        fb_scrubbed: fb.all_zero(),
    }
}

fn assert_clean_scrubbed_shutdown(r: &CeremonyResult, ctx: &str) {
    assert!(r.reached_normal_shutdown, "{ctx}: must reach the ordinary scrub-and-shutdown halt exactly once");
    assert_eq!(r.hook_steps, ALL_SCRUB_STEPS.to_vec(), "{ctx}: every SPEC §26 scrub step's fault hook must have fired, in order");
    assert!(r.arena_scrubbed, "{ctx}: arena must be fully scrubbed");
    assert!(r.passphrase_scrubbed, "{ctx}: both passphrase buffers must be scrubbed");
    assert!(r.fb_scrubbed, "{ctx}: framebuffer must be scrubbed blank");
}

/// Post-secret keystream common prefix: hide the phrase, then re-enter every
/// word correctly, landing at the `PassphraseOffer`.
fn reenter_all(case: &seed_fault_injection::FrozenCase) -> Vec<InputEvent> {
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    let mut secret = vec![InputEvent::Char('h')];
    secret.extend(reentry_keystream(&words));
    secret
}

/// SPEC_PASSPHRASE §4.1: a `PassphraseConfirm` mismatch is a scrub-on-fault
/// point — the driver scrubs BOTH the committed and the confirm passphrase
/// buffers on a non-matching second entry and routes forward-back to
/// `PassphraseEntry` with no retained state. The ceremony must then still
/// recover (cancel-to-empty) and reach a fully-scrubbed halt. That the
/// keystream drives entry-1 -> mismatched entry-2 -> back-to-entry at all
/// is itself the proof the mismatch routed exactly as production does (a
/// keystream desync would panic on a stale `PassphraseOffer`/verification
/// read, not reach shutdown).
#[test]
fn passphrase_confirm_mismatch_scrubs_both_buffers_and_ceremony_halts_clean() {
    let case = seed_fault_injection::load_frozen_case("dice_only_12w_min_budget.json");
    let mut secret = reenter_all(&case);
    secret.push(InputEvent::Char('y')); // passphrase offer: add a passphrase
    secret.extend(typed("river-tango-42")); // entry 1 (committed, non-empty)
    secret.extend(typed("DIFFERENT-99!")); // entry 2: MISMATCH -> both buffers scrubbed
    secret.push(InputEvent::Escape); // back at entry: cancel-to-empty (forward-only)
    // 2026-08-07 ceremony redesign, Stage 7: the verdict screen is shown
    // directly (no "view verification?" offer) and `[Enter] Finish` leaves
    // it; the Finish screen absorbed the completion education and shuts
    // down on `[Enter]`.
    secret.push(InputEvent::Enter); // Verify: Finish
    secret.push(InputEvent::Enter); // Finish: Shut down

    let r = run_ceremony(&case, secret);
    assert_clean_scrubbed_shutdown(&r, "passphrase-confirm-mismatch");
    assert_eq!(1, coverage::J_PASSPHRASE_CONFIRM_MISMATCH_SCRUB);
}

/// A committed+matched passphrase stays resident through the verification
/// display (SPEC_PASSPHRASE §7.3), then MUST be zeroed by the ordered SPEC
/// §26 scrub chain like every other resident secret when the ceremony
/// completes. Proves the passphrase buffer is on the scrub path, not left
/// behind.
#[test]
fn passphrase_committed_and_matched_is_scrubbed_by_the_completion_chain() {
    let case = seed_fault_injection::load_frozen_case("dice_only_12w_min_budget.json");
    let mut secret = reenter_all(&case);
    secret.push(InputEvent::Char('y')); // passphrase offer: add a passphrase
    secret.extend(typed("river-tango-42")); // entry 1
    secret.extend(typed("river-tango-42")); // entry 2: MATCH -> committed resident
    // 2026-08-07 ceremony redesign, Stage 7: the verdict screen is shown
    // directly (no "view verification?" offer) and `[Enter] Finish` leaves
    // it; the Finish screen absorbed the completion education and shuts
    // down on `[Enter]`.
    secret.push(InputEvent::Enter); // Verify: Finish
    secret.push(InputEvent::Enter); // Finish: Shut down

    let r = run_ceremony(&case, secret);
    assert_clean_scrubbed_shutdown(&r, "passphrase-committed-matched");
    assert_eq!(1, coverage::J_PASSPHRASE_COMMITTED_THEN_SCRUBBED);
}

/// SPEC_PASSPHRASE §6.2: a mid-entry cancel (`[Esc]`) is a scrub-on-fault
/// point — `run_entry` (the exact production primitive the driver's
/// `PassphraseEntry`/`PassphraseConfirm` arms call) MUST scrub the
/// arena-resident buffer before returning `Cancelled`. Asserted directly on
/// the live buffer at the fault point, so no later ceremony-end scrub can
/// mask a regression here.
#[test]
fn passphrase_mid_entry_cancel_scrubs_the_live_arena_buffer_at_the_fault_point() {
    let mut arena = SecretArena::new();
    let mut fb = VecFb::new(256, 128);
    // Type a non-empty secret, then a fault interrupts entry: Escape.
    let mut keys = ScriptedKeys::new({
        let mut v: Vec<InputEvent> = "Hunter2!".chars().map(InputEvent::Char).collect();
        v.push(InputEvent::Escape);
        v
    });

    let outcome = passphrase::run_entry(
        &mut fb,
        &mut keys,
        arena.passphrase(),
        passphrase::EntryPhase::First,
        None,
    );

    assert_eq!(outcome, passphrase::EntryOutcome::Cancelled, "Escape mid-entry must cancel");
    assert!(arena.passphrase().is_empty(), "the passphrase buffer must be scrubbed at the cancel fault point");
    assert_eq!(1, coverage::J_PASSPHRASE_ENTRY_CANCEL_SCRUB);
}
