//! Category F (SPEC §29.5 "during every re-entry position"): drives the
//! real SPEC §23.1-§23.2 hidden re-entry loop
//! (`seed_flow::flow_secret::run_secret_flow`) through a frozen-vector
//! ceremony, injecting a wrong word at **every single position** of both
//! a 12-word and a 24-word phrase, taking each of the two SPEC §23.2
//! branches (destroy, retry-then-correct), plus reveal-again at several
//! positions. Every case checks both invariants: the ceremony must reach
//! the scrub-and-shutdown chain with the full SPEC §26 step order
//! recorded, and the arena/framebuffer must end up fully scrubbed.

use seed_fault_injection::{
    coverage, reentry_keystream, ArchId, CountingWatchdog, MockOut, RecordingHook, ScriptedKeys,
    ScriptedMenuKeys, SecretArena, TestTimer, VecFb, ALL_SCRUB_STEPS,
};
use seed_flow::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use seed_flow::flow_secret::machine::{AcquiredSources, MachineAcquisitionError, MachineSourceGate};
use seed_flow::flow_secret::{run_secret_flow, SecretProviders};
use seed_flow::keys::MenuKey;
use seed_platform_x86::input::InputEvent;
use seed_platform_x86::watchdog::Watchdog;
use seed_protocol::state::{AppState, EntropyMode, Event, StateMachine};

struct UnusedMachineGate;
impl MachineSourceGate for UnusedMachineGate {
    fn acquire(
        &mut self,
        _extras: seed_flow::flow_secret::machine::MachineExtras,
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

/// What to do once the injected wrong word at `fault_position` triggers a
/// mismatch (SPEC §23.2).
#[derive(Clone, Copy)]
enum FaultAction {
    /// `[3]` Destroy phrase and shut down, immediately.
    Destroy,
    /// `[1]` Retry this position, then type it correctly and continue.
    RetryThenCorrect,
}

fn wrong_prefix() -> Vec<InputEvent> {
    vec![InputEvent::Char('z'), InputEvent::Char('z'), InputEvent::Char('z'), InputEvent::Char('z'), InputEvent::Enter]
}

/// Builds the full post-secret keystream for a ceremony that gets exactly
/// one position wrong (`fault_position`, 0-based) and takes `action` at
/// the resulting mismatch screen.
fn build_secret_keystream(words: &[&str], fault_position: usize, action: FaultAction) -> Vec<InputEvent> {
    let mut secret = vec![InputEvent::Char('h')]; // [H] hide -> begin re-entry
    for (i, w) in words.iter().enumerate() {
        if i == fault_position {
            secret.extend(wrong_prefix());
            match action {
                FaultAction::Destroy => {
                    secret.push(InputEvent::Char('3')); // [3] Destroy phrase
                    // Second confirmation: [P] wipe and power off (SPEC §26
                    // amendment 2026-08-08 — a bare Enter no longer destroys;
                    // [P] preserves the scrub-and-shutdown this test asserts).
                    secret.push(InputEvent::Char('p'));
                    return secret; // ceremony ends here
                }
                FaultAction::RetryThenCorrect => {
                    secret.push(InputEvent::Char('1')); // [1] Retry this position
                    secret.extend(reentry_keystream(&[w]));
                }
            }
        } else {
            secret.extend(reentry_keystream(&[w]));
        }
    }
    secret.push(InputEvent::Char('n')); // SPEC_PASSPHRASE §6.1: skip passphrase (empty)
    // 2026-08-07 ceremony redesign, Stage 7: the verdict screen is shown
    // directly (no "view verification?" offer) and `[Enter] Finish` leaves
    // it; the Finish screen absorbed the completion education and shuts
    // down on `[Enter]`.
    secret.push(InputEvent::Enter); // Verify: Finish
    secret.push(InputEvent::Enter); // Finish: Shut down
    secret
}

/// Builds the post-secret keystream for a ceremony that gets one position
/// wrong, chooses `[2]` Reveal, then re-enters the *entire* phrase
/// correctly from word 1 (SPEC §23.2: reveal resets all re-entry
/// progress).
fn build_reveal_keystream(words: &[&str], fault_position: usize) -> Vec<InputEvent> {
    let mut secret = vec![InputEvent::Char('h')];
    for w in words.iter().take(fault_position) {
        secret.extend(reentry_keystream(&[w]));
    }
    secret.extend(wrong_prefix());
    secret.push(InputEvent::Char('2')); // [2] Reveal the phrase again
    secret.push(InputEvent::Char('h')); // hide again -> restart re-entry at position 0
    secret.extend(reentry_keystream(words));
    secret.push(InputEvent::Char('n')); // SPEC_PASSPHRASE §6.1: skip passphrase (empty)
    // 2026-08-07 ceremony redesign, Stage 7: the verdict screen is shown
    // directly, `[Enter] Finish` leaves it, and the Finish screen (which
    // absorbed the completion education) shuts down on `[Enter]`.
    secret.push(InputEvent::Enter); // Verify: Finish
    secret.push(InputEvent::Enter); // Finish: Shut down
    secret
}

struct CeremonyResult {
    reached_normal_shutdown: bool,
    hook_steps: Vec<&'static str>,
    arena_scrubbed: bool,
    fb_scrubbed: bool,
}

fn run_ceremony(dice_rolls: &[u8], bits: seed_fault_injection::TargetBits, secret_events: Vec<InputEvent>) -> CeremonyResult {
    use seed_fault_injection::WordCount;
    let word_count = match bits {
        seed_fault_injection::TargetBits::Bits128 => WordCount::Twelve,
        seed_fault_injection::TargetBits::Bits256 => WordCount::TwentyFour,
    };

    let mut term = MockOut::new();
    let mut menu = Vec::new();
    for &v in dice_rolls {
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
            word_count: word_count,
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
        extras: seed_flow::flow_secret::machine::MachineExtras::default(),
        instrument: seed_flow::flow_secret::physical::Instrument::Both,
        passphrase_policy:
            seed_flow::flow_secret::passphrase::PassphraseKeyboardPolicy::HostKeyboardTrusted,
        build_id: "fault-injection-test",
        recap: seed_flow::diagnostics::DiagRecap::unknown(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_secret_flow(&mut sm, &mut arena, &mut watchdog, ArchId::X86_64, 1, &mut providers)
    }));

    CeremonyResult {
        reached_normal_shutdown: result.is_err() && shutdown.attempts == 1,
        hook_steps: hook.steps,
        arena_scrubbed: arena.final_entropy().iter().all(|&b| b == 0) && arena.mnemonic_indexes().iter().all(|&i| i == 0),
        fb_scrubbed: fb.all_zero(),
    }
}

fn assert_clean_scrubbed_shutdown(r: &CeremonyResult, ctx: &str) {
    assert!(r.reached_normal_shutdown, "{ctx}: must reach the ordinary scrub-and-shutdown halt exactly once");
    assert_eq!(r.hook_steps, ALL_SCRUB_STEPS.to_vec(), "{ctx}: every SPEC §26 scrub step's fault hook must have fired, in order");
    assert!(r.arena_scrubbed, "{ctx}: arena must be fully scrubbed");
    assert!(r.fb_scrubbed, "{ctx}: framebuffer must be scrubbed blank");
}

#[test]
fn mismatch_destroy_at_every_position_12_words() {
    let case = seed_fault_injection::load_frozen_case("dice_only_12w_min_budget.json");
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    assert_eq!(words.len(), 12);
    let mut checked = 0usize;
    for pos in 0..12 {
        let secret = build_secret_keystream(&words, pos, FaultAction::Destroy);
        let r = run_ceremony(&case.dice_rolls, case.bits, secret);
        assert_clean_scrubbed_shutdown(&r, &format!("destroy@12w:pos{pos}"));
        checked += 1;
    }
    assert_eq!(checked, coverage::F_REENTRY_12W_MISMATCH_DESTROY);
}

#[test]
fn mismatch_retry_recovers_at_every_position_12_words() {
    let case = seed_fault_injection::load_frozen_case("dice_only_12w_min_budget.json");
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    let mut checked = 0usize;
    for pos in 0..12 {
        let secret = build_secret_keystream(&words, pos, FaultAction::RetryThenCorrect);
        let r = run_ceremony(&case.dice_rolls, case.bits, secret);
        assert_clean_scrubbed_shutdown(&r, &format!("retry@12w:pos{pos}"));
        checked += 1;
    }
    assert_eq!(checked, coverage::F_REENTRY_12W_MISMATCH_RETRY);
}

#[test]
fn mismatch_destroy_at_every_position_24_words() {
    let case = seed_fault_injection::load_frozen_case("dice_only_24w_min_budget.json");
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    assert_eq!(words.len(), 24);
    let mut checked = 0usize;
    for pos in 0..24 {
        let secret = build_secret_keystream(&words, pos, FaultAction::Destroy);
        let r = run_ceremony(&case.dice_rolls, case.bits, secret);
        assert_clean_scrubbed_shutdown(&r, &format!("destroy@24w:pos{pos}"));
        checked += 1;
    }
    assert_eq!(checked, coverage::F_REENTRY_24W_MISMATCH_DESTROY);
}

#[test]
fn mismatch_retry_recovers_at_every_position_24_words() {
    let case = seed_fault_injection::load_frozen_case("dice_only_24w_min_budget.json");
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    let mut checked = 0usize;
    for pos in 0..24 {
        let secret = build_secret_keystream(&words, pos, FaultAction::RetryThenCorrect);
        let r = run_ceremony(&case.dice_rolls, case.bits, secret);
        assert_clean_scrubbed_shutdown(&r, &format!("retry@24w:pos{pos}"));
        checked += 1;
    }
    assert_eq!(checked, coverage::F_REENTRY_24W_MISMATCH_RETRY);
}

#[test]
fn reveal_again_resets_progress_at_several_positions_24_words() {
    let case = seed_fault_injection::load_frozen_case("dice_only_24w_min_budget.json");
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    let positions = [0usize, 5, 11, 17, 23];
    assert_eq!(positions.len(), coverage::F_REENTRY_REVEAL_AT_POSITIONS);

    let mut checked = 0usize;
    for pos in positions {
        let secret = build_reveal_keystream(&words, pos);
        let r = run_ceremony(&case.dice_rolls, case.bits, secret);
        assert_clean_scrubbed_shutdown(&r, &format!("reveal@24w:pos{pos}"));
        checked += 1;
    }
    assert_eq!(checked, coverage::F_REENTRY_REVEAL_AT_POSITIONS);
}
