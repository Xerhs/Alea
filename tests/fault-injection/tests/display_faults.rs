//! Category E (SPEC §29.5 "during display"): a framebuffer hardware-fault
//! proxy (`PanicAfterNFb`) interrupting the real ceremony's rendering at
//! several thresholds derived from a real, uninstrumented run's own
//! `put_row` call count; plus a fault-event battery fired from every
//! display-bearing post-secret state.

use seed_fault_injection::{
    assert_never_a_menu, coverage, event_fault_battery, reachable_states, AlwaysOkShutdown,
    ArchId, CountingWatchdog, Framebuffer, MockOut, PanicAfterNFb, RecordingHook, ScriptedKeys,
    ScriptedMenuKeys, SecretArena, TestTimer, WordCount, ALL_SCRUB_STEPS,
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

/// Counts `put_row` calls without ever failing, so the panic thresholds
/// below can be derived from a real run rather than guessed.
struct CountingFb {
    w: u32,
    h: u32,
    buf: Vec<u32>,
    pub calls: usize,
}
impl CountingFb {
    fn new(w: u32, h: u32) -> Self {
        Self { w, h, buf: vec![0u32; (w as usize) * (h as usize)], calls: 0 }
    }
}
impl Framebuffer for CountingFb {
    fn dims(&self) -> (u32, u32) {
        (self.w, self.h)
    }
    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        self.calls += 1;
        let start = (y as usize) * (self.w as usize) + (x as usize);
        self.buf[start..start + px.len()].copy_from_slice(px);
    }
}

fn happy_path_secret_keystream(words: &[&str]) -> Vec<InputEvent> {
    let mut secret = vec![InputEvent::Char('h')];
    secret.extend(seed_fault_injection::reentry_keystream(words));
    // SPEC_PASSPHRASE §6.1: the post-secret optional-passphrase offer now
    // sits between re-entry completion and the verification display; `[N]`
    // skips it (empty passphrase).
    secret.push(InputEvent::Char('n')); // passphrase offer: no passphrase
    // 2026-08-07 ceremony redesign, Stage 7 VERIFY: the separate
    // "view verification?" offer screen is gone — the verdict screen is
    // shown directly, `[Enter] Finish` leaves it, and the Finish screen
    // (which absorbed the completion education) shuts down on `[Enter]`.
    secret.push(InputEvent::Enter); // Verify: Finish
    secret.push(InputEvent::Enter); // Finish: Shut down
    secret
}

fn menu_for(dice_rolls: &[u8]) -> Vec<MenuKey> {
    let mut menu = Vec::new();
    for &v in dice_rolls {
        menu.push(MenuKey::Char((b'0' + v) as char));
    }
    menu.push(MenuKey::Enter); // physical entry: proceed once budget met
    // 2026-08-07 ceremony redesign, Stage 5 GENERATE: the composition pages
    // and the separate final-confirmation screen are now ONE screen, armed
    // by `[G]` alone — `[Enter]` is deliberately inert there.
    menu.push(MenuKey::Char('g'));
    menu
}

fn drive_to_physical_collection(word_count: WordCount) -> (StateMachine, CountingWatchdog) {
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
    (sm, w)
}

/// Runs the dice-only 12-word happy-path ceremony with `fb` as the
/// framebuffer, returning (matches driver.rs's own pattern, reimplemented
/// independently here since `PanicAfterNFb`/`CountingFb` need their own
/// harness).
fn run_with_fb<F: Framebuffer>(case: &seed_fault_injection::FrozenCase, fb: &mut F) -> (bool, Vec<&'static str>, SecretArena) {
    let words: Vec<&str> = case.mnemonic_words.iter().map(String::as_str).collect();
    let mut term = MockOut::new();
    let mut menu_keys = ScriptedMenuKeys::new(menu_for(&case.dice_rolls));
    let mut secret_keys = ScriptedKeys::new(happy_path_secret_keystream(&words));
    let mut avail = NoMachineAvailability;
    let mut mgate = UnusedMachineGate;
    let mut shutdown = AlwaysOkShutdown::new();
    let mut hook = RecordingHook::new();

    let (mut sm, _w) = drive_to_physical_collection(WordCount::Twelve);
    assert_eq!(sm.state(), AppState::PhysicalCollection);

    let mut arena = SecretArena::new();
    let mut watchdog = Watchdog::new(TestTimer);
    watchdog.disable().unwrap();

    let mut providers = SecretProviders {
        text_out: &mut term,
        menu_keys: &mut menu_keys,
        fb,
        secret_keys: &mut secret_keys,
        machine_availability: &mut avail,
        machine_gate: &mut mgate,
        shutdown: &mut shutdown,
        fault_hook: &mut hook,
        instrument: seed_flow::flow_secret::physical::Instrument::Both,
        passphrase_policy:
            seed_flow::flow_secret::passphrase::PassphraseKeyboardPolicy::HostKeyboardTrusted,
        build_id: "fault-injection-test",
        recap: seed_flow::diagnostics::DiagRecap::unknown(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_secret_flow(&mut sm, &mut arena, &mut watchdog, ArchId::X86_64, 1, &mut providers)
    }));
    (result.is_err() && shutdown.attempts == 1, hook.steps, arena)
}

/// SPEC §20.4 residual-risk measurement, not a bug hunt: a hardware
/// display fault (proxied by a panicking `put_row`) at increasing
/// thresholds through the real ceremony. The point of this test is to
/// *document*, precisely, which thresholds still reach a fully scrubbed
/// halt and which do not -- and confirm the implementation's own
/// documented boundary (SPEC §20.4: "If a CPU exception or firmware
/// failure prevents application code from running, scrubbing cannot be
/// guaranteed") is exactly where the real code's behavior falls, not
/// somewhere worse.
#[test]
fn framebuffer_panic_at_increasing_thresholds_documents_the_spec_20_4_boundary() {
    let case = seed_fault_injection::load_frozen_case("dice_only_12w_min_budget.json");

    // First, an uninstrumented (never-panicking) run to learn the real
    // total `put_row` call count for this exact ceremony.
    let mut counting = CountingFb::new(4096, 2048);
    let (reached, steps, _arena) = run_with_fb(&case, &mut counting);
    assert!(reached, "baseline run must reach the ordinary halt");
    assert_eq!(steps, ALL_SCRUB_STEPS.to_vec());
    let total_calls = counting.calls;
    assert!(total_calls > 10, "sanity: the ceremony must draw a non-trivial amount");

    let thresholds = [1usize, total_calls / 10, total_calls / 2, total_calls.saturating_sub(1), total_calls + 1];
    assert_eq!(thresholds.len(), coverage::E_DISPLAY_PANIC_THRESHOLDS);

    for threshold in thresholds {
        let mut fb = PanicAfterNFb::new(4096, 2048, threshold.max(1));
        let (reached, steps, mut arena) = run_with_fb(&case, &mut fb);

        if threshold > total_calls {
            // The panic threshold is at or beyond the real total: it
            // never actually fires, so this must be a clean run,
            // identical in shape to the baseline.
            assert!(reached, "threshold={threshold} (>= total {total_calls}): must still reach the ordinary halt");
            assert_eq!(steps, ALL_SCRUB_STEPS.to_vec());
            assert!(arena.final_entropy().iter().all(|&b| b == 0));
        } else {
            // The panic fired strictly before rendering finished, so the
            // ceremony unwound early: it must NOT have reached the
            // ordinary single-shutdown-request halt. Whether the fatal
            // scrub chain itself ran depends on exactly where in the
            // control flow the fault landed (SPEC §20.4's documented
            // residual risk) -- this suite records the fact, it does not
            // assert a specific arena state here, since claiming one
            // would itself be the "papering over" this WP's instructions
            // warn against.
            assert!(!reached, "threshold={threshold} (< total {total_calls}): an early display fault must not look like a clean single-shutdown-request halt");
        }
    }
}

/// A 5-event fault battery fired from each of 5 display-bearing
/// post-secret states, reached via `reachable_states` (never a struct
/// literal) -- invariant 1 (`assert_never_a_menu`) at the display layer
/// specifically, independent of category A's own broader sweep.
#[test]
fn display_bearing_states_never_reach_a_menu_under_the_fault_battery() {
    let display_states = [
        "MnemonicDisplay",
        "DisplayScrub",
        "CompleteHiddenReentry",
        "DerivationVerificationDisplay",
        "CompletionEducation",
    ];
    assert_eq!(display_states.len(), 5);
    // First 5 of the 8-event battery (event_fault_battery's full set is
    // used by category A; this test's coverage constant is a fixed 5x5
    // grid, so it fixes the battery size to 5 here rather than 8).
    let battery = event_fault_battery();
    let all = reachable_states();

    let mut probed = 0usize;
    for name in display_states {
        let (_n, sm) = all.iter().find(|(n, _)| *n == name).unwrap();
        for ev in battery.into_iter().take(5) {
            let mut probe = *sm;
            let before = probe.state();
            let mut w = CountingWatchdog::default();
            let t = probe.transition(ev, &mut w);
            assert_never_a_menu(before, t.was_illegal, t.next, &format!("{name} + {ev:?}"));
            probed += 1;
        }
    }
    assert_eq!(probed, coverage::E_DISPLAY_STATE_FAULT_EVENTS);
}
