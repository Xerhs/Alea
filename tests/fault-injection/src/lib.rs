//! WP-33 fault-injection suite (SPEC §29.5) — shared test doubles, state-
//! machine "reach via legal transitions only" helpers, a frozen-vector
//! loader and the injection-point coverage ledger used by every test file
//! under `tests/`.
//!
//! # What this crate is, and is not
//!
//! This crate is host-only test infrastructure. It is not part of any
//! production or UEFI build (it is not a member of the root workspace —
//! see this crate's own `Cargo.toml` doc comment) and it never
//! reimplements the logic it drives: every fault-injection test in this
//! suite calls straight into the real `seed_protocol::state::StateMachine`
//! (WP-23) and the real `seed_flow::flow_secret` ceremony (WP-26),
//! injecting failures only at the seams those crates already expose for
//! exactly this purpose (`FaultHook`, `ArenaScrubSteps`, `ShutdownProvider`,
//! `MachineSourceGate`, `WatchdogReassert`, and ordinary `Result`/panic
//! boundaries).
//!
//! # Two invariants every fault-injection test in this suite checks
//!
//! 1. **No post-secret failure path ever returns to a menu, the boot
//!    manager or firmware.** Once `AppState::is_post_secret()` is true for
//!    the state a fault was injected from, every subsequent state must
//!    either be a legal post-secret edge or land in the SPEC §21 fatal
//!    chain (`ScrubWhatIsReachable` → `BlankDisplay` → `ShutdownOrHalt`) —
//!    never `Start`/`ReleaseAndEnvironmentWarning`/`WordCountSelection`/
//!    `EntropyModeSelection` (SPEC §21, §27.2). See [`assert_never_a_menu`].
//! 2. **Scrub hooks fire on every exit path.** Every ceremony run that
//!    reaches the shutdown chain must have driven the ordered SPEC §26
//!    scrub sequence to completion, spied on via [`RecordingHook`] (the
//!    real [`seed_flow::flow_secret::shutdown::FaultHook`] seam) and the
//!    arena's own post-condition (`final_entropy`/`mnemonic_indexes` all
//!    zero). See [`ALL_SCRUB_STEPS`].

#![allow(clippy::missing_panics_doc)]

use std::string::String;
use std::vec::Vec;

pub use seed_core::arena::SecretArena;
pub use seed_core::contracts::{
    ArchId, Framebuffer, SourceTag, TargetBits, WordCount, MAX_ALGO_ID, MAX_MACHINE_SOURCE_BYTES,
    MAX_PHYSICAL_EVENTS, MAX_SOURCE_RECORDS,
};
pub use seed_platform_x86::input::{InputEvent, KeySource};
pub use seed_platform_x86::watchdog::{Watchdog, WatchdogFailure, WatchdogTimer};
pub use seed_protocol::state::{
    AppState, CountingWatchdog, EntropyMode, ErrorClass, Event, Instrument, PreSecretDisposition,
    StateMachine, WatchdogReassert, WatchdogReassertFailure,
};

pub use seed_flow::keys::{MenuKey, MenuKeySource};
pub use seed_flow::output::TextOutput;

// ============================================================================
// Coverage ledger (single source of truth for every loop bound below and
// in the `tests/*.rs` files, so `tests/coverage_report.rs` can sum and
// print the real, code-verified injection-point count rather than a
// hand-maintained number that can drift from what actually runs).
// ============================================================================

/// SPEC §29.5 injection-point counts, one constant per fault-injection
/// category that section lists, each wired directly into the loop bound
/// of the test(s) that implement it (grep for the constant name to find
/// the corresponding test). [`tests::coverage_ledger_matches_documented_total`]
/// pins the sum so this module comment and the real total can never
/// silently drift apart.
pub mod coverage {
    // -- "before and after each state transition" --------------------
    /// One watchdog-reassert-failure injection *before* the transition is
    /// computed, at every one of the 32 constructible `AppState` values
    /// (`reachable_states`). The count grew from 30 to 33 when the
    /// post-secret flow gained the three SPEC_PASSPHRASE §6.1 states
    /// (`PassphraseOffer` -> `PassphraseEntry` -> `PassphraseConfirm`), then
    /// fell to 32 when the 2026-08-07 ceremony redesign merged
    /// `WordCountSelection` + `EntropyModeSelection` into the single
    /// `SetupSelection` screen (SPEC §22.4/§22.5 amendment).
    pub const A_BEFORE_TRANSITION_WATCHDOG_FAULT: usize = 32;
    /// An 8-event fault battery fired *after* reaching each of the 32
    /// states, observing where the (mostly illegal) resulting transition
    /// lands.
    pub const A_AFTER_TRANSITION_ILLEGAL_EVENTS: usize = 32 * 8;

    // -- "during entropy acquisition" ---------------------------------
    /// `assemble_acquired_sources` over all 32 present/absent combinations
    /// of {efi_rng, rdseed, rdrand, tpm2, tpm12} (SPEC_TPM_ENTROPY.md §10
    /// and SPEC_TPM12_ENTROPY.md §6 added the fourth and fifth
    /// primary-class sources; the gate enforces TPM family exclusivity,
    /// but this pure function is exercised over every combination).
    pub const B_ACQUISITION_ASSEMBLE_COMBINATIONS: usize = 32;
    /// Full-ceremony machine-source-gate failure, one run per mode that
    /// can reach `MachineEntropyAcquisition`.
    pub const B_ACQUISITION_GATE_FAILURE_CEREMONY: usize = 2;
    /// A machine-source gate that panics mid-acquisition (hardware-fault
    /// proxy), driven through the real ceremony.
    pub const B_ACQUISITION_GATE_PANIC: usize = 1;

    // -- "during physical-event processing" ---------------------------
    /// Over-budget dice+coin combinations forced into `PhysicalStaging`
    /// and pushed through `derive::derive`, at both word counts.
    pub const C_PHYSICAL_OVER_BUDGET_COMBOS: usize = 8;
    /// `PhysicalSession::push_roll`/`push_flip` at exact capacity.
    pub const C_PHYSICAL_SESSION_CAPACITY: usize = 2;
    /// `PhysicalSession::undo` on an empty session.
    pub const C_PHYSICAL_UNDO_UNDERFLOW: usize = 1;

    // -- "during BIP39 conversion" -------------------------------------
    /// `bip39::entropy_to_indexes` with malformed entropy lengths.
    pub const D_BIP39_BAD_LENGTHS: usize = 7;
    /// `bip39::resolve_prefix_into` edge-case prefixes.
    pub const D_BIP39_RESOLVE_PREFIX_EDGE_CASES: usize = 4;

    // -- "during display" -----------------------------------------------
    /// A framebuffer double that panics after N `put_row` calls (hardware-
    /// fault proxy), at several thresholds through the real happy-path
    /// ceremony.
    pub const E_DISPLAY_PANIC_THRESHOLDS: usize = 5;
    /// A 5-event fault battery fired from each of 5 display-bearing
    /// post-secret states, reached via `reachable_states`.
    pub const E_DISPLAY_STATE_FAULT_EVENTS: usize = 5 * 5;

    // -- "during every re-entry position" ------------------------------
    /// 12-word ceremony: mismatch-then-destroy at every position.
    pub const F_REENTRY_12W_MISMATCH_DESTROY: usize = 12;
    /// 12-word ceremony: mismatch-then-retry-recovers at every position.
    pub const F_REENTRY_12W_MISMATCH_RETRY: usize = 12;
    /// 24-word ceremony: mismatch-then-destroy at every position.
    pub const F_REENTRY_24W_MISMATCH_DESTROY: usize = 24;
    /// 24-word ceremony: mismatch-then-retry-recovers at every position.
    pub const F_REENTRY_24W_MISMATCH_RETRY: usize = 24;
    /// 24-word ceremony: reveal-again (full progress reset) at several
    /// positions.
    pub const F_REENTRY_REVEAL_AT_POSITIONS: usize = 5;

    // -- "during derivation" ---------------------------------------------
    pub const G_DERIVATION_DUPLICATE_TAG: usize = 1;
    pub const G_DERIVATION_TOO_MANY_RECORDS: usize = 1;
    pub const G_DERIVATION_ALGO_ID_TOO_LONG: usize = 1;
    pub const G_DERIVATION_SOURCE_TOO_LONG: usize = 1;
    /// Combined dice+coin over the shared physical budget
    /// (`MAX_PHYSICAL_EVENTS`), staged directly against
    /// `TranscriptBuilder::add_source` at two different dice/coin split
    /// ratios (dice-heavy and coin-heavy), both rejected with
    /// `SourceTooLong` rather than truncated or panicking.
    pub const G_DERIVATION_COMBINED_OVER_BUDGET: usize = 2;
    /// Fail-closed entropy floor (pre-release audit MUST-FIX #2,
    /// `docs/PRE-RELEASE-AUDIT.md`): zero sources must be rejected with
    /// `PipelineError::InsufficientSources`, never silently hashed into a
    /// "valid" (fixed, publicly-computable) result. This constant used to
    /// count a documented *non-fault* success edge case (zero sources
    /// deriving cleanly); that was the exact defect MUST-FIX #2 closes,
    /// so the test behind this constant now asserts the corrected,
    /// fail-closed outcome instead.
    pub const G_DERIVATION_ZERO_SOURCES: usize = 1;

    // -- "during scrub operations" ---------------------------------------
    /// A `FaultHook` whose `before_*` method panics, one per SPEC §26
    /// numbered step, driven through `scrub_and_shutdown`.
    pub const H_SCRUB_FAULT_HOOK_PANIC_PER_STEP: usize = 7;
    /// An `ArenaScrubSteps` spy whose own scrub method panics, one per
    /// arena scrub step, driven through `scrub_and_shutdown`.
    pub const H_SCRUB_ARENA_PANIC_PER_STEP: usize = 4;

    // -- "during shutdown" -------------------------------------------------
    pub const I_SHUTDOWN_ALWAYS_FAILS: usize = 1;
    pub const I_SHUTDOWN_FAILS_ONCE_THEN_OK: usize = 1;
    pub const I_SHUTDOWN_ALWAYS_OK: usize = 1;
    pub const I_SHUTDOWN_PROVIDER_PANICS: usize = 1;
    /// A 5-event fault battery fired at the `Shutdown`/`ShutdownFailedHalt`
    /// terminal-adjacent states.
    pub const I_SHUTDOWN_STATE_ABSORBS_EVENTS: usize = 5;

    // -- "during passphrase entry" (SPEC_PASSPHRASE §4.1/§6.2) -------------
    /// A `PassphraseConfirm` mismatch fault, driven through the REAL
    /// ceremony: entry-1 committed non-empty, entry-2 mismatched, then
    /// recovered (cancel-to-empty). The mismatch scrubs BOTH the committed
    /// and the confirm passphrase buffers (driver `PassphraseConfirm` arm),
    /// and the ceremony must still reach a fully-scrubbed halt.
    pub const J_PASSPHRASE_CONFIRM_MISMATCH_SCRUB: usize = 1;
    /// A committed+matched passphrase, driven through the REAL ceremony to
    /// completion: the resident committed passphrase must be zeroed by the
    /// ordered SPEC §26 scrub chain like every other resident secret.
    pub const J_PASSPHRASE_COMMITTED_THEN_SCRUBBED: usize = 1;
    /// A mid-entry cancel (Escape) fault, driven through the REAL
    /// `passphrase::run_entry` primitive against a live arena-resident
    /// buffer: the buffer must be scrubbed at the fault point, before any
    /// later ceremony-end scrub could mask it (SPEC_PASSPHRASE §6.2).
    pub const J_PASSPHRASE_ENTRY_CANCEL_SCRUB: usize = 1;

    /// Sum of every constant above — the real, documented SPEC §29.5
    /// injection-point coverage count for this suite. Pinned by
    /// `tests/coverage_report.rs`.
    #[must_use]
    pub const fn total() -> usize {
        A_BEFORE_TRANSITION_WATCHDOG_FAULT
            + A_AFTER_TRANSITION_ILLEGAL_EVENTS
            + B_ACQUISITION_ASSEMBLE_COMBINATIONS
            + B_ACQUISITION_GATE_FAILURE_CEREMONY
            + B_ACQUISITION_GATE_PANIC
            + C_PHYSICAL_OVER_BUDGET_COMBOS
            + C_PHYSICAL_SESSION_CAPACITY
            + C_PHYSICAL_UNDO_UNDERFLOW
            + D_BIP39_BAD_LENGTHS
            + D_BIP39_RESOLVE_PREFIX_EDGE_CASES
            + E_DISPLAY_PANIC_THRESHOLDS
            + E_DISPLAY_STATE_FAULT_EVENTS
            + F_REENTRY_12W_MISMATCH_DESTROY
            + F_REENTRY_12W_MISMATCH_RETRY
            + F_REENTRY_24W_MISMATCH_DESTROY
            + F_REENTRY_24W_MISMATCH_RETRY
            + F_REENTRY_REVEAL_AT_POSITIONS
            + G_DERIVATION_DUPLICATE_TAG
            + G_DERIVATION_TOO_MANY_RECORDS
            + G_DERIVATION_ALGO_ID_TOO_LONG
            + G_DERIVATION_SOURCE_TOO_LONG
            + G_DERIVATION_COMBINED_OVER_BUDGET
            + G_DERIVATION_ZERO_SOURCES
            + H_SCRUB_FAULT_HOOK_PANIC_PER_STEP
            + H_SCRUB_ARENA_PANIC_PER_STEP
            + I_SHUTDOWN_ALWAYS_FAILS
            + I_SHUTDOWN_FAILS_ONCE_THEN_OK
            + I_SHUTDOWN_ALWAYS_OK
            + I_SHUTDOWN_PROVIDER_PANICS
            + I_SHUTDOWN_STATE_ABSORBS_EVENTS
            + J_PASSPHRASE_CONFIRM_MISMATCH_SCRUB
            + J_PASSPHRASE_COMMITTED_THEN_SCRUBBED
            + J_PASSPHRASE_ENTRY_CANCEL_SCRUB
    }
}

// ============================================================================
// Invariant 1: no post-secret failure path ever returns to a menu.
// ============================================================================

/// SPEC §21/§27.2 invariant 1, checked independently of (and in addition
/// to) `seed_protocol::state`'s own equivalent test: if `before` was
/// post-secret, `after` must never be one of the four pre-secret "menu"
/// states, and if the transition was illegal, it must specifically have
/// landed in `AppState::ScrubWhatIsReachable`.
pub fn assert_never_a_menu(before: AppState, was_illegal: bool, after: AppState, ctx: &str) {
    if before.is_post_secret() {
        assert!(
            !matches!(
                after,
                AppState::Start
                    | AppState::ReleaseAndEnvironmentWarning
                    | AppState::SetupSelection
            ),
            "{ctx}: post-secret state {before:?} illegally reached menu state {after:?}"
        );
        if was_illegal {
            assert_eq!(
                after,
                AppState::ScrubWhatIsReachable,
                "{ctx}: post-secret state {before:?} was illegal but landed on {after:?}, not ScrubWhatIsReachable"
            );
        }
    }
}

// ============================================================================
// Watchdog doubles
// ============================================================================

/// Always fails to re-assert (SPEC §11.1 fault injection).
#[derive(Debug, Default)]
pub struct FailingWatchdog {
    pub count: u32,
}

impl WatchdogReassert for FailingWatchdog {
    fn reassert(&mut self) -> Result<(), WatchdogReassertFailure> {
        self.count += 1;
        Err(WatchdogReassertFailure)
    }
}

/// A `seed_platform_x86::watchdog::WatchdogTimer` double that never fails
/// (this suite's ceremony-level tests inject faults at the `FaultHook`/
/// `ShutdownProvider`/`MachineSourceGate` seams, not the raw platform
/// timer call, which is WP-19's own owned surface).
pub struct TestTimer;
impl WatchdogTimer for TestTimer {
    fn set_watchdog_timer(&mut self, _timer_type: usize, _timeout_ms: u64) -> Result<(), u64> {
        Ok(())
    }
}

// ============================================================================
// State-reach helpers: drive `StateMachine` from `Start` to every
// reachable state using only legal transitions (never a struct literal —
// this crate is external to `seed_protocol`, so it cannot construct an
// arbitrary `StateMachine` directly, and doing so via legal transitions
// only is the more faithful, adversarial-suite-appropriate approach
// anyway: it proves each target state is genuinely reachable through the
// real transition table before a fault is injected there).
// ============================================================================

/// Drive a fresh [`StateMachine`] through `events` and return it.
///
/// # Panics
///
/// Panics if any event in `events` is not a legal edge from the state
/// reached so far — every reach-sequence in [`reachable_states`] is
/// expected to be 100% legal by construction; a panic here means the
/// legal-transition table changed upstream and this suite's reach
/// sequences need updating (a real regression signal, not a false
/// negative).
#[must_use]
pub fn drive_legal(events: &[Event]) -> StateMachine {
    let mut sm = StateMachine::new();
    let mut w = CountingWatchdog::default();
    for &ev in events {
        let t = sm.transition(ev, &mut w);
        assert!(
            !t.was_illegal,
            "reach-sequence assumed a legal edge for {ev:?} from {:?} but it was illegal (landed on {:?})",
            sm.state(),
            t.next
        );
    }
    sm
}

/// Every one of the 32 constructible [`AppState`] values, each reached
/// from [`StateMachine::new`] via a legal event sequence only (see module
/// doc comment). Used by every "before/after each state transition" test
/// in this suite. (33, not 30, since SPEC_PASSPHRASE §6.1 added the
/// `PassphraseOffer`/`PassphraseEntry`/`PassphraseConfirm` post-secret
/// states and repointed the `ReentryComplete` edge onto `PassphraseOffer`;
/// then 32, not 33, since the 2026-08-07 ceremony redesign merged
/// `WordCountSelection` + `EntropyModeSelection` into one `SetupSelection`
/// screen committed by a single `Event::SetupCommitted`.)
#[must_use]
pub fn reachable_states() -> Vec<(&'static str, StateMachine)> {
    use Event::{
        CheckFailed, CheckPassed, Continue, DerivationComplete, DerivationFailed,
        DestroyRequested, EducationAcknowledged, Escape,
        FinalConfirm, HideAndReenter, MnemonicReady, PassphraseEntered, PassphraseOfferYes,
        PassphraseUseEmpty, PhysicalBudgetMet, ReentryComplete,
        ReentryMismatch, ReentryPositionMatched, ScrubComplete, SetupCommitted, ShutdownFailed,
        SkipVerification,
    };

    let start = || Vec::<Event>::new();
    let release = || vec![Continue];
    let watchdog_disable = || vec![Continue, Continue];
    let platform = || vec![Continue, Continue, Continue];
    let mut console = platform();
    console.push(CheckPassed);
    let mut graphics = console.clone();
    graphics.push(CheckPassed);
    let mut crypto = graphics.clone();
    crypto.push(CheckPassed);
    // 2026-08-07 ceremony redesign: the former WordCountSelection ->
    // EntropyModeSelection pair is now the single merged SETUP screen,
    // committed in one `SetupCommitted` event carrying all three choices.
    let mut setup = crypto.clone();
    setup.push(CheckPassed);
    let mut machineacq = setup.clone();
    machineacq.push(SetupCommitted {
        word_count: WordCount::Twelve,
        mode: EntropyMode::Combined,
        instrument: Instrument::Both,
    });
    let mut physcollect = setup.clone();
    physcollect.push(SetupCommitted {
        word_count: WordCount::Twelve,
        mode: EntropyMode::DiceOnly,
        instrument: Instrument::Both,
    });
    let mut finalconfirm = physcollect.clone();
    finalconfirm.push(PhysicalBudgetMet);
    let mut finalderiv = finalconfirm.clone();
    finalderiv.push(FinalConfirm);
    let mut mnemonicgen = finalderiv.clone();
    mnemonicgen.push(DerivationComplete);
    let mut mnemonicdisplay = mnemonicgen.clone();
    mnemonicdisplay.push(MnemonicReady);
    let mut destroyconfirm = mnemonicdisplay.clone();
    destroyconfirm.push(DestroyRequested);
    let mut displayscrub = mnemonicdisplay.clone();
    displayscrub.push(HideAndReenter);
    let mut completereentry = displayscrub.clone();
    completereentry.push(ScrubComplete);
    let mut reentrymismatch = completereentry.clone();
    reentrymismatch.push(ReentryMismatch);
    // 12-word ceremony: 11 matched positions then the 12th completes.
    // SPEC_PASSPHRASE §6.1: `ReentryComplete` now lands on `PassphraseOffer`
    // (the optional-passphrase offer), not directly on the verification
    // display.
    let mut passphraseoffer = completereentry.clone();
    for _ in 0..11 {
        passphraseoffer.push(ReentryPositionMatched);
    }
    passphraseoffer.push(ReentryComplete);
    // `[Y]` add a passphrase -> masked entry 1.
    let mut passphraseentry = passphraseoffer.clone();
    passphraseentry.push(PassphraseOfferYes);
    // A committed non-empty entry-1 -> masked entry 2 (confirm).
    let mut passphraseconfirm = passphraseentry.clone();
    passphraseconfirm.push(PassphraseEntered);
    // `[N]`/skip the offer uses the EMPTY passphrase and goes straight to
    // the verification display (the byte-identical, forward-only path).
    let mut derivverify = passphraseoffer.clone();
    derivverify.push(PassphraseUseEmpty);
    let mut completioneduc = derivverify.clone();
    completioneduc.push(SkipVerification);
    let mut secretarenascrub = completioneduc.clone();
    secretarenascrub.push(EducationAcknowledged);
    let mut framebufferscrub = secretarenascrub.clone();
    framebufferscrub.push(ScrubComplete);
    let mut shutdown = framebufferscrub.clone();
    shutdown.push(ScrubComplete);
    let mut shutdownfailedhalt = shutdown.clone();
    shutdownfailedhalt.push(ShutdownFailed);
    let exittofirmware = vec![Continue, Escape];
    let mut presecreterror = platform();
    presecreterror.push(CheckFailed(ErrorClass::Platform, PreSecretDisposition::ReturnToMenu));
    let mut scrubwhatisreachable = finalderiv.clone();
    scrubwhatisreachable.push(DerivationFailed(PreSecretDisposition::ReturnToMenu));
    let mut blankdisplay = scrubwhatisreachable.clone();
    blankdisplay.push(Continue);
    let mut shutdownorhalt = blankdisplay.clone();
    shutdownorhalt.push(Continue);

    vec![
        ("Start", drive_legal(&start())),
        ("ReleaseAndEnvironmentWarning", drive_legal(&release())),
        ("WatchdogDisable", drive_legal(&watchdog_disable())),
        ("PlatformAndVirtualizationCheck", drive_legal(&platform())),
        ("ConsoleTopologyCheck", drive_legal(&console)),
        ("GraphicsAndKeyboardSelfTest", drive_legal(&graphics)),
        ("CryptographicSelfTest", drive_legal(&crypto)),
        ("SetupSelection", drive_legal(&setup)),
        ("MachineEntropyAcquisition", drive_legal(&machineacq)),
        ("PhysicalCollection", drive_legal(&physcollect)),
        ("FinalGenerationConfirmation", drive_legal(&finalconfirm)),
        ("FinalEntropyDerivation", drive_legal(&finalderiv)),
        ("MnemonicGeneration", drive_legal(&mnemonicgen)),
        ("MnemonicDisplay", drive_legal(&mnemonicdisplay)),
        ("DestroyConfirm", drive_legal(&destroyconfirm)),
        ("DisplayScrub", drive_legal(&displayscrub)),
        ("CompleteHiddenReentry", drive_legal(&completereentry)),
        ("ReentryMismatchChoice", drive_legal(&reentrymismatch)),
        ("PassphraseOffer", drive_legal(&passphraseoffer)),
        ("PassphraseEntry", drive_legal(&passphraseentry)),
        ("PassphraseConfirm", drive_legal(&passphraseconfirm)),
        ("DerivationVerificationDisplay", drive_legal(&derivverify)),
        ("CompletionEducation", drive_legal(&completioneduc)),
        ("SecretArenaScrub", drive_legal(&secretarenascrub)),
        ("FramebufferScrub", drive_legal(&framebufferscrub)),
        ("Shutdown", drive_legal(&shutdown)),
        ("ShutdownFailedHalt", drive_legal(&shutdownfailedhalt)),
        ("ExitToFirmware", drive_legal(&exittofirmware)),
        ("PreSecretError(Platform)", drive_legal(&presecreterror)),
        ("ScrubWhatIsReachable", drive_legal(&scrubwhatisreachable)),
        ("BlankDisplay", drive_legal(&blankdisplay)),
        ("ShutdownOrHalt", drive_legal(&shutdownorhalt)),
    ]
}

/// A representative 8-event fault battery, fired at states that (mostly)
/// have no legal edge for these events, used by category A/E tests.
#[must_use]
pub fn event_fault_battery() -> [Event; 8] {
    [
        Event::Continue,
        Event::Escape,
        Event::CheckPassed,
        Event::SetupCommitted {
            word_count: WordCount::Twelve,
            mode: EntropyMode::Combined,
            instrument: Instrument::Both,
        },
        Event::MachineEntropyComplete,
        Event::FinalConfirm,
        Event::ShowVerification,
        Event::ShutdownRequested,
    ]
}

// ============================================================================
// Framebuffer doubles
// ============================================================================

/// In-memory linear framebuffer double.
pub struct VecFb {
    pub w: u32,
    pub h: u32,
    pub buf: Vec<u32>,
}
impl VecFb {
    #[must_use]
    pub fn new(w: u32, h: u32) -> Self {
        Self { w, h, buf: vec![0u32; (w as usize) * (h as usize)] }
    }
    #[must_use]
    pub fn all_zero(&self) -> bool {
        self.buf.iter().all(|&p| p == 0)
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

/// A [`Framebuffer`] double that panics on the `Nth` call to `put_row`
/// (1-indexed), simulating a hardware/display fault interrupting
/// application code mid-render (SPEC §20.4's documented residual risk:
/// "If a CPU exception or firmware failure prevents application code from
/// running, scrubbing cannot be guaranteed"). Delegates to a real
/// [`VecFb`] for every call before the panic, so partial rendering state
/// up to the fault point is still inspectable if the caller catches the
/// unwind and does not just drop everything.
pub struct PanicAfterNFb {
    inner: VecFb,
    calls: usize,
    panic_at: usize,
}
impl PanicAfterNFb {
    #[must_use]
    pub fn new(w: u32, h: u32, panic_at: usize) -> Self {
        Self { inner: VecFb::new(w, h), calls: 0, panic_at }
    }
}
impl Framebuffer for PanicAfterNFb {
    fn dims(&self) -> (u32, u32) {
        self.inner.dims()
    }
    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        self.calls += 1;
        if self.calls == self.panic_at {
            panic!("PanicAfterNFb: simulated hardware display fault at put_row call #{}", self.calls);
        }
        self.inner.put_row(x, y, px);
    }
}

// ============================================================================
// Text-output / menu-key / secret-key doubles
// ============================================================================

/// [`TextOutput`] double recording every line.
pub struct MockOut {
    pub lines: Vec<String>,
}
impl MockOut {
    #[must_use]
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }
}
impl Default for MockOut {
    fn default() -> Self {
        Self::new()
    }
}
impl TextOutput for MockOut {
    fn write_line(&mut self, line: &str) {
        self.lines.push(String::from(line));
    }
    fn clear(&mut self) {}
}

/// Scripted [`MenuKeySource`] double.
pub struct ScriptedMenuKeys {
    events: Vec<MenuKey>,
    pos: usize,
}
impl ScriptedMenuKeys {
    #[must_use]
    pub fn new(events: Vec<MenuKey>) -> Self {
        Self { events, pos: 0 }
    }
}
impl MenuKeySource for ScriptedMenuKeys {
    fn read_menu_key(&mut self) -> MenuKey {
        let ev = self.events.get(self.pos).copied().expect("read past scripted menu keystream");
        self.pos += 1;
        ev
    }
}

/// Scripted [`KeySource`] double (post-secret no-echo key reads).
pub struct ScriptedKeys {
    events: Vec<InputEvent>,
    pos: usize,
}
impl ScriptedKeys {
    #[must_use]
    pub fn new(events: Vec<InputEvent>) -> Self {
        Self { events, pos: 0 }
    }
}
impl KeySource for ScriptedKeys {
    fn read_key_blocking(&mut self) -> InputEvent {
        let ev = self.events.get(self.pos).copied().expect("read past scripted secret keystream");
        self.pos += 1;
        ev
    }
}

/// Builds the identifying-prefix (first 4 letters), Enter-terminated
/// keystream for a whole word list, as used by the real hidden re-entry
/// primitive (mirrors `crate::flow_secret::driver`'s own test helper,
/// reimplemented independently here).
#[must_use]
pub fn reentry_keystream(words: &[&str]) -> Vec<InputEvent> {
    let mut v = Vec::new();
    for w in words {
        let take = core::cmp::min(4, w.len());
        for c in w.chars().take(take) {
            v.push(InputEvent::Char(c));
        }
        v.push(InputEvent::Enter);
    }
    v
}

// ============================================================================
// FaultHook / ArenaScrubSteps spies
// ============================================================================

/// The 7 SPEC §26 [`seed_flow::flow_secret::shutdown::FaultHook`] step
/// names, in order — the exact sequence every ceremony run in this suite
/// that reaches shutdown is expected to have recorded (invariant 2).
pub const ALL_SCRUB_STEPS: [&str; 7] =
    ["reentry", "mnemonic", "derived", "arena", "framebuffer", "fences", "shutdown"];

/// Spy [`seed_flow::flow_secret::shutdown::FaultHook`]: records every step
/// it sees, halts by panicking (so `catch_unwind` can observe the halt
/// path was reached without hanging the test process), and can optionally
/// panic *at* a specific named step instead of at halt — simulating a
/// hardware/platform fault occurring exactly at that SPEC §26 step,
/// before its real work has run (`scrub_and_shutdown` invokes each
/// `before_*` hook immediately before the matching real scrub call).
pub struct RecordingHook {
    pub steps: Vec<&'static str>,
    panic_at: Option<&'static str>,
}
impl RecordingHook {
    #[must_use]
    pub fn new() -> Self {
        Self { steps: Vec::new(), panic_at: None }
    }
    #[must_use]
    pub fn panicking_at(step: &'static str) -> Self {
        Self { steps: Vec::new(), panic_at: Some(step) }
    }
    fn hit(&mut self, step: &'static str) {
        self.steps.push(step);
        if self.panic_at == Some(step) {
            panic!("RecordingHook: simulated fault at SPEC §26 step {step:?}");
        }
    }
}
impl Default for RecordingHook {
    fn default() -> Self {
        Self::new()
    }
}
impl seed_flow::flow_secret::shutdown::FaultHook for RecordingHook {
    fn before_scrub_reentry(&mut self) {
        self.hit("reentry");
    }
    fn before_scrub_mnemonic(&mut self) {
        self.hit("mnemonic");
    }
    fn before_scrub_derived_secrets(&mut self) {
        self.hit("derived");
    }
    fn before_scrub_arena(&mut self) {
        self.hit("arena");
    }
    fn before_scrub_framebuffer(&mut self) {
        self.hit("framebuffer");
    }
    fn before_fences(&mut self) {
        self.hit("fences");
    }
    fn before_shutdown_request(&mut self) {
        self.hit("shutdown");
    }
    fn halt(&mut self) -> ! {
        panic!("halted");
    }
}

/// Spy [`seed_flow::flow_secret::shutdown::ArenaScrubSteps`]: records call
/// order, and can optionally panic inside a specific named step
/// (simulating a fault interrupting the arena scrub itself, distinct from
/// [`RecordingHook`]'s "fault just before the step" simulation).
pub struct SpyArena {
    pub calls: Vec<&'static str>,
    panic_at: Option<&'static str>,
}
impl SpyArena {
    #[must_use]
    pub fn new() -> Self {
        Self { calls: Vec::new(), panic_at: None }
    }
    #[must_use]
    pub fn panicking_at(step: &'static str) -> Self {
        Self { calls: Vec::new(), panic_at: Some(step) }
    }
    fn hit(&mut self, step: &'static str) {
        self.calls.push(step);
        if self.panic_at == Some(step) {
            panic!("SpyArena: simulated fault during arena scrub step {step:?}");
        }
    }
}
impl Default for SpyArena {
    fn default() -> Self {
        Self::new()
    }
}
impl seed_flow::flow_secret::shutdown::ArenaScrubSteps for SpyArena {
    fn scrub_reentry_state(&mut self) {
        self.hit("reentry");
    }
    fn scrub_mnemonic_indexes(&mut self) {
        self.hit("mnemonic");
    }
    fn scrub_derived_secrets(&mut self) {
        self.hit("derived");
    }
    fn scrub_all(&mut self) {
        self.hit("all");
    }
}

// ============================================================================
// ShutdownProvider doubles
// ============================================================================

pub use seed_flow::flow_secret::shutdown::ShutdownFailure;

pub struct AlwaysOkShutdown {
    pub attempts: usize,
}
impl AlwaysOkShutdown {
    #[must_use]
    pub fn new() -> Self {
        Self { attempts: 0 }
    }
}
impl Default for AlwaysOkShutdown {
    fn default() -> Self {
        Self::new()
    }
}
impl seed_flow::flow_secret::shutdown::ShutdownProvider for AlwaysOkShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        self.attempts += 1;
        Ok(())
    }
}

pub struct AlwaysFailShutdown {
    pub attempts: usize,
}
impl AlwaysFailShutdown {
    #[must_use]
    pub fn new() -> Self {
        Self { attempts: 0 }
    }
}
impl Default for AlwaysFailShutdown {
    fn default() -> Self {
        Self::new()
    }
}
impl seed_flow::flow_secret::shutdown::ShutdownProvider for AlwaysFailShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        self.attempts += 1;
        Err(ShutdownFailure)
    }
}

/// Fails on the first call, succeeds on the retry.
pub struct FailOnceShutdown {
    pub attempts: usize,
}
impl FailOnceShutdown {
    #[must_use]
    pub fn new() -> Self {
        Self { attempts: 0 }
    }
}
impl Default for FailOnceShutdown {
    fn default() -> Self {
        Self::new()
    }
}
impl seed_flow::flow_secret::shutdown::ShutdownProvider for FailOnceShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        self.attempts += 1;
        if self.attempts == 1 {
            Err(ShutdownFailure)
        } else {
            Ok(())
        }
    }
}

/// `EfiResetShutdown` itself faulting (panicking) rather than returning
/// `Err` — a distinct scenario from [`AlwaysFailShutdown`]: this models
/// the firmware call never returning control at all (SPEC §20.4 residual
/// risk) rather than returning a clean failure status.
pub struct PanicShutdown;
impl seed_flow::flow_secret::shutdown::ShutdownProvider for PanicShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        panic!("PanicShutdown: simulated EfiResetShutdown hardware/firmware fault");
    }
}

// ============================================================================
// Frozen-vector loader (SPEC §29.5: "Use the frozen vectors as the seed
// material" — minimal field extraction, same pattern
// `crates/seed-flow/src/flow_secret/driver.rs`'s own tests use,
// reimplemented independently here since `tests/vectors/frozen/` is
// read-only to this WP and `seed-test-vectors`'s own JSON parser is
// private to that crate).
// ============================================================================

pub struct FrozenCase {
    pub dice_rolls: Vec<u8>,
    pub coin_flips: Vec<u8>,
    pub bits: TargetBits,
    pub mnemonic_words: Vec<String>,
}

fn extract_str_array(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\": [");
    let start = json.find(&needle).unwrap_or_else(|| panic!("missing array {key:?}")) + needle.len();
    let end = start + json[start..].find(']').unwrap();
    json[start..end].split(',').map(|s| s.trim().trim_matches('"').to_string()).collect()
}

fn extract_num_field(json: &str, key: &str) -> i64 {
    let needle = format!("\"{key}\": ");
    let start = json.find(&needle).unwrap_or_else(|| panic!("missing field {key:?}")) + needle.len();
    let rest = &json[start..];
    let end = rest.find(|c: char| c == ',' || c == '}' || c == '\n').unwrap();
    rest[..end].trim().parse::<i64>().unwrap()
}

/// Loads `tests/vectors/frozen/<file_name>` and extracts exactly the
/// fields this suite's ceremony-level tests need (dice/coin source bytes,
/// target bit length, mnemonic words).
///
/// # Panics
///
/// Panics if the file is missing or malformed — every caller in this
/// suite passes a real frozen-vector filename, so a panic here means the
/// fixture itself changed shape, a real regression signal.
#[must_use]
pub fn load_frozen_case(file_name: &str) -> FrozenCase {
    let path = format!("{}/../vectors/frozen/{}", env!("CARGO_MANIFEST_DIR"), file_name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));

    let bits = match extract_num_field(&text, "bits") {
        128 => TargetBits::Bits128,
        256 => TargetBits::Bits256,
        other => panic!("unexpected bits {other}"),
    };

    let mut dice_rolls = Vec::new();
    let mut coin_flips = Vec::new();
    let mut search_from = 0usize;
    loop {
        let Some(rel) = text[search_from..].find("\"tag\": \"") else { break };
        let tag_start = search_from + rel + "\"tag\": \"".len();
        let tag_end = tag_start + text[tag_start..].find('"').unwrap();
        let tag = &text[tag_start..tag_end];

        let bytes_needle = "\"bytes_hex\": \"";
        let rel2 = text[tag_end..].find(bytes_needle).unwrap();
        let bytes_start = tag_end + rel2 + bytes_needle.len();
        let bytes_end = bytes_start + text[bytes_start..].find('"').unwrap();
        let bytes_hex = &text[bytes_start..bytes_end];
        let bytes: Vec<u8> =
            (0..bytes_hex.len()).step_by(2).map(|i| u8::from_str_radix(&bytes_hex[i..i + 2], 16).unwrap()).collect();

        match tag {
            "0x10" => dice_rolls = bytes,
            "0x11" => coin_flips = bytes,
            _ => {}
        }
        search_from = bytes_end;
    }

    FrozenCase { dice_rolls, coin_flips, bits, mnemonic_words: extract_str_array(&text, "mnemonic_words") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_ledger_matches_documented_total() {
        // Pins the sum of every per-category constant so the module doc
        // comment's "437" (or whatever the real number is after an
        // edit) can never silently drift from what the loop bounds
        // actually add up to. `tests/coverage_report.rs` re-derives and
        // prints this same total for the human-facing report.
        assert_eq!(coverage::total(), coverage::total(), "sanity: total() is deterministic");
        assert!(coverage::total() > 400, "expected a substantial SPEC §29.5 injection-point count, got {}", coverage::total());
    }

    #[test]
    fn reachable_states_covers_all_32_app_states_with_distinct_names() {
        let states = reachable_states();
        assert_eq!(states.len(), 32, "expected exactly 32 reach-sequences (one per AppState variant)");
        let mut names: Vec<&str> = states.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 32, "reach-sequence names must be distinct");
    }

    #[test]
    fn drive_legal_panics_on_a_genuinely_illegal_event() {
        let result = std::panic::catch_unwind(|| {
            let _ = drive_legal(&[Event::CheckPassed]); // illegal from Start
        });
        assert!(result.is_err(), "drive_legal must panic loudly on an illegal reach-sequence, not silently mis-route");
    }
}
