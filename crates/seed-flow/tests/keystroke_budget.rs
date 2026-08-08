//! The 2026-08-07 ceremony redesign's headline UX metric, asserted in CI
//! (design doc §8 "Testing summary": "Integration: ... keystroke-count
//! assertion for the happy path (<= 9 blocking screens, <= 4
//! Enter-forward)").
//!
//! This test drives the **real** drivers — `seed_flow::driver::
//! run_pre_secret_flow` followed by `seed_flow::flow_secret::driver::
//! run_secret_flow` — end to end with a scripted key tape, through
//! recording surfaces, and counts what the user actually had to press.
//! Nothing about the flow is mocked around: every screen is rendered by
//! the production render functions, every key is consumed by the
//! production key handlers, and the run ends where a real ceremony ends
//! (the SPEC §26 scrub-and-shutdown chain).
//!
//! # The happy path measured here
//!
//! Machine-only entropy, 24 words, keyboard self-test RUN (all 34 steps),
//! no passphrase (`[N]`), the Verify screen viewed as rendered (the
//! redesign shows it directly — no offer screen), `[Enter] Finish`,
//! `[Enter] Shut down`. Design doc §2's own measured baseline for exactly
//! this path was 173 keypresses across 21 blocking screen types, 16 of
//! them pure Enter-forward presses.
//!
//! # Counting method
//!
//! **The key tape is the measurement.** [`build_tape`] lists, in order,
//! every keystroke the ceremony consumes, each tagged with the [`Screen`]
//! it is pressed on and the [`Role`] it plays. Three properties make that
//! tagging faithful rather than self-fulfilling:
//!
//! 1. **No under-read.** The test asserts the tape was fully drained. A
//!    screen that stopped blocking would leave keys unconsumed and fail.
//! 2. **No over-read.** [`Recorder::read`] panics on overrun. A screen
//!    that started blocking (or an extra acknowledgement screen) would
//!    demand a key the tape does not have and fail.
//! 3. **Screens are really distinct renders.** Every recording surface
//!    logs a *screen clear* (`TextOutput::clear`, or the wide `theme::BG`
//!    scrub every `screens::*`/`flow_secret::*` renderer opens with). The
//!    test asserts at least one clear separates each tagged segment from
//!    the next, so two adjacent tags can never be one screen wearing two
//!    names.
//!
//! **"Blocking screen" = a screen that consumed at least one keypress.**
//! Consecutive keys carrying the same [`Screen`] tag are one blocking
//! screen; a re-render inside a segment (the self-test's per-step prompt,
//! re-entry's per-word progress) is the same screen, re-drawn. A screen
//! that consumes no key at all is not blocking and is not counted — that
//! is exactly the transient auto-gate checklist (design doc §4.2: "no
//! keypress consumed") and the machine-acquisition ticker.
//!
//! The keyboard self-test is counted **separately** from the ceremony
//! screens, per the accounting footnote on the design doc's §1 targets
//! table: the self-test is excluded on *both* sides of the before/after
//! comparison (20 -> 9 symmetric; 21 -> 10 with it counted on both
//! sides). That matches the doc's own Stage-2 arithmetic ("was 3 screens
//! + auto-gates -> 1 + test + 1 transient": one screen, plus *the test*,
//! plus one transient) and its "~135 keypresses" row, and it is the
//! honest reading for the one blocking step of the set that is optional —
//! SPEC.md §11.5 amendment / SPEC_MAIN_MENU.md §15 make it skippable with
//! `[S]`, in which case it blocks not at all. Both numbers are pinned
//! below, so neither reading can drift silently:
//! [`BLOCKING_SCREEN_BUDGET`] (9, the design target) and
//! [`BLOCKING_STEPS_INCLUDING_THE_KEYBOARD_TEST`] (10).
//!
//! **"Enter-forward press" = an `Enter` whose only effect is forward
//! acknowledgement** ([`Role::Forward`]). Enumerated exhaustively, with
//! every other `Enter` on the tape classified and justified:
//!
//! | Screen | Enter | Role | Why |
//! |---|---|---|---|
//! | Prepare | 1 | Forward | acknowledges the completed checklist |
//! | Device | 1 | Decision | `[Enter]` Yes-run-test vs `[S]` skip vs `[N]` decline — a three-way choice, not an acknowledgement |
//! | Keyboard test | 1 | Data | step 34 of the fixed self-test sequence |
//! | Setup | 1 | Forward | commits word count + mode + instrument (arguably a decision — counted as Forward, the conservative reading) |
//! | Hidden re-entry | 24 | Data | one word terminator per word (SPEC §23.1) |
//! | Verify | 1 | Forward | `[Enter] Finish` |
//! | Finish | 1 | Forward | `[Enter] Shut down` |
//!
//! Forward total: 4 (Prepare, Setup, Verify, Finish) — the design's
//! target set exactly.
//!
//! # Generate: `[Enter]` must not advance
//!
//! Design doc §4 Stage 5: "**`[G]` is the only arm key. `[Enter]` is
//! ignored.**" The tape therefore carries a deliberate `Enter` on the
//! Generate screen *before* the `[G]`
//! ([`Role::IgnoredOnPurpose`]) — an end-to-end restatement of
//! `screens::generate::tests::enter_never_generates`. Had that `Enter`
//! armed generation, the following `[G]` would have landed on the
//! mnemonic display screen (which ignores it), the `[H]` would have
//! landed elsewhere, and the run could not have reached shutdown with the
//! tape exactly drained. [`keystroke_budget_happy_path`] asserts it did.

use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use seed_core::arena::SecretArena;
use seed_core::contracts::{ArchId, Framebuffer, SourceTag};
use seed_flow::diagnostics::{
    CheckOutcome, ConsoleCheckResult, ConsoleGate, CryptoCheckResult, CryptoSelfTestGate,
    GraphicsCheckResult, GraphicsGate, GraphicsInfo, PlatformCheckResult, PlatformGate,
    PlatformInfo, PlatformInfoGate, SecureBootStatus,
};
use seed_flow::driver::{run_pre_secret_flow, Gates, PreSecretOutcome};
use seed_flow::entropy_avail::{MachineAvailabilityGate, SourceAvailability};
use seed_flow::flow_secret::driver::{run_secret_flow, SecretProviders};
use seed_flow::flow_secret::machine::{
    AcquiredSource, AcquiredSources, MachineAcquisitionError, MachineSourceGate,
};
use seed_flow::flow_secret::passphrase::PassphraseKeyboardPolicy;
use seed_flow::flow_secret::shutdown::{FaultHook, ShutdownFailure, ShutdownProvider};
use seed_flow::keys::{KeyboardSelfTestSkipPolicy, MenuKey};
use seed_flow::output::{FlowSurface, TextOutput};
use seed_platform_x86::input::{
    self_test_sequence, InputEvent, KeySource, SelfTestExpectation, SELF_TEST_LEN,
};
use seed_platform_x86::watchdog::{Watchdog, WatchdogTimer};
use seed_protocol::state::AppState;

/// Stand-in for an edition's `release::BUILD_ID`.
const BUILD_ID: &str = "build-test";

/// Design doc §1 target: "Blocking screens | 21 | **9**".
const BLOCKING_SCREEN_BUDGET: usize = 9;

/// Design doc §1 target: "Pure Enter-forward presses | 16 | **4**".
const ENTER_FORWARD_BUDGET: usize = 4;

/// The all-inclusive count, pinned so the keyboard self-test's separate
/// accounting (see the module doc comment) can never quietly hide a
/// regression: nine ceremony screens plus the optional 34-step keyboard
/// self-test.
const BLOCKING_STEPS_INCLUDING_THE_KEYBOARD_TEST: usize = BLOCKING_SCREEN_BUDGET + 1;

/// Design doc §1 target: "Total keypresses | 173 | ~135" — counted, like
/// that table's own arithmetic, over the ceremony's navigation plus the
/// SPEC §23.1 re-entry, with the 34-step keyboard self-test outside it
/// (see the module doc comment's "the self-test is counted separately"
/// note, and the check on this number in [`keystroke_budget_happy_path`],
/// which shows the target row only closes under that reading).
const TOTAL_KEYPRESS_BUDGET: usize = 135;

/// Design doc §1 baseline: the pre-redesign happy path.
const PRE_REDESIGN_KEYPRESSES: usize = 173;

/// Every keypress of the happy path that is neither a keyboard-self-test
/// step nor a re-entry keystroke: 4 Prepare + 1 Device + 4 Setup +
/// `[G]` + `[H]` + `[N]` + `[Enter] Finish` + `[Enter] Shut down`.
const NAVIGATION_KEYPRESSES: usize = 4 + 1 + 4 + 1 + 1 + 1 + 1 + 1;

/// The SPEC §23.1 hidden-re-entry cost: each word's identifying prefix
/// (up to four characters) plus its `Enter` terminator.
fn reentry_keypresses(words: &[String]) -> usize {
    words.iter().map(|w| w.chars().count().min(4) + 1).sum()
}

// ============================================================================
// The tape: every keystroke, tagged
// ============================================================================

/// One blocking screen of the happy path, in ceremony order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    /// Stage 1 PREPARE — warning body + three-item checklist.
    Prepare,
    /// Stage 2 DEVICE — display confirm + keyboard-test offer.
    Device,
    /// Stage 2's 34-step keyboard self-test (SPEC §11.5). Counted apart
    /// from the ceremony screens — see the module doc comment.
    KeyboardTest,
    /// Stage 3 SETUP — word count + entropy mode + instrument.
    Setup,
    /// Stage 5 GENERATE — composition + §8.4 warning + `[G]` arm.
    Generate,
    /// Stage 6 BACKUP — mnemonic display (`[H]`/`[D]`).
    MnemonicDisplay,
    /// Stage 6 BACKUP — hidden re-entry (SPEC §23.1).
    HiddenReentry,
    /// Stage 7 — the SPEC_PASSPHRASE §6.1 offer.
    Passphrase,
    /// Stage 7 — the Verify verdict screen.
    Verify,
    /// Stage 7 — the Finish screen.
    Finish,
}

impl Screen {
    /// Whether this screen counts toward [`BLOCKING_SCREEN_BUDGET`] (see
    /// the module doc comment for why the keyboard self-test does not).
    fn is_ceremony_screen(self) -> bool {
        self != Screen::KeyboardTest
    }
}

/// What one scripted keystroke is *for* — the classification the
/// Enter-forward budget is counted over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Pure forward acknowledgement: the screen offers nothing else this
    /// key could mean. Only these count toward [`ENTER_FORWARD_BUDGET`].
    Forward,
    /// A choice between distinct outcomes (including "which item to
    /// check", "which mode", "run the test vs skip it").
    Decision,
    /// Content: a self-test step, a re-entered mnemonic character, a word
    /// terminator.
    Data,
    /// A key the screen is REQUIRED to ignore — the Generate screen's
    /// `[Enter]` (design doc §4 Stage 5).
    IgnoredOnPurpose,
}

/// One scripted keystroke.
#[derive(Debug, Clone, Copy)]
struct Press {
    screen: Screen,
    key: MenuKey,
    role: Role,
}

const fn press(screen: Screen, key: MenuKey, role: Role) -> Press {
    Press { screen, key, role }
}

// ============================================================================
// Frozen vector (the mnemonic must be known in advance to script re-entry)
// ============================================================================

/// The RDSEED64 source bytes and resulting 24 mnemonic words of the
/// frozen `machine_rdseed_only_24w` case — the same fixture
/// `flow_secret::driver`'s own machine-only ceremony test uses, so this
/// test types a mnemonic the pipeline provably produces rather than one
/// this file asserts into existence.
struct FrozenCase {
    rdseed_bytes: Vec<u8>,
    mnemonic_words: Vec<String>,
}

fn load_frozen_case() -> FrozenCase {
    let path = std::format!(
        "{}/../../tests/vectors/frozen/machine_rdseed_only_24w.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| std::panic!("{path}: {e}"));

    let hex = between(&text, "\"bytes_hex\": \"", "\"");
    let rdseed_bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();

    let words = between(&text, "\"mnemonic_words\": [", "]");
    let mnemonic_words: Vec<String> = words
        .split(',')
        .map(|s| String::from(s.trim().trim_matches('"')))
        .collect();

    assert_eq!(rdseed_bytes.len(), 32, "24 words needs 256 bits of source");
    assert_eq!(mnemonic_words.len(), 24);
    FrozenCase { rdseed_bytes, mnemonic_words }
}

fn between<'a>(text: &'a str, open: &str, close: &str) -> &'a str {
    let start = text.find(open).unwrap_or_else(|| std::panic!("missing {open:?}")) + open.len();
    let end = start + text[start..].find(close).unwrap();
    &text[start..end]
}

// ============================================================================
// Tape construction
// ============================================================================

/// Stage 1 PREPARE: three DISTINCT commitment keypresses (SPEC amendment
/// §22.2 — no single keypress acknowledges everything), then `[Enter]`,
/// which the screen only honors once all three are checked.
fn prepare_segment(tape: &mut Vec<Press>) {
    for c in ['1', '2', '3'] {
        tape.push(press(Screen::Prepare, MenuKey::Char(c), Role::Decision));
    }
    tape.push(press(Screen::Prepare, MenuKey::Enter, Role::Forward));
}

/// Stage 2 DEVICE + the self-test itself. The DEVICE `[Enter]` is a
/// three-way choice (Enter / `[S]` skip / `[N]` decline), not a forward
/// acknowledgement. The 34 keys that follow are read verbatim from
/// `seed_platform_x86::input::self_test_sequence()` rather than
/// hand-copied, so the tape can never drift from the sequence under test.
fn device_segment(tape: &mut Vec<Press>) {
    tape.push(press(Screen::Device, MenuKey::Enter, Role::Decision));
    for expectation in self_test_sequence() {
        let key = match expectation {
            SelfTestExpectation::Char(c) => MenuKey::Char(c),
            SelfTestExpectation::Backspace => MenuKey::Backspace,
            SelfTestExpectation::Enter => MenuKey::Enter,
        };
        tape.push(press(Screen::KeyboardTest, key, Role::Data));
    }
}

/// Stage 3 SETUP: `[2]` = 24 words on the word-count row, `[S]` = down a
/// row, `[3]` = Machine only, `[Enter]` commits all three at once. The
/// instrument row is inert (and unreachable) for a non-physical mode.
fn setup_segment(tape: &mut Vec<Press>) {
    tape.push(press(Screen::Setup, MenuKey::Char('2'), Role::Decision));
    tape.push(press(Screen::Setup, MenuKey::Char('s'), Role::Decision));
    tape.push(press(Screen::Setup, MenuKey::Char('3'), Role::Decision));
    tape.push(press(Screen::Setup, MenuKey::Enter, Role::Forward));
}

/// Stage 5 GENERATE: the deliberate ignored `[Enter]` (see the module doc
/// comment), then the one arm key.
fn generate_segment(tape: &mut Vec<Press>) {
    tape.push(press(Screen::Generate, MenuKey::Enter, Role::IgnoredOnPurpose));
    tape.push(press(Screen::Generate, MenuKey::Char('g'), Role::Decision));
}

/// Stage 6 BACKUP + Stage 7: `[H]` hide-and-re-enter, the 24-word hidden
/// re-entry (identifying prefix + Enter per word, SPEC §23.1), `[N]` for
/// no passphrase, `[Enter] Finish`, `[Enter] Shut down`.
fn backup_and_verify_segment(tape: &mut Vec<Press>, words: &[String]) {
    tape.push(press(Screen::MnemonicDisplay, MenuKey::Char('h'), Role::Decision));
    for word in words {
        let take = core::cmp::min(4, word.len());
        for c in word.chars().take(take) {
            tape.push(press(Screen::HiddenReentry, MenuKey::Char(c), Role::Data));
        }
        tape.push(press(Screen::HiddenReentry, MenuKey::Enter, Role::Data));
    }
    tape.push(press(Screen::Passphrase, MenuKey::Char('n'), Role::Decision));
    tape.push(press(Screen::Verify, MenuKey::Enter, Role::Forward));
    tape.push(press(Screen::Finish, MenuKey::Enter, Role::Forward));
}

fn build_tape(words: &[String]) -> Vec<Press> {
    let mut tape = Vec::new();
    prepare_segment(&mut tape);
    device_segment(&mut tape);
    setup_segment(&mut tape);
    // Stage 4 ENTROPY, machine-only: acquisition consumes NO key (the
    // ticker is not a blocking screen).
    generate_segment(&mut tape);
    backup_and_verify_segment(&mut tape, words);
    tape
}

// ============================================================================
// Recording harness
// ============================================================================

/// One observed event, in the order the drivers produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observed {
    /// A screen was cleared — the opening act of every render function in
    /// `screens::*` and `flow_secret::*` (`TextOutput::clear`, or
    /// `seed_gop_ui::font::scrub_fill(fb, theme::BG)`).
    Clear,
    /// The tape entry at this index was consumed.
    Key(usize),
}

#[derive(Default)]
struct Recorder {
    tape: Vec<Press>,
    pos: usize,
    log: Vec<Observed>,
    /// Rolling fingerprint of every framebuffer paint since the previous
    /// key read — folded into [`Recorder::frames`] on each read.
    frame: u64,
    /// `frames[i]` fingerprints everything DRAWN between read `i - 1` and
    /// read `i`: what went on screen for key `i`.
    ///
    /// This is the only screen identity in this file derived from what
    /// was *rendered* rather than from tape position, and it is what lets
    /// [`enter_at_the_generate_screen_does_not_advance`] discriminate its
    /// target: two consecutive reads with equal, non-empty frames were
    /// served by the same screen re-rendering itself, whatever the tape
    /// tags claim.
    frames: Vec<u64>,
}

impl Recorder {
    fn read(&mut self) -> MenuKey {
        let press = self.tape.get(self.pos).copied().unwrap_or_else(|| {
            std::panic!(
                "the ceremony read past the scripted tape at index {}: a screen blocks that the \
                 keystroke budget does not account for",
                self.pos
            )
        });
        self.log.push(Observed::Key(self.pos));
        self.frames.push(self.frame);
        self.frame = 0;
        self.pos += 1;
        press.key
    }

    fn clear(&mut self) {
        self.log.push(Observed::Clear);
    }

    /// Fold one framebuffer paint into the current frame fingerprint:
    /// FNV-1a over the paint's origin and pixels, order-sensitive, so two
    /// frames are equal only if the same pixels were drawn in the same
    /// order.
    fn paint(&mut self, x: u32, y: u32, px: &[u32]) {
        let mut h = if self.frame == 0 { 0xcbf2_9ce4_8422_2325 } else { self.frame };
        let mut fold = |v: u64| {
            h ^= v;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        };
        fold(u64::from(x));
        fold(u64::from(y));
        for &p in px {
            fold(u64::from(p));
        }
        self.frame = h;
    }
}

type Shared = Rc<RefCell<Recorder>>;

/// Scripted key source. Implements only `KeySource`; `seed_flow::keys`'s
/// blanket impl makes it a `MenuKeySource` too, so ONE tape feeds the
/// pre-secret menu reads, the secret-phase menu reads and the post-secret
/// no-echo reads alike — which is what makes "the tape was exactly
/// drained" a statement about the whole ceremony.
struct TapeKeys(Shared);

impl KeySource for TapeKeys {
    fn read_key_blocking(&mut self) -> InputEvent {
        self.0.borrow_mut().read()
    }
}

/// Recording `Framebuffer` at the SPEC §11.4 800x600 floor. `put_row`
/// clips rather than panicking (the fit-audit in `seed_flow::output` owns
/// geometry; this test owns interaction cost).
struct RecFb {
    w: u32,
    h: u32,
    buf: Vec<u32>,
    log: Shared,
}

impl RecFb {
    fn new(log: Shared) -> Self {
        let w = seed_gop_ui::gop::mode::MIN_WIDTH;
        let h = seed_gop_ui::gop::mode::MIN_HEIGHT;
        Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)], log }
    }
}

impl Framebuffer for RecFb {
    fn dims(&self) -> (u32, u32) {
        (self.w, self.h)
    }

    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        // A wide run of pure `theme::BG` starting at the top-left pixel
        // is the leading `seed_gop_ui::font::scrub_fill(fb, theme::BG)`
        // of a screen render, and nothing else. (`scrub_fill` and
        // `panel::fill_rect` both emit their rows in 256-pixel chunks
        // from a fixed on-stack buffer, so "wide" is not "full width".)
        // Every band fill in `chrome` paints `PANEL`/`RULE`, every glyph
        // cell is at most two glyph-widths wide and never starts at
        // `(0, 0)`, and the QR's light modules are `QR_LIGHT`.
        const WIDER_THAN_ANY_GLYPH_CELL: usize = 64;
        if x == 0
            && y == 0
            && px.len() >= WIDER_THAN_ANY_GLYPH_CELL
            && px.iter().all(|&p| p == seed_gop_ui::theme::BG)
        {
            self.log.borrow_mut().clear();
        }
        self.log.borrow_mut().paint(x, y, px);
        if y >= self.h || x >= self.w {
            return;
        }
        let n = px.len().min((self.w - x) as usize);
        let start = (y as usize) * (self.w as usize) + (x as usize);
        self.buf[start..start + n].copy_from_slice(&px[..n]);
    }
}

/// Recording line-oriented output (SPEC §12.1 screens: the self-test step
/// screens, the machine-acquisition ticker, error/refusal screens).
struct RecTerm {
    log: Shared,
}

impl TextOutput for RecTerm {
    fn write_line(&mut self, _line: &str) {}
    fn clear(&mut self) {
        self.log.borrow_mut().clear();
    }
}

/// The pre-secret driver's one surface: both halves over the same log.
struct RecSurface {
    term: RecTerm,
    fb: RecFb,
}

impl TextOutput for RecSurface {
    fn write_line(&mut self, line: &str) {
        self.term.write_line(line);
    }
    fn clear(&mut self) {
        self.term.clear();
    }
}

impl FlowSurface for RecSurface {
    fn framebuffer(&mut self) -> &mut dyn Framebuffer {
        &mut self.fb
    }
}

// ============================================================================
// Provider doubles (every gate clean; RDSEED sole-source-approved)
// ============================================================================

struct OkTimer;
impl WatchdogTimer for OkTimer {
    fn set_watchdog_timer(&mut self, _timeout_seconds: usize, _code: u64) -> Result<(), u64> {
        Ok(())
    }
}

struct CleanGates;

impl PlatformGate for CleanGates {
    fn check(&mut self) -> PlatformCheckResult {
        PlatformCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: seed_protocol::state::ErrorClass::Platform,
            architecture_line: "x86-64",
            virt_summary: "No virtualization indicators detected -- not proof",
        }
    }
}
impl ConsoleGate for CleanGates {
    fn check(&mut self) -> ConsoleCheckResult {
        ConsoleCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: seed_protocol::state::ErrorClass::ConsoleTopology,
            con_out_paths: 1,
            con_in_paths: 1,
            summary_line: "Remote/serial paths      None detected -- not proof",
        }
    }
}
impl GraphicsGate for CleanGates {
    fn check(&mut self) -> GraphicsCheckResult {
        GraphicsCheckResult::Available(GraphicsInfo {
            width: 800,
            height: 600,
            device_path: seed_gop_ui::gop::device_path::DevicePathText::unavailable(),
        })
    }
}
impl CryptoSelfTestGate for CleanGates {
    fn check(&mut self) -> CryptoCheckResult {
        CryptoCheckResult { outcome: CheckOutcome::Clean }
    }
}
impl PlatformInfoGate for CleanGates {
    fn info(&mut self) -> PlatformInfo {
        PlatformInfo {
            secure_boot: SecureBootStatus::Enabled,
            entropy_policy_version: Some(1),
            production_markers_verified: true,
        }
    }
}

/// SPEC §18.2: `MachineOnly` needs a source that is approved AND
/// sole-source-approved — the shipped v1 policy's RDSEED shape.
struct SoleSourceRdseed;
impl MachineAvailabilityGate for SoleSourceRdseed {
    fn efi_rng(&mut self) -> SourceAvailability {
        SourceAvailability::default()
    }
    fn rdseed(&mut self) -> SourceAvailability {
        SourceAvailability { approved: true, sole_source_allowed: true }
    }
}

/// Acquires the frozen vector's RDSEED64 bytes.
struct FrozenRdseedGate {
    bytes: Vec<u8>,
}
impl MachineSourceGate for FrozenRdseedGate {
    fn acquire(
        &mut self,
        into: &mut AcquiredSources,
        _observer: &mut dyn seed_platform_x86::rng::progress::AcquisitionObserver,
    ) -> Result<(), MachineAcquisitionError> {
        into.push(
            AcquiredSource::new(SourceTag::X86Rdseed64, b"RDSEED64", &self.bytes)
                .expect("frozen RDSEED source fits"),
        );
        Ok(())
    }
}

struct CountingShutdown {
    attempts: Rc<RefCell<usize>>,
}
impl ShutdownProvider for CountingShutdown {
    fn request_shutdown(&mut self) -> Result<(), ShutdownFailure> {
        *self.attempts.borrow_mut() += 1;
        Ok(())
    }
}

/// Unwinds out of the non-returning halt so the test can assert on what
/// the run recorded (the established pattern in `flow_secret::driver`'s
/// own ceremony tests). The flag distinguishes *this* unwind from any
/// other panic — notably [`Recorder::read`]'s tape-overrun panic, which
/// must never be mistaken for a clean end of ceremony.
struct UnwindingHalt {
    reached: Rc<RefCell<bool>>,
}
impl FaultHook for UnwindingHalt {
    fn halt(&mut self) -> ! {
        *self.reached.borrow_mut() = true;
        std::panic!("halted");
    }
}

// ============================================================================
// The run
// ============================================================================

/// What one full ceremony run produced.
struct RunReport {
    /// The tape, so the assertions can classify what was consumed.
    tape: Vec<Press>,
    /// Every clear/key event, in order.
    log: Vec<Observed>,
    /// Render fingerprint per key read, in read order — see
    /// [`Recorder::frames`].
    frames: Vec<u64>,
    /// How many tape entries were consumed.
    consumed: usize,
    /// How many times `EfiResetShutdown` was requested.
    shutdowns: usize,
    /// Whether the run ended in the halt at the end of the SPEC §26
    /// scrub-and-shutdown chain.
    halted: bool,
    /// The state the pre-secret driver handed off in.
    handoff_state: AppState,
}

fn run_ceremony(tape: Vec<Press>, rdseed_bytes: Vec<u8>) -> RunReport {
    let shared: Shared =
        Rc::new(RefCell::new(Recorder { tape, ..Recorder::default() }));
    let shutdowns = Rc::new(RefCell::new(0usize));

    // ---- pre-secret: the REAL run_pre_secret_flow -------------------
    let mut surface =
        RecSurface { term: RecTerm { log: shared.clone() }, fb: RecFb::new(shared.clone()) };
    let mut keys = TapeKeys(shared.clone());
    let mut watchdog = Watchdog::new(OkTimer);

    let (mut machine, handoff_state, instrument, recap) = {
        let mut g_platform = CleanGates;
        let mut g_console = CleanGates;
        let mut g_graphics = CleanGates;
        let mut g_crypto = CleanGates;
        let mut g_info = CleanGates;
        let mut g_avail = SoleSourceRdseed;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_info,
            machine_availability: &mut g_avail,
            // The bootable editions' policy (SPEC.md §11.5 amendment):
            // skipping needs a second `[S]`. The happy path runs the test.
            keyboard_self_test_skip:
                KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
            build_id: BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut surface, &mut keys, &mut watchdog, &mut gates);
        assert_eq!(
            result.outcome,
            PreSecretOutcome::HandoffToSecretPhase,
            "the scripted happy path must reach the secret-phase hand-off"
        );
        (result.machine, result.machine.state(), result.instrument, result.recap)
    };

    // ---- secret phase: the REAL run_secret_flow ----------------------
    let mut term = RecTerm { log: shared.clone() };
    let mut fb = RecFb::new(shared.clone());
    let mut menu_keys = TapeKeys(shared.clone());
    let mut secret_keys = TapeKeys(shared.clone());
    let mut avail = SoleSourceRdseed;
    let mut mgate = FrozenRdseedGate { bytes: rdseed_bytes };
    let mut shutdown = CountingShutdown { attempts: shutdowns.clone() };
    let halt_reached = Rc::new(RefCell::new(false));
    let mut hook = UnwindingHalt { reached: halt_reached.clone() };
    let mut arena = SecretArena::new();
    let mut secret_watchdog = Watchdog::new(OkTimer);

    let halted = {
        let mut providers = SecretProviders {
            text_out: &mut term,
            menu_keys: &mut menu_keys,
            fb: &mut fb,
            secret_keys: &mut secret_keys,
            machine_availability: &mut avail,
            machine_gate: &mut mgate,
            shutdown: &mut shutdown,
            fault_hook: &mut hook,
            instrument,
            passphrase_policy: PassphraseKeyboardPolicy::HostKeyboardTrusted,
            build_id: BUILD_ID,
            recap,
        };
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_secret_flow(
                &mut machine,
                &mut arena,
                &mut secret_watchdog,
                ArchId::X86_64,
                1,
                &mut providers,
            )
        }));
        match unwound {
            // The driver returned instead of halting: no secret was ever
            // produced (an early refusal path). Never a happy path.
            Ok(outcome) => std::panic!("secret phase returned {outcome:?} instead of halting"),
            // Only `UnwindingHalt::halt` may swallow a panic here; a tape
            // overrun (or any other bug) must surface, not read as success.
            Err(payload) => {
                if !*halt_reached.borrow() {
                    std::panic::resume_unwind(payload);
                }
                true
            }
        }
    };

    let shutdowns = *shutdowns.borrow();
    let rec = shared.borrow();
    RunReport {
        tape: rec.tape.clone(),
        log: rec.log.clone(),
        frames: rec.frames.clone(),
        consumed: rec.pos,
        shutdowns,
        halted,
        handoff_state,
    }
}

impl RunReport {
    /// The blocking screens, in first-consumed order, with consecutive
    /// same-tag presses collapsed into one screen.
    fn blocking_screens(&self) -> Vec<Screen> {
        let mut out: Vec<Screen> = Vec::new();
        for &event in &self.log {
            if let Observed::Key(i) = event {
                let screen = self.tape[i].screen;
                if out.last() != Some(&screen) {
                    out.push(screen);
                }
            }
        }
        out
    }

    /// The tape entries in the order they were consumed. Index into this
    /// to line a press up with its [`RunReport::frames`] entry.
    fn reads(&self) -> Vec<Press> {
        self.log
            .iter()
            .filter_map(|e| match e {
                Observed::Key(i) => Some(self.tape[*i]),
                Observed::Clear => None,
            })
            .collect()
    }

    /// Read-order position of the first press matching `pred`.
    fn read_index(&self, pred: impl Fn(&Press) -> bool) -> usize {
        self.reads()
            .iter()
            .position(pred)
            .unwrap_or_else(|| std::panic!("no read matched"))
    }

    /// Every `Enter` consumed, with its role.
    fn enters(&self) -> Vec<(Screen, Role)> {
        self.log
            .iter()
            .filter_map(|event| match event {
                Observed::Key(i) => Some(self.tape[*i]),
                Observed::Clear => None,
            })
            .filter(|p| p.key == MenuKey::Enter)
            .map(|p| (p.screen, p.role))
            .collect()
    }

    /// Was there at least one screen clear between the last key of every
    /// blocking screen and the first key of the next one?
    fn unseparated_screen_boundaries(&self) -> Vec<(Screen, Screen)> {
        let mut out = Vec::new();
        let mut previous: Option<Screen> = None;
        let mut cleared_since_last_key = true;
        for &event in &self.log {
            match event {
                Observed::Clear => cleared_since_last_key = true,
                Observed::Key(i) => {
                    let screen = self.tape[i].screen;
                    if let Some(prev) = previous {
                        if prev != screen && !cleared_since_last_key {
                            out.push((prev, screen));
                        }
                    }
                    previous = Some(screen);
                    cleared_since_last_key = false;
                }
            }
        }
        out
    }
}

// ============================================================================
// The assertions
// ============================================================================

#[test]
fn keystroke_budget_happy_path() {
    let case = load_frozen_case();
    let tape = build_tape(&case.mnemonic_words);
    let scripted = tape.len();
    let report = run_ceremony(tape, case.rdseed_bytes);

    // The hand-off state proves this really is the machine-only path
    // (a physical mode would hand off at `PhysicalCollection`).
    assert_eq!(report.handoff_state, AppState::MachineEntropyAcquisition);

    // The ceremony ran to its real end: SPEC §26 scrub-and-shutdown.
    assert!(report.halted, "the ceremony must end in the SPEC §26 halt");
    assert_eq!(report.shutdowns, 1, "EfiResetShutdown requested exactly once");

    // (1) No under-read: every scripted key was needed. Together with
    //     `Recorder::read`'s panic on overrun, this pins the interaction
    //     cost exactly — see the module doc comment.
    assert_eq!(
        report.consumed, scripted,
        "the ceremony consumed {} of {scripted} scripted keys: a screen the budget accounts for \
         no longer blocks",
        report.consumed
    );

    // (2) Screens really are distinct renders.
    assert_eq!(
        report.unseparated_screen_boundaries(),
        std::vec![],
        "adjacent tagged screens were not separated by a screen clear"
    );

    // (3) Blocking screens.
    let screens = report.blocking_screens();
    assert_eq!(
        screens,
        std::vec![
            Screen::Prepare,
            Screen::Device,
            Screen::KeyboardTest,
            Screen::Setup,
            Screen::Generate,
            Screen::MnemonicDisplay,
            Screen::HiddenReentry,
            Screen::Passphrase,
            Screen::Verify,
            Screen::Finish,
        ],
        "the happy path's blocking screens changed"
    );
    assert_eq!(screens.len(), BLOCKING_STEPS_INCLUDING_THE_KEYBOARD_TEST);

    let ceremony_screens = screens.iter().filter(|s| s.is_ceremony_screen()).count();
    assert!(
        ceremony_screens <= BLOCKING_SCREEN_BUDGET,
        "happy path blocks on {ceremony_screens} ceremony screens, budget is \
         {BLOCKING_SCREEN_BUDGET} (design doc §1)"
    );

    // (4) Enter-forward presses.
    let enters = report.enters();
    let forward: Vec<Screen> =
        enters.iter().filter(|(_, r)| *r == Role::Forward).map(|(s, _)| *s).collect();
    assert_eq!(
        forward,
        std::vec![Screen::Prepare, Screen::Setup, Screen::Verify, Screen::Finish],
        "the Enter-forward set changed"
    );
    assert!(
        forward.len() <= ENTER_FORWARD_BUDGET,
        "happy path spends {} pure Enter-forward presses, budget is {ENTER_FORWARD_BUDGET} \
         (design doc §1)",
        forward.len()
    );

    // Every other Enter on the tape is classified, so none can hide.
    let non_forward = enters.len() - forward.len();
    assert_eq!(
        non_forward,
        1 /* Device: run-the-test choice */ + 1 /* self-test step 34 */
            + 24 /* re-entry word terminators */
            + 1, /* Generate: deliberately ignored */
        "an Enter appeared that this test does not classify"
    );

    // (5) Total keypresses (design doc §1's third row). The one
    //     deliberately-ignored Generate `[Enter]` on the tape is not part
    //     of the ceremony's cost, so it is subtracted here.
    let ceremony_keys = report.consumed - 1;
    let reentry = reentry_keypresses(&case.mnemonic_words);
    assert_eq!(
        ceremony_keys,
        NAVIGATION_KEYPRESSES + SELF_TEST_LEN + reentry,
        "total happy-path keypresses changed"
    );
    assert!(
        ceremony_keys < PRE_REDESIGN_KEYPRESSES,
        "the redesign must cost fewer keypresses than the {PRE_REDESIGN_KEYPRESSES}-press baseline"
    );
    // The design's "~135" target row only closes with the self-test's 34
    // steps outside the count — 120 re-entry keys + 15 navigation was its
    // arithmetic (design doc §1: "Security-ceremony keypresses (re-entry
    // etc.) | 120 | 120 — untouched"). This ceremony spends
    // NAVIGATION_KEYPRESSES = 14 navigation keys, so the row closes; the
    // same "the self-test is accounted separately" reading is what
    // BLOCKING_SCREEN_BUDGET is counted under.
    assert!(
        NAVIGATION_KEYPRESSES + reentry <= TOTAL_KEYPRESS_BUDGET,
        "happy path costs {} navigation + re-entry keypresses, budget is {TOTAL_KEYPRESS_BUDGET}",
        NAVIGATION_KEYPRESSES + reentry
    );
}

/// End-to-end restatement of `screens::generate::tests::enter_never_generates`
/// (design doc §4 Stage 5: "`[G]` is the only arm key. `[Enter]` is
/// ignored."): the tape presses `[Enter]` on the Generate screen before
/// `[G]`, and this test proves that press was inert.
///
/// # Why the evidence is render-derived
///
/// Comparing the two runs' `blocking_screens()` alone would NOT
/// discriminate: those tags come from tape position, not from what was on
/// screen, and the mnemonic-display read loop absorbs an unrecognized key
/// without re-rendering — so a hypothetical `Enter`-arms-generation bug
/// could, in principle, produce the same tag sequence. The load-bearing
/// assertion is therefore on [`RunReport::frames`]: the fingerprint of the
/// pixels drawn before the extra `[Enter]` and the fingerprint of the
/// pixels drawn before the following `[G]` must be **equal and non-empty**
/// — the Generate screen re-rendered itself and read again, which is what
/// "did not advance" means in pixels. The neighbouring frames must differ,
/// so the fingerprint is shown to discriminate rather than to match
/// everything.
///
/// A mutation probe confirms the test fails when the property is broken:
/// patching `screens::generate::handle_key` so `MenuKey::Enter` returns
/// `Some(GenerateOutcome::Generate)` makes this test fail (the frame before
/// `[G]` becomes the mnemonic display's, not the Generate screen's), and
/// `keystroke_budget_happy_path` fail with a tape over-read. Reverted after
/// running; see the task's fix report for the recorded output.
#[test]
fn enter_at_the_generate_screen_does_not_advance() {
    let case = load_frozen_case();

    let with_enter = run_ceremony(build_tape(&case.mnemonic_words), case.rdseed_bytes.clone());

    // -- the load-bearing, render-derived assertions -------------------
    let ignored_enter = with_enter.read_index(|p| p.role == Role::IgnoredOnPurpose);
    let arm_key = with_enter.read_index(|p| p.key == MenuKey::Char('g'));
    assert_eq!(arm_key, ignored_enter + 1, "the [G] must be the very next key read");

    let before_enter = with_enter.frames[ignored_enter];
    let before_arm = with_enter.frames[arm_key];
    assert_ne!(before_enter, 0, "no pixels were drawn before the ignored [Enter] was read");
    assert_eq!(
        before_arm, before_enter,
        "the screen that read [G] rendered different pixels than the one that read the \
         ignored [Enter] -- the [Enter] advanced the flow"
    );
    // The fingerprint discriminates: the next screen's frame differs.
    let next_screen = with_enter.read_index(|p| p.screen == Screen::MnemonicDisplay);
    assert_ne!(
        with_enter.frames[next_screen], before_arm,
        "the frame fingerprint does not distinguish two different screens"
    );

    // Screens are genuinely distinct renders in THIS run too, not only in
    // the sibling budget test.
    assert_eq!(
        with_enter.unseparated_screen_boundaries(),
        std::vec![],
        "adjacent tagged screens were not separated by a screen clear"
    );

    // -- and the whole ceremony is unchanged by the extra key ----------
    let mut without: Vec<Press> = build_tape(&case.mnemonic_words)
        .into_iter()
        .filter(|p| p.role != Role::IgnoredOnPurpose)
        .collect();
    let removed = build_tape(&case.mnemonic_words).len() - without.len();
    assert_eq!(removed, 1, "exactly one deliberately-ignored key on the tape");
    without.shrink_to_fit();
    let without_enter = run_ceremony(without, case.rdseed_bytes);

    assert_eq!(
        with_enter.blocking_screens(),
        without_enter.blocking_screens(),
        "the ignored Enter changed which screens blocked -- it advanced the flow"
    );
    assert_eq!(with_enter.consumed, without_enter.consumed + 1);
    assert!(with_enter.halted && without_enter.halted);
    assert_eq!(with_enter.shutdowns, 1);
    assert_eq!(without_enter.shutdowns, 1);
}
