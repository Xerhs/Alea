//! The desktop rehearsal ceremony (SPEC §4.3, §12, §17.4, §21-§26):
//! drives `seed_flow::run_pre_secret_flow` **unmodified** for the entire
//! secret-free pre-secret phase, then a WP-28-owned secret-phase driver
//! modeled closely on (and reusing every screen-rendering/input-reading
//! function from) `seed_flow::flow_secret::driver::run_secret_flow`, with
//! exactly one deliberate difference from that function: the derivation
//! step (`AppState::FinalEntropyDerivation`) always uses
//! [`crate::fixed_entropy::fixed_case`]'s bytes, never whatever the user
//! actually typed on the physical-entry rehearsal screen.
//!
//! # Why not call `run_secret_flow` itself
//!
//! `run_secret_flow` derives from the real `PhysicalStaging`/
//! `AcquiredSources` it collected (correct for the real ceremony, WP-26).
//! SPEC §4.3 requires the opposite here: "Have no real-entropy generation
//! mode" — the physical-entry screen must still *feel* real (live
//! dice/coin progress, undo, clear-all, budget gate, all reused verbatim
//! from `seed_flow::flow_secret::physical::run_physical_entry`) so the
//! rehearsal is honest practice for the real ceremony, but what actually
//! gets derived must always be one of exactly two published, audited
//! public test vectors. That one substitution cannot be expressed by
//! implementing `run_secret_flow`'s existing provider traits (its own
//! `derive` step is not itself a provider seam), so this module re-hosts
//! the rest of that function's state dispatch loop instead of calling it
//! — every individual screen function it calls (`screens::*`,
//! `physical::*`, `display::*`, `reentry::*`, `verification::*`,
//! `custom_path::*`, `shutdown::scrub_and_shutdown`,
//! `flow_secret::run_export_branch`) is still the exact same `seed-flow`
//! code the real UEFI ceremony uses, called the same way, in the same
//! order.
//!
//! # Making the fixed-entropy substitution obvious on screen
//!
//! Every screen already carries the permanent SPEC §4.3 watermark bands
//! (`crate::window` composites those every frame, above and below this
//! module's own rendering — see that module's doc comment). In addition:
//! the single first-run orientation screen ([`ORIENTATION_LINES`]) states
//! the fixed-public-vector substitution in full, in words, before anything
//! else happens (2026-08-07 ceremony redesign, design doc §5 — it absorbed
//! the former per-attempt `PUBLIC REHEARSAL` interstitial), and the
//! mnemonic-display screen itself is annotated with the exact frozen-vector
//! file name the displayed phrase always is
//! ([`render_fixed_vector_notice`]).

use seed_core::arena::SecretArena;
use seed_core::contracts::{ArchId, SourceTag, TargetBits, WordCount};
use seed_core::pipeline::{derive_final_entropy, ExtendedVerificationValues, SourceInput};
use seed_platform_x86::watchdog::{Watchdog, WatchdogTimer};
use seed_protocol::state::{
    AppState, Event, PreSecretDisposition, StateMachine, WatchdogReassert, WatchdogReassertFailure,
};

use seed_flow::entropy_avail::compute_mode_availability;
use seed_flow::flow_secret::composition::{CompositionModel, MachineTagSet};
use seed_flow::flow_secret::custom_path;
use seed_flow::flow_secret::derive::FlowTranscript;
use seed_flow::flow_secret::derive::{compute_extended_verification, scrub_after_verification};
use seed_flow::flow_secret::display;
use seed_flow::flow_secret::gop_screen::draw_lines;
use seed_flow::flow_secret::passphrase::{self, PassphraseKeyboardPolicy};
use seed_flow::flow_secret::physical::{self, PhysicalEntryOutcome, PhysicalStaging};
use seed_flow::flow_secret::reentry;
use seed_flow::flow_secret::shutdown::{self, FaultHook};
use seed_flow::flow_secret::verification;
use seed_flow::keys::{read_continue_or_escape, ContinueOrEscape, MenuKeySource};
use seed_flow::output::TextOutput;
use seed_flow::screens;
use seed_flow::{run_pre_secret_flow, Gates, PreSecretOutcome};
use seed_platform_x86::input::{InputEvent, KeySource};

use crate::channel_keys::ChannelKeys;
use crate::fixed_entropy;
/// SPEC §4.1 build identifier, drawn permanently in every ceremony
/// screen's chrome header band (2026-08-07 ceremony redesign, design doc
/// §3.3) — the same value this edition's launcher About screen shows.
use crate::launcher::about::BUILD_ID;
use crate::providers::{DesktopFaultHook, DesktopGates, DesktopShutdown, DesktopWatchdogTimer};
use crate::shared_screen::{SharedFramebuffer, WindowTextOutput};

/// Watchdog adapter (mirrors `seed_flow`'s own private `SmWatchdog` —
/// duplicated here since that one is not `pub`).
struct SmWatchdog<'a, T: WatchdogTimer>(&'a mut Watchdog<T>);

impl<T: WatchdogTimer> WatchdogReassert for SmWatchdog<'_, T> {
    fn reassert(&mut self) -> Result<(), WatchdogReassertFailure> {
        self.0.reassert().map_err(|_| WatchdogReassertFailure)
    }
}

fn transition<T: WatchdogTimer>(sm: &mut StateMachine, watchdog: &mut Watchdog<T>, event: Event) -> AppState {
    sm.transition(event, &mut SmWatchdog(watchdog)).next
}

fn word_count_len(word_count: Option<WordCount>) -> usize {
    match word_count {
        Some(WordCount::Twelve) => 12,
        Some(WordCount::TwentyFour) => 24,
        None => 0,
    }
}

/// The desktop rehearsal edition's single first-run ORIENTATION screen,
/// shown exactly once before [`seed_flow::run_pre_secret_flow`] draws the
/// real Stage-1 Prepare screen.
///
/// 2026-08-07 ceremony redesign, design doc §5: "the desktop-only welcome
/// and rehearsal-notice screens merge into one orientation screen". Before
/// the merge this was two screens — a welcome shown once at the start, and
/// a `PUBLIC REHEARSAL` interstitial re-shown before EVERY physical-entry
/// attempt. Both sets of content live here now, so the SPEC §4.3 "no real
/// entropy" statement is still made in full, in words, before the user
/// touches anything — just not once per attempt, and not on a screen of
/// its own. (The permanent SPEC §4.3 watermark bands `crate::window`
/// composites above and below every frame are unchanged and remain the
/// always-on statement.)
///
/// Deliberately *not* a restatement of the SPEC §22.1 warning: that screen
/// states what the application does and that it cannot prove the
/// environment trustworthy; this one orients a first-time user of *this
/// edition specifically* -- that nothing here is the real ceremony -- and
/// gives one consolidated reminder of the key conventions that stay
/// constant across every later screen. Own wording throughout, verified
/// distinct from the SPEC §22.1 text by
/// [`tests::orientation_screen_does_not_duplicate_the_spec_opening_warning_wording`].
/// Calm, instructional copy only -- not SPEC-mandated wording, and never
/// a replacement for any screen `seed-flow` owns.
const ORIENTATION_LINES: &[&str] = &[
    "Welcome to Alea Test -- desktop rehearsal edition",
    "",
    "This is a safe practice run, not the real ceremony. Every phrase this",
    "window ever shows comes from a fixed PUBLIC test vector, never from",
    "real entropy -- so nothing you do here can protect (or endanger) real",
    "funds. A permanent banner at the top and bottom of the window says so",
    "on every screen, the whole time.",
    "",
    "You will practice entering dice rolls / coin flips exactly as the real",
    "ceremony works: live progress, undo, and a minimum-entropy budget gate",
    "all behave identically. But nothing you type changes what comes out --",
    "the phrase always comes from the fixed, published PUBLIC test",
    "transcript, so the result is a known test mnemonic every time.",
    "",
    "The key conventions stay the same throughout the rehearsal:",
    "  1-6        one die roll        H or T      one coin flip",
    "  Enter      confirm / continue  Backspace   undo the last entry",
    "  Esc        leave before a phrase is generated",
    "  H / D / S  hide, destroy, or skip -- offered only where shown",
    "",
    // FIX (live desktop rehearsal, 2026-08-05): advertise the Back
    // affordance explicitly in the footer, consistent with every other
    // pre-secret screen's uniform `[Esc] Back` label (SPEC.md §21
    // amendment) — Esc here backs all the way out to the launcher menu,
    // the (Start/opening-warning, Back) edge, which the key legend above
    // already alludes to but the footer previously never surfaced.
    "[Enter] Continue      [Esc] Back",
];

/// Render [`ORIENTATION_LINES`] and clear beforehand (SPEC §12.2-style
/// "fixed layouts" discipline, applied here even though this pre-secret
/// screen only needs the plain [`TextOutput`] seam).
fn render_orientation(out: &mut dyn TextOutput) {
    out.clear();
    for line in ORIENTATION_LINES {
        out.write_line(line);
    }
}

fn render_fixed_vector_notice(fb: &mut dyn seed_core::contracts::Framebuffer, word_count: Option<WordCount>) {
    let file = match word_count {
        Some(WordCount::Twelve) => fixed_entropy::VECTOR_FILE_12W,
        Some(WordCount::TwentyFour) => fixed_entropy::VECTOR_FILE_24W,
        None => "?",
    };
    let x = seed_gop_ui::font::GLYPH_WIDTH * 2;
    let y = 4 * (seed_gop_ui::font::GLYPH_HEIGHT * 2) + seed_gop_ui::font::GLYPH_HEIGHT * 6;
    seed_gop_ui::font::draw_text(
        fb,
        x,
        y,
        &format!("This is published PUBLIC test vector \"{file}\" -- never use with funds."),
        seed_flow::flow_secret::gop_screen::SCREEN_STYLE,
    );
}

/// Final closing screen + non-returning idle loop, used both for the
/// SPEC §26 success path ([`ClosingScreenHook::halt`]) and for the
/// pre-secret "user exited before generating anything" path
/// ([`render_goodbye_and_idle_forever`]).
struct ClosingScreenHook {
    fb: SharedFramebuffer,
}

impl FaultHook for ClosingScreenHook {
    fn halt(&mut self) -> ! {
        draw_lines(&mut self.fb, &["Ceremony complete.", "", "You may now close this window."]);
        idle_forever()
    }
}

fn idle_forever() -> ! {
    loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn render_goodbye_and_idle_forever(fb: &mut SharedFramebuffer) -> ! {
    seed_gop_ui::font::scrub_fill(fb, 0);
    draw_lines(fb, &["You exited before generating anything.", "", "You may now close this window."]);
    idle_forever()
}

/// How [`run_rehearsal`] ended (SPEC.md §21 amendment, 2026-08-04:
/// "pre-secret Back navigation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RehearsalOutcome {
    /// Control returns to the caller — `crate::launcher::run`'s landing
    /// loop re-renders the main menu (SPEC_MAIN_MENU.md §4.5). Returned on
    /// two safe (no-real-secret) paths:
    ///
    /// - the user backed all the way out **before any secret existed** —
    ///   either Back at the very first ceremony screen
    ///   ([`seed_flow::PreSecretOutcome::BackToCaller`]) or Back a second
    ///   time from the re-shown entropy-mode panel of the merged
    ///   `AppState::SetupSelection` screen (landing on
    ///   `AppState::GraphicsAndKeyboardSelfTest`, which — like `seed_flow::
    ///   flow_secret::driver::run_secret_flow`'s own
    ///   `SecretFlowOutcome::BackBeforeSecret` — this function cannot
    ///   itself render, since it owns no mandatory-gate providers); or
    /// - the user chose `[M] Back to menu` at the DESKTOP-REHEARSAL-ONLY
    ///   post-ceremony screen, **after** the fixed-public-vector fake seed
    ///   was scrubbed ([`finish_rehearsal_post_ceremony`]). This return is
    ///   safe *only* because the rehearsal's "secret" is always a fixed
    ///   PUBLIC test vector (SPEC §4.3); the production UEFI editions must
    ///   never return to a menu after a real secret (SPEC §26) and do not.
    BackToMenu,
}

/// FIX (live desktop rehearsal, 2026-08-05): the user's choice at the
/// DESKTOP-REHEARSAL-ONLY post-ceremony screen. This screen and enum exist
/// only in this rehearsal crate; no UEFI edition offers a post-secret menu
/// return (SPEC §26 forbids it), and this fix touches neither the
/// production driver nor the `seed-protocol` state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostCeremonyChoice {
    /// `[M]` — the fake seed is already scrubbed; return to the launcher
    /// menu to rehearse again without relaunching.
    BackToMenu,
    /// `[Q]` — the pre-fix terminal behavior: shut down / idle forever,
    /// never returning (SPEC §26 step 8).
    Quit,
}

/// Render the DESKTOP-REHEARSAL-ONLY post-ceremony choice screen. The fake
/// seed has already been scrubbed by [`finish_rehearsal_post_ceremony`]
/// before this is shown.
fn render_post_ceremony_choice(fb: &mut dyn seed_core::contracts::Framebuffer) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    draw_lines(
        fb,
        &[
            "Rehearsal complete -- the fake test seed has been scrubbed.",
            "",
            "This is the practice edition on a fixed PUBLIC test vector, so it is",
            "safe to rehearse again from the main menu.",
            "",
            "[M] Back to menu      [Q] Quit",
        ],
    );
}

/// Block until the user chooses at the post-ceremony screen. `[M]` returns
/// to the menu; `[Q]` quits. Any other key is ignored (there is no default,
/// so a stray keypress never silently quits or returns).
fn read_post_ceremony_choice<K: KeySource + ?Sized>(keys: &mut K) -> PostCeremonyChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'m') => return PostCeremonyChoice::BackToMenu,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'q') => return PostCeremonyChoice::Quit,
            _ => {}
        }
    }
}

/// DESKTOP-REHEARSAL-ONLY terminal handler for the state machine's
/// post-secret shutdown states. Scrubs every fake-seed field first — in
/// SPEC §26 order, exactly as [`shutdown::scrub_and_shutdown`] does, and
/// unconditionally, so nothing survives on **either** branch — then offers
/// `[M] Back to menu` alongside `[Q] Quit`. `[M]` returns
/// [`RehearsalOutcome::BackToMenu`] (safe: the scrubbed material was only
/// ever a fixed PUBLIC test vector, SPEC §4.3); `[Q]` diverges into the
/// unchanged `scrub_and_shutdown` idle-forever path (SPEC §26 step 8).
///
/// This is the whole of FIX 4 and lives entirely in the rehearsal crate:
/// the production UEFI editions still route every post-secret shutdown
/// state straight to scrub→shutdown with no menu edge (SPEC §26).
fn finish_rehearsal_post_ceremony<K: KeySource + ?Sized>(
    arena: &mut SecretArena,
    fb: &mut SharedFramebuffer,
    keys: &mut K,
) -> RehearsalOutcome {
    // SPEC §26/§27.2 scrub order, run before any choice is offered.
    arena.scrub_reentry_state();
    arena.scrub_mnemonic_indexes();
    arena.scrub_derived_secrets();
    arena.scrub_all();
    seed_gop_ui::gop::scrub_sequence(fb, seed_gop_ui::gop::NEUTRAL_SCRUB_PATTERN);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    render_post_ceremony_choice(fb);
    match read_post_ceremony_choice(keys) {
        PostCeremonyChoice::BackToMenu => RehearsalOutcome::BackToMenu,
        PostCeremonyChoice::Quit => {
            // Unchanged terminal behavior: re-run the (idempotent) scrub and
            // idle forever via the closing screen, never returning.
            let mut shutdown_provider = DesktopShutdown;
            let mut hook = ClosingScreenHook { fb: fb.clone() };
            shutdown::scrub_and_shutdown(arena, fb, &mut shutdown_provider, &mut hook);
        }
    }
}

/// Entry point: runs the complete pre-secret + secret-phase rehearsal
/// ceremony against a shared pixel buffer and a channel-backed keystream
/// (both supplied by `crate::window`'s OS-window/event-loop thread, via
/// `crate::launcher::run`'s landing loop). Returns
/// [`RehearsalOutcome::BackToMenu`] on the two safe (no-real-secret)
/// return paths documented on that variant: backing out before any secret
/// exists (SPEC.md §21 amendment, 2026-08-04, "pre-secret Back
/// navigation"), or choosing `[M] Back to menu` at the
/// DESKTOP-REHEARSAL-ONLY post-ceremony screen after the fixed-public
/// fake seed has been scrubbed ([`finish_rehearsal_post_ceremony`]). Every
/// fatal/refusal path — and choosing `[Q] Quit` at that post-ceremony
/// screen — still ends in a non-returning idle loop (SPEC §21/§26's
/// "never return to a menu" discipline, inherited even though there is no
/// boot manager to avoid returning to on a desktop OS). The rehearsal only
/// ever operates on a fixed PUBLIC test vector (SPEC §4.3), which is the
/// sole reason the post-ceremony menu return is safe here and forbidden in
/// the production UEFI editions (SPEC §26).
pub fn run_rehearsal(
    fb: &mut SharedFramebuffer,
    keys: &mut ChannelKeys,
    window_width: u32,
    window_height: u32,
) -> RehearsalOutcome {
    let mut text_out = WindowTextOutput::new(fb.clone());
    let mut watchdog = Watchdog::new(DesktopWatchdogTimer);

    render_orientation(&mut text_out);
    // FIX (live desktop rehearsal, 2026-08-05): the orientation footer
    // advertises `[Esc] Back`, so honor it here — Esc here (still pre-secret,
    // no secret exists) backs straight out to the launcher menu, exactly like
    // Back at the Stage-1 Prepare screen that follows. Enter continues.
    if let ContinueOrEscape::Escape = read_continue_or_escape(keys) {
        return RehearsalOutcome::BackToMenu;
    }

    let base_gates = DesktopGates { window_width, window_height };
    let mut g_platform = base_gates;
    let mut g_console = base_gates;
    let mut g_graphics = base_gates;
    let mut g_crypto = base_gates;
    let mut g_platform_info = base_gates;
    let mut g_machine_availability = base_gates;
    let mut gates = Gates {
        platform: &mut g_platform,
        console: &mut g_console,
        graphics: &mut g_graphics,
        crypto: &mut g_crypto,
        platform_info: &mut g_platform_info,
        machine_availability: &mut g_machine_availability,
        // SPEC.md §11.5 amendment (2026-08-04): desktop rehearsal edition
        // -- the keyboard self-test is simply optional (offer + skip, no
        // extra ceremony). See `seed_flow::keys::KeyboardSelfTestSkipPolicy`.
        keyboard_self_test_skip: seed_flow::keys::KeyboardSelfTestSkipPolicy::DesktopOptional,
        // 2026-08-07 ceremony redesign (design doc §3.3/§4 Stage 1): the
        // build identifier lives permanently in every ceremony screen's
        // chrome header band. This edition already exposes the same value
        // through its launcher's About screen.
        build_id: crate::launcher::about::BUILD_ID,
    };

    let result = run_pre_secret_flow(&mut text_out, keys, &mut watchdog, &mut gates);

    // 2026-08-07 ceremony redesign: the SPEC §22.3 recap the Stage-3 Setup
    // screen showed, so backing into `AppState::SetupSelection` below
    // re-renders that identical screen rather than a partial one.
    let recap = result.recap;
    let mut sm = match result.outcome {
        PreSecretOutcome::HandoffToSecretPhase => result.machine,
        // SPEC.md §21 amendment: Back at the opening warning (the first
        // ceremony screen) hands control straight back to this
        // function's caller -- the desktop launcher's main menu.
        PreSecretOutcome::BackToCaller => return RehearsalOutcome::BackToMenu,
        PreSecretOutcome::ExitedToFirmware | PreSecretOutcome::Unexpected(_) => {
            render_goodbye_and_idle_forever(fb);
        }
    };

    let mut arena = SecretArena::new();
    let mut staging = PhysicalStaging::new();
    let mut word_count: Option<WordCount> = None;
    let mut position: usize = 0;
    // SPEC_DICE_COIN_VISUAL.md §22.5a: presentation-only leading-instrument
    // sub-selection, from the pre-secret flow; re-chosen on a Back re-pick.
    let mut instrument = result.instrument;

    loop {
        match sm.state() {
            AppState::MachineEntropyAcquisition => {
                // Structurally unreachable: `DesktopGates`'s
                // `MachineAvailabilityGate` impl always reports every
                // machine source unavailable (SPEC §4.3), so
                // `SetupSelection` never offers a mode that leads
                // here. See `crate::providers::NeverCalledMachineGate`
                // for the analogous structural guard on the trait-object
                // seam this crate does not otherwise wire up at all.
                unreachable!(
                    "seed-desktop-test: AppState::MachineEntropyAcquisition reached, but no \
                     machine source is ever available in this edition (SPEC §4.3)"
                );
            }

            AppState::PhysicalCollection => {
                // 2026-08-07 ceremony redesign (design doc §5): the
                // per-attempt `PUBLIC REHEARSAL` interstitial is gone — its
                // content moved into the single orientation screen shown once
                // at the start, and the permanent watermark bands
                // `crate::window` composites every frame still state the same
                // thing continuously.
                let target = sm.target_bits().expect("word count must be chosen before physical collection");
                let mut session = seed_protocol::physical::PhysicalSession::new();
                match physical::run_physical_entry(&mut text_out, keys, &mut session, &mut staging, target, instrument) {
                    PhysicalEntryOutcome::BudgetMet => {
                        transition(&mut sm, &mut watchdog, Event::PhysicalBudgetMet);
                    }
                    // SPEC.md §21 amendment: go back one step --
                    // `Event::Back`'s legal edge from `PhysicalCollection`
                    // is `SetupSelection`.
                    PhysicalEntryOutcome::Back => {
                        staging.scrub();
                        transition(&mut sm, &mut watchdog, Event::Back);
                    }
                }
            }

            // 2026-08-07 ceremony redesign, Stage 5 GENERATE: the same one
            // screen the production driver uses — composition summary + the
            // SPEC §8.4 required warning + the `[G]`-only arm confirm.
            // `[Enter]` is deliberately inert here (design doc §4 Stage 5).
            AppState::FinalGenerationConfirmation => {
                let target = sm.target_bits().expect("word count must be chosen before final confirmation");
                let wc_choice = match target {
                    TargetBits::Bits128 => WordCount::Twelve,
                    TargetBits::Bits256 => WordCount::TwentyFour,
                };
                let model = CompositionModel::new(
                    staging.dice_bytes().len() as u32,
                    staging.coin_bytes().len() as u32,
                    // This edition never has a machine source (SPEC §4.3).
                    MachineTagSet::new(),
                    target,
                    fixed_entropy::fixed_case(wc_choice).policy_version,
                );
                let ev = loop {
                    screens::generate::render(fb, &model, BUILD_ID);
                    match screens::generate::handle_key(keys.read_menu_key()) {
                        Some(screens::generate::GenerateOutcome::Generate) => break Event::FinalConfirm,
                        Some(screens::generate::GenerateOutcome::Back) => {
                            staging.scrub();
                            // SPEC.md §21 amendment: same target as the
                            // previous frozen `Event::Escape` edge
                            // (`SetupSelection`).
                            break Event::Back;
                        }
                        None => {}
                    }
                };
                transition(&mut sm, &mut watchdog, ev);
            }

            // SPEC.md §21 amendment: only reachable here via a prior Back
            // from `PhysicalCollection`/the Stage-5 Generate screen.
            //
            // 2026-08-07 ceremony redesign, Stage 3 SETUP: this re-renders
            // THE SAME merged Setup screen `run_pre_secret_flow` drew,
            // seeded from the setup the machine already holds, exactly like
            // `seed_flow::flow_secret::driver::run_secret_flow`. The §22.3
            // recap it folds in comes from `FlowResult::recap` — this
            // function owns none of the SPEC §11 mandatory-gate providers
            // that produced it.
            //
            // Escape fires `Event::Back`, whose legal edge from
            // `SetupSelection` is `AppState::GraphicsAndKeyboardSelfTest` --
            // Stage 2's DEVICE screen, which this function likewise cannot
            // render, so it ends the rehearsal instead, mirroring
            // `SecretFlowOutcome::BackBeforeSecret` for exactly the same
            // reason. No secret exists yet at any state this fires from
            // (SPEC §27.1, not §27.2).
            AppState::SetupSelection => {
                let Some(committed_word_count) = sm.word_count() else {
                    staging.scrub();
                    return RehearsalOutcome::BackToMenu;
                };
                let mut setup = screens::setup::SetupState::new();
                setup.words24 = committed_word_count == WordCount::TwentyFour;
                setup.instrument = instrument;
                let committed = loop {
                    let avail = compute_mode_availability(&mut g_machine_availability);
                    screens::setup::render(fb, &setup, &avail, &recap, BUILD_ID);
                    match setup.handle_key(keys.read_menu_key(), &avail) {
                        Some(screens::setup::SetupOutcome::Committed { words24, mode, instrument: instr }) => {
                            break Some((words24, mode, instr));
                        }
                        Some(screens::setup::SetupOutcome::Back) => break None,
                        None => {}
                    }
                };
                match committed {
                    Some((words24, mode, instr)) => {
                        instrument = instr;
                        let word_count = if words24 { WordCount::TwentyFour } else { WordCount::Twelve };
                        transition(
                            &mut sm,
                            &mut watchdog,
                            Event::SetupCommitted { word_count, mode, instrument: instr },
                        );
                    }
                    None => {
                        transition(&mut sm, &mut watchdog, Event::Back);
                        staging.scrub();
                        return RehearsalOutcome::BackToMenu;
                    }
                }
            }

            AppState::FinalEntropyDerivation => {
                let bits = sm.target_bits().expect("word count must be chosen before derivation");
                let wc_choice = match bits {
                    TargetBits::Bits128 => WordCount::Twelve,
                    TargetBits::Bits256 => WordCount::TwentyFour,
                };
                // SPEC §4.3: derive from the fixed public transcript ONLY
                // -- never from `staging` (see module doc comment).
                let fixed = fixed_entropy::fixed_case(wc_choice);
                let source = &fixed.sources[0];
                assert_eq!(source.tag, SourceTag::DiceRolls);
                let inputs = [SourceInput { tag: source.tag, algo_id: &source.algo, bytes: &source.bytes }];

                let result =
                    derive_final_entropy(&mut arena, FlowTranscript::new(), &inputs, ArchId::X86_64, bits, fixed.policy_version);

                // The user's rehearsal keystrokes are discarded here,
                // regardless of outcome (SPEC §19.4-style hygiene: this
                // crate scrubs staged input the moment it is no longer
                // needed, even though it was never live secret material).
                staging.scrub();

                match result {
                    Ok(wc) => {
                        word_count = Some(wc);
                        transition(&mut sm, &mut watchdog, Event::DerivationComplete);
                    }
                    Err(_) => {
                        transition(&mut sm, &mut watchdog, Event::DerivationFailed(PreSecretDisposition::ReturnToMenu));
                    }
                }
            }

            AppState::MnemonicGeneration => {
                transition(&mut sm, &mut watchdog, Event::MnemonicReady);
            }

            AppState::MnemonicDisplay => {
                let count = word_count_len(word_count);
                seed_gop_ui::font::scrub_fill(fb, 0);
                display::render_mnemonic_display(fb, arena.mnemonic_indexes(), count);
                render_fixed_vector_notice(fb, word_count);
                match display::read_display_choice(keys) {
                    display::DisplayChoice::Hide => {
                        transition(&mut sm, &mut watchdog, Event::HideAndReenter);
                    }
                    display::DisplayChoice::DestroyRequested => {
                        transition(&mut sm, &mut watchdog, Event::DestroyRequested);
                    }
                }
            }

            AppState::DestroyConfirm => {
                display::render_destroy_confirm(fb);
                // This desktop harness models the frozen state machine, not
                // the production driver's terminal menu-vs-power-off branch
                // (SPEC §26 amendment 2026-08-08); both destructive choices
                // drive the same `DestroyConfirmed` edge here.
                match display::read_destroy_double_confirm(keys) {
                    display::DestroyDecision::ReturnToMenu | display::DestroyDecision::PowerOff => {
                        transition(&mut sm, &mut watchdog, Event::DestroyConfirmed);
                    }
                    display::DestroyDecision::Cancel => {
                        transition(&mut sm, &mut watchdog, Event::Continue);
                    }
                }
            }

            AppState::DisplayScrub => {
                position = 0;
                seed_gop_ui::gop::scrub_sequence(fb, seed_gop_ui::gop::NEUTRAL_SCRUB_PATTERN);
                transition(&mut sm, &mut watchdog, Event::ScrubComplete);
            }

            AppState::CompleteHiddenReentry => {
                let count = word_count_len(word_count);
                let outcome =
                    reentry::read_and_check_one_word(fb, keys, position, count, &arena.mnemonic_indexes()[position]);
                match outcome {
                    reentry::ReentryOutcome::Matched => {
                        position += 1;
                        if position >= count {
                            transition(&mut sm, &mut watchdog, Event::ReentryComplete);
                        } else {
                            transition(&mut sm, &mut watchdog, Event::ReentryPositionMatched);
                        }
                    }
                    reentry::ReentryOutcome::Mismatch => {
                        transition(&mut sm, &mut watchdog, Event::ReentryMismatch);
                    }
                }
            }

            AppState::ReentryMismatchChoice => {
                reentry::render_mismatch_screen(fb);
                let ev = match reentry::read_mismatch_choice(keys) {
                    reentry::MismatchChoice::Retry => Event::RetryPosition,
                    reentry::MismatchChoice::RevealAgain => Event::RevealAgain,
                    reentry::MismatchChoice::Destroy => Event::DestroyRequested,
                };
                transition(&mut sm, &mut watchdog, ev);
            }

            // SPEC_PASSPHRASE §6.1/§8.3: desktop rehearsal edition — the
            // host keyboard delivers the full printable-ASCII charset, so
            // passphrase entry is available without a firmware self-test.
            AppState::PassphraseOffer => {
                let _policy = PassphraseKeyboardPolicy::HostKeyboardTrusted;
                passphrase::render_offer(fb, true);
                match passphrase::read_offer_choice(keys, true) {
                    passphrase::OfferChoice::No => {
                        arena.passphrase().scrub();
                        transition(&mut sm, &mut watchdog, Event::PassphraseUseEmpty);
                    }
                    passphrase::OfferChoice::Yes => {
                        transition(&mut sm, &mut watchdog, Event::PassphraseOfferYes);
                    }
                }
            }

            AppState::PassphraseEntry => {
                let outcome = passphrase::run_entry(
                    fb,
                    keys,
                    arena.passphrase(),
                    passphrase::EntryPhase::First,
                    None,
                );
                match outcome {
                    passphrase::EntryOutcome::Cancelled => {
                        transition(&mut sm, &mut watchdog, Event::PassphraseUseEmpty);
                    }
                    passphrase::EntryOutcome::Committed => {
                        if arena.passphrase().is_empty() {
                            transition(&mut sm, &mut watchdog, Event::PassphraseUseEmpty);
                        } else {
                            transition(&mut sm, &mut watchdog, Event::PassphraseEntered);
                        }
                    }
                }
            }

            AppState::PassphraseConfirm => {
                let outcome = passphrase::run_entry(
                    fb,
                    keys,
                    arena.passphrase_confirm(),
                    passphrase::EntryPhase::Confirm,
                    None,
                );
                match outcome {
                    passphrase::EntryOutcome::Cancelled => {
                        arena.passphrase().scrub();
                        arena.passphrase_confirm().scrub();
                        transition(&mut sm, &mut watchdog, Event::PassphraseConfirmMismatch);
                    }
                    passphrase::EntryOutcome::Committed => {
                        if arena.passphrase_confirm_matches() {
                            arena.passphrase_confirm().scrub();
                            transition(&mut sm, &mut watchdog, Event::PassphraseConfirmMatch);
                        } else {
                            arena.passphrase().scrub();
                            arena.passphrase_confirm().scrub();
                            transition(&mut sm, &mut watchdog, Event::PassphraseConfirmMismatch);
                        }
                    }
                }
            }

            // 2026-08-07 ceremony redesign, Stage 7 VERIFY: mirrors
            // `seed_flow::flow_secret::driver` exactly — the SPEC §24.1
            // offer screen is gone, `screens::verify` always shows the
            // verdict + fingerprint, `[V]` is the inline address reveal,
            // and `[M]`/`[B]`/`[X]` open the unchanged grid / custom-path
            // builder / export branch. SPEC_DERIVATION_OPTIONS §A.0 Model A
            // and its scrub point are unchanged: the whole bounded grid is
            // derived eagerly and the seed scrubbed BEFORE any input loop.
            // The grid/builder/export operate over the rehearsal's fixed
            // PUBLIC seed, which is correct for a rehearsal (§24.3:
            // addresses + fingerprint only, never a secret key).
            AppState::DerivationVerificationDisplay => {
                let wc = word_count.expect("mnemonic must be generated before verification");
                let mut ext = ExtendedVerificationValues::new();
                if compute_extended_verification(&mut arena, wc, &mut ext).is_err() {
                    verification::render_failed(fb);
                    verification::read_acknowledged(keys);
                    transition(&mut sm, &mut watchdog, Event::VerificationFailed);
                    continue;
                }
                scrub_after_verification(&mut arena);
                let passphrase_set = !arena.passphrase().is_empty();
                let values = ext.base_values();

                let mut vst = screens::verify::VerifyState::new();
                let mut derive_failed = false;
                loop {
                    screens::verify::render(fb, &vst, &values, passphrase_set, BUILD_ID);
                    let Some(outcome) = vst.handle_key(keys.read_key_blocking()) else {
                        continue;
                    };
                    match outcome {
                        screens::verify::VerifyOutcome::Finish => break,
                        screens::verify::VerifyOutcome::Grid => {
                            verification::run_more_options(fb, keys, &ext, passphrase_set);
                        }
                        screens::verify::VerifyOutcome::CustomPath => {
                            match custom_path::run_custom_builder(fb, keys, &mut arena, wc, passphrase_set) {
                                custom_path::BuilderOutcome::Back => {}
                                // Wallet-export design D6: a committed `48'`
                                // path opens the export screen's COSIGNER
                                // view, behind the same never-bypassed
                                // warning gate `[X]` goes through.
                                custom_path::BuilderOutcome::CosignerExport => {
                                    let mut st = screens::export::ExportState::new();
                                    st.kind = screens::export::ExportKind::Bip48Cosigner;
                                    if seed_flow::flow_secret::run_export_branch(
                                        fb, keys, &mut arena, wc, BUILD_ID, st,
                                    ) == seed_flow::flow_secret::ExportBranchOutcome::DeriveFailed
                                    {
                                        derive_failed = true;
                                        break;
                                    }
                                }
                                custom_path::BuilderOutcome::DeriveFailed => {
                                    derive_failed = true;
                                    break;
                                }
                            }
                        }
                        screens::verify::VerifyOutcome::Export => {
                            // SPEC §27.2/§27.3: a real derivation failure in
                            // the export branch takes the SAME fatal route
                            // the custom-path builder's `DeriveFailed` takes.
                            if seed_flow::flow_secret::run_export_branch(
                                fb,
                                keys,
                                &mut arena,
                                wc,
                                BUILD_ID,
                                screens::export::ExportState::new(),
                            ) == seed_flow::flow_secret::ExportBranchOutcome::DeriveFailed
                            {
                                derive_failed = true;
                                break;
                            }
                        }
                    }
                }
                if derive_failed {
                    verification::render_failed(fb);
                    verification::read_acknowledged(keys);
                    transition(&mut sm, &mut watchdog, Event::VerificationFailed);
                } else {
                    transition(&mut sm, &mut watchdog, Event::VerificationAcknowledged);
                }
            }

            // 2026-08-07 ceremony redesign, Stage 7 FINISH: the SPEC
            // §23.3 completion-education content (referenced verbatim from
            // `education.rs`) now lives on the Finish screen; `[Enter] Shut
            // down` starts the unchanged scrub chain.
            AppState::CompletionEducation => {
                screens::finish::render(fb, BUILD_ID);
                // This harness models the frozen state machine, not the
                // production driver's menu-vs-power-off terminal branch
                // (SPEC §26 amendment 2026-08-08); either Finish choice
                // ([Enter] power off, [M] menu) drives the same edge here.
                loop {
                    if screens::finish::finish_choice(keys.read_key_blocking()).is_some() {
                        break;
                    }
                }
                transition(&mut sm, &mut watchdog, Event::EducationAcknowledged);
            }

            AppState::SecretArenaScrub
            | AppState::FramebufferScrub
            | AppState::Shutdown
            | AppState::ShutdownFailedHalt
            | AppState::ScrubWhatIsReachable
            | AppState::BlankDisplay
            | AppState::ShutdownOrHalt => {
                // FIX (live desktop rehearsal, 2026-08-05): scrub the fake
                // seed and then offer `[M] Back to menu` alongside `[Q]
                // Quit`. DESKTOP-REHEARSAL-ONLY — see
                // `finish_rehearsal_post_ceremony`. `[M]` returns to the
                // launcher menu; `[Q]` keeps the pre-fix scrub→shutdown
                // idle-forever behavior. Production UEFI editions are
                // untouched (SPEC §26 post-secret scrub→shutdown only).
                return finish_rehearsal_post_ceremony(&mut arena, fb, keys);
            }

            AppState::ExitToFirmware => {
                staging.scrub();
                render_goodbye_and_idle_forever(fb);
            }

            other => {
                if other.is_post_secret() {
                    transition(&mut sm, &mut watchdog, Event::Fault(seed_protocol::state::ErrorClass::StateMachine));
                } else {
                    staging.scrub();
                    render_goodbye_and_idle_forever(fb);
                }
            }
        }
    }
}

// Kept referenced so `DesktopFaultHook` (used elsewhere as the plain
// no-op default) is not flagged unused if this module is the only
// consumer of `crate::providers` in a given build configuration.
#[allow(dead_code)]
fn _keep_desktop_fault_hook_referenced(_: &DesktopFaultHook) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal local [`TextOutput`] double (this crate cannot reach
    /// `seed_flow::output::test_support::MockTerminal` -- that module is
    /// `pub(crate)` to `seed-flow` -- so this mirrors its shape just
    /// enough to assert on rendered screen content).
    struct RecordingOutput {
        lines: std::vec::Vec<std::string::String>,
    }

    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: std::vec::Vec::new() }
        }
    }

    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {
            self.lines.clear();
        }
    }

    #[test]
    fn orientation_screen_reassures_and_shows_the_continue_hint() {
        let mut out = RecordingOutput::new();
        render_orientation(&mut out);
        let joined = out.lines.join("\n");
        assert!(
            joined.to_lowercase().contains("safe practice"),
            "orientation screen should plainly say this is a safe rehearsal, not the real ceremony"
        );
        assert!(joined.contains("[Enter] Continue"), "orientation screen must show how to continue");
    }

    /// 2026-08-07 ceremony redesign (design doc §5): the former per-attempt
    /// `PUBLIC REHEARSAL` interstitial is gone, so its SPEC §4.3 substance —
    /// that the phrase always comes from a fixed PUBLIC test transcript, and
    /// that entry practice otherwise behaves identically to the real
    /// ceremony — must be stated on the ONE orientation screen that replaced
    /// both screens.
    #[test]
    fn orientation_screen_absorbs_the_rehearsal_notice_substance() {
        let mut out = RecordingOutput::new();
        render_orientation(&mut out);
        let joined = out.lines.join("\n").to_lowercase();
        assert!(
            joined.contains("public test") || joined.contains("public test vector"),
            "the orientation screen must still say the phrase comes from a PUBLIC test vector"
        );
        assert!(
            joined.contains("nothing you type changes what comes out"),
            "the orientation screen must still say the user's entry does not affect the result"
        );
        assert!(
            joined.contains("undo") && joined.contains("budget"),
            "the orientation screen must still say entry practice behaves like the real ceremony"
        );
    }

    /// FIX (live desktop rehearsal): the orientation footer explicitly
    /// advertises the Back affordance, consistent with `seed-flow`'s uniform
    /// `[Esc] Back` label on every other pre-secret screen.
    #[test]
    fn orientation_screen_advertises_the_back_affordance() {
        let mut out = RecordingOutput::new();
        render_orientation(&mut out);
        let joined = out.lines.join("\n");
        assert!(
            joined.contains("[Esc] Back"),
            "orientation footer must advertise Back so the user knows they can leave to the menu"
        );
    }

    /// FIX (live desktop rehearsal): pressing Esc at the orientation screen
    /// (still pre-secret) backs all the way out to the launcher menu,
    /// honoring the advertised footer affordance.
    #[test]
    fn escape_at_orientation_screen_returns_back_to_menu() {
        use crate::channel_keys::KeyMsg;
        use crate::shared_screen::{SharedFramebuffer, CANVAS_WIDTH, CANVAS_HEIGHT};

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Escape).unwrap(); // orientation: Back -> BackToMenu, no Enter needed

        let mut fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
        let mut keys = ChannelKeys::new(rx);

        assert_eq!(
            run_rehearsal(&mut fb, &mut keys, CANVAS_WIDTH, CANVAS_HEIGHT),
            RehearsalOutcome::BackToMenu
        );
    }

    /// The SPEC §22.1 opening warning is `seed-flow`'s own text, shown
    /// immediately after this screen by the unmodified
    /// `run_pre_secret_flow` call. This screen must stay clearly
    /// distinct orientation copy, never a restatement of that exact
    /// sentence (see [`WELCOME_LINES`]'s doc comment).
    #[test]
    fn orientation_screen_does_not_duplicate_the_spec_opening_warning_wording() {
        let mut out = RecordingOutput::new();
        render_orientation(&mut out);
        let joined = out.lines.join("\n");
        assert!(!joined.contains("before your normal operating system loads"));
        assert!(!joined.contains("cannot prove that your firmware"));
    }

    #[test]
    fn orientation_screen_documents_every_key_convention_the_task_brief_names() {
        // dice 1-6, coin H/T, Enter, Backspace, Esc, [H]/[D]/[S].
        let mut out = RecordingOutput::new();
        render_orientation(&mut out);
        let joined = out.lines.join("\n");
        for needle in ["1-6", "H or T", "Enter", "Backspace", "Esc", "H / D / S"] {
            assert!(joined.contains(needle), "orientation screen is missing key hint {needle:?}");
        }
    }

    #[test]
    fn orientation_screen_clears_before_drawing() {
        let mut out = RecordingOutput::new();
        out.write_line("stale line from a previous screen");
        render_orientation(&mut out);
        assert!(!out.lines.iter().any(|l| l.contains("stale line")));
    }

    // ------------------------------------------------------------------
    // SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation"):
    // `run_rehearsal` returns `RehearsalOutcome::BackToMenu` instead of
    // idling forever once the user backs all the way out before any
    // secret exists -- confirmed end to end, through the real
    // `ChannelKeys`/`SharedFramebuffer` seams `crate::launcher` uses.
    // ------------------------------------------------------------------

    #[test]
    fn escape_at_opening_warning_returns_back_to_menu_instead_of_idling() {
        use crate::channel_keys::KeyMsg;
        use crate::shared_screen::{SharedFramebuffer, CANVAS_WIDTH, CANVAS_HEIGHT};

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Enter).unwrap(); // orientation screen
        tx.send(KeyMsg::Escape).unwrap(); // Stage 1 PREPARE: Back -> BackToCaller

        let mut fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
        let mut keys = ChannelKeys::new(rx);

        let outcome = run_rehearsal(&mut fb, &mut keys, CANVAS_WIDTH, CANVAS_HEIGHT);
        assert_eq!(outcome, RehearsalOutcome::BackToMenu);
    }

    #[test]
    fn run_rehearsal_is_reenterable_after_back_to_menu() {
        // Regression guard for the item-1-reentrancy fix (SPEC_MAIN_MENU.md
        // §6.2's own "Refactor note", resolved by the SPEC.md §21
        // amendment): a second `run_rehearsal` call over the same
        // `ChannelKeys` after a `BackToMenu` must behave identically, not
        // panic or hang.
        use crate::channel_keys::KeyMsg;
        use crate::shared_screen::{SharedFramebuffer, CANVAS_WIDTH, CANVAS_HEIGHT};

        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            tx.send(KeyMsg::Enter).unwrap(); // orientation screen
            tx.send(KeyMsg::Escape).unwrap(); // Stage 1 PREPARE: back to caller
        }

        let mut fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
        let mut keys = ChannelKeys::new(rx);

        assert_eq!(run_rehearsal(&mut fb, &mut keys, CANVAS_WIDTH, CANVAS_HEIGHT), RehearsalOutcome::BackToMenu);
        assert_eq!(run_rehearsal(&mut fb, &mut keys, CANVAS_WIDTH, CANVAS_HEIGHT), RehearsalOutcome::BackToMenu);
    }

    // ------------------------------------------------------------------
    // FIX 4 (live desktop rehearsal, 2026-08-05): DESKTOP-REHEARSAL-ONLY
    // post-ceremony `[M] Back to menu`. Scrubs the fixed-public fake seed
    // and returns `BackToMenu`; `[Q]` keeps the pre-fix idle-forever path.
    // Production UEFI editions are untouched (SPEC §26) — see
    // `production_post_secret_edges_are_scrub_then_shutdown_only` in
    // `seed-protocol`/`seed-flow`.
    // ------------------------------------------------------------------

    #[test]
    fn post_ceremony_choice_m_scrubs_the_fake_seed_and_returns_back_to_menu() {
        use crate::channel_keys::KeyMsg;
        use crate::shared_screen::{SharedFramebuffer, CANVAS_WIDTH, CANVAS_HEIGHT};

        let mut arena = SecretArena::new();
        // Plant non-zero fake-seed material so we can prove it is scrubbed.
        arena.mnemonic_indexes()[0] = 1234;
        arena.mnemonic_indexes()[1] = 2047;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Enter).unwrap(); // ignored at this screen
        tx.send(KeyMsg::Char('m')).unwrap(); // [M] Back to menu

        let mut fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
        let mut keys = ChannelKeys::new(rx);

        let outcome = finish_rehearsal_post_ceremony(&mut arena, &mut fb, &mut keys);
        assert_eq!(outcome, RehearsalOutcome::BackToMenu);
        // The fake seed was scrubbed before the choice was honored.
        assert!(
            arena.mnemonic_indexes().iter().all(|&w| w == 0),
            "the fake test seed must be scrubbed before returning to the menu"
        );
    }

    #[test]
    fn post_ceremony_choice_reader_requires_m_or_q_and_ignores_other_keys() {
        use crate::channel_keys::KeyMsg;
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Enter).unwrap(); // ignored
        tx.send(KeyMsg::Backspace).unwrap(); // ignored
        tx.send(KeyMsg::Char('m')).unwrap(); // honored
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(read_post_ceremony_choice(&mut keys), PostCeremonyChoice::BackToMenu);

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Char('q')).unwrap();
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(read_post_ceremony_choice(&mut keys), PostCeremonyChoice::Quit);
    }

    /// The post-ceremony `[M]` return is re-enterable: after it, a fresh
    /// `run_rehearsal` over the same keystream behaves identically (here,
    /// backing out again), never panicking or hanging.
    #[test]
    fn rehearsal_is_reenterable_after_post_ceremony_back_to_menu() {
        use crate::channel_keys::KeyMsg;
        use crate::shared_screen::{SharedFramebuffer, CANVAS_WIDTH, CANVAS_HEIGHT};

        let mut arena = SecretArena::new();
        arena.mnemonic_indexes()[0] = 42;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Char('m')).unwrap(); // post-ceremony: back to menu
        // A subsequent full rehearsal, backing out at the orientation screen.
        tx.send(KeyMsg::Escape).unwrap();

        let mut fb = SharedFramebuffer::new(CANVAS_WIDTH, CANVAS_HEIGHT);
        let mut keys = ChannelKeys::new(rx);

        assert_eq!(
            finish_rehearsal_post_ceremony(&mut arena, &mut fb, &mut keys),
            RehearsalOutcome::BackToMenu
        );
        assert_eq!(
            run_rehearsal(&mut fb, &mut keys, CANVAS_WIDTH, CANVAS_HEIGHT),
            RehearsalOutcome::BackToMenu
        );
    }

    // ------------------------------------------------------------------
    // GAP 1+2 (desktop rehearsal feature parity, 2026-08-05): the
    // ceremony's DerivationVerificationDisplay verify screen offers the
    // SAME [M] bounded-grid menu and [B] custom-path builder as the
    // production `flow_secret::driver`. The arm renders `screens::verify`
    // and dispatches through its `handle_key`, reusing `run_more_options`
    // + the `custom_path` builder verbatim over the rehearsal's fixed
    // PUBLIC seed (§24.3: addresses + fingerprint only).
    // ------------------------------------------------------------------

    /// Rebuild exactly the arena state the verify arm sees: run the same
    /// `derive_final_entropy` over the rehearsal's fixed PUBLIC 12-word
    /// vector that `AppState::FinalEntropyDerivation` runs. Also returns the
    /// reconstructed BIP39 seed (empty passphrase) for an independent
    /// cross-derivation.
    fn arena_and_seed_at_verification_12w() -> (SecretArena, WordCount, [u8; 64]) {
        let fixed = fixed_entropy::fixed_case(WordCount::Twelve);
        let source = &fixed.sources[0];
        let inputs = [SourceInput { tag: source.tag, algo_id: &source.algo, bytes: &source.bytes }];
        let mut arena = SecretArena::new();
        let wc = derive_final_entropy(
            &mut arena,
            FlowTranscript::new(),
            &inputs,
            ArchId::X86_64,
            TargetBits::Bits128,
            fixed.policy_version,
        )
        .expect("fixed public vector must derive");
        let mut seed = [0u8; 64];
        seed_core::bip39::mnemonic_to_seed(&arena.mnemonic_indexes()[..], WordCount::Twelve, &mut seed);
        (arena, wc, seed)
    }

    /// The verify screen's [M] bounded grid — the exact
    /// `ExtendedVerificationValues` the arm computes and hands to
    /// `run_more_options` — must reproduce the published defaults AND hold a
    /// correct non-default cell (task DoD).
    #[test]
    fn verify_more_options_grid_reproduces_defaults_and_a_known_nonzero_cell() {
        use crate::channel_keys::KeyMsg;
        use seed_core::contracts::PathStandard;

        let (mut arena, wc, seed) = arena_and_seed_at_verification_12w();
        let mut ext = ExtendedVerificationValues::new();
        compute_extended_verification(&mut arena, wc, &mut ext)
            .expect("extended verification must compute over the fixed public seed");

        // Independent anchor: the four §24.3 defaults (account0/index0) and
        // the master fingerprint MUST equal the published, on-disk frozen
        // vector `dice_only_12w_min_budget.json` (SPEC §24.3).
        let base = ext.base_values();
        assert_eq!(base.master_fingerprint, [0x82, 0xec, 0x24, 0xf2]);
        let default_of = |std_: PathStandard| ext.address(std_, 0, 0, 0).and_then(|a| a.as_str()).map(str::to_owned);
        assert_eq!(default_of(PathStandard::Bip44).as_deref(), Some("18W3Dbw93RQG5g6ozshfUrkvdBnHs9Qvda"));
        assert_eq!(default_of(PathStandard::Bip49).as_deref(), Some("38wB6tWmXCBTUBZMLp3jHxnH3h7GNPEHr4"));
        assert_eq!(default_of(PathStandard::Bip84).as_deref(), Some("bc1qhzz8ehuceuxygd5n4fhj02wyvvr7n4zgvm0s9m"));
        assert_eq!(
            default_of(PathStandard::Bip86).as_deref(),
            Some("bc1p8w2xpnyjvfupxc25d7u44qu3dnfzzkzlv92sctxc7as356k74tjsklsr7l")
        );

        // Non-default cell: account0/external/index1 BIP84 — what the [M]
        // menu shows after one `[S] Index +`. Cross-check it independently
        // via the already-verified custom-path derivation (`run_over`,
        // proven against published vectors in `launcher::custom_path`) over
        // the SAME reconstructed seed: both paths must agree, and the value
        // must differ from the index0 default.
        let grid_index1 = ext
            .address(PathStandard::Bip84, 0, 0, 1)
            .and_then(|a| a.as_str())
            .expect("account0/index1 BIP84 is within the pre-derived bounds")
            .to_owned();

        // Transcript-accumulating output (clear() is a no-op) so the result
        // screen survives `run_over`'s inter-screen clears.
        struct Transcript {
            lines: std::vec::Vec<std::string::String>,
        }
        impl TextOutput for Transcript {
            fn write_line(&mut self, line: &str) {
                self.lines.push(line.to_string());
            }
            fn clear(&mut self) {}
        }
        let mut out = Transcript { lines: std::vec::Vec::new() };
        let mut script = std::vec::Vec::new();
        script.extend("m/84'/0'/0'/0/1".chars().map(KeyMsg::Char));
        script.push(KeyMsg::Enter); // parse -> script picker
        script.push(KeyMsg::Char('3')); // P2WPKH -> result
        script.push(KeyMsg::Escape); // result -> entry
        script.push(KeyMsg::Escape); // entry -> exit
        let mut it = script.into_iter();
        crate::launcher::custom_path::run_over(&mut out, || it.next().unwrap_or(KeyMsg::Escape), &seed);
        let joined = out.lines.join("\n");

        assert!(
            joined.contains(&grid_index1),
            "the independent custom-path derivation of m/84'/0'/0'/0/1 must contain the grid's index1 cell {grid_index1}"
        );
        assert_ne!(
            grid_index1,
            "bc1qhzz8ehuceuxygd5n4fhj02wyvvr7n4zgvm0s9m",
            "the index1 cell must be a distinct non-default address, proving grid navigation works"
        );
    }

    /// The canonical verify-footer copy (`CONTINUE_MORE_AND_CUSTOM_PROMPT`)
    /// advertises BOTH [M] and [B], and the shared derivation-options reader
    /// (`read_default_choice`) maps those keys to the MoreOptions /
    /// CustomBuilder branches. (The live rehearsal arm renders
    /// `screens::verify` and dispatches through its `handle_key`; this test
    /// pins the shared footer contract and reader those affordances rest on.)
    #[test]
    fn verify_screen_advertises_and_handles_m_and_b() {
        use crate::channel_keys::KeyMsg;

        // Advertised on the canonical derivation-options footer copy.
        assert!(verification::CONTINUE_MORE_AND_CUSTOM_PROMPT.contains("[M]"));
        assert!(verification::CONTINUE_MORE_AND_CUSTOM_PROMPT.contains("[B]"));

        // Handled: [M] -> MoreOptions, [B] -> CustomBuilder, [Enter] ->
        // Continue, through the exact reader the ceremony arm calls.
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Char('m')).unwrap();
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(verification::read_default_choice(&mut keys), verification::DefaultChoice::MoreOptions);

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Char('b')).unwrap();
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(verification::read_default_choice(&mut keys), verification::DefaultChoice::CustomBuilder);

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(KeyMsg::Enter).unwrap();
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(verification::read_default_choice(&mut keys), verification::DefaultChoice::Continue);
    }
}
