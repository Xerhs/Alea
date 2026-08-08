//! The pre-secret flow driver (SPEC §21, §22.1-§22.5, §8.4, §11).
//!
//! [`run_pre_secret_flow`] drives `seed_protocol::state::StateMachine`
//! (WP-23, reused verbatim, never re-implemented) through every state from
//! `AppState::Start` to `AppState::SetupSelection` (the 2026-08-07 merged
//! word-count + entropy-mode + instrument setup screen), rendering the
//! matching screen at each
//! step and reading input through the [`crate::keys::MenuKeySource`]/
//! [`crate::output::TextOutput`] seams. It hands back a still-live
//! [`StateMachine`] once an entropy mode is chosen — `AppState::
//! MachineEntropyAcquisition`/`AppState::PhysicalCollection` and
//! everything after is WP-26's owned territory (SPEC §17.4's physical-
//! entry screen is the first screen after this crate's scope ends).
//!
//! # The watchdog call-ordering subtlety
//!
//! SPEC §11.1 requires the watchdog disabled "immediately after startup"
//! and re-asserted "at every major state transition." SPEC §21's own
//! state list puts an explicit `WATCHDOG_DISABLE` step *after* the
//! opening warning + acknowledgement screens. But
//! `seed_platform_x86::watchdog::Watchdog::reassert` is documented to
//! *panic* if called before `disable()` has succeeded once ("The state
//! machine must never reach a transition point without having disabled
//! the watchdog first"), and `StateMachine::transition` calls
//! `WatchdogReassert::reassert` on *every* call, including the very first
//! (`Start -> ReleaseAndEnvironmentWarning`).
//!
//! The only ordering that satisfies both frozen contracts is: call
//! `Watchdog::disable()` for real *before* the first `StateMachine::
//! transition` call of any kind (literally "immediately after startup"),
//! and treat `AppState::WatchdogDisable` — reached later, after the
//! opening/acknowledgement screens — as a confirmation checkpoint whose
//! firmware work already happened. This function does exactly that; see
//! its body for where.
//!
//! # Watchdog-reassert failures mid-gate
//!
//! `StateMachine::transition` itself detects a `WatchdogReassert` failure
//! and, pre-secret, routes to `AppState::PreSecretError(ErrorClass::
//! Watchdog)` regardless of the event that was being sent (SPEC §11.1).
//! `ErrorClass::Watchdog` is not one of the four SPEC §11 mandatory-gate
//! classes `StateMachine` special-cases for retry
//! (`ErrorClass::mandatory_gate_retry` returns `None` for it), so a
//! `Continue` from that error resumes at `AppState::SetupSelection` —
//! *skipping* whichever of the four mandatory gates had not yet completed
//! this run. This is a property of the frozen WP-23 state machine (not
//! editable here), and SPEC §11 is unconditional: "No secret entropy may
//! be collected until every mandatory startup gate passes." Editing
//! `seed-protocol` is out of scope, and inventing ad-hoc control flow that
//! bypasses the state machine is explicitly against this work package's
//! brief ("driven BY the WP-23 state machine, never ad-hoc control
//! flow").
//!
//! The fix that respects both constraints lives in the mandatory-gate
//! loop inside [`run_pre_secret_flow`] (see [`drive_gate_step`]): it never
//! treats "the state machine landed somewhere" as "this gate passed" —
//! after every gate's `step_recoverable` call it checks that the landing
//! state is *exactly* that gate's own retry target (a legitimate
//! `CheckFailed`-driven re-check) or its legitimate next-gate target, both
//! of which are states the state machine only ever reaches via its own
//! documented legal edges. Landing anywhere else — in practice only
//! reachable via the watchdog-jump described above — is never treated as
//! progress: [`force_exit_after_gate_bypass`] takes over and drives the
//! machine to `AppState::ExitToFirmware` using nothing but the state
//! machine's own legal `Event::Fault`/`Event::Escape` edges (SPEC §27.1),
//! so a run can never reach [`PreSecretOutcome::HandoffToSecretPhase`]
//! with an unverified gate. The user restarts and the full sequence
//! re-runs every gate from the top.

use seed_core::contracts::WordCount;
use seed_platform_x86::watchdog::{Watchdog, WatchdogTimer};
use seed_protocol::state::{
    AppState, ErrorClass, Event, PreSecretDisposition, StateMachine, WatchdogReassert,
    WatchdogReassertFailure,
};

use crate::diagnostics::{
    render_named_refusal, render_pre_secret_error_screen, render_self_test_step, ConsoleCheckResult,
    ConsoleGate, CryptoCheckResult, CryptoSelfTestGate, DiagRecap, GraphicsCheckResult,
    GraphicsGate, GraphicsInfo, PlatformCheckResult, PlatformGate, PlatformInfoGate,
};
use crate::entropy_avail::{compute_mode_availability, MachineAvailabilityGate};
use crate::flow_secret::physical::Instrument;
use crate::keys::{
    read_continue_or_escape, read_enter, run_keyboard_self_test, ContinueOrEscape,
    KeyboardSelfTestSkipPolicy, MenuKeySource,
};
use crate::output::{FlowSurface, TextOutput};
use crate::screens;

/// Adapter: `seed_platform_x86::watchdog::Watchdog<T>` implements
/// [`WatchdogReassert`] so `StateMachine::transition` can drive it
/// directly (SPEC §11.1's per-transition re-assertion hook).
struct SmWatchdog<'a, T: WatchdogTimer>(&'a mut Watchdog<T>);

impl<T: WatchdogTimer> WatchdogReassert for SmWatchdog<'_, T> {
    fn reassert(&mut self) -> Result<(), WatchdogReassertFailure> {
        self.0.reassert().map_err(|_| WatchdogReassertFailure)
    }
}

/// The bundle of provider traits [`run_pre_secret_flow`] needs beyond
/// `TextOutput`/`MenuKeySource`/`Watchdog` — one field per SPEC §22.3/
/// §22.5 machine-checked fact.
pub struct Gates<'a> {
    /// SPEC §11.2/§22.3: architecture + virtualization-indicator gate.
    pub platform: &'a mut dyn PlatformGate,
    /// SPEC §11.3/§22.3: console-topology gate.
    pub console: &'a mut dyn ConsoleGate,
    /// SPEC §11.4/§22.3: GOP mode-selection gate.
    pub graphics: &'a mut dyn GraphicsGate,
    /// SPEC §11.6/§22.3: cryptographic self-test gate.
    pub crypto: &'a mut dyn CryptoSelfTestGate,
    /// SPEC §22.3 informational items (Secure Boot, entropy policy
    /// version, production build markers) — never gates generation.
    pub platform_info: &'a mut dyn PlatformInfoGate,
    /// SPEC §18.2/§22.5: machine-source availability for mode gating.
    pub machine_availability: &'a mut dyn MachineAvailabilityGate,
    /// SPEC.md §11.5 amendment (2026-08-04) / SPEC_MAIN_MENU.md §15
    /// ("Keyboard-layout self-test: OPTIONAL/skippable"): this edition's
    /// keyboard self-test skip policy — see [`KeyboardSelfTestSkipPolicy`]'s
    /// own doc comment for what each variant means and why this is a plain
    /// field each edition's own `Gates`-construction call site sets,
    /// rather than a hidden runtime switch.
    pub keyboard_self_test_skip: KeyboardSelfTestSkipPolicy,
    /// SPEC §4.1 immutable build identifier (each edition's own
    /// `release::BUILD_ID`), drawn permanently in every redesigned screen's
    /// [`crate::chrome`] header band (design doc §3.3 + §4 Stage 1: "Build
    /// ID and version live in this screen's header permanently — fixes
    /// finding 5"). A plain field for the same reason
    /// [`Self::keyboard_self_test_skip`] is: it is per-edition constant
    /// data, not a runtime provider.
    pub build_id: &'static str,
}

/// How [`run_pre_secret_flow`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSecretOutcome {
    /// An entropy mode was chosen; `FlowResult::machine` is now at
    /// `AppState::MachineEntropyAcquisition` or
    /// `AppState::PhysicalCollection`, ready for WP-26 to continue driving
    /// it.
    HandoffToSecretPhase,
    /// The initial watchdog disable failed, or an unrecoverable
    /// pre-secret error/refusal was escalated to firmware exit (SPEC
    /// §22.1, §27.1) — a genuine refusal, not the user choosing to step
    /// back.
    ExitedToFirmware,
    /// SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation"):
    /// the user pressed Back at the very first ceremony screen (the
    /// opening warning) — `Event::Back` landed on `AppState::Start`,
    /// which has no predecessor. Control returns to the CALLER: a UEFI
    /// caller treats this exactly like [`PreSecretOutcome::ExitedToFirmware`]
    /// (SPEC §22.1's "Exit before generation"); the desktop launcher
    /// instead shows its main menu again.
    BackToCaller,
    /// Defense-in-depth only: this driver never intentionally sends an
    /// event that would land the machine anywhere outside the two
    /// expected handoff states, but `StateMachine` is a total function
    /// over every state and event (a real watchdog re-assert failure is
    /// firmware behavior, not a logic bug this crate could prevent by
    /// construction — see the module doc comment), so this arm exists to
    /// keep every match in this crate exhaustive without ever panicking.
    Unexpected(AppState),
}

/// The result of one [`run_pre_secret_flow`] call: the state machine, live
/// and ready for the caller to continue driving if `outcome` is
/// [`PreSecretOutcome::HandoffToSecretPhase`], plus how the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowResult {
    /// The WP-23 state machine, live, in whatever state the run ended in.
    pub machine: StateMachine,
    /// How the run ended (SPEC §21/§22.1/§27.1).
    pub outcome: PreSecretOutcome,
    /// SPEC_DICE_COIN_VISUAL.md §2.2/§22.5a: the physical-instrument
    /// sub-selection (Dice/Coins/Both) the user made just before the
    /// entropy mode was committed, threaded to the secret phase's
    /// `run_physical_entry` (`AppState::PhysicalCollection`). Presentation-
    /// only -- selects which picker/controls lead; both key families stay
    /// accepted (§2.3). `Instrument::default()` (`Both`) unless the run
    /// reached [`PreSecretOutcome::HandoffToSecretPhase`] via a physical-
    /// bearing mode.
    pub instrument: Instrument,
    /// SPEC_TPM_ENTROPY.md §11a (§22.5b): the machine-extras opt-ins
    /// committed on the same Stage-3 Setup screen, threaded to the secret
    /// phase's `MachineSourceGate::acquire` exactly like `instrument`
    /// above. All-OFF unless the run reached
    /// [`PreSecretOutcome::HandoffToSecretPhase`] with an explicit
    /// toggle.
    pub extras: crate::flow_secret::machine::MachineExtras,
    /// 2026-08-07 ceremony redesign: the condensed SPEC §22.3 diagnostics
    /// the merged Stage-3 Setup screen shows inline. Carried out of this
    /// function so the SECRET-phase driver can re-render that same one
    /// screen when the user backs into `AppState::SetupSelection` after
    /// hand-off, instead of the pre-redesign partial mode+instrument
    /// re-render it used to own (see
    /// `crate::flow_secret::SecretProviders::recap`).
    /// [`DiagRecap::unknown`] on every path that never reached the recap.
    pub recap: DiagRecap,
}

fn finish(machine: StateMachine, state: AppState, recap: DiagRecap) -> FlowResult {
    let outcome = match state {
        AppState::ExitToFirmware => PreSecretOutcome::ExitedToFirmware,
        // SPEC.md §21 amendment: `Event::Back` from `ReleaseAndEnvironmentWarning`
        // (the opening warning, the first ceremony screen) lands on
        // `AppState::Start`, which has no predecessor of its own —
        // that is this driver's "return to caller" signal.
        AppState::Start => PreSecretOutcome::BackToCaller,
        AppState::MachineEntropyAcquisition | AppState::PhysicalCollection => {
            PreSecretOutcome::HandoffToSecretPhase
        }
        other => PreSecretOutcome::Unexpected(other),
    };
    // The instrument and extras are set by the caller
    // (`run_pre_secret_flow`'s Stage-3 Setup arm) on the handoff path;
    // default `Both` / all-OFF everywhere else.
    FlowResult {
        machine,
        outcome,
        instrument: Instrument::default(),
        extras: crate::flow_secret::machine::MachineExtras::default(),
        recap,
    }
}

/// Drive one `event` through `sm` (watchdog re-assert included via
/// [`SmWatchdog`]). If the resulting state is `AppState::PreSecretError`,
/// render the generic recovery screen and let the user retry (`Continue`)
/// or exit (`Escape`), looping until the machine leaves the error state —
/// this uniformly absorbs both this driver's own intentional
/// `CheckFailed`/similar events *and* any watchdog-reassert failure the
/// state machine injects on its own (SPEC §11.1). Returns the state the
/// machine settled in once out of the error loop (which may be
/// `AppState::ExitToFirmware`).
fn step_recoverable<O: TextOutput, K: MenuKeySource, T: WatchdogTimer>(
    sm: &mut StateMachine,
    watchdog: &mut Watchdog<T>,
    out: &mut O,
    keys_src: &mut K,
    event: Event,
) -> AppState {
    let mut ev = event;
    loop {
        let t = sm.transition(ev, &mut SmWatchdog(watchdog));
        match t.next {
            AppState::PreSecretError(class) => {
                render_pre_secret_error_screen(out, class);
                ev = match read_continue_or_escape(keys_src) {
                    ContinueOrEscape::Continue => Event::Continue,
                    ContinueOrEscape::Escape => Event::Escape,
                };
            }
            other => return other,
        }
    }
}

/// Run the complete SPEC §22.1-§22.5 pre-secret flow.
///
/// # Watchdog ordering
///
/// See the module doc comment. This function calls `watchdog.disable()`
/// itself, first, before touching the state machine at all.
pub fn run_pre_secret_flow<O, K, T>(
    out: &mut O,
    keys_src: &mut K,
    watchdog: &mut Watchdog<T>,
    gates: &mut Gates<'_>,
) -> FlowResult
where
    O: FlowSurface,
    K: MenuKeySource,
    T: WatchdogTimer,
{
    // SPEC §11.1: "Immediately after startup, the application MUST
    // disable the UEFI watchdog." "Refuse generation if the initial
    // disablement call fails." No `StateMachine` exists to route this
    // through yet (see module doc comment), so a fresh, untouched
    // `StateMachine::new()` plus `ExitedToFirmware` is returned directly.
    if watchdog.disable().is_err() {
        out.clear();
        out.write_line("CANNOT CONTINUE");
        out.write_line("");
        out.write_line("The UEFI watchdog could not be disabled. Generation refused.");
        return FlowResult {
            machine: StateMachine::new(),
            outcome: PreSecretOutcome::ExitedToFirmware,
            instrument: Instrument::default(),
            extras: crate::flow_secret::machine::MachineExtras::default(),
            recap: DiagRecap::unknown(),
        };
    }

    let build = gates.build_id;
    let mut sm = StateMachine::new();

    // Start -> ReleaseAndEnvironmentWarning (always legal from a fresh
    // machine; `step_recoverable` still handles it uniformly in case a
    // watchdog reassert hiccup ever fires here too).
    let next = step_recoverable(&mut sm, watchdog, out, keys_src, Event::Continue);
    if next != AppState::ReleaseAndEnvironmentWarning {
        return finish(sm, next, DiagRecap::unknown());
    }

    // 2026-08-07 ceremony redesign, Stage 1 "PREPARE" (design doc §4 Stage
    // 1): the SPEC §22.1 opening warning and SPEC §22.2's three grouped
    // acknowledgement screens are ONE screen — the §22.1 warning body shown
    // once above a three-item checklist, each item requiring its own
    // distinct `[1]`/`[2]`/`[3]` keypress before `[Enter]` is enabled at
    // all (SPEC amendment §22.2: "three acknowledgements, each requiring a
    // distinct confirmation keypress" — the screen count is not
    // load-bearing, the "no single keypress acknowledges everything"
    // security intent is, and `screens::prepare::PrepareState` enforces it
    // including against key-repeat of one key).
    //
    // Still exactly one pass of `AppState::ReleaseAndEnvironmentWarning`:
    // the state machine never had a notion of "which panel", only "all
    // acknowledged" as a real transition. SPEC.md §21 amendment
    // (2026-08-04, "pre-secret Back navigation"): `[Esc]` here fires
    // `Event::Back`, whose legal edge from `ReleaseAndEnvironmentWarning`
    // is `AppState::Start` — this driver's "hand control back to the
    // caller" signal (see `PreSecretOutcome::BackToCaller`). The old
    // one-panel-at-a-time Back walk is gone with the panels themselves;
    // Back from the single screen still lands on exactly the same state.
    let mut prepare = screens::prepare::PrepareState::new();
    loop {
        screens::prepare::render(out.framebuffer(), &prepare, build);
        match prepare.handle_key(keys_src.read_menu_key()) {
            Some(screens::prepare::PrepareOutcome::Continue) => break,
            Some(screens::prepare::PrepareOutcome::Exit) => {
                let next = step_recoverable(&mut sm, watchdog, out, keys_src, Event::Back);
                return finish(sm, next, DiagRecap::unknown());
            }
            None => {}
        }
    }

    // Stage 1 acknowledged -> advance out of ReleaseAndEnvironmentWarning.
    let next = step_recoverable(&mut sm, watchdog, out, keys_src, Event::Continue);
    if next != AppState::WatchdogDisable {
        return finish(sm, next, DiagRecap::unknown());
    }

    // 2026-08-07 ceremony redesign, Stage 2's transient auto-gate checklist
    // (design doc §4.2: "The silent auto-gates (platform, console topology,
    // crypto self-test, watchdog) render as one transient checklist screen
    // with `OK` ticks appearing as each passes — no keypress consumed").
    // `AppState::WatchdogDisable` is the first tick: the real `disable()`
    // call already succeeded above (see module doc comment), so this state
    // is a confirmation checkpoint only — it consumes no key here either,
    // exactly as it did not before.
    let mut gate_list = screens::gates::GateList::new();
    gate_list.passed[3] = true;
    screens::gates::render_gates(out.framebuffer(), &gate_list, build);
    let next = step_recoverable(&mut sm, watchdog, out, keys_src, Event::Continue);
    if next != AppState::PlatformAndVirtualizationCheck {
        return finish(sm, next, DiagRecap::unknown());
    }

    // SPEC §11.2-§11.6 / §22.3: the four mandatory startup gates, driven
    // in order by `sm.state()` so a retry after a `PreSecretError` (which
    // resumes at the *same* gate, SPEC §11/§22.3: "'Inconclusive' on a
    // mandatory item disables generation") naturally re-runs exactly that
    // gate's check.
    let mut last_platform: Option<PlatformCheckResult> = None;
    let mut last_console: Option<ConsoleCheckResult> = None;
    let mut last_crypto: Option<CryptoCheckResult> = None;

    loop {
        match sm.state() {
            AppState::PlatformAndVirtualizationCheck => {
                let r = gates.platform.check();
                let ev = if r.outcome.blocks_generation() {
                    Event::CheckFailed(r.error_class, PreSecretDisposition::ReturnToMenu)
                } else {
                    gate_list.passed[0] = true;
                    screens::gates::render_gates(out.framebuffer(), &gate_list, build);
                    Event::CheckPassed
                };
                last_platform = Some(r);
                if let GateStep::Stop(next) = drive_gate_step(
                    &mut sm,
                    watchdog,
                    out,
                    keys_src,
                    ev,
                    AppState::PlatformAndVirtualizationCheck,
                    AppState::ConsoleTopologyCheck,
                ) {
                    return finish(sm, next, DiagRecap::unknown());
                }
            }
            AppState::ConsoleTopologyCheck => {
                let r = gates.console.check();
                let ev = if r.outcome.blocks_generation() {
                    Event::CheckFailed(r.error_class, PreSecretDisposition::ReturnToMenu)
                } else {
                    gate_list.passed[1] = true;
                    screens::gates::render_gates(out.framebuffer(), &gate_list, build);
                    Event::CheckPassed
                };
                last_console = Some(r);
                if let GateStep::Stop(next) = drive_gate_step(
                    &mut sm,
                    watchdog,
                    out,
                    keys_src,
                    ev,
                    AppState::ConsoleTopologyCheck,
                    AppState::GraphicsAndKeyboardSelfTest,
                ) {
                    return finish(sm, next, DiagRecap::unknown());
                }
            }
            AppState::GraphicsAndKeyboardSelfTest => {
                let next = run_graphics_and_keyboard_gate(
                    &mut sm,
                    watchdog,
                    out,
                    keys_src,
                    gates.graphics,
                    gates.keyboard_self_test_skip,
                    build,
                );
                if next == AppState::ExitToFirmware {
                    return finish(sm, next, DiagRecap::unknown());
                }
                if next != AppState::GraphicsAndKeyboardSelfTest
                    && next != AppState::CryptographicSelfTest
                {
                    // SPEC §11: see the module doc comment -- `next` is
                    // neither this gate's own retry target nor its
                    // legitimate next-gate target, so it must not be
                    // treated as progress.
                    let final_state = force_exit_after_gate_bypass(&mut sm, watchdog, out, keys_src);
                    return finish(sm, final_state, DiagRecap::unknown());
                }
            }
            AppState::CryptographicSelfTest => {
                let r = gates.crypto.check();
                let ev = if r.outcome.blocks_generation() {
                    Event::CheckFailed(ErrorClass::Cryptographic, PreSecretDisposition::ReturnToMenu)
                } else {
                    gate_list.passed[2] = true;
                    screens::gates::render_gates(out.framebuffer(), &gate_list, build);
                    Event::CheckPassed
                };
                last_crypto = Some(r);
                if let GateStep::Stop(next) = drive_gate_step(
                    &mut sm,
                    watchdog,
                    out,
                    keys_src,
                    ev,
                    AppState::CryptographicSelfTest,
                    AppState::SetupSelection,
                ) {
                    return finish(sm, next, DiagRecap::unknown());
                }
            }
            // 2026-08-07 ceremony redesign, Stage 3 "SETUP" (design doc §4
            // Stage 3): SPEC §22.3's diagnostics recap, SPEC §22.4's word
            // count, SPEC §22.5's entropy mode and SPEC_DICE_COIN_VISUAL.md
            // §22.5a's instrument sub-selection are now ONE screen
            // (`screens::setup`) — three stacked pickers, the selected
            // mode's mandated §18.2/§18.3/§6 warning inline in a WARN panel
            // that swaps with the selection, and the §22.3 recap folded in
            // as a CAPTION block with its own Enter-gate removed. Moving
            // between pickers fires no event at all; only `[Enter]` does,
            // as the single `Event::SetupCommitted` carrying all three
            // values.
            //
            // The standalone SPEC §8.4 required-warning screen that used to
            // sit immediately before this commit is GONE (SPEC amendment
            // §8.4, design doc §4 Stage 5): that warning now renders on the
            // Stage-5 Generate screen, still "before production generation"
            // and no longer a near-verbatim duplicate of the Stage-1
            // opening warning ~14 screens earlier.
            //
            // SPEC.md §21 amendment (2026-08-05, "Back skips automatic
            // gates"): `[Esc]` here fires `Event::Back`, whose legal edge
            // from `SetupSelection` skips the AUTOMATIC
            // `CryptographicSelfTest` gate and lands on
            // `AppState::GraphicsAndKeyboardSelfTest` — the last INTERACTIVE
            // pre-secret screen (Stage 2's DEVICE screen). The user visibly
            // returns there; proceeding forward re-runs the automatic crypto
            // gate and lands back on this one screen. With the four panels
            // collapsed into one there is no longer any "back one panel"
            // case at all — every `[Esc]` on this screen is that same single
            // documented edge.
            AppState::SetupSelection => {
                // SPEC §11: this state is only ever reached with all four
                // mandatory gates' own results in hand. Missing any of them
                // is exactly the gate-bypass condition
                // `force_exit_after_gate_bypass` exists for — never a reason
                // to render a recap that claims less than it knows.
                let (Some(p), Some(c), Some(x)) = (&last_platform, &last_console, &last_crypto)
                else {
                    let final_state = force_exit_after_gate_bypass(&mut sm, watchdog, out, keys_src);
                    return finish(sm, final_state, DiagRecap::unknown());
                };
                let platform_info = gates.platform_info.info();
                let recap = DiagRecap::from_parts(p, c, x, &platform_info);

                let mut setup = screens::setup::SetupState::new();
                loop {
                    // Re-run on every frame exactly as the pre-redesign mode
                    // panel re-ran it on every re-entry: availability is a
                    // live policy/hardware question, never cached across a
                    // user decision.
                    let avail = compute_mode_availability(gates.machine_availability);
                    screens::setup::render(out.framebuffer(), &setup, &avail, &recap, build);
                    match setup.handle_key(keys_src.read_menu_key(), &avail) {
                        Some(screens::setup::SetupOutcome::Committed {
                            words24,
                            mode,
                            instrument,
                            extras,
                        }) => {
                            let wc = if words24 { WordCount::TwentyFour } else { WordCount::Twelve };
                            // The ONE commit of the merged setup screen:
                            // word count + mode + instrument + §22.5b
                            // extras together.
                            let next = step_recoverable(
                                &mut sm,
                                watchdog,
                                out,
                                keys_src,
                                Event::SetupCommitted { word_count: wc, mode, instrument },
                            );
                            let mut result = finish(sm, next, recap);
                            result.instrument = instrument;
                            result.extras = extras;
                            return result;
                        }
                        Some(screens::setup::SetupOutcome::Back) => {
                            let next = step_recoverable(&mut sm, watchdog, out, keys_src, Event::Back);
                            if next != AppState::GraphicsAndKeyboardSelfTest {
                                return finish(sm, next, recap);
                            }
                            break;
                        }
                        None => {}
                    }
                }
            }

            other => return finish(sm, other, DiagRecap::unknown()),
        }
    }
}

/// SPEC §11.4/§11.5/§22.3, SPEC_MAIN_MENU.md §15: the graphics + keyboard
/// gate — 2026-08-07 ceremony redesign Stage 2 "DEVICE" (design doc §4.2).
/// Split out of [`run_pre_secret_flow`] only to keep that function's line
/// count sane; not part of the public API.
fn run_graphics_and_keyboard_gate<O: FlowSurface, K: MenuKeySource, T: WatchdogTimer>(
    sm: &mut StateMachine,
    watchdog: &mut Watchdog<T>,
    out: &mut O,
    keys_src: &mut K,
    graphics: &mut dyn GraphicsGate,
    keyboard_self_test_skip: KeyboardSelfTestSkipPolicy,
    build: &'static str,
) -> AppState {
    let failed =
        Event::CheckFailed(ErrorClass::GraphicsOrKeyboard, PreSecretDisposition::ReturnToMenu);
    match graphics.check() {
        GraphicsCheckResult::Refused(reason) => {
            render_named_refusal(out, "GRAPHICS OUTPUT REFUSED", reason);
            step_recoverable(sm, watchdog, out, keys_src, failed)
        }
        // The graphics gate's own machine-checked facts still decide
        // `Refused` vs `Available` exactly as before; what changed is only
        // that the SPEC §11.4 resolution/device-path DISPLAY, the SPEC §11.4
        // *confirmation* and the SPEC §11.5 keyboard-self-test *offer* are
        // now one screen instead of three (design doc §4.2). `info` is
        // threaded into that screen because SPEC §11.4's "Display its
        // resolution and device path before generation" is satisfied
        // nowhere else.
        GraphicsCheckResult::Available(info) => {
            let ev = match run_device_screen(out, keys_src, keyboard_self_test_skip, build, &info) {
                DeviceGateOutcome::PassedOrSkipped => Event::CheckPassed,
                // The fail-closed handling of an *attempted* self-test that
                // failed is unchanged by the SPEC.md §11.5 amendment
                // (SPEC.md: "nothing about the fail-closed handling of an
                // attempted self-test changes"), and declining the display
                // fails the gate exactly as the pre-redesign decline path did.
                DeviceGateOutcome::Failed | DeviceGateOutcome::NotMyDisplay => failed,
            };
            step_recoverable(sm, watchdog, out, keys_src, ev)
        }
    }
}

/// Outcome of [`run_device_screen`].
enum DeviceGateOutcome {
    /// The self-test ran and matched every expected keystroke, OR the
    /// user skipped it under whatever [`KeyboardSelfTestSkipPolicy`] the
    /// edition enforces. SPEC.md §11.5 amendment (SPEC_MAIN_MENU.md §15):
    /// skipping is a pre-secret choice that advances the gate exactly like
    /// a clean check — it is not itself a check result, but nothing in the
    /// frozen SPEC §21 state machine distinguishes "passed" from "not
    /// required to run" at this gate, and the amendment only removes the
    /// hard MUST-run, never adds a new state.
    PassedOrSkipped,
    /// The self-test was attempted and failed closed (SPEC §11.5,
    /// unchanged by the amendment).
    Failed,
    /// `[N]` — "this is not my local physical display" (SPEC §11.4's
    /// decline path).
    NotMyDisplay,
}

/// 2026-08-07 ceremony redesign Stage 2 (design doc §4.2): drive the one
/// combined display-confirm + keyboard-test-offer screen
/// ([`crate::screens::device`]) until it yields a terminal choice.
///
/// The SPEC.md §11.5 amendment's two skip policies both survive the merge:
///
/// * [`KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement`]
///   (the bootable editions) uses the screen's own two-press inline form —
///   the first `[S]` arms the inline `WARN` acknowledgement line, only a
///   second `[S]` confirms the skip, and any other key disarms. That is the
///   design doc's explicit replacement for the old full-screen
///   skip-acknowledgement: "the §11.5 amendment's 'skippable with
///   acknowledgement' is satisfied by the two-press inline form".
/// * [`KeyboardSelfTestSkipPolicy::DesktopOptional`] (the rehearsal edition,
///   where the amendment makes the test "simply optional") needs no
///   acknowledgement at all, so the FIRST `[S]` — the keypress that merely
///   arms the warning under the other policy — is itself the skip. The
///   acknowledgement copy is therefore never shown in that edition, exactly
///   as it never was before the merge.
fn run_device_screen<O: FlowSurface, K: MenuKeySource>(
    out: &mut O,
    keys_src: &mut K,
    policy: KeyboardSelfTestSkipPolicy,
    build: &'static str,
    info: &GraphicsInfo,
) -> DeviceGateOutcome {
    let mut st = screens::device::DeviceState::new();
    loop {
        screens::device::render(out.framebuffer(), &st, info, build);
        match st.handle_key(keys_src.read_menu_key()) {
            Some(screens::device::DeviceOutcome::RunTest) => {
                let result = run_keyboard_self_test(keys_src, |i, total, expected| {
                    render_self_test_step(out, i, total, expected);
                });
                return match result {
                    Ok(()) => DeviceGateOutcome::PassedOrSkipped,
                    Err(_) => DeviceGateOutcome::Failed,
                };
            }
            Some(screens::device::DeviceOutcome::SkipConfirmed) => {
                return DeviceGateOutcome::PassedOrSkipped;
            }
            Some(screens::device::DeviceOutcome::NotMyDisplay) => {
                return DeviceGateOutcome::NotMyDisplay;
            }
            None => {
                if st.skip_armed && policy == KeyboardSelfTestSkipPolicy::DesktopOptional {
                    return DeviceGateOutcome::PassedOrSkipped;
                }
            }
        }
    }
}

/// Outcome of [`drive_gate_step`] (SPEC §11 mandatory-gate loop).
enum GateStep {
    /// The landing state was exactly the gate's own retry target or its
    /// legitimate next-gate target; the caller's `loop { match sm.state()
    /// }` should simply continue (it will naturally re-run the same gate
    /// or move on to the next one).
    Continue,
    /// The run is over: either a clean give-up (`AppState::
    /// ExitToFirmware`, the user escaped a `PreSecretError` screen) or
    /// SPEC §11's gate-bypass guard fired
    /// ([`force_exit_after_gate_bypass`]). Either way the caller must
    /// return `finish(sm, ..)` with the carried state immediately,
    /// without looping again.
    Stop(AppState),
}

/// Drive one mandatory-gate arm's already-computed `event` through
/// [`step_recoverable`], then enforce SPEC §11's invariant: the resulting
/// state must be *exactly* `retry` (this same gate, reached again via a
/// legitimate `CheckFailed` → `PreSecretError` → `Continue` round trip,
/// SPEC §11/§22.3 "'Inconclusive' on a mandatory item disables
/// generation") or `advance` (the next state in the fixed SPEC §11.2-11.6
/// gate order) — never anything else.
///
/// See the module doc comment ("Watchdog-reassert failures mid-gate") for
/// why any other landing state is reachable at all (a transient watchdog
/// re-assert failure whose recovery the frozen `seed_protocol::state`
/// state machine resumes at `AppState::SetupSelection` regardless of
/// which gate was in flight) and why this check, rather than an edit to
/// that frozen crate, is this work package's fix.
fn drive_gate_step<O: TextOutput, K: MenuKeySource, T: WatchdogTimer>(
    sm: &mut StateMachine,
    watchdog: &mut Watchdog<T>,
    out: &mut O,
    keys_src: &mut K,
    event: Event,
    retry: AppState,
    advance: AppState,
) -> GateStep {
    let next = step_recoverable(sm, watchdog, out, keys_src, event);
    if next == AppState::ExitToFirmware {
        return GateStep::Stop(next);
    }
    if next == retry || next == advance {
        return GateStep::Continue;
    }
    GateStep::Stop(force_exit_after_gate_bypass(sm, watchdog, out, keys_src))
}

/// SPEC §11: "No secret entropy may be collected until every mandatory
/// startup gate passes." Called only by [`drive_gate_step`] (and directly
/// by [`run_pre_secret_flow`]'s graphics/keyboard arm, which cannot use
/// that helper because [`run_graphics_and_keyboard_gate`] already owns
/// its own `step_recoverable` calls) once the mandatory-gate loop has
/// observed a landing state that is neither a gate's retry target nor its
/// legitimate next-gate target — in practice, only reachable via the
/// transient-watchdog-reassert-failure interaction the module doc comment
/// describes.
///
/// Rather than resume normal flow with an unverified mandatory gate, this
/// renders an explanation and drives the machine to
/// `AppState::ExitToFirmware` using only the state machine's own legal
/// edges (SPEC §27.1): `Event::Fault` always lands on some
/// `AppState::PreSecretError` (it is not a legal edge from any state, so
/// `StateMachine`'s illegal-event fallback applies unconditionally), and
/// `Event::Escape` is a legal edge from any `AppState::PreSecretError` to
/// `AppState::ExitToFirmware`. `Continue` is deliberately never sent here
/// — resuming normal flow is exactly the bypass this function exists to
/// prevent. The two-call sequence is retried a bounded number of times so
/// that a watchdog re-assert failure striking one of *these* two calls
/// (still possible, if unlikely, immediately after the original fault)
/// does not leave the exit itself stuck; the bound only guards against
/// that residual case; it does not attempt to recover from a watchdog
/// that never stops failing (out of this work package's scope — see the
/// module doc comment).
fn force_exit_after_gate_bypass<O: TextOutput, K: MenuKeySource, T: WatchdogTimer>(
    sm: &mut StateMachine,
    watchdog: &mut Watchdog<T>,
    out: &mut O,
    keys_src: &mut K,
) -> AppState {
    render_gate_bypass_screen(out);
    read_enter(keys_src);

    for _ in 0..8 {
        sm.transition(Event::Fault(ErrorClass::Watchdog), &mut SmWatchdog(watchdog));
        let t = sm.transition(Event::Escape, &mut SmWatchdog(watchdog));
        if t.next == AppState::ExitToFirmware {
            return t.next;
        }
    }
    sm.state()
}

/// SPEC §11 gate-bypass refusal screen (see [`force_exit_after_gate_bypass`]).
/// Deliberately offers no "retry" option — unlike
/// [`crate::diagnostics::render_pre_secret_error_screen`], which is
/// appropriate for an ordinary single-gate `CheckFailed`, resuming here
/// would repeat the exact bypass this screen exists to prevent. Carries
/// no secret data (SPEC §27.3).
fn render_gate_bypass_screen<O: TextOutput>(out: &mut O) {
    out.clear();
    out.write_line("CANNOT CONTINUE");
    out.write_line("");
    out.write_line("A platform watchdog fault interrupted a mandatory startup");
    out.write_line("check before it finished (SPEC section 11). Generation");
    out.write_line("cannot proceed without every mandatory check completing.");
    out.write_line("");
    out.write_line("Restart the device and run the full startup sequence again.");
    out.write_line("");
    out.write_line("[Enter] Exit before generation");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{CheckOutcome, PlatformInfo, SecureBootStatus};
    use crate::entropy_avail::SourceAvailability;
    use crate::text;
    use crate::keys::test_support::ScriptedMenuKeys;
    use crate::keys::MenuKey;
    use crate::output::test_support::MockTerminal;
    use seed_gop_ui::gop::device_path::DevicePathText;

    /// Stand-in for an edition's `release::BUILD_ID`, drawn into every
    /// redesigned screen's chrome header band.
    const TEST_BUILD_ID: &str = "build-test";

    // ---- watchdog double ----

    struct MockTimer {
        fail_disable: bool,
        /// If `Some(n)`, the nth `set_watchdog_timer` call (1-based, across
        /// disable + every reassert) fails transiently; every other call
        /// succeeds. Mirrors the `MockTimer::failing_on` pattern in
        /// `seed_platform_x86::watchdog`'s own tests.
        fail_once_at: Option<usize>,
        /// Like `fail_once_at` but for more than one call index at once
        /// (SPEC §11 regression: exercises two separate transient
        /// watchdog-reassert failures in the same run -- one that
        /// triggers the gate-bypass guard, a second that strikes
        /// `force_exit_after_gate_bypass`'s own exit sequence).
        fail_at_multi: &'static [usize],
        calls: usize,
    }

    impl MockTimer {
        fn ok() -> Self {
            Self { fail_disable: false, fail_once_at: None, fail_at_multi: &[], calls: 0 }
        }
        fn failing_disable() -> Self {
            Self { fail_disable: true, fail_once_at: None, fail_at_multi: &[], calls: 0 }
        }
        fn failing_once_at(call: usize) -> Self {
            Self { fail_disable: false, fail_once_at: Some(call), fail_at_multi: &[], calls: 0 }
        }
        fn failing_at(calls: &'static [usize]) -> Self {
            Self { fail_disable: false, fail_once_at: None, fail_at_multi: calls, calls: 0 }
        }
    }

    impl WatchdogTimer for MockTimer {
        fn set_watchdog_timer(&mut self, _timeout_seconds: usize, _watchdog_code: u64) -> Result<(), u64> {
            self.calls += 1;
            if self.calls == 1 && self.fail_disable {
                return Err(1);
            }
            if self.fail_once_at == Some(self.calls) || self.fail_at_multi.contains(&self.calls) {
                return Err(2);
            }
            Ok(())
        }
    }

    // ---- gate doubles: everything clean / everything available ----

    struct AllCleanGates;

    impl PlatformGate for AllCleanGates {
        fn check(&mut self) -> crate::diagnostics::PlatformCheckResult {
            crate::diagnostics::PlatformCheckResult {
                outcome: CheckOutcome::Clean,
                error_class: ErrorClass::Platform,
                architecture_line: "x86-64",
                virt_summary: "No virtualization indicators detected -- not proof",
            }
        }
    }
    impl ConsoleGate for AllCleanGates {
        fn check(&mut self) -> ConsoleCheckResult {
            ConsoleCheckResult {
                outcome: CheckOutcome::Clean,
                error_class: ErrorClass::ConsoleTopology,
                con_out_paths: 1,
                con_in_paths: 1,
                summary_line: "Remote/serial paths      None detected -- not proof",
            }
        }
    }
    impl GraphicsGate for AllCleanGates {
        fn check(&mut self) -> GraphicsCheckResult {
            GraphicsCheckResult::Available(GraphicsInfo {
                width: 1920,
                height: 1080,
                device_path: DevicePathText::unavailable(),
            })
        }
    }
    impl CryptoSelfTestGate for AllCleanGates {
        fn check(&mut self) -> CryptoCheckResult {
            CryptoCheckResult { outcome: CheckOutcome::Clean }
        }
    }
    impl PlatformInfoGate for AllCleanGates {
        fn info(&mut self) -> PlatformInfo {
            PlatformInfo {
                secure_boot: SecureBootStatus::Enabled,
                entropy_policy_version: Some(1),
                production_markers_verified: true,
                tpm_status: "detected",
            }
        }
    }
    impl MachineAvailabilityGate for AllCleanGates {
        fn efi_rng(&mut self) -> SourceAvailability {
            SourceAvailability { approved: true, sole_source_allowed: true }
        }
        fn rdseed(&mut self) -> SourceAvailability {
            SourceAvailability::default()
        }
    }

    // ---- gate double: everything clean, and counts how many times each
    // trait method actually ran on this particular instance (SPEC §11
    // regression: proves a not-yet-reached gate genuinely never ran,
    // rather than just asserting the overall outcome) ----

    #[derive(Default)]
    struct CountingCleanGates {
        calls: usize,
    }

    impl PlatformGate for CountingCleanGates {
        fn check(&mut self) -> crate::diagnostics::PlatformCheckResult {
            self.calls += 1;
            crate::diagnostics::PlatformCheckResult {
                outcome: CheckOutcome::Clean,
                error_class: ErrorClass::Platform,
                architecture_line: "x86-64",
                virt_summary: "No virtualization indicators detected -- not proof",
            }
        }
    }
    impl ConsoleGate for CountingCleanGates {
        fn check(&mut self) -> ConsoleCheckResult {
            self.calls += 1;
            ConsoleCheckResult {
                outcome: CheckOutcome::Clean,
                error_class: ErrorClass::ConsoleTopology,
                con_out_paths: 1,
                con_in_paths: 1,
                summary_line: "Remote/serial paths      None detected -- not proof",
            }
        }
    }
    impl GraphicsGate for CountingCleanGates {
        fn check(&mut self) -> GraphicsCheckResult {
            self.calls += 1;
            GraphicsCheckResult::Available(GraphicsInfo {
                width: 1920,
                height: 1080,
                device_path: DevicePathText::unavailable(),
            })
        }
    }
    impl CryptoSelfTestGate for CountingCleanGates {
        fn check(&mut self) -> CryptoCheckResult {
            self.calls += 1;
            CryptoCheckResult { outcome: CheckOutcome::Clean }
        }
    }

    /// Stage 1 PREPARE (design doc §4 Stage 1): three DISTINCT commitment
    /// keypresses, then `[Enter]` — which the screen only honors once all
    /// three are checked (SPEC amendment §22.2).
    fn prepare_keystream() -> std::vec::Vec<MenuKey> {
        std::vec![
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
        ]
    }

    /// Stage 2 DEVICE (design doc §4.2): the leading `Enter` is the
    /// combined display-confirm + keyboard-test-offer screen's
    /// `[Enter] Run keyboard test` (it both confirms the local display and
    /// starts the test — the two used to be separate screens with a key
    /// each); the rest is the exact self-test keystream itself.
    fn valid_self_test_keystream() -> std::vec::Vec<MenuKey> {
        let mut v = std::vec::Vec::new();
        v.push(MenuKey::Enter); // DEVICE screen: run the keyboard test
        for c in b'A'..=b'Z' {
            v.push(MenuKey::Char(c as char));
        }
        for d in b'1'..=b'6' {
            v.push(MenuKey::Char(d as char));
        }
        v.push(MenuKey::Backspace);
        v.push(MenuKey::Enter);
        v
    }

    /// Stage 3 SETUP (design doc §4 Stage 3): one screen, three stacked
    /// pickers. `word` direct-selects on the word-count row, `[S]` moves
    /// down a row, `mode` direct-selects the entropy mode, and (for a
    /// physical-bearing mode only — the instrument row is inert and
    /// unreachable for `MachineOnly`) a second `[S]` plus `[3]` picks
    /// "Both". `[Enter]` commits all three at once. The mandated
    /// §18.2/§18.3/§6 warning is inline on this same screen and consumes
    /// no keypress of its own, and the standalone §8.4 warning screen is
    /// gone entirely (it moved to Stage 5).
    fn setup_keystream(word: char, mode: char) -> std::vec::Vec<MenuKey> {
        let mut v = std::vec::Vec::new();
        v.push(MenuKey::Char(word));
        v.push(MenuKey::Char('s'));
        v.push(MenuKey::Char(mode));
        if mode != '3' {
            v.push(MenuKey::Char('s'));
            v.push(MenuKey::Char('3')); // instrument: Both (presentation-only)
        }
        v.push(MenuKey::Enter);
        v
    }

    /// Full happy-path keystream for the redesigned pre-secret ceremony:
    /// Stage 1 PREPARE, Stage 2 DEVICE (incl. the keyboard self-test),
    /// Stage 3 SETUP. No key is read for the `WatchdogDisable`
    /// confirmation, for the transient auto-gate checklist, or for any
    /// gate that passes cleanly (`step_recoverable` only reads a key when
    /// it lands on `PreSecretError`).
    fn happy_path_keys(word: char, mode: char) -> std::vec::Vec<MenuKey> {
        let mut v = prepare_keystream();
        v.extend(valid_self_test_keystream());
        v.extend(setup_keystream(word, mode));
        v
    }

    /// Run the pre-secret flow and return BOTH the result and the mock
    /// terminal, so a test can inspect exactly which screens were rendered
    /// (used to prove Back visibly navigated to a different screen rather
    /// than silently looping).
    fn run_with_keys_term(keys: std::vec::Vec<MenuKey>) -> (FlowResult, MockTerminal) {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(keys);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        (result, term)
    }

    fn run_with_keys(keys: std::vec::Vec<MenuKey>) -> FlowResult {
        run_with_keys_term(keys).0
    }

    fn run_happy_path(word: char, mode: char) -> FlowResult {
        run_with_keys(happy_path_keys(word, mode))
    }

    #[test]
    fn happy_path_combined_12_word_reaches_handoff_at_machine_entropy_acquisition() {
        let result = run_happy_path('1', '1');
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::MachineEntropyAcquisition);
        assert_eq!(result.machine.target_bits(), Some(seed_core::contracts::TargetBits::Bits128));
    }

    #[test]
    fn happy_path_dice_only_24_word_reaches_physical_collection() {
        let result = run_happy_path('2', '2');
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::PhysicalCollection);
        assert_eq!(result.machine.target_bits(), Some(seed_core::contracts::TargetBits::Bits256));
    }

    #[test]
    fn happy_path_machine_only_reaches_machine_entropy_acquisition() {
        let result = run_happy_path('1', '3');
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::MachineEntropyAcquisition);
    }

    // ---- watchdog refusal ----

    #[test]
    fn initial_watchdog_disable_failure_exits_to_firmware_before_any_screen() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![]); // never read
        let mut wd = Watchdog::new(MockTimer::failing_disable());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert_eq!(result.machine.state(), AppState::Start);
        assert!(term.contains("watchdog"));
    }

    // ---- Esc handling ----

    #[test]
    fn escape_at_opening_warning_reports_back_to_caller() {
        // SPEC.md §21 amendment (2026-08-04, "pre-secret Back
        // navigation"): Escape at the very first ceremony screen is Back
        // with no predecessor -- it hands control back to the caller
        // (`PreSecretOutcome::BackToCaller`), landing the state machine
        // on `AppState::Start`, not `AppState::ExitToFirmware`.
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Escape]);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::BackToCaller);
        assert_eq!(result.machine.state(), AppState::Start);
    }

    /// Design doc §4 Stage 1 / SPEC amendment §22.2: `[Enter]` does
    /// nothing at all until every one of the three commitments has been
    /// checked by its OWN distinct keypress. The scripted stream below
    /// presses Enter twice while only two boxes are ticked; if either
    /// press advanced the ceremony, the remaining keys would desync and
    /// the run could not reach handoff.
    #[test]
    fn enter_before_all_three_commitments_are_checked_never_advances() {
        let mut keys = std::vec::Vec::new();
        keys.push(MenuKey::Char('1'));
        keys.push(MenuKey::Enter); // ignored: only 1 of 3 checked
        keys.push(MenuKey::Char('2'));
        keys.push(MenuKey::Enter); // ignored: only 2 of 3 checked
        keys.push(MenuKey::Char('3'));
        keys.push(MenuKey::Enter); // honored
        keys.extend(valid_self_test_keystream());
        keys.extend(setup_keystream('1', '1'));
        let result = run_with_keys(keys);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
    }

    /// The same key pressed repeatedly toggles ONE commitment on and off
    /// (`screens::prepare`'s own contract) — key-repeat can never walk a
    /// user through Stage 1. Driven here end to end through the real
    /// driver: `[1]` three times leaves item 1 checked and items 2/3 not,
    /// so the following `[Enter]` is ignored and the run only proceeds
    /// after `[2]` and `[3]` are pressed too.
    #[test]
    fn key_repeat_at_stage_one_cannot_acknowledge_everything() {
        let mut keys = std::vec::Vec::new();
        keys.push(MenuKey::Char('1'));
        keys.push(MenuKey::Char('1')); // toggles item 1 back OFF
        keys.push(MenuKey::Char('1')); // ON again
        keys.push(MenuKey::Enter); // ignored: items 2 and 3 still unchecked
        keys.push(MenuKey::Char('2'));
        keys.push(MenuKey::Char('3'));
        keys.push(MenuKey::Enter); // honored
        keys.extend(valid_self_test_keystream());
        keys.extend(setup_keystream('1', '1'));
        let result = run_with_keys(keys);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
    }

    /// SPEC.md §21 amendment (2026-08-05, "Back skips automatic gates"):
    /// `[Esc]` on the merged Stage-3 Setup screen must VISIBLY navigate to
    /// the last INTERACTIVE pre-secret screen — Stage 2's DEVICE screen
    /// (`AppState::GraphicsAndKeyboardSelfTest`) — NOT silently loop back
    /// to Setup in one step (the original "Esc does nothing" bug, where
    /// Back landed on the automatic `CryptographicSelfTest` gate that
    /// re-ran instantly and returned here).
    ///
    /// Pinned two ways, neither of which depends on rendered text (the
    /// redesigned screens draw pixels, not lines):
    ///
    /// 1. The graphics gate's `check()` ran exactly TWICE — it is only
    ///    called when the driver genuinely re-enters that interactive gate.
    /// 2. The detour keystream re-supplies the WHOLE Stage-2 keystream. A
    ///    silent self-loop would leave those keys to be consumed by Setup
    ///    instead, desyncing the rest of the stream so handoff is never
    ///    reached.
    #[test]
    fn escape_at_setup_navigates_back_to_the_device_screen_not_a_silent_loop() {
        let mut term = MockTerminal::new();
        let mut keys_vec = prepare_keystream();
        keys_vec.extend(valid_self_test_keystream());
        keys_vec.push(MenuKey::Escape); // Setup: Back -> Stage 2 DEVICE
        keys_vec.extend(valid_self_test_keystream()); // the DEVICE screen, re-run
        keys_vec.extend(setup_keystream('1', '1')); // Setup again, forward
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = CountingCleanGates::default();
        let mut g_console = CountingCleanGates::default();
        let mut g_graphics = CountingCleanGates::default();
        let mut g_crypto = CountingCleanGates::default();
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);

        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(
            g_graphics.calls, 2,
            "Setup's Back must re-enter the interactive Stage-2 DEVICE gate exactly once \
             (graphics gate ran {} time(s), expected 2)",
            g_graphics.calls
        );
        // The AUTOMATIC crypto gate re-ran on the way forward again, and
        // the platform/console gates did NOT (Back deliberately skips them,
        // landing past them on the last interactive screen).
        assert_eq!(g_crypto.calls, 2, "the automatic crypto gate re-runs on the forward pass");
        assert_eq!(g_platform.calls, 1, "Back must not re-run the platform gate");
        assert_eq!(g_console.calls, 1, "Back must not re-run the console gate");
    }

    /// The merged Stage-3 screen commits word count, entropy mode and
    /// instrument in ONE `Event::SetupCommitted` — moving between its
    /// pickers fires nothing. Re-picking the word count after moving down
    /// and back up still commits the LAST selection, proving the screen
    /// (not the state machine) owns the intermediate state.
    #[test]
    fn setup_pickers_can_be_revisited_and_only_the_final_selection_commits() {
        let mut keys = prepare_keystream();
        keys.extend(valid_self_test_keystream());
        keys.push(MenuKey::Char('2')); // word count: 24
        keys.push(MenuKey::Char('s')); // -> mode row
        keys.push(MenuKey::Char('2')); // DiceOnly
        keys.push(MenuKey::Char('w')); // back up to the word-count row
        keys.push(MenuKey::Char('1')); // word count: 12 after all
        keys.push(MenuKey::Char('s')); // -> mode row
        keys.push(MenuKey::Char('s')); // -> instrument row (physical mode)
        keys.push(MenuKey::Char('1')); // instrument: Dice
        keys.push(MenuKey::Enter); // ONE commit
        let result = run_with_keys(keys);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::PhysicalCollection);
        assert_eq!(result.machine.target_bits(), Some(seed_core::contracts::TargetBits::Bits128));
        assert_eq!(result.instrument, crate::flow_secret::physical::Instrument::Dice);
    }

    /// The diagnostics recap the redesigned Setup screen folds in is
    /// carried out on [`FlowResult::recap`] so the SECRET-phase driver can
    /// re-render the identical screen when the user backs into
    /// `AppState::SetupSelection` after hand-off. It must reflect the
    /// gates that actually ran, never `DiagRecap::unknown()`.
    #[test]
    fn handoff_carries_the_diagnostics_recap_the_setup_screen_showed() {
        let result = run_happy_path('1', '1');
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.recap.architecture_line, "x86-64");
        assert_eq!(result.recap.con_in_paths, 1);
        assert_eq!(result.recap.con_out_paths, 1);
        assert!(result.recap.crypto_clean);
        assert!(result.recap.production_markers_verified);
    }

    /// A run that never reached the recap carries the deliberately
    /// pessimistic [`DiagRecap::unknown`], so no caller can mistake an
    /// un-run ceremony's recap for a passing one.
    #[test]
    fn back_at_stage_one_carries_an_unknown_recap() {
        let result = run_with_keys(std::vec![MenuKey::Escape]);
        assert_eq!(result.outcome, PreSecretOutcome::BackToCaller);
        assert_eq!(result.recap, crate::diagnostics::DiagRecap::unknown());
    }

    // ---- refusal paths: virt detected ----

    struct VirtDetectedGates;
    impl PlatformGate for VirtDetectedGates {
        fn check(&mut self) -> crate::diagnostics::PlatformCheckResult {
            crate::diagnostics::PlatformCheckResult {
                outcome: CheckOutcome::Failed,
                error_class: ErrorClass::Virtualization,
                architecture_line: "x86-64",
                virt_summary: "Virtualization indicators detected -- not proof",
            }
        }
    }

    #[test]
    fn virtualization_detected_blocks_and_escape_from_error_exits() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Escape, // exit from the PreSecretError(Virtualization) screen
        ]);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut virt_gate = VirtDetectedGates;
        let mut r_console = AllCleanGates;
        let mut r_graphics = AllCleanGates;
        let mut r_crypto = AllCleanGates;
        let mut r_platform_info = AllCleanGates;
        let mut r_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut virt_gate,
            console: &mut r_console,
            graphics: &mut r_graphics,
            crypto: &mut r_crypto,
            platform_info: &mut r_platform_info,
            machine_availability: &mut r_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert!(term.contains("Virtualization indicators were detected on this platform."));
    }

    // ---- refusal paths: console refused, then retry succeeds ----

    struct FlakyConsoleGate {
        calls: usize,
    }
    impl ConsoleGate for FlakyConsoleGate {
        fn check(&mut self) -> ConsoleCheckResult {
            self.calls += 1;
            if self.calls == 1 {
                ConsoleCheckResult {
                    outcome: CheckOutcome::Failed,
                    error_class: ErrorClass::ConsoleTopology,
                    con_out_paths: 0,
                    con_in_paths: 0,
                    summary_line: "a serial console path is active",
                }
            } else {
                ConsoleCheckResult {
                    outcome: CheckOutcome::Clean,
                    error_class: ErrorClass::ConsoleTopology,
                    con_out_paths: 1,
                    con_in_paths: 1,
                    summary_line: "Remote/serial paths      None detected -- not proof",
                }
            }
        }
    }

    #[test]
    fn console_refused_then_retry_succeeds_and_resumes_at_console_gate_only() {
        let mut term = MockTerminal::new();
        let mut keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Enter, // retry from PreSecretError(ConsoleTopology)
        ];
        keys_vec.extend(valid_self_test_keystream());
        keys_vec.extend(setup_keystream('1', '1'));
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut console_gate = FlakyConsoleGate { calls: 0 };
        let mut r_platform = AllCleanGates;
        let mut r_graphics = AllCleanGates;
        let mut r_crypto = AllCleanGates;
        let mut r_platform_info = AllCleanGates;
        let mut r_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut r_platform,
            console: &mut console_gate,
            graphics: &mut r_graphics,
            crypto: &mut r_crypto,
            platform_info: &mut r_platform_info,
            machine_availability: &mut r_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(console_gate_calls(&console_gate), 2);
    }

    fn console_gate_calls(g: &FlakyConsoleGate) -> usize {
        g.calls
    }

    // ---- refusal path: PixelBltOnly ----

    struct BltOnlyGates;
    impl GraphicsGate for BltOnlyGates {
        fn check(&mut self) -> GraphicsCheckResult {
            GraphicsCheckResult::Refused(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON)
        }
    }

    #[test]
    fn pixel_blt_only_is_refused_with_named_reason() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Escape, // exit after seeing the refusal
        ]);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut gfx = BltOnlyGates;
        let mut r_platform = AllCleanGates;
        let mut r_console = AllCleanGates;
        let mut r_crypto = AllCleanGates;
        let mut r_platform_info = AllCleanGates;
        let mut r_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut r_platform,
            console: &mut r_console,
            graphics: &mut gfx,
            crypto: &mut r_crypto,
            platform_info: &mut r_platform_info,
            machine_availability: &mut r_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert!(term.contains(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON));
    }

    // ---- refusal path: user declines local-display confirmation ----

    #[test]
    fn declining_local_display_confirmation_blocks_generation() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Char('n'), // decline local display
            MenuKey::Escape, // exit
        ]);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert!(term.contains("The graphics or keyboard self-test did not pass."));
    }

    // ---- refusal path: keyboard self-test fails ----

    #[test]
    fn keyboard_self_test_failure_blocks_generation() {
        let mut term = MockTerminal::new();
        // `run_keyboard_self_test` stops at the first mismatch, so only
        // one self-test key is ever actually read here.
        let keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Enter,     // Stage 2 DEVICE: run the keyboard test
            MenuKey::Char('Z'), // wrong, expected 'A' -- fails closed immediately
            MenuKey::Escape,    // exit from the resulting error screen
        ];
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
    }

    // ---- refusal path: crypto self-test fails ----

    struct CryptoFailGates;
    impl CryptoSelfTestGate for CryptoFailGates {
        fn check(&mut self) -> CryptoCheckResult {
            CryptoCheckResult { outcome: CheckOutcome::Failed }
        }
    }

    #[test]
    fn crypto_self_test_failure_blocks_generation() {
        let mut term = MockTerminal::new();
        let mut keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
        ];
        keys_vec.extend(valid_self_test_keystream());
        keys_vec.push(MenuKey::Escape);
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut crypto = CryptoFailGates;
        let mut r_platform = AllCleanGates;
        let mut r_console = AllCleanGates;
        let mut r_graphics = AllCleanGates;
        let mut r_platform_info = AllCleanGates;
        let mut r_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut r_platform,
            console: &mut r_console,
            graphics: &mut r_graphics,
            crypto: &mut crypto,
            platform_info: &mut r_platform_info,
            machine_availability: &mut r_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert!(term.contains("A cryptographic self-test did not pass."));
    }

    // ---- refusal path: no approved policy at all ----

    struct NoPolicyGates;
    impl MachineAvailabilityGate for NoPolicyGates {
        fn efi_rng(&mut self) -> SourceAvailability {
            SourceAvailability::default()
        }
        fn rdseed(&mut self) -> SourceAvailability {
            SourceAvailability::default()
        }
    }

    #[test]
    fn no_machine_source_forces_dice_only_and_still_reaches_handoff() {
        let mut term = MockTerminal::new();
        let mut keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
        ];
        keys_vec.extend(valid_self_test_keystream());
        // '2' = dice-only, the only available mode with no machine source.
        keys_vec.extend(setup_keystream('1', '2'));
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut avail = NoPolicyGates;
        let mut r_platform = AllCleanGates;
        let mut r_console = AllCleanGates;
        let mut r_graphics = AllCleanGates;
        let mut r_crypto = AllCleanGates;
        let mut r_platform_info = AllCleanGates;
        let mut gates = Gates {
            platform: &mut r_platform,
            console: &mut r_console,
            graphics: &mut r_graphics,
            crypto: &mut r_crypto,
            platform_info: &mut r_platform_info,
            machine_availability: &mut avail,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::PhysicalCollection);
        // Design doc §4 Stage 3 / SPEC amendment §22.5: the SPEC §18.3
        // mandated warning is still displayed before the commit, but INLINE
        // in the Setup screen's WARN panel (`screens::setup`, whose own
        // tests pin the exact const it draws) — never as a separate
        // line-oriented screen with an Enter of its own any more.
        assert!(
            !term.contains_wrapped(text::PHYSICAL_ONLY_WARNING_18_3, text::PROSE_WRAP_COLS),
            "the standalone §18.3 warning screen must be gone; the warning is inline on Setup"
        );
    }

    // ---- transient watchdog reassert failure mid-run: absorbed, never a panic ----

    #[test]
    fn transient_watchdog_reassert_failure_on_first_transition_is_absorbed_without_panicking() {
        // Disable succeeds (call 1). The very first re-assertion (call 2,
        // for Start -> ReleaseAndEnvironmentWarning) fails once and then
        // recovers. `StateMachine::transition` routes that failure to
        // `PreSecretError(ErrorClass::Watchdog)` (SPEC §11.1); `Watchdog`
        // is not one of the four mandatory-gate classes
        // `ErrorClass::mandatory_gate_retry` special-cases, so a
        // `Continue` from that error resumes at `SetupSelection` per
        // the frozen WP-23 machine (see this module's doc comment) --
        // this driver's own `run_pre_secret_flow` treats landing anywhere
        // other than the state it was expecting next as a defined,
        // non-panicking `Unexpected` outcome rather than guessing how to
        // resume mid-sequence.
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        let mut wd = Watchdog::new(MockTimer::failing_once_at(2));
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        assert_eq!(
            result.outcome,
            PreSecretOutcome::Unexpected(AppState::SetupSelection)
        );
        assert_eq!(result.machine.state(), AppState::SetupSelection);
    }

    // ---- SPEC §11 regression: a transient watchdog-reassert failure
    // *inside* the four-mandatory-gate loop must never let the flow reach
    // HandoffToSecretPhase with an unverified gate (adversarial-review
    // finding for WP-25) ----

    /// Failure on the Platform -> Console transition (the very first gate
    /// hand-off): the platform check itself ran and passed, but the
    /// re-assertion carrying that result out of
    /// `AppState::PlatformAndVirtualizationCheck` transiently fails.
    /// `StateMachine`'s frozen `Continue`-from-`PreSecretError(Watchdog)`
    /// behavior jumps straight to `AppState::SetupSelection`, skipping
    /// the console, graphics/keyboard and cryptographic gates entirely.
    /// Before the fix this reached `PreSecretOutcome::HandoffToSecretPhase`
    /// (SPEC §11 violation); after the fix it must force a safe exit
    /// instead, and the three not-yet-run gates must never have been
    /// invoked.
    #[test]
    fn watchdog_reassert_failure_after_first_gate_forces_exit_and_never_hands_off() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Enter, // PreSecretError(Watchdog) screen: Continue
            MenuKey::Enter, // gate-bypass refusal screen: acknowledge
        ]);
        // Call 1 = disable, 2 = Start->Release, 3 = Release->WatchdogDisable,
        // 4 = WatchdogDisable->PlatformAndVirtualizationCheck, 5 =
        // PlatformAndVirtualizationCheck->ConsoleTopologyCheck (fails once).
        let mut wd = Watchdog::new(MockTimer::failing_once_at(5));
        let mut g_platform = CountingCleanGates::default();
        let mut g_console = CountingCleanGates::default();
        let mut g_graphics = CountingCleanGates::default();
        let mut g_crypto = CountingCleanGates::default();
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);

        assert_eq!(
            result.outcome,
            PreSecretOutcome::ExitedToFirmware,
            "a bypassed mandatory gate must never hand off to the secret phase"
        );
        assert_eq!(result.machine.state(), AppState::ExitToFirmware);
        assert_eq!(g_platform.calls, 1, "the platform gate legitimately ran once");
        assert_eq!(g_console.calls, 0, "the console gate must not have been skipped-over as passed");
        assert_eq!(g_graphics.calls, 0, "the graphics/keyboard gate must not have been skipped-over as passed");
        assert_eq!(g_crypto.calls, 0, "the crypto gate must not have been skipped-over as passed");
        assert!(term.contains("Restart the device"));
    }

    /// Same defect, but the transient failure strikes a *later* hand-off
    /// (Graphics/keyboard -> Cryptographic), after the graphics gate and
    /// its keyboard self-test have already genuinely completed this run.
    /// Confirms the fix is not special-cased to only the first gate.
    #[test]
    fn watchdog_reassert_failure_after_third_gate_forces_exit_and_never_hands_off() {
        let mut term = MockTerminal::new();
        let mut keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
        ];
        keys_vec.extend(valid_self_test_keystream()); // keyboard self-test
        keys_vec.push(MenuKey::Enter); // PreSecretError(Watchdog) screen: Continue
        keys_vec.push(MenuKey::Enter); // gate-bypass refusal screen: acknowledge
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        // Calls 5 = Platform->Console, 6 = Console->Graphics both succeed;
        // call 7 = GraphicsAndKeyboardSelfTest->CryptographicSelfTest fails
        // once, after the graphics check and keyboard self-test already
        // ran to completion.
        let mut wd = Watchdog::new(MockTimer::failing_once_at(7));
        let mut g_platform = CountingCleanGates::default();
        let mut g_console = CountingCleanGates::default();
        let mut g_graphics = CountingCleanGates::default();
        let mut g_crypto = CountingCleanGates::default();
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);

        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert_eq!(result.machine.state(), AppState::ExitToFirmware);
        assert_eq!(g_platform.calls, 1);
        assert_eq!(g_console.calls, 1);
        assert_eq!(g_graphics.calls, 1, "graphics gate legitimately ran once");
        assert_eq!(g_crypto.calls, 0, "the crypto gate must not have been skipped-over as passed");
    }

    /// Negative control: a transient failure landing on the *last* gate's
    /// hand-off (Cryptographic -> SetupSelection) is legitimately the
    /// same target the frozen `Continue`-from-`PreSecretError(Watchdog)`
    /// jump produces, because every mandatory gate genuinely has passed by
    /// then. This must be accepted as ordinary progress -- not misfire the
    /// new gate-bypass guard -- and still reach
    /// `PreSecretOutcome::HandoffToSecretPhase` normally.
    #[test]
    fn watchdog_reassert_failure_on_final_gate_transition_is_not_a_false_positive_bypass() {
        let mut term = MockTerminal::new();
        let mut keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
        ];
        keys_vec.extend(valid_self_test_keystream()); // keyboard self-test
        keys_vec.push(MenuKey::Enter); // PreSecretError(Watchdog) screen: Continue
        keys_vec.extend(setup_keystream('1', '1'));
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        // Call 8 = CryptographicSelfTest->SetupSelection fails once;
        // the retry (call 9) lands on SetupSelection too, which is
        // this gate's own legitimate advance target.
        let mut wd = Watchdog::new(MockTimer::failing_once_at(8));
        let mut g_platform = CountingCleanGates::default();
        let mut g_console = CountingCleanGates::default();
        let mut g_graphics = CountingCleanGates::default();
        let mut g_crypto = CountingCleanGates::default();
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);

        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert_eq!(result.machine.state(), AppState::MachineEntropyAcquisition);
        assert_eq!(g_platform.calls, 1);
        assert_eq!(g_console.calls, 1);
        assert_eq!(g_graphics.calls, 1);
        assert_eq!(g_crypto.calls, 1, "crypto gate legitimately ran exactly once (not retried)");
    }

    /// [`force_exit_after_gate_bypass`]'s own two-call exit sequence
    /// (`Event::Fault` then `Event::Escape`) is itself defended with a
    /// bounded retry: a *second*, independent transient watchdog failure
    /// striking one of those two calls must not prevent reaching
    /// `AppState::ExitToFirmware` -- it must simply retry, without asking
    /// the user for another keystroke.
    #[test]
    fn a_second_transient_watchdog_failure_during_the_forced_exit_sequence_still_converges() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Enter, // PreSecretError(Watchdog) screen: Continue
            MenuKey::Enter, // gate-bypass refusal screen: acknowledge
        ]);
        // Call 5 (Platform->Console) fails, triggering the bypass guard as
        // in the first test above; call 7, the *first* attempt inside
        // `force_exit_after_gate_bypass` (`Event::Fault`), also fails --
        // that call is idempotent regardless (see that function's doc
        // comment), but this proves the bounded retry tolerates it too.
        let mut wd = Watchdog::new(MockTimer::failing_at(&[5, 7]));
        let mut g_platform = CountingCleanGates::default();
        let mut g_console = CountingCleanGates::default();
        let mut g_graphics = CountingCleanGates::default();
        let mut g_crypto = CountingCleanGates::default();
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: KeyboardSelfTestSkipPolicy::DesktopOptional,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);

        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
        assert_eq!(result.machine.state(), AppState::ExitToFirmware);
        assert_eq!(g_console.calls, 0);
        assert_eq!(g_graphics.calls, 0);
        assert_eq!(g_crypto.calls, 0);
    }

    // ---- SPEC.md §11.5 amendment (2026-08-04): keyboard self-test made
    // OPTIONAL/skippable, per edition. The gate keeps using only the
    // existing `Event::CheckPassed`/`Event::CheckFailed` edges (SPEC §21
    // is frozen -- see the module doc comment); these tests exercise the
    // new pre-secret choice these three tests add in front of that gate.

    fn run_with_keyboard_policy(
        keys_vec: std::vec::Vec<MenuKey>,
        policy: KeyboardSelfTestSkipPolicy,
    ) -> (FlowResult, MockTerminal) {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(keys_vec);
        let mut wd = Watchdog::new(MockTimer::ok());
        let mut g_platform = AllCleanGates;
        let mut g_console = AllCleanGates;
        let mut g_graphics = AllCleanGates;
        let mut g_crypto = AllCleanGates;
        let mut g_platform_info = AllCleanGates;
        let mut g_machine_availability = AllCleanGates;
        let mut gates = Gates {
            platform: &mut g_platform,
            console: &mut g_console,
            graphics: &mut g_graphics,
            crypto: &mut g_crypto,
            platform_info: &mut g_platform_info,
            machine_availability: &mut g_machine_availability,
            keyboard_self_test_skip: policy,
            build_id: TEST_BUILD_ID,
        };
        let result = run_pre_secret_flow(&mut term, &mut keys, &mut wd, &mut gates);
        (result, term)
    }

    /// Desktop rehearsal edition (SPEC.md §11.5 amendment: "simply
    /// optional"): a SINGLE `[S]` on the merged Stage-2 DEVICE screen skips
    /// the test immediately — no second confirming press, no inline
    /// acknowledgement, and none of the production acknowledgement copy
    /// ever shown.
    #[test]
    fn desktop_optional_skip_proceeds_to_handoff_without_any_acknowledgement() {
        let mut keys_vec = prepare_keystream();
        keys_vec.push(MenuKey::Char('S')); // Stage 2 DEVICE: skip, no second press
        keys_vec.extend(setup_keystream('1', '1'));
        let (result, term) =
            run_with_keyboard_policy(keys_vec, KeyboardSelfTestSkipPolicy::DesktopOptional);
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
        assert!(
            !term.contains(text::KEYBOARD_SELF_TEST_SKIP_WARNING_11_5),
            "desktop's plain skip must never show the production acknowledgement text"
        );
    }

    /// Production-style edition (SPEC.md §11.5 amendment: "offered by
    /// default and strongly recommended, but skippable via an explicit
    /// acknowledgement of the consequence"): the skip needs TWO `[S]`
    /// presses — the first arms `screens::device`'s inline `WARN`
    /// acknowledgement line, only the second confirms. Design doc §4.2
    /// states this two-press inline form IS the amendment's required
    /// acknowledgement, replacing the old full-screen one. If a single
    /// `[S]` had skipped, the following keys would desync and handoff
    /// would never be reached.
    #[test]
    fn recommended_skip_shows_mandated_warning_before_proceeding() {
        let mut keys_vec = prepare_keystream();
        keys_vec.push(MenuKey::Char('S')); // arms the inline WARN acknowledgement
        keys_vec.push(MenuKey::Char('S')); // confirms the skip
        keys_vec.extend(setup_keystream('1', '1'));
        let (result, _term) = run_with_keyboard_policy(
            keys_vec,
            KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
        );
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
    }

    /// Any key other than a second `[S]` DISARMS the armed skip rather
    /// than silently confirming it (`screens::device`'s two-press
    /// contract) — the redesign's equivalent of the old acknowledgement
    /// screen's "Back". The user can still change their mind and run the
    /// real self-test, which then passes and reaches handoff normally.
    #[test]
    fn recommended_skip_back_returns_to_offer_and_the_test_can_still_be_run() {
        let mut keys_vec = prepare_keystream();
        keys_vec.push(MenuKey::Char('S')); // arms the inline WARN acknowledgement
        keys_vec.push(MenuKey::Char('X')); // any other key DISARMS it again
        keys_vec.push(MenuKey::Char('S')); // arms it once more (not a confirm)
        // ... and the user changes their mind: Enter runs the real test.
        keys_vec.extend(valid_self_test_keystream());
        keys_vec.extend(setup_keystream('1', '1'));
        let (result, _term) = run_with_keyboard_policy(
            keys_vec,
            KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
        );
        assert_eq!(result.outcome, PreSecretOutcome::HandoffToSecretPhase);
    }

    /// SPEC.md §11.5 amendment: "nothing about the fail-closed handling
    /// of an attempted self-test changes" -- an attempted-and-failed
    /// self-test still blocks generation even under the most permissive
    /// (production, skippable) policy, exactly as it did before the
    /// amendment.
    #[test]
    fn attempted_and_failed_self_test_still_blocks_generation_under_recommended_policy() {
        let keys_vec = std::vec![
            // Stage 1 PREPARE: three distinct commitments, then Enter.
            MenuKey::Char('1'),
            MenuKey::Char('2'),
            MenuKey::Char('3'),
            MenuKey::Enter,
            MenuKey::Enter,     // Stage 2 DEVICE: run the keyboard test
            MenuKey::Char('Z'), // wrong, expected 'A' -- fails closed immediately
            MenuKey::Escape,    // exit from the resulting error screen
        ];
        let (result, _term) = run_with_keyboard_policy(
            keys_vec,
            KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement,
        );
        assert_eq!(result.outcome, PreSecretOutcome::ExitedToFirmware);
    }
}
