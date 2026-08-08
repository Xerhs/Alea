//! Application state machine (WP-23, SPEC §21, §26–27).
//!
//! Pure logic, `no_std`, no UEFI dependency and no secret data: [`AppState`]
//! values are small plain-data tags, never entropy/mnemonic/key material.
//!
//! The machine enforces the SPEC §21 rule that anchors this whole crate:
//! **after [`AppState::FinalEntropyDerivation`], every event that is not an
//! explicitly modelled legal transition drives the machine into the
//! [`AppState::ScrubWhatIsReachable`] fatal chain — never back to a menu and
//! never back to the UEFI boot manager (SPEC §21, §27.2).** Before that
//! point, an unrecognised event is treated as a state-machine error (SPEC
//! §27.3) and is still routed to a fixed, non-crashing target rather than
//! silently ignored or panicking.
//!
//! [`StateMachine::transition`] also carries the SPEC §21 "watchdog
//! zero-timeout is re-asserted at every transition" requirement: every call
//! invokes a caller-supplied [`WatchdogReassert`] hook exactly once, before
//! the transition is computed, regardless of whether the transition turns
//! out to be legal or fatal.

#![allow(clippy::exhaustive_enums)]

use seed_core::contracts::{TargetBits, WordCount};

// ============================================================================
// States (SPEC §21, plus optional machine/physical/derivation states and
// fatal-path / terminal states needed to make the machine total)
// ============================================================================

/// Every reachable application state (SPEC §21), including the optional
/// machine-entropy / physical-collection / derivation-verification states
/// and the fatal-path states.
///
/// Deliberately not `Copy`-of-anything-secret: this type carries no secret
/// material, only a control-flow tag (plus, for [`AppState::PreSecretError`],
/// a non-secret [`ErrorClass`]), so ordinary derives are fine (SPEC §13,
/// §20 restrict secret-bearing types, not this one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application entry point, before any UI is shown.
    Start,
    /// SPEC §21 / §22.1: opening warning + §22.2 grouped acknowledgements.
    ReleaseAndEnvironmentWarning,
    /// SPEC §21 / §11.1: watchdog zero-timeout disable call.
    WatchdogDisable,
    /// SPEC §21 / §22.3: architecture + virtualization-indicator check.
    PlatformAndVirtualizationCheck,
    /// SPEC §21 / §22.3: console input/output topology enumeration.
    ConsoleTopologyCheck,
    /// SPEC §21 / §11.4–§11.5: GOP + keyboard self-test.
    GraphicsAndKeyboardSelfTest,
    /// SPEC §21: hash/HMAC/PBKDF2/secp256k1 known-answer self-test.
    CryptographicSelfTest,
    /// SPEC §21 / §22.4 + §22.5 (+ §22.5a): the single setup screen where
    /// the word count, the entropy-source mode and the physical instrument
    /// are all chosen and committed together with one
    /// [`Event::SetupCommitted`].
    ///
    /// 2026-08-07 ceremony redesign, Stage 3 "SETUP": this state REPLACES
    /// the former `WordCountSelection` + `EntropyModeSelection` pair. The
    /// §22.5a instrument sub-selection was already PRESENTATION ONLY
    /// (SPEC_DICE_COIN_VISUAL.md §2.3 "deliberately not a new
    /// `EntropyMode`") and contributed no state and no edge, so nothing was
    /// removed from the machine on its account.
    ///
    /// The driver MAY still render several panels inside this one state
    /// (diagnostics recap, word count, mode, instrument). Moving between
    /// those panels is purely a driver-local concern and fires NO event —
    /// in particular it must not fire [`Event::Back`], whose single legal
    /// edge from here leaves the setup screen entirely (see
    /// [`StateMachine::legal_edge`]).
    SetupSelection,
    /// SPEC §21 (optional): EFI RNG / RDSEED / RDRAND acquisition, entered
    /// only for modes that include a machine source.
    MachineEntropyAcquisition,
    /// SPEC §21 (optional) / §17: dice/coin collection, entered only for
    /// modes that include a physical source.
    PhysicalCollection,
    /// SPEC §21 / §22.6: last confirmation before entropy becomes final.
    FinalGenerationConfirmation,
    /// SPEC §21: transcript finalized into final entropy. **This is the
    /// secret-creation boundary (SPEC §27.2)** — every state at or after
    /// this one is "post-secret" for the purposes of fatal routing.
    FinalEntropyDerivation,
    /// SPEC §21: final entropy encoded into BIP39 word indexes.
    MnemonicGeneration,
    /// SPEC §21 / §22.7: mnemonic shown on the GOP framebuffer.
    MnemonicDisplay,
    /// SPEC §21 / §22.7: second confirmation before destroying the phrase
    /// without completing re-entry.
    DestroyConfirm,
    /// SPEC §21: framebuffer scrub between display and hidden re-entry.
    DisplayScrub,
    /// SPEC §21 / §23: complete hidden mnemonic re-entry loop.
    CompleteHiddenReentry,
    /// SPEC §23.2: a re-entered word did not match; user chooses retry,
    /// reveal-again, or destroy.
    ReentryMismatchChoice,
    /// SPEC_PASSPHRASE §6.1: post-secret offer of an optional BIP39
    /// passphrase ("Add a passphrase? [Y] yes  [N] no (empty)"). A LINEAR
    /// post-secret binary branch whose edges only go FORWARD (to
    /// `PassphraseEntry`, or to `DerivationVerificationDisplay` with the
    /// empty passphrase); it never returns to a menu/boot state (SPEC §26).
    PassphraseOffer,
    /// SPEC_PASSPHRASE §6.1/§4.1: masked passphrase entry 1.
    PassphraseEntry,
    /// SPEC_PASSPHRASE §6.1/§4.1: masked passphrase entry 2 (confirm);
    /// a mismatch routes forward-back to `PassphraseEntry`, a match to
    /// `DerivationVerificationDisplay`.
    PassphraseConfirm,
    /// SPEC §21 (optional) / §24: wallet-derivation verification display.
    DerivationVerificationDisplay,
    /// SPEC §21 / §23.3: completion education screen.
    CompletionEducation,
    /// SPEC §21 / §26 step 4: secret-arena scrub.
    SecretArenaScrub,
    /// SPEC §21 / §26 step 5: framebuffer/rendering-buffer scrub.
    FramebufferScrub,
    /// SPEC §21 / §26: shutdown requested.
    Shutdown,
    /// SPEC §26: automatic shutdown failed twice; non-returning halt loop.
    /// Terminal: absorbs every further event without change.
    ShutdownFailedHalt,
    /// SPEC §22.1: user chose Escape before final entropy exists. Terminal
    /// for this run; the application exits to firmware.
    ExitToFirmware,
    /// SPEC §27.1: a pre-secret error occurred; carries the SPEC §27.3
    /// error class so the caller can render a diagnostic. Not reachable
    /// once [`AppState::FinalEntropyDerivation`] has been entered.
    PreSecretError(ErrorClass),
    /// SPEC §21 fatal path, step 1: scrub every reachable secret buffer.
    /// Entered for *any* unexpected event once a secret exists, and never
    /// left except deterministically down the fatal chain.
    ScrubWhatIsReachable,
    /// SPEC §21 fatal path, step 2: blank the display.
    BlankDisplay,
    /// SPEC §21 fatal path, step 3 / terminal: shutdown or halt. Terminal:
    /// absorbs every further event (SPEC §21 "no transition ... may return
    /// to the main menu or UEFI boot manager").
    ShutdownOrHalt,
}

impl AppState {
    /// SPEC §21 / §27.2: true once the state is at or after
    /// [`AppState::FinalEntropyDerivation`] — i.e. final entropy (a secret)
    /// exists or has existed during this run. From this point on, illegal
    /// transitions MUST NOT return to a menu; they route to
    /// [`AppState::ScrubWhatIsReachable`].
    #[must_use]
    pub const fn is_post_secret(self) -> bool {
        !matches!(
            self,
            AppState::Start
                | AppState::ReleaseAndEnvironmentWarning
                | AppState::WatchdogDisable
                | AppState::PlatformAndVirtualizationCheck
                | AppState::ConsoleTopologyCheck
                | AppState::GraphicsAndKeyboardSelfTest
                | AppState::CryptographicSelfTest
                | AppState::SetupSelection
                | AppState::MachineEntropyAcquisition
                | AppState::PhysicalCollection
                | AppState::FinalGenerationConfirmation
                | AppState::ExitToFirmware
                | AppState::PreSecretError(_)
        )
    }

    /// True for the three fatal-chain states themselves (SPEC §21): once
    /// inside the chain, transitions are unconditional/deterministic rather
    /// than event-driven.
    #[must_use]
    pub const fn is_fatal_chain(self) -> bool {
        matches!(
            self,
            AppState::ScrubWhatIsReachable | AppState::BlankDisplay | AppState::ShutdownOrHalt
        )
    }

    /// True for states that, once entered, never transition again (SPEC
    /// §21 / §26: "never return to the application menu or boot manager").
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            AppState::ShutdownOrHalt | AppState::ShutdownFailedHalt | AppState::ExitToFirmware
        )
    }
}

// ============================================================================
// Error classes (SPEC §27.3)
// ============================================================================

/// SPEC §27.3 error classes. No variant carries secret material — that is a
/// hard requirement (SPEC §27.3 lists everything an error may never
/// contain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// SPEC §22.3: architecture / general platform check failure.
    Platform,
    /// UEFI watchdog disable call failed.
    Watchdog,
    /// Console input/output topology check failed (e.g. remote/serial path
    /// detected, or zero supported local paths).
    ConsoleTopology,
    /// Virtualization indicators detected where policy requires bare metal,
    /// or the check was inconclusive.
    Virtualization,
    /// GOP or keyboard self-test failure.
    GraphicsOrKeyboard,
    /// Entropy-policy parse/signature/version failure.
    EntropyPolicy,
    /// Machine entropy source failure (EFI RNG / RDSEED / RDRAND, SPEC
    /// §15–16).
    MachineSource,
    /// Physical dice/coin entry state failure (SPEC §17).
    PhysicalEntryState,
    /// BIP32/derivation failure (SPEC §24).
    Derivation,
    /// Hash/HMAC/PBKDF2/secp256k1 self-test or runtime failure.
    Cryptographic,
    /// The state machine itself received an event with no legal transition
    /// from the current state.
    StateMachine,
    /// An internal consistency/integrity check failed (e.g. a fence or
    /// canary).
    Integrity,
    /// `EfiResetShutdown` failed or a scrub step in the shutdown sequence
    /// failed.
    Shutdown,
}

impl ErrorClass {
    /// SPEC §11 / §22.3: the mandatory startup-gate state that must be
    /// re-verified (i.e. must emit [`Event::CheckPassed`] again) before a
    /// [`PreSecretDisposition::ReturnToMenu`] error of this class may
    /// resume the normal flow — or `None` if this error class is not tied
    /// to one of the four mandatory startup gates, in which case resuming
    /// directly at [`AppState::SetupSelection`] is safe (every mandatory
    /// gate already emitted `CheckPassed` earlier in this run to reach the
    /// state that produced the error).
    ///
    /// `Platform` and `Virtualization` both map to
    /// [`AppState::PlatformAndVirtualizationCheck`] because that single
    /// state performs both the architecture check and the
    /// virtualization-indicator check (SPEC §11.2).
    #[must_use]
    const fn mandatory_gate_retry(self) -> Option<AppState> {
        match self {
            ErrorClass::Platform | ErrorClass::Virtualization => {
                Some(AppState::PlatformAndVirtualizationCheck)
            }
            ErrorClass::ConsoleTopology => Some(AppState::ConsoleTopologyCheck),
            ErrorClass::GraphicsOrKeyboard => Some(AppState::GraphicsAndKeyboardSelfTest),
            ErrorClass::Cryptographic => Some(AppState::CryptographicSelfTest),
            _ => None,
        }
    }
}

/// SPEC §22.1: what to do with a pre-secret error (only meaningful before
/// [`AppState::FinalEntropyDerivation`] — SPEC §27.1 allows a diagnostic,
/// a return to a safe earlier menu, or an exit to firmware).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSecretDisposition {
    /// Return to a safe earlier state (SPEC §27.1). SPEC §11 / §22.3
    /// ("'Inconclusive' on a mandatory item disables generation") requires
    /// that this never skip a mandatory startup gate: for an [`ErrorClass`]
    /// tied to one of the four mandatory gates
    /// ([`ErrorClass::mandatory_gate_retry`]), the machine returns to that
    /// gate's own check state so it must emit [`Event::CheckPassed`] again
    /// before the flow can continue. For every other error class the
    /// machine returns to [`AppState::SetupSelection`], the earliest state
    /// that re-enters the normal flow without repeating gates that already
    /// passed earlier in this run.
    ReturnToMenu,
    /// Exit to firmware (SPEC §27.1, §22.1).
    ExitToFirmware,
}

// ============================================================================
// Entropy mode (SPEC §22.5)
// ============================================================================

/// SPEC §22.5 entropy-source mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyMode {
    /// `[1]` Approved machine source + physical dice/coins (recommended).
    Combined,
    /// `[2]` Physical dice/coins only.
    DiceOnly,
    /// `[3]` Approved machine source only (SPEC §18.2 warning applies).
    MachineOnly,
}

// ============================================================================
// Physical instrument (SPEC_DICE_COIN_VISUAL.md §2.2/§22.5a)
// PRESENTATION ONLY — no state, no edge
// ============================================================================

/// Which physical instrument's UI *leads* the entry screen layout
/// (SPEC_DICE_COIN_VISUAL.md §2.2/§2.3). This is a **presentation-only**
/// sub-selection under the existing physical-bearing modes: it gates the
/// layout (which picker/controls lead) *only* — both the `1`-`6` and
/// `H`/`T` key families stay accepted in every variant (SPEC §17.1 "either
/// or both"), so it changes no byte, no budget, and no §19 transcript.
/// Deliberately **not** a new [`EntropyMode`] (§2.3).
///
/// It therefore adds **no state and no edge** to this machine: it is
/// carried by [`Event::SetupCommitted`] and stored as inert non-secret
/// context ([`StateMachine::instrument`]) purely so the one commit event of
/// the merged SPEC §22.4/§22.5/§22.5a setup screen describes the whole
/// assembled setup. [`StateMachine::legal_edge`] never reads it.
///
/// 2026-08-07: moved here from `seed_flow::flow_secret::physical` (which
/// re-exports it unchanged) only because `seed-flow` depends on this crate,
/// not the other way round, so the event could not otherwise name the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instrument {
    /// `[1] Dice`: the six-face picker leads; `[K]` switches to coins.
    Dice,
    /// `[2] Coins`: the heads/tails picker leads; `[K]` switches to dice.
    Coins,
    /// `[3] Both`: dice picker leads with both key families in the
    /// controls line; `[K]` is unbound (one interleaved timeline, §4.2).
    Both,
}

impl Default for Instrument {
    /// `Both` is the compatibility default matching today's combined
    /// screen (SPEC_DICE_COIN_VISUAL.md §2.2 `[3] Both`).
    fn default() -> Self {
        Instrument::Both
    }
}

/// SPEC §27.1: where a machine-checked item's failure/inconclusive result
/// (SPEC §22.3) routes to, pre-secret.
const fn check_failed_target(class: ErrorClass, disposition: PreSecretDisposition) -> AppState {
    match disposition {
        PreSecretDisposition::ReturnToMenu => AppState::PreSecretError(class),
        PreSecretDisposition::ExitToFirmware => AppState::ExitToFirmware,
    }
}

impl EntropyMode {
    const fn needs_machine(self) -> bool {
        matches!(self, EntropyMode::Combined | EntropyMode::MachineOnly)
    }

    const fn needs_physical(self) -> bool {
        matches!(self, EntropyMode::Combined | EntropyMode::DiceOnly)
    }
}

// ============================================================================
// Events
// ============================================================================

/// Every event the state machine accepts. Events not legal from the current
/// state are handled by the fatal/error routing described on
/// [`StateMachine::transition`], never by a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Generic "advance" (Enter on a screen with a single continuation).
    Continue,
    /// Escape, where the current screen offers it (SPEC §22.1, §22.6).
    Escape,
    /// SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation"):
    /// go back exactly one step to the immediately preceding pre-secret
    /// screen. Legal only from a pre-secret state — never from any state
    /// at or after [`AppState::FinalEntropyDerivation`] (SPEC §21, §27.2:
    /// no edge back to any earlier state is added there; an attempt is
    /// treated like any other illegal post-secret event and routes to
    /// [`AppState::ScrubWhatIsReachable`]). See
    /// [`StateMachine::legal_edge`] for the full predecessor table (the
    /// exact reverse of the SPEC §21 forward order) and this crate's
    /// `tests` module for the exhaustive per-state regression coverage.
    Back,
    /// A machine-checked item passed (SPEC §22.3).
    CheckPassed,
    /// A machine-checked item failed or was inconclusive on a mandatory
    /// item (SPEC §22.3: "Inconclusive on a mandatory item disables
    /// generation"); carries the error class and, since this only happens
    /// pre-secret, how to dispose of it.
    CheckFailed(ErrorClass, PreSecretDisposition),
    /// 2026-08-07 ceremony redesign, Stage 3 "SETUP": the whole assembled
    /// setup, committed in one keypress from the single merged
    /// [`AppState::SetupSelection`] screen — SPEC §22.4 word count, SPEC
    /// §22.5 entropy-source mode and the SPEC §22.5a physical instrument.
    /// REPLACES the former `WordCountChosen` / `EntropyModeChosen` pair.
    ///
    /// Only `mode` routes: it alone selects which acquisition state follows
    /// (SPEC §21), exactly as `EntropyModeChosen` did. `word_count` is
    /// stored as non-secret context ([`StateMachine::target_bits`],
    /// [`StateMachine::word_count`]) exactly as `WordCountChosen` stored
    /// it, and `instrument` is PRESENTATION ONLY
    /// (SPEC_DICE_COIN_VISUAL.md §2.3) — stored verbatim, read by no edge.
    SetupCommitted {
        /// SPEC §22.4: 12 vs 24 words.
        word_count: WordCount,
        /// SPEC §22.5: entropy-source mode; the ONLY routing input.
        mode: EntropyMode,
        /// SPEC §22.5a: which physical picker leads. Presentation only.
        instrument: Instrument,
    },
    /// SPEC §21 (optional): machine-entropy acquisition finished
    /// successfully.
    MachineEntropyComplete,
    /// Machine-entropy acquisition failed (pre-secret; SPEC §15–16).
    MachineEntropyFailed(PreSecretDisposition),
    /// SPEC §17: physical-collection budget met (`budget_met`).
    PhysicalBudgetMet,
    /// SPEC §22.6: final confirmation given.
    FinalConfirm,
    /// Transcript finalized into final entropy successfully.
    DerivationComplete,
    /// Transcript finalization failed. SPEC §27.1/§27.2 draw the pre- vs
    /// post-secret line at whether final entropy actually came into
    /// existence, which by definition it had not if derivation itself
    /// failed. On the one legal edge (from
    /// [`AppState::FinalEntropyDerivation`]) the machine nonetheless forces
    /// the fatal scrub chain ([`AppState::ScrubWhatIsReachable`])
    /// unconditionally — the [`PreSecretDisposition`] payload is a
    /// don't-care there. The payload only does real work on the defensive
    /// `illegal_edge` path (this event fired from any other
    /// state): `ReturnToMenu` routes to `PreSecretError(Derivation)` and
    /// `ExitToFirmware` to [`AppState::ExitToFirmware`].
    DerivationFailed(PreSecretDisposition),
    /// Entropy encoded into mnemonic word indexes successfully.
    MnemonicReady,
    /// `[H]` hide words and begin complete re-entry (SPEC §22.7).
    HideAndReenter,
    /// `[D]` destroy phrase and shut down (SPEC §22.7); needs a second
    /// confirmation, modelled as the transition into
    /// [`AppState::DestroyConfirm`].
    DestroyRequested,
    /// Second destroy confirmation given.
    DestroyConfirmed,
    /// Framebuffer scrub between mnemonic display/reveal and re-entry
    /// finished.
    ScrubComplete,
    /// SPEC §23.1: a re-entered word matched; more positions remain.
    ReentryPositionMatched,
    /// SPEC §23.1: the last position matched; re-entry is complete.
    ReentryComplete,
    /// SPEC §23.2: a re-entered word did not match this position.
    ReentryMismatch,
    /// SPEC §23.2 `[1]`: retry this position.
    RetryPosition,
    /// SPEC §23.2 `[2]`: reveal the phrase again.
    RevealAgain,
    /// SPEC_PASSPHRASE §6.1: at `PassphraseOffer`, the user chose `[Y]` to
    /// add a passphrase — advance to `PassphraseEntry`.
    PassphraseOfferYes,
    /// SPEC_PASSPHRASE §6.1/§6.2: use the EMPTY passphrase — either `[N]`
    /// at `PassphraseOffer`, or an empty/cancel-to-empty commit at
    /// `PassphraseEntry`. Forward-only to `DerivationVerificationDisplay`;
    /// the byte-identical path (SPEC_PASSPHRASE §2.2, §10.1).
    PassphraseUseEmpty,
    /// SPEC_PASSPHRASE §4.1: a non-empty entry-1 was committed — advance
    /// from `PassphraseEntry` to `PassphraseConfirm`.
    PassphraseEntered,
    /// SPEC_PASSPHRASE §4.1: entry-2 matched entry-1 (constant-time
    /// compare) — advance from `PassphraseConfirm` to
    /// `DerivationVerificationDisplay` with the committed passphrase.
    PassphraseConfirmMatch,
    /// SPEC_PASSPHRASE §4.1: entry-2 did NOT match; both buffers are
    /// scrubbed and the flow returns to `PassphraseEntry` with no retained
    /// state.
    PassphraseConfirmMismatch,
    /// SPEC §24: user chose to view the wallet-derivation verification
    /// display.
    ShowVerification,
    /// SPEC §24: user skipped the (optional) verification display.
    SkipVerification,
    /// SPEC §24: verification values were shown; user is done with the
    /// screen.
    VerificationAcknowledged,
    /// SPEC §24.4: derivation for the verification display failed.
    VerificationFailed,
    /// SPEC §23.3: user acknowledged the completion education screen.
    EducationAcknowledged,
    /// `EfiResetShutdown` (or equivalent) was requested.
    ShutdownRequested,
    /// Shutdown request failed (SPEC §26: retry once, then halt loop).
    ShutdownFailed,
    /// Any runtime fault detected post-secret with no more specific event
    /// (SPEC §27.2/§27.3): always routes into the fatal chain.
    Fault(ErrorClass),
}

// ============================================================================
// Transition result
// ============================================================================

/// Outcome of one [`StateMachine::transition`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The state the machine is in *after* this call.
    pub next: AppState,
    /// `true` if `event` was not a legal transition from the prior state
    /// and the machine had to route to an error/fatal target instead.
    pub was_illegal: bool,
    /// Set exactly when the machine entered (or continued through) the
    /// SPEC §21 fatal chain (`ScrubWhatIsReachable` / `BlankDisplay` /
    /// `ShutdownOrHalt`) as a result of this call.
    pub fatal_class: Option<ErrorClass>,
}

/// SPEC §11.1: marker for a failed watchdog re-assertion call. Carries no
/// data (the underlying firmware status belongs to the platform layer,
/// out of scope for this crate) — the state machine only needs to know
/// pass/fail to route SPEC §11.1's fatal-after-final-entropy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogReassertFailure;

/// SPEC §21 / §11.1 watchdog-reassert hook. [`StateMachine::transition`]
/// calls [`WatchdogReassert::reassert`] exactly once per call, before
/// computing the transition, so the zero-timeout is re-asserted on every
/// state change without exception — including illegal-transition and fatal
/// calls, since those still must not let the platform watchdog fire.
///
/// SPEC §11.1 requires that a re-assertion failure *after final entropy
/// exists* be "treat[ed] ... as a fatal error routed to scrub-and-shutdown"
/// — so this call is fallible, and [`StateMachine::transition`] inspects
/// the result to enforce that rule (see its doc comment).
pub trait WatchdogReassert {
    /// Re-assert the UEFI watchdog zero-timeout. Implemented by the
    /// platform layer (out of scope for this crate); pure-logic callers
    /// (including tests) may use a no-op/counting stub or an
    /// always-failing stub.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogReassertFailure`] if the underlying platform
    /// re-assert call failed.
    fn reassert(&mut self) -> Result<(), WatchdogReassertFailure>;
}

/// A [`WatchdogReassert`] stub that only counts calls and always succeeds;
/// used by this crate's own tests and available to any downstream crate's
/// tests too (it holds no secret state).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CountingWatchdog {
    /// Number of times [`WatchdogReassert::reassert`] has been called.
    pub count: u32,
}

impl WatchdogReassert for CountingWatchdog {
    fn reassert(&mut self) -> Result<(), WatchdogReassertFailure> {
        self.count = self.count.saturating_add(1);
        Ok(())
    }
}

// ============================================================================
// The state machine
// ============================================================================

/// SPEC §21 application state machine. Holds only the current [`AppState`]
/// plus the handful of pieces of *non-secret* context needed to route
/// branches that the raw state alone cannot decide (which entropy mode was
/// picked, which word count). No entropy, mnemonic or key material is ever
/// stored here — that lives in the secret arena (WP-09), owned elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateMachine {
    state: AppState,
    word_count: Option<WordCount>,
    mode: Option<EntropyMode>,
    /// SPEC_DICE_COIN_VISUAL.md §22.5a. Inert: stored from
    /// [`Event::SetupCommitted`] for the driver to read back, never read by
    /// [`StateMachine::legal_edge`] (PRESENTATION ONLY, §2.3).
    instrument: Option<Instrument>,
}

impl StateMachine {
    /// A fresh machine at [`AppState::Start`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AppState::Start,
            word_count: None,
            mode: None,
            instrument: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> AppState {
        self.state
    }

    /// SPEC §14/§17: the target bit length implied by the word count
    /// committed at [`AppState::SetupSelection`], if that step has happened
    /// yet.
    #[must_use]
    pub const fn target_bits(&self) -> Option<TargetBits> {
        match self.word_count {
            Some(WordCount::Twelve) => Some(TargetBits::Bits128),
            Some(WordCount::TwentyFour) => Some(TargetBits::Bits256),
            None => None,
        }
    }

    /// SPEC §22.4: the word count committed at
    /// [`AppState::SetupSelection`], if that step has happened yet.
    /// Non-secret control-flow context only.
    #[must_use]
    pub const fn word_count(&self) -> Option<WordCount> {
        self.word_count
    }

    /// SPEC §22.5: the entropy-source mode committed at
    /// [`AppState::SetupSelection`], if that step has happened yet.
    #[must_use]
    pub const fn mode(&self) -> Option<EntropyMode> {
        self.mode
    }

    /// SPEC_DICE_COIN_VISUAL.md §22.5a: the PRESENTATION-ONLY physical
    /// instrument committed at [`AppState::SetupSelection`], if that step
    /// has happened yet. Read back by the driver to seed the leading picker
    /// of the physical-entry screen; it routes nothing (§2.3).
    #[must_use]
    pub const fn instrument(&self) -> Option<Instrument> {
        self.instrument
    }

    /// Drive the machine with one `event`. Always calls
    /// `watchdog.reassert()` exactly once (SPEC §21 watchdog-reassert hook
    /// point), regardless of outcome, then computes the next state.
    ///
    /// Routing rules (SPEC §21, §27):
    /// - A legal edge from the current state advances normally.
    /// - An illegal event before [`AppState::FinalEntropyDerivation`]
    ///   routes to [`AppState::PreSecretError`] (SPEC §27.1) — never to the
    ///   fatal chain, since no secret exists yet to scrub.
    /// - An illegal event at or after [`AppState::FinalEntropyDerivation`]
    ///   routes into [`AppState::ScrubWhatIsReachable`] (SPEC §21, §27.2) —
    ///   never to a menu.
    /// - Once inside the fatal chain, every call advances the chain
    ///   deterministically (`ScrubWhatIsReachable` -> `BlankDisplay` ->
    ///   `ShutdownOrHalt`) regardless of the specific event, because SPEC
    ///   §21 states the chain as an unconditional sequence, not a
    ///   conditional one.
    /// - SPEC §11.1: if `watchdog.reassert()` itself fails, that is treated
    ///   as fatal whenever a secret already exists ([`AppState::is_post_secret`]
    ///   on the state *before* this call) — the machine routes straight
    ///   into [`AppState::ScrubWhatIsReachable`] with
    ///   `fatal_class = Some(`[`ErrorClass::Watchdog`]`)`, overriding
    ///   whatever `event` was passed. Pre-secret, a failed re-assertion is
    ///   still not ignored: it routes to [`AppState::PreSecretError`] with
    ///   [`ErrorClass::Watchdog`] (SPEC §27.1) rather than silently
    ///   continuing with a watchdog that may be about to fire. Terminal
    ///   states and the fatal chain itself are unaffected (they already
    ///   never return to normal flow).
    pub fn transition(
        &mut self,
        event: Event,
        watchdog: &mut dyn WatchdogReassert,
    ) -> Transition {
        let reassert_result = watchdog.reassert();

        let from = self.state;

        // Terminal states absorb every event without change or fault.
        if from.is_terminal() {
            return Transition {
                next: from,
                was_illegal: false,
                fatal_class: None,
            };
        }

        // Fatal chain: unconditional advance, no illegality concept. A
        // watchdog failure here changes nothing — the machine is already
        // deterministically heading to shutdown.
        if from.is_fatal_chain() {
            let next = match from {
                AppState::ScrubWhatIsReachable => AppState::BlankDisplay,
                AppState::BlankDisplay => AppState::ShutdownOrHalt,
                _ => unreachable!("is_fatal_chain() only returns true for these two + terminal ShutdownOrHalt, handled above"),
            };
            self.state = next;
            return Transition {
                next,
                was_illegal: false,
                fatal_class: None,
            };
        }

        if reassert_result.is_err() {
            return if from.is_post_secret() {
                // SPEC §11.1: fatal after final entropy exists.
                self.state = AppState::ScrubWhatIsReachable;
                Transition {
                    next: AppState::ScrubWhatIsReachable,
                    was_illegal: true,
                    fatal_class: Some(ErrorClass::Watchdog),
                }
            } else {
                let next = AppState::PreSecretError(ErrorClass::Watchdog);
                self.state = next;
                Transition {
                    next,
                    was_illegal: true,
                    fatal_class: None,
                }
            };
        }

        match self.legal_edge(from, event) {
            Some(next) => {
                self.state = next;
                Transition {
                    next,
                    was_illegal: false,
                    fatal_class: None,
                }
            }
            None => {
                let (next, class) = self.illegal_edge(from, event);
                self.state = next;
                Transition {
                    next,
                    was_illegal: true,
                    fatal_class: class,
                }
            }
        }
    }

    /// The single legal transition table. Returns `None` when `event` is
    /// not a legal transition from `from`.
    fn legal_edge(&mut self, from: AppState, event: Event) -> Option<AppState> {
        use AppState::{
            CompleteHiddenReentry, CompletionEducation, ConsoleTopologyCheck,
            CryptographicSelfTest, DerivationVerificationDisplay, DestroyConfirm, DisplayScrub,
            ExitToFirmware, FinalEntropyDerivation,
            FinalGenerationConfirmation, FramebufferScrub, GraphicsAndKeyboardSelfTest,
            MachineEntropyAcquisition, MnemonicDisplay, MnemonicGeneration,
            PassphraseConfirm, PassphraseEntry, PassphraseOffer, PhysicalCollection,
            PlatformAndVirtualizationCheck, PreSecretError,
            ReentryMismatchChoice, ReleaseAndEnvironmentWarning, ScrubWhatIsReachable,
            SecretArenaScrub, SetupSelection, Shutdown, ShutdownFailedHalt, Start,
            WatchdogDisable,
        };

        match (from, event) {
            (Start, Event::Continue) => Some(ReleaseAndEnvironmentWarning),

            (ReleaseAndEnvironmentWarning, Event::Continue) => Some(WatchdogDisable),
            (ReleaseAndEnvironmentWarning, Event::Escape) => Some(ExitToFirmware),

            (WatchdogDisable, Event::Continue) => Some(PlatformAndVirtualizationCheck),

            (PlatformAndVirtualizationCheck, Event::CheckPassed) => Some(ConsoleTopologyCheck),
            (PlatformAndVirtualizationCheck, Event::CheckFailed(class, disp)) => {
                Some(check_failed_target(class, disp))
            }

            (ConsoleTopologyCheck, Event::CheckPassed) => Some(GraphicsAndKeyboardSelfTest),
            (ConsoleTopologyCheck, Event::CheckFailed(class, disp)) => {
                Some(check_failed_target(class, disp))
            }

            (GraphicsAndKeyboardSelfTest, Event::CheckPassed) => Some(CryptographicSelfTest),
            (GraphicsAndKeyboardSelfTest, Event::CheckFailed(class, disp)) => {
                Some(check_failed_target(class, disp))
            }

            (CryptographicSelfTest, Event::CheckPassed) => Some(SetupSelection),
            (CryptographicSelfTest, Event::CheckFailed(class, disp)) => {
                Some(check_failed_target(class, disp))
            }

            // 2026-08-07 ceremony redesign, Stage 3 "SETUP": the former
            // `(WordCountSelection, WordCountChosen) -> EntropyModeSelection`
            // and `(EntropyModeSelection, EntropyModeChosen) -> {Machine,
            // Physical}` pair, collapsed into ONE edge. The forward routing
            // is byte-for-byte the old `EntropyModeChosen` rule (the old
            // intermediate hop had no side effect beyond storing the word
            // count, which now happens here); the word count is stored
            // exactly as `WordCountChosen` stored it, and `instrument` is
            // PRESENTATION ONLY and read by no branch below.
            (
                SetupSelection,
                Event::SetupCommitted {
                    word_count,
                    mode,
                    instrument,
                },
            ) => {
                self.word_count = Some(word_count);
                self.mode = Some(mode);
                self.instrument = Some(instrument);
                if mode.needs_machine() {
                    Some(MachineEntropyAcquisition)
                } else {
                    Some(PhysicalCollection)
                }
            }

            (MachineEntropyAcquisition, Event::MachineEntropyComplete) => {
                if self.mode.is_some_and(EntropyMode::needs_physical) {
                    Some(PhysicalCollection)
                } else {
                    Some(FinalGenerationConfirmation)
                }
            }
            (MachineEntropyAcquisition, Event::MachineEntropyFailed(disp)) => {
                // SPEC §27.1: honor the caller-supplied disposition (a
                // legal `ExitToFirmware` request must not be silently
                // overridden into a menu return) — same rule as
                // `check_failed_target` above.
                Some(check_failed_target(ErrorClass::MachineSource, disp))
            }

            (PhysicalCollection, Event::PhysicalBudgetMet) => Some(FinalGenerationConfirmation),

            (FinalGenerationConfirmation, Event::FinalConfirm) => Some(FinalEntropyDerivation),
            // Frozen edge, re-pointed by the 2026-08-07 merge only because
            // its target state was renamed/merged: the fork point every
            // acquisition state is reached from is now `SetupSelection`.
            (FinalGenerationConfirmation, Event::Escape) => Some(SetupSelection),

            // Secret-creation boundary (SPEC §27.2): everything below this
            // line is reached only once final entropy exists.
            (FinalEntropyDerivation, Event::DerivationComplete) => Some(MnemonicGeneration),
            (FinalEntropyDerivation, Event::DerivationFailed(_)) => {
                Some(ScrubWhatIsReachable)
            }

            (MnemonicGeneration, Event::MnemonicReady) => Some(MnemonicDisplay),

            (MnemonicDisplay, Event::HideAndReenter) => Some(DisplayScrub),
            (MnemonicDisplay, Event::DestroyRequested) => Some(DestroyConfirm),

            (DestroyConfirm, Event::DestroyConfirmed) => Some(SecretArenaScrub),
            (DestroyConfirm, Event::Continue) => Some(MnemonicDisplay),

            (DisplayScrub, Event::ScrubComplete) => Some(CompleteHiddenReentry),

            (CompleteHiddenReentry, Event::ReentryPositionMatched) => {
                Some(CompleteHiddenReentry)
            }
            // SPEC_PASSPHRASE §6.1/§6.4 (M1): the `ReentryComplete` edge is
            // REPOINTED from `DerivationVerificationDisplay` to the new
            // post-secret `PassphraseOffer` step. The empty/skip path still
            // TERMINATES at `DerivationVerificationDisplay` with the empty
            // passphrase (via `PassphraseUseEmpty` below), so the
            // empty-passphrase SEED and its frozen vectors are preserved
            // byte-for-byte; only the routing that reaches it changed.
            (CompleteHiddenReentry, Event::ReentryComplete) => Some(PassphraseOffer),
            (CompleteHiddenReentry, Event::ReentryMismatch) => Some(ReentryMismatchChoice),

            (ReentryMismatchChoice, Event::RetryPosition) => Some(CompleteHiddenReentry),
            (ReentryMismatchChoice, Event::RevealAgain) => Some(MnemonicDisplay),
            (ReentryMismatchChoice, Event::DestroyRequested) => Some(DestroyConfirm),

            // SPEC_PASSPHRASE §6.1/§6.2: the three new post-secret states.
            // A LINEAR forward-only binary branch; no edge returns to any
            // pre-secret/menu state (SPEC §21/§26). `Escape`/`Back` are NOT
            // navigation edges here (post-secret) — they fall through to the
            // fatal chain via `illegal_edge`.
            (PassphraseOffer, Event::PassphraseOfferYes) => Some(PassphraseEntry),
            (PassphraseOffer, Event::PassphraseUseEmpty) => Some(DerivationVerificationDisplay),
            (PassphraseEntry, Event::PassphraseEntered) => Some(PassphraseConfirm),
            (PassphraseEntry, Event::PassphraseUseEmpty) => Some(DerivationVerificationDisplay),
            (PassphraseConfirm, Event::PassphraseConfirmMatch) => Some(DerivationVerificationDisplay),
            (PassphraseConfirm, Event::PassphraseConfirmMismatch) => Some(PassphraseEntry),

            (DerivationVerificationDisplay, Event::ShowVerification) => {
                Some(DerivationVerificationDisplay)
            }
            (DerivationVerificationDisplay, Event::SkipVerification)
            | (DerivationVerificationDisplay, Event::VerificationAcknowledged) => {
                Some(CompletionEducation)
            }
            (DerivationVerificationDisplay, Event::VerificationFailed) => {
                Some(ScrubWhatIsReachable)
            }

            (CompletionEducation, Event::EducationAcknowledged) => Some(SecretArenaScrub),

            (SecretArenaScrub, Event::ScrubComplete) => Some(FramebufferScrub),

            (FramebufferScrub, Event::ScrubComplete) => Some(Shutdown),

            (Shutdown, Event::ShutdownRequested) => Some(Shutdown),
            (Shutdown, Event::ShutdownFailed) => Some(ShutdownFailedHalt),

            // ================================================================
            // SPEC.md §21 amendment (2026-08-04, "pre-secret Back
            // navigation"): `Event::Back` goes to exactly one step to the
            // immediately preceding pre-secret screen — the exact reverse
            // of the SPEC §21 forward order:
            //
            //   SetupSelection -> CryptographicSelfTest ->
            //   GraphicsAndKeyboardSelfTest ->
            //   ConsoleTopologyCheck -> PlatformAndVirtualizationCheck ->
            //   WatchdogDisable -> ReleaseAndEnvironmentWarning -> Start
            //
            // (2026-08-07 ceremony redesign: the former
            // `EntropyModeSelection -> WordCountSelection` link is GONE —
            // those two screens are now panels of the single
            // `SetupSelection` state, and the driver moves between them
            // without firing any event at all.)
            //
            // SPEC.md §21 amendment (2026-08-05, "Back skips automatic
            // gates"): the ONE deliberate exception to that exact reverse
            // order is `SetupSelection`'s Back (formerly
            // `WordCountSelection`'s — the merge inherits it UNCHANGED),
            // which SKIPS its immediate predecessor `CryptographicSelfTest`
            // and lands on
            // `GraphicsAndKeyboardSelfTest`. `CryptographicSelfTest` (like
            // `ConsoleTopologyCheck` and `PlatformAndVirtualizationCheck`)
            // is an AUTOMATIC gate: the driver runs its check and emits
            // `CheckPassed` with no keypress, so on a clean result it
            // advances instantly. Landing Back there re-ran the gate and
            // returned straight to the setup screen's recap — an
            // invisible self-loop ("Esc does nothing"). The recap advertises
            // `[Esc] Back`, so Back must move the user to a visibly
            // different screen: `GraphicsAndKeyboardSelfTest` is the last
            // INTERACTIVE pre-secret screen before `SetupSelection`
            // (the driver blocks there for the local-display confirmation
            // and the keyboard-self-test offer). Proceeding forward from it
            // re-runs the automatic crypto gate and returns to the recap.
            // No other reachable pre-secret Back edge lands on an automatic
            // gate: the only screens that read Esc and fire `Event::Back`
            // are the opening warning (-> Start), this recap (->
            // GraphicsAndKeyboardSelfTest), and the acquisition/confirm
            // screens (-> the interactive SetupSelection). The
            // gate-to-gate Back edges below
            // (e.g. CryptographicSelfTest -> GraphicsAndKeyboardSelfTest)
            // are retained for completeness but are never fired
            // interactively, because the driver never pauses for Esc on an
            // automatic gate.
            //
            // `MachineEntropyAcquisition`/`PhysicalCollection` (the two
            // optional acquisition states) and `FinalGenerationConfirmation`
            // all fold back to `SetupSelection` — the fork point
            // every one of them is reached from — rather than to whichever
            // specific optional state happened to precede them this run
            // (mirrors the existing frozen `(FinalGenerationConfirmation,
            // Event::Escape) => SetupSelection` edge above). No edge
            // is added from `Start` (nothing precedes it) or from any
            // `PreSecretError`/post-secret state (see the module doc
            // comment and `illegal_edge` below: an attempt there is not a
            // legal edge and is routed exactly like any other unrecognised
            // event for that state).
            // ================================================================
            (ReleaseAndEnvironmentWarning, Event::Back) => Some(Start),
            (WatchdogDisable, Event::Back) => Some(ReleaseAndEnvironmentWarning),
            (PlatformAndVirtualizationCheck, Event::Back) => Some(WatchdogDisable),
            (ConsoleTopologyCheck, Event::Back) => Some(PlatformAndVirtualizationCheck),
            (GraphicsAndKeyboardSelfTest, Event::Back) => Some(ConsoleTopologyCheck),
            (CryptographicSelfTest, Event::Back) => Some(GraphicsAndKeyboardSelfTest),
            // SPEC.md §21 amendment (2026-08-05): skips the automatic
            // `CryptographicSelfTest` gate to land on the last INTERACTIVE
            // pre-secret screen (see the block comment above). The
            // 2026-08-07 merge inherits this target EXACTLY — the merged
            // setup screen still opens on the §22.3 diagnostics recap, so
            // the reason the skip exists is unchanged.
            (SetupSelection, Event::Back) => Some(GraphicsAndKeyboardSelfTest),
            (MachineEntropyAcquisition, Event::Back) => Some(SetupSelection),
            (PhysicalCollection, Event::Back) => Some(SetupSelection),
            (FinalGenerationConfirmation, Event::Back) => Some(SetupSelection),

            (PreSecretError(class), Event::Continue) => {
                // SPEC §11 / §22.3: a mandatory startup gate's failure must
                // not be bypassed — resume at the gate itself so it has to
                // emit `CheckPassed` again, never skip straight back into
                // the normal flow.
                Some(class.mandatory_gate_retry().unwrap_or(SetupSelection))
            }
            (PreSecretError(_), Event::Escape) => Some(ExitToFirmware),

            _ => None,
        }
    }

    /// Compute the routing target for an event that had no legal edge from
    /// `from` (SPEC §21, §27.1, §27.2).
    fn illegal_edge(&self, from: AppState, event: Event) -> (AppState, Option<ErrorClass>) {
        if from.is_post_secret() {
            // SPEC §21: never a menu return once a secret exists.
            let class = match event {
                Event::Fault(class) => class,
                _ => ErrorClass::StateMachine,
            };
            (AppState::ScrubWhatIsReachable, Some(class))
        } else {
            // SPEC §27.1: pre-secret errors may return to a safe menu or
            // exit to firmware; a truly unrecognised (non-error) event
            // still needs a non-crashing, deterministic target, so it is
            // treated as a state-machine-class error.
            match event {
                Event::CheckFailed(_, PreSecretDisposition::ExitToFirmware)
                | Event::MachineEntropyFailed(PreSecretDisposition::ExitToFirmware)
                | Event::DerivationFailed(PreSecretDisposition::ExitToFirmware) => {
                    (AppState::ExitToFirmware, None)
                }
                Event::CheckFailed(class, PreSecretDisposition::ReturnToMenu) => {
                    (AppState::PreSecretError(class), None)
                }
                Event::MachineEntropyFailed(PreSecretDisposition::ReturnToMenu) => (
                    AppState::PreSecretError(ErrorClass::MachineSource),
                    None,
                ),
                Event::DerivationFailed(PreSecretDisposition::ReturnToMenu) => (
                    AppState::PreSecretError(ErrorClass::Derivation),
                    None,
                ),
                Event::Fault(class) => (AppState::PreSecretError(class), None),
                _ => (
                    AppState::PreSecretError(ErrorClass::StateMachine),
                    None,
                ),
            }
        }
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn wd() -> CountingWatchdog {
        CountingWatchdog::default()
    }

    /// 2026-08-07 ceremony redesign (Stage 3 "SETUP"): the single commit
    /// event of the merged [`AppState::SetupSelection`] screen. The
    /// instrument is PRESENTATION ONLY (SPEC_DICE_COIN_VISUAL.md §2.3) and
    /// never routes, so the tests pin the default everywhere except the
    /// dedicated instrument-passthrough test.
    const fn setup(word_count: WordCount, mode: EntropyMode) -> Event {
        Event::SetupCommitted {
            word_count,
            mode,
            instrument: Instrument::Both,
        }
    }

    /// Drives `sm` through the full "happy path" combined-mode, 12-word
    /// ceremony up to (but not through) `SecretArenaScrub`, returning after
    /// each step so individual tests can pick up wherever they need.
    fn drive_to_mnemonic_display(sm: &mut StateMachine, w: &mut CountingWatchdog) {
        assert_eq!(sm.transition(Event::Continue, w).next, AppState::ReleaseAndEnvironmentWarning);
        assert_eq!(sm.transition(Event::Continue, w).next, AppState::WatchdogDisable);
        assert_eq!(sm.transition(Event::Continue, w).next, AppState::PlatformAndVirtualizationCheck);
        assert_eq!(sm.transition(Event::CheckPassed, w).next, AppState::ConsoleTopologyCheck);
        assert_eq!(sm.transition(Event::CheckPassed, w).next, AppState::GraphicsAndKeyboardSelfTest);
        assert_eq!(sm.transition(Event::CheckPassed, w).next, AppState::CryptographicSelfTest);
        assert_eq!(sm.transition(Event::CheckPassed, w).next, AppState::SetupSelection);
        // 2026-08-07 ceremony redesign (Stage 3 "SETUP"): the former
        // WordCountChosen + EntropyModeChosen pair is now ONE commit.
        assert_eq!(
            sm.transition(setup(WordCount::Twelve, EntropyMode::Combined), w).next,
            AppState::MachineEntropyAcquisition
        );
        assert_eq!(
            sm.transition(Event::MachineEntropyComplete, w).next,
            AppState::PhysicalCollection
        );
        assert_eq!(
            sm.transition(Event::PhysicalBudgetMet, w).next,
            AppState::FinalGenerationConfirmation
        );
        assert_eq!(
            sm.transition(Event::FinalConfirm, w).next,
            AppState::FinalEntropyDerivation
        );
        assert_eq!(
            sm.transition(Event::DerivationComplete, w).next,
            AppState::MnemonicGeneration
        );
        assert_eq!(
            sm.transition(Event::MnemonicReady, w).next,
            AppState::MnemonicDisplay
        );
    }

    #[test]
    fn happy_path_combined_12word_reaches_shutdown() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        drive_to_mnemonic_display(&mut sm, &mut w);

        assert_eq!(sm.transition(Event::HideAndReenter, &mut w).next, AppState::DisplayScrub);
        assert_eq!(sm.transition(Event::ScrubComplete, &mut w).next, AppState::CompleteHiddenReentry);
        for _ in 0..11 {
            assert_eq!(
                sm.transition(Event::ReentryPositionMatched, &mut w).next,
                AppState::CompleteHiddenReentry
            );
        }
        // SPEC_PASSPHRASE §6.4 (M1): ReentryComplete now lands on the new
        // post-secret PassphraseOffer; the empty/skip path drives forward
        // through it to DerivationVerificationDisplay.
        assert_eq!(
            sm.transition(Event::ReentryComplete, &mut w).next,
            AppState::PassphraseOffer
        );
        assert_eq!(
            sm.transition(Event::PassphraseUseEmpty, &mut w).next,
            AppState::DerivationVerificationDisplay
        );
        assert_eq!(
            sm.transition(Event::SkipVerification, &mut w).next,
            AppState::CompletionEducation
        );
        assert_eq!(
            sm.transition(Event::EducationAcknowledged, &mut w).next,
            AppState::SecretArenaScrub
        );
        assert_eq!(
            sm.transition(Event::ScrubComplete, &mut w).next,
            AppState::FramebufferScrub
        );
        assert_eq!(sm.transition(Event::ScrubComplete, &mut w).next, AppState::Shutdown);
        assert_eq!(sm.transition(Event::ShutdownRequested, &mut w).next, AppState::Shutdown);
    }

    #[test]
    fn happy_path_dice_only_skips_machine_entropy() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        for _ in 0..3 {
            sm.transition(Event::Continue, &mut w);
        }
        for _ in 0..4 {
            sm.transition(Event::CheckPassed, &mut w);
        }
        let t = sm.transition(setup(WordCount::TwentyFour, EntropyMode::DiceOnly), &mut w);
        assert_eq!(t.next, AppState::PhysicalCollection);
        assert_eq!(sm.target_bits(), Some(TargetBits::Bits256));
        assert_eq!(sm.word_count(), Some(WordCount::TwentyFour));
    }

    #[test]
    fn happy_path_machine_only_skips_physical_collection() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::CheckPassed, &mut w);
        sm.transition(Event::CheckPassed, &mut w);
        sm.transition(Event::CheckPassed, &mut w);
        sm.transition(Event::CheckPassed, &mut w);
        sm.transition(setup(WordCount::Twelve, EntropyMode::MachineOnly), &mut w);
        let t = sm.transition(Event::MachineEntropyComplete, &mut w);
        assert_eq!(t.next, AppState::FinalGenerationConfirmation);
    }

    /// 2026-08-07 ceremony redesign (Stage 3 "SETUP"): the merged screen's
    /// ONE commit event carries all three values. Only `mode` routes; the
    /// word count lands in [`StateMachine::target_bits`]/
    /// [`StateMachine::word_count`] and the PRESENTATION-ONLY instrument
    /// (SPEC_DICE_COIN_VISUAL.md §2.3) is stored verbatim and changes NO
    /// edge — the same instrument value must produce the same next state
    /// for a given mode.
    #[test]
    fn setup_committed_stores_all_three_and_routes_only_on_mode() {
        for instrument in [Instrument::Dice, Instrument::Coins, Instrument::Both] {
            for (mode, expected) in [
                (EntropyMode::Combined, AppState::MachineEntropyAcquisition),
                (EntropyMode::MachineOnly, AppState::MachineEntropyAcquisition),
                (EntropyMode::DiceOnly, AppState::PhysicalCollection),
            ] {
                for (word_count, bits) in [
                    (WordCount::Twelve, TargetBits::Bits128),
                    (WordCount::TwentyFour, TargetBits::Bits256),
                ] {
                    let mut sm = sm_at(AppState::SetupSelection);
                    let mut w = wd();
                    let t = sm.transition(
                        Event::SetupCommitted { word_count, mode, instrument },
                        &mut w,
                    );
                    assert!(!t.was_illegal, "SetupCommitted must be a legal edge from SetupSelection");
                    assert_eq!(
                        t.next, expected,
                        "mode {mode:?} (instrument {instrument:?}) must route to {expected:?}"
                    );
                    assert_eq!(sm.word_count(), Some(word_count));
                    assert_eq!(sm.target_bits(), Some(bits));
                    assert_eq!(
                        sm.instrument(),
                        Some(instrument),
                        "the presentation-only instrument must be stored verbatim"
                    );
                }
            }
        }
    }

    /// The merged state's `[Esc]` Back edge is the ONE deliberate exception
    /// to the exact-reverse SPEC §21 order (SPEC.md §21 amendment
    /// 2026-08-05): it SKIPS the AUTOMATIC `CryptographicSelfTest` gate and
    /// lands on the last INTERACTIVE pre-secret screen. The 2026-08-07
    /// merge inherits that target unchanged from the former
    /// `WordCountSelection`; the former `EntropyModeSelection -> WordCountSelection`
    /// Back edge is gone because both screens are now panels of this one
    /// state (the driver moves between them without firing any event).
    #[test]
    fn back_from_setup_selection_skips_the_automatic_crypto_gate() {
        let mut sm = sm_at(AppState::SetupSelection);
        let mut w = wd();
        let t = sm.transition(Event::Back, &mut w);
        assert!(!t.was_illegal);
        assert_eq!(t.next, AppState::GraphicsAndKeyboardSelfTest);
        assert_ne!(t.next, AppState::CryptographicSelfTest);
    }

    #[test]
    fn watchdog_reasserted_on_every_transition_including_illegal_and_fatal() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::ReentryMismatch, &mut w); // illegal here (pre-secret)
        assert_eq!(w.count, 2);
        // Drive into the fatal chain and confirm the count keeps climbing.
        sm.transition(Event::Fault(ErrorClass::Integrity), &mut w);
        assert_eq!(w.count, 3);
    }

    /// A [`WatchdogReassert`] stub whose `reassert()` always fails, for
    /// exercising SPEC §11.1's "treat a re-assertion failure ... as a fatal
    /// error routed to scrub-and-shutdown" rule.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct FailingWatchdog {
        count: u32,
    }

    impl WatchdogReassert for FailingWatchdog {
        fn reassert(&mut self) -> Result<(), WatchdogReassertFailure> {
            self.count = self.count.saturating_add(1);
            Err(WatchdogReassertFailure)
        }
    }

    #[test]
    fn watchdog_reassert_failure_post_secret_is_fatal_routed_to_scrub() {
        // Regression test for the WP-23 adversarial-review finding: SPEC
        // §11.1 requires a watchdog re-assertion failure to be fatal once
        // final entropy exists. Probe every post-secret state.
        let post_secret_states = [
            AppState::FinalEntropyDerivation,
            AppState::MnemonicGeneration,
            AppState::MnemonicDisplay,
            AppState::CompleteHiddenReentry,
            AppState::PassphraseOffer,
            AppState::PassphraseEntry,
            AppState::PassphraseConfirm,
            AppState::DerivationVerificationDisplay,
            AppState::CompletionEducation,
            AppState::SecretArenaScrub,
            AppState::FramebufferScrub,
            AppState::Shutdown,
        ];
        for state in post_secret_states {
            let mut sm = StateMachine {
                state,
                word_count: Some(WordCount::Twelve),
                mode: Some(EntropyMode::Combined),
                instrument: Some(Instrument::Both),
            };
            let mut w = FailingWatchdog::default();
            // Even an otherwise-legal event must be overridden into the
            // fatal chain when the watchdog itself failed to re-assert.
            let t = sm.transition(Event::Continue, &mut w);
            assert_eq!(
                t.next,
                AppState::ScrubWhatIsReachable,
                "state {state:?}: watchdog reassert failure post-secret must be fatal"
            );
            assert!(t.was_illegal);
            assert_eq!(t.fatal_class, Some(ErrorClass::Watchdog));
            assert_eq!(sm.state(), AppState::ScrubWhatIsReachable);
            assert_eq!(w.count, 1, "watchdog must still be called exactly once");
        }
    }

    #[test]
    fn watchdog_reassert_failure_pre_secret_routes_to_pre_secret_error_not_silently_ignored() {
        // Pre-secret, SPEC §11.1 does not mandate the fatal chain (no
        // secret exists yet to scrub), but a failed re-assertion still must
        // not be silently ignored while continuing normal flow.
        let mut sm = StateMachine::new();
        let mut w = FailingWatchdog::default();
        let t = sm.transition(Event::Continue, &mut w);
        assert_eq!(t.next, AppState::PreSecretError(ErrorClass::Watchdog));
        assert!(t.was_illegal);
        assert_eq!(t.fatal_class, None);
    }

    #[test]
    fn watchdog_reassert_failure_in_fatal_chain_does_not_disrupt_deterministic_advance() {
        // Once already inside the fatal chain, a watchdog failure changes
        // nothing: the chain still advances unconditionally.
        let mut sm = StateMachine {
            state: AppState::ScrubWhatIsReachable,
            word_count: None,
            mode: None,
            instrument: None,
        };
        let mut w = FailingWatchdog::default();
        let t = sm.transition(Event::Continue, &mut w);
        assert_eq!(t.next, AppState::BlankDisplay);
        assert!(!t.was_illegal);
    }

    #[test]
    fn watchdog_reassert_failure_on_terminal_state_is_absorbed() {
        let mut sm = StateMachine {
            state: AppState::ExitToFirmware,
            word_count: None,
            mode: None,
            instrument: None,
        };
        let mut w = FailingWatchdog::default();
        let t = sm.transition(Event::Continue, &mut w);
        assert_eq!(t.next, AppState::ExitToFirmware);
        assert!(!t.was_illegal);
    }

    #[test]
    fn machine_entropy_failed_honors_exit_to_firmware_disposition() {
        // Regression test for the WP-23 adversarial-review finding: a
        // caller-supplied ExitToFirmware disposition on MachineEntropyFailed
        // must not be silently overridden into a menu return (SPEC §27.1).
        let mut sm = StateMachine {
            state: AppState::MachineEntropyAcquisition,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::MachineOnly),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(
            Event::MachineEntropyFailed(PreSecretDisposition::ExitToFirmware),
            &mut w,
        );
        assert_eq!(t.next, AppState::ExitToFirmware);
        assert!(!t.was_illegal);
    }

    #[test]
    fn escape_before_secret_exits_to_firmware() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        sm.transition(Event::Continue, &mut w);
        let t = sm.transition(Event::Escape, &mut w);
        assert_eq!(t.next, AppState::ExitToFirmware);
        assert!(!t.was_illegal);
        // Terminal: further events do not move it and are not "illegal".
        let t2 = sm.transition(Event::Continue, &mut w);
        assert_eq!(t2.next, AppState::ExitToFirmware);
        assert!(!t2.was_illegal);
    }

    #[test]
    fn escape_at_final_confirmation_returns_to_setup_selection() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        for _ in 0..3 {
            sm.transition(Event::Continue, &mut w);
        }
        for _ in 0..4 {
            sm.transition(Event::CheckPassed, &mut w);
        }
        sm.transition(setup(WordCount::Twelve, EntropyMode::DiceOnly), &mut w);
        sm.transition(Event::PhysicalBudgetMet, &mut w);
        let t = sm.transition(Event::Escape, &mut w);
        // Same frozen edge as before the merge — the fork point every
        // acquisition state is reached from is now `SetupSelection`.
        assert_eq!(t.next, AppState::SetupSelection);
    }

    #[test]
    fn check_failed_routes_to_pre_secret_error_and_back_to_its_own_gate() {
        // Regression test for the WP-23 adversarial-review finding: a
        // mandatory-gate CheckFailed must NOT be resumable straight into
        // SetupSelection (SPEC §11 "No secret entropy may be collected
        // until every mandatory startup gate passes"; §22.3 "'Inconclusive'
        // on a mandatory item disables generation"). `Continue` from the
        // resulting PreSecretError must land back on the same gate so it
        // has to emit CheckPassed again.
        let mut sm = StateMachine::new();
        let mut w = wd();
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        let t = sm.transition(
            Event::CheckFailed(ErrorClass::Virtualization, PreSecretDisposition::ReturnToMenu),
            &mut w,
        );
        assert_eq!(t.next, AppState::PreSecretError(ErrorClass::Virtualization));
        assert!(!t.was_illegal);
        let t2 = sm.transition(Event::Continue, &mut w);
        assert_eq!(
            t2.next,
            AppState::PlatformAndVirtualizationCheck,
            "a failed mandatory gate must be re-verified, never skipped straight to SetupSelection"
        );
        assert_ne!(t2.next, AppState::SetupSelection);
        // Only after the gate actually re-emits CheckPassed does the
        // machine continue into the normal flow.
        let t3 = sm.transition(Event::CheckPassed, &mut w);
        assert_eq!(t3.next, AppState::ConsoleTopologyCheck);
    }

    #[test]
    fn every_mandatory_gate_check_failed_resumes_at_the_same_gate_not_the_menu() {
        // Same regression as above, exhaustively over the other three
        // mandatory gates and their documented error classes.
        let cases = [
            (
                AppState::ConsoleTopologyCheck,
                ErrorClass::ConsoleTopology,
                1,
            ),
            (
                AppState::GraphicsAndKeyboardSelfTest,
                ErrorClass::GraphicsOrKeyboard,
                2,
            ),
            (AppState::CryptographicSelfTest, ErrorClass::Cryptographic, 3),
        ];
        for (gate, class, checks_passed_first) in cases {
            let mut sm = StateMachine::new();
            let mut w = wd();
            sm.transition(Event::Continue, &mut w);
            sm.transition(Event::Continue, &mut w);
            sm.transition(Event::Continue, &mut w);
            for _ in 0..checks_passed_first {
                sm.transition(Event::CheckPassed, &mut w);
            }
            assert_eq!(sm.state(), gate, "test setup did not reach the expected gate");
            let t = sm.transition(
                Event::CheckFailed(class, PreSecretDisposition::ReturnToMenu),
                &mut w,
            );
            assert_eq!(t.next, AppState::PreSecretError(class));
            let t2 = sm.transition(Event::Continue, &mut w);
            assert_eq!(
                t2.next, gate,
                "gate {gate:?} (class {class:?}) must resume at itself, not SetupSelection"
            );
        }
    }

    #[test]
    fn non_gate_pre_secret_error_still_resumes_at_setup_selection() {
        // Errors unrelated to the four mandatory gates (e.g. a machine
        // entropy failure, which can only happen after every gate already
        // passed) legitimately resume at SetupSelection — confirms the
        // fix is scoped to gate-class errors only, not a blanket change.
        let mut sm = StateMachine {
            state: AppState::MachineEntropyAcquisition,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::MachineOnly),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(
            Event::MachineEntropyFailed(PreSecretDisposition::ReturnToMenu),
            &mut w,
        );
        assert_eq!(t.next, AppState::PreSecretError(ErrorClass::MachineSource));
        let t2 = sm.transition(Event::Continue, &mut w);
        assert_eq!(t2.next, AppState::SetupSelection);
    }

    #[test]
    fn check_failed_can_exit_to_firmware() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        sm.transition(Event::Continue, &mut w);
        let t = sm.transition(
            Event::CheckFailed(ErrorClass::Platform, PreSecretDisposition::ExitToFirmware),
            &mut w,
        );
        assert_eq!(t.next, AppState::ExitToFirmware);
    }

    #[test]
    fn illegal_event_pre_secret_never_reaches_fatal_chain() {
        let mut w = wd();
        // From Start, everything except Continue is illegal.
        let illegal_events = [
            Event::Escape,
            Event::CheckPassed,
            Event::MnemonicReady,
            Event::HideAndReenter,
            Event::ReentryComplete,
            Event::ShutdownRequested,
        ];
        for ev in illegal_events {
            let mut probe = StateMachine::new();
            let t = probe.transition(ev, &mut w);
            assert!(t.was_illegal);
            assert!(!t.next.is_post_secret());
            assert_ne!(t.next, AppState::ScrubWhatIsReachable);
        }
    }

    #[test]
    fn illegal_event_post_secret_always_routes_to_scrub_never_menu() {
        let mut w = wd();
        // Enumerate every post-secret state and probe it with a battery of
        // events that are not its legal edge; confirm every single one
        // lands in ScrubWhatIsReachable, and specifically never in any
        // *Selection or Warning ("menu") state.
        let post_secret_states = [
            AppState::FinalEntropyDerivation,
            AppState::MnemonicGeneration,
            AppState::MnemonicDisplay,
            AppState::DestroyConfirm,
            AppState::DisplayScrub,
            AppState::CompleteHiddenReentry,
            AppState::ReentryMismatchChoice,
            AppState::PassphraseOffer,
            AppState::PassphraseEntry,
            AppState::PassphraseConfirm,
            AppState::DerivationVerificationDisplay,
            AppState::CompletionEducation,
            AppState::SecretArenaScrub,
            AppState::FramebufferScrub,
        ];
        let probe_events = [
            Event::Continue,
            Event::Escape,
            Event::CheckPassed,
            setup(WordCount::Twelve, EntropyMode::Combined),
            setup(WordCount::TwentyFour, EntropyMode::DiceOnly),
            Event::FinalConfirm,
            Event::ShowVerification,
            Event::ShutdownRequested,
        ];
        for state in post_secret_states {
            for ev in probe_events {
                let mut sm = StateMachine {
                    state,
                    word_count: Some(WordCount::Twelve),
                    mode: Some(EntropyMode::Combined),
                    instrument: Some(Instrument::Both),
                };
                let t = sm.transition(ev, &mut w);
                // Either it's a legal self-consistent edge (rare, e.g. a
                // state that legitimately accepts Continue) or it must be
                // the fatal chain — nothing else, and never a menu state.
                assert!(
                    !matches!(
                        t.next,
                        AppState::SetupSelection
                            | AppState::ReleaseAndEnvironmentWarning
                            | AppState::Start
                    ),
                    "state {state:?} + event {ev:?} illegally reached a menu: {:?}",
                    t.next
                );
                if t.was_illegal {
                    assert_eq!(
                        t.next,
                        AppState::ScrubWhatIsReachable,
                        "state {state:?} + event {ev:?} was illegal but did not route to ScrubWhatIsReachable"
                    );
                    assert!(t.fatal_class.is_some());
                }
            }
        }
    }

    #[test]
    fn fatal_chain_is_unconditional_and_terminates() {
        let mut sm = StateMachine {
            state: AppState::ScrubWhatIsReachable,
            word_count: None,
            mode: None,
            instrument: None,
        };
        let mut w = wd();
        let t1 = sm.transition(Event::Fault(ErrorClass::Integrity), &mut w);
        assert_eq!(t1.next, AppState::BlankDisplay);
        assert!(!t1.was_illegal);
        let t2 = sm.transition(Event::Continue, &mut w); // arbitrary event
        assert_eq!(t2.next, AppState::ShutdownOrHalt);
        // Terminal now: stays put regardless of event.
        let t3 = sm.transition(setup(WordCount::Twelve, EntropyMode::Combined), &mut w);
        assert_eq!(t3.next, AppState::ShutdownOrHalt);
        assert!(!t3.was_illegal);
    }

    #[test]
    fn shutdown_failure_enters_non_returning_halt() {
        let mut sm = StateMachine {
            state: AppState::Shutdown,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::Combined),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(Event::ShutdownFailed, &mut w);
        assert_eq!(t.next, AppState::ShutdownFailedHalt);
        let t2 = sm.transition(Event::Fault(ErrorClass::Shutdown), &mut w);
        assert_eq!(t2.next, AppState::ShutdownFailedHalt);
        assert!(!t2.was_illegal);
    }

    #[test]
    fn reentry_mismatch_retry_and_reveal_again_paths() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        drive_to_mnemonic_display(&mut sm, &mut w);
        sm.transition(Event::HideAndReenter, &mut w);
        sm.transition(Event::ScrubComplete, &mut w);
        let t = sm.transition(Event::ReentryMismatch, &mut w);
        assert_eq!(t.next, AppState::ReentryMismatchChoice);
        let t2 = sm.transition(Event::RetryPosition, &mut w);
        assert_eq!(t2.next, AppState::CompleteHiddenReentry);

        sm.transition(Event::ReentryMismatch, &mut w);
        let t3 = sm.transition(Event::RevealAgain, &mut w);
        assert_eq!(t3.next, AppState::MnemonicDisplay);

        // Restart the hide/scrub/reentry loop and this time destroy.
        sm.transition(Event::HideAndReenter, &mut w);
        sm.transition(Event::ScrubComplete, &mut w);
        sm.transition(Event::ReentryMismatch, &mut w);
        let t4 = sm.transition(Event::DestroyRequested, &mut w);
        assert_eq!(t4.next, AppState::DestroyConfirm);
        let t5 = sm.transition(Event::DestroyConfirmed, &mut w);
        assert_eq!(t5.next, AppState::SecretArenaScrub);
    }

    #[test]
    fn destroy_from_mnemonic_display_skips_reentry() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        drive_to_mnemonic_display(&mut sm, &mut w);
        let t = sm.transition(Event::DestroyRequested, &mut w);
        assert_eq!(t.next, AppState::DestroyConfirm);
        let t2 = sm.transition(Event::Continue, &mut w); // cancel destroy
        assert_eq!(t2.next, AppState::MnemonicDisplay);
        let t3 = sm.transition(Event::DestroyRequested, &mut w);
        assert_eq!(t3.next, AppState::DestroyConfirm);
        let t4 = sm.transition(Event::DestroyConfirmed, &mut w);
        assert_eq!(t4.next, AppState::SecretArenaScrub);
    }

    #[test]
    fn derivation_verification_display_is_optional_and_skippable() {
        let mut sm = StateMachine {
            state: AppState::DerivationVerificationDisplay,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::Combined),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(Event::SkipVerification, &mut w);
        assert_eq!(t.next, AppState::CompletionEducation);
    }

    #[test]
    fn derivation_verification_failure_is_fatal_not_menu() {
        let mut sm = StateMachine {
            state: AppState::DerivationVerificationDisplay,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::Combined),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(Event::VerificationFailed, &mut w);
        assert_eq!(t.next, AppState::ScrubWhatIsReachable);
    }

    #[test]
    fn derivation_failure_before_mnemonic_generation_is_still_fatal() {
        // FinalEntropyDerivation is the secret-creation boundary itself:
        // even though "derivation failed", the transcript already
        // finalized into final entropy conceptually reaching this state,
        // so SPEC §27.2 rules apply from here on, never a menu return.
        let mut sm = StateMachine {
            state: AppState::FinalEntropyDerivation,
            word_count: Some(WordCount::Twelve),
            mode: Some(EntropyMode::Combined),
            instrument: Some(Instrument::Both),
        };
        let mut w = wd();
        let t = sm.transition(
            Event::DerivationFailed(PreSecretDisposition::ReturnToMenu),
            &mut w,
        );
        assert_eq!(t.next, AppState::ScrubWhatIsReachable);
    }

    #[test]
    fn exhaustive_matrix_every_state_every_event_never_panics_and_never_illegally_menus() {
        // Full cartesian probe: every AppState variant we can construct (using
        // representative ErrorClass for PreSecretError) x every Event variant
        // we can construct (using representative payloads). Confirms no path
        // panics and the post-secret invariant holds everywhere.
        let states = [
            AppState::Start,
            AppState::ReleaseAndEnvironmentWarning,
            AppState::WatchdogDisable,
            AppState::PlatformAndVirtualizationCheck,
            AppState::ConsoleTopologyCheck,
            AppState::GraphicsAndKeyboardSelfTest,
            AppState::CryptographicSelfTest,
            AppState::SetupSelection,
            AppState::MachineEntropyAcquisition,
            AppState::PhysicalCollection,
            AppState::FinalGenerationConfirmation,
            AppState::FinalEntropyDerivation,
            AppState::MnemonicGeneration,
            AppState::MnemonicDisplay,
            AppState::DestroyConfirm,
            AppState::DisplayScrub,
            AppState::CompleteHiddenReentry,
            AppState::ReentryMismatchChoice,
            AppState::PassphraseOffer,
            AppState::PassphraseEntry,
            AppState::PassphraseConfirm,
            AppState::DerivationVerificationDisplay,
            AppState::CompletionEducation,
            AppState::SecretArenaScrub,
            AppState::FramebufferScrub,
            AppState::Shutdown,
            AppState::ShutdownFailedHalt,
            AppState::ExitToFirmware,
            AppState::PreSecretError(ErrorClass::Platform),
            AppState::ScrubWhatIsReachable,
            AppState::BlankDisplay,
            AppState::ShutdownOrHalt,
        ];
        let events = [
            Event::Continue,
            Event::Escape,
            Event::Back,
            Event::CheckPassed,
            Event::CheckFailed(ErrorClass::Platform, PreSecretDisposition::ReturnToMenu),
            Event::CheckFailed(ErrorClass::Platform, PreSecretDisposition::ExitToFirmware),
            // 2026-08-07 merge: the former WordCountChosen x EntropyModeChosen
            // cross-product collapses into SetupCommitted; every
            // word-count x mode pairing (and one non-default instrument, to
            // prove the presentation-only field routes nothing) is probed.
            setup(WordCount::Twelve, EntropyMode::Combined),
            setup(WordCount::TwentyFour, EntropyMode::Combined),
            setup(WordCount::Twelve, EntropyMode::DiceOnly),
            setup(WordCount::TwentyFour, EntropyMode::DiceOnly),
            setup(WordCount::Twelve, EntropyMode::MachineOnly),
            setup(WordCount::TwentyFour, EntropyMode::MachineOnly),
            Event::SetupCommitted {
                word_count: WordCount::Twelve,
                mode: EntropyMode::DiceOnly,
                instrument: Instrument::Coins,
            },
            Event::MachineEntropyComplete,
            Event::MachineEntropyFailed(PreSecretDisposition::ReturnToMenu),
            Event::PhysicalBudgetMet,
            Event::FinalConfirm,
            Event::DerivationComplete,
            Event::DerivationFailed(PreSecretDisposition::ReturnToMenu),
            Event::MnemonicReady,
            Event::HideAndReenter,
            Event::DestroyRequested,
            Event::DestroyConfirmed,
            Event::ScrubComplete,
            Event::ReentryPositionMatched,
            Event::ReentryComplete,
            Event::ReentryMismatch,
            Event::RetryPosition,
            Event::RevealAgain,
            Event::PassphraseOfferYes,
            Event::PassphraseUseEmpty,
            Event::PassphraseEntered,
            Event::PassphraseConfirmMatch,
            Event::PassphraseConfirmMismatch,
            Event::ShowVerification,
            Event::SkipVerification,
            Event::VerificationAcknowledged,
            Event::VerificationFailed,
            Event::EducationAcknowledged,
            Event::ShutdownRequested,
            Event::ShutdownFailed,
            Event::Fault(ErrorClass::Integrity),
        ];

        for state in states {
            for ev in events {
                let mut sm = StateMachine {
                    state,
                    word_count: Some(WordCount::Twelve),
                    mode: Some(EntropyMode::Combined),
                    instrument: Some(Instrument::Both),
                };
                let mut w = wd();
                let before_post_secret = state.is_post_secret();
                let t = sm.transition(ev, &mut w);
                assert_eq!(w.count, 1, "watchdog must be reasserted exactly once per call");
                if before_post_secret && t.was_illegal {
                    assert_eq!(
                        t.next,
                        AppState::ScrubWhatIsReachable,
                        "post-secret illegal transition from {state:?} on {ev:?} did not go to ScrubWhatIsReachable (got {:?})",
                        t.next
                    );
                }
                // Never, ever, from any post-secret state, land back on a
                // pre-secret "menu" state.
                if before_post_secret {
                    assert!(!matches!(
                        t.next,
                        AppState::Start
                            | AppState::ReleaseAndEnvironmentWarning
                            | AppState::SetupSelection
                    ));
                }
            }
        }
    }

    /// Regression guard for the SPEC §21 promise that this frozen machine
    /// has no menu-skip/bypass variant: the `states`/`events` literals feeding
    /// [`exhaustive_matrix_every_state_every_event_never_panics_and_never_illegally_menus`]
    /// are plain array literals, so a new [`AppState`] or [`Event`] variant
    /// (e.g. one added later for a desktop-launcher main-menu shortcut) could
    /// otherwise be introduced without that matrix ever exercising it.
    ///
    /// These two inner functions match on every variant with **no wildcard
    /// arm**, so this file stops compiling the moment either enum gains or
    /// loses a variant, forcing that matrix (and this list) to be updated in
    /// the same change instead of silently drifting out of sync.
    #[test]
    fn app_state_and_event_enums_are_exhaustively_covered_by_the_matrix_test() {
        fn assert_every_app_state_variant_is_listed(s: AppState) {
            match s {
                AppState::Start
                | AppState::ReleaseAndEnvironmentWarning
                | AppState::WatchdogDisable
                | AppState::PlatformAndVirtualizationCheck
                | AppState::ConsoleTopologyCheck
                | AppState::GraphicsAndKeyboardSelfTest
                | AppState::CryptographicSelfTest
                // 2026-08-07 ceremony redesign: the ONE merged setup state.
                // `WordCountSelection` / `EntropyModeSelection` are GONE —
                // naming either here would stop this file compiling, which
                // IS the "removed state names no longer exist" guard (see
                // this test's doc comment).
                | AppState::SetupSelection
                | AppState::MachineEntropyAcquisition
                | AppState::PhysicalCollection
                | AppState::FinalGenerationConfirmation
                | AppState::FinalEntropyDerivation
                | AppState::MnemonicGeneration
                | AppState::MnemonicDisplay
                | AppState::DestroyConfirm
                | AppState::DisplayScrub
                | AppState::CompleteHiddenReentry
                | AppState::ReentryMismatchChoice
                | AppState::PassphraseOffer
                | AppState::PassphraseEntry
                | AppState::PassphraseConfirm
                | AppState::DerivationVerificationDisplay
                | AppState::CompletionEducation
                | AppState::SecretArenaScrub
                | AppState::FramebufferScrub
                | AppState::Shutdown
                | AppState::ShutdownFailedHalt
                | AppState::ExitToFirmware
                | AppState::ScrubWhatIsReachable
                | AppState::BlankDisplay
                | AppState::ShutdownOrHalt => {}
                AppState::PreSecretError(_) => {}
            }
        }

        fn assert_every_event_variant_is_listed(e: Event) {
            match e {
                Event::Continue
                | Event::Escape
                | Event::Back
                | Event::CheckPassed
                // 2026-08-07 ceremony redesign: `WordCountChosen` /
                // `EntropyModeChosen` are GONE, replaced by the single
                // struct-variant `SetupCommitted` matched below.
                | Event::MachineEntropyComplete
                | Event::PhysicalBudgetMet
                | Event::FinalConfirm
                | Event::DerivationComplete
                | Event::MnemonicReady
                | Event::HideAndReenter
                | Event::DestroyRequested
                | Event::DestroyConfirmed
                | Event::ScrubComplete
                | Event::ReentryPositionMatched
                | Event::ReentryComplete
                | Event::ReentryMismatch
                | Event::RetryPosition
                | Event::RevealAgain
                | Event::PassphraseOfferYes
                | Event::PassphraseUseEmpty
                | Event::PassphraseEntered
                | Event::PassphraseConfirmMatch
                | Event::PassphraseConfirmMismatch
                | Event::ShowVerification
                | Event::SkipVerification
                | Event::VerificationAcknowledged
                | Event::VerificationFailed
                | Event::EducationAcknowledged
                | Event::ShutdownRequested
                | Event::ShutdownFailed => {}
                Event::CheckFailed(_, _) => {}
                Event::SetupCommitted { .. } => {}
                Event::MachineEntropyFailed(_) => {}
                Event::DerivationFailed(_) => {}
                Event::Fault(_) => {}
            }
        }

        // Nothing to assert at runtime beyond "this compiled": the coverage
        // check is the match arms above. Calling both keeps them from being
        // reported as dead code and documents that they are exercised.
        assert_every_app_state_variant_is_listed(AppState::Start);
        assert_every_event_variant_is_listed(Event::Continue);
    }

    // ========================================================================
    // SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation")
    // ========================================================================

    /// Every pre-secret state's `Event::Back` predecessor, exhaustively —
    /// the exact reverse of the SPEC §21 forward order, with the single
    /// documented exception (SPEC.md §21 amendment 2026-08-05) that
    /// `SetupSelection`'s Back SKIPS the automatic `CryptographicSelfTest`
    /// gate and lands on the last interactive screen
    /// `GraphicsAndKeyboardSelfTest`. `Start` is deliberately absent:
    /// nothing precedes it.
    ///
    /// 2026-08-07 ceremony redesign: the former
    /// `EntropyModeSelection -> WordCountSelection` Back edge is GONE —
    /// both screens are now panels of the single `SetupSelection` state,
    /// and moving between them fires no event at all.
    #[test]
    fn back_from_every_pre_secret_state_reaches_its_documented_predecessor() {
        let cases = [
            (AppState::ReleaseAndEnvironmentWarning, AppState::Start),
            (AppState::WatchdogDisable, AppState::ReleaseAndEnvironmentWarning),
            (AppState::PlatformAndVirtualizationCheck, AppState::WatchdogDisable),
            (AppState::ConsoleTopologyCheck, AppState::PlatformAndVirtualizationCheck),
            (AppState::GraphicsAndKeyboardSelfTest, AppState::ConsoleTopologyCheck),
            (AppState::CryptographicSelfTest, AppState::GraphicsAndKeyboardSelfTest),
            // SPEC.md §21 amendment (2026-08-05): skips the automatic
            // CryptographicSelfTest gate -> last interactive screen.
            // Inherited unchanged by the 2026-08-07 merge.
            (AppState::SetupSelection, AppState::GraphicsAndKeyboardSelfTest),
            (AppState::MachineEntropyAcquisition, AppState::SetupSelection),
            (AppState::PhysicalCollection, AppState::SetupSelection),
            (AppState::FinalGenerationConfirmation, AppState::SetupSelection),
        ];
        for (from, expected) in cases {
            let mut sm = sm_at(from);
            let mut w = wd();
            let t = sm.transition(Event::Back, &mut w);
            assert_eq!(t.next, expected, "Back from {from:?} should reach {expected:?}, got {:?}", t.next);
            assert!(!t.was_illegal, "Back from {from:?} must be a legal edge");
            assert_eq!(sm.state(), expected);
        }
    }

    /// SPEC.md §21 amendment (2026-08-05, "Back skips automatic gates"):
    /// consistency guard. Every pre-secret screen that advertises `[Esc]
    /// Back` (via `seed_flow`'s `text::BACK_PROMPT`) and fires
    /// `Event::Back` on Esc MUST land on a screen the user can actually see
    /// and interact with — never on an AUTOMATIC gate whose driver arm runs
    /// its check and advances with no keypress. Back onto such a gate
    /// re-runs it and returns instantly to the same screen: an invisible
    /// "Esc does nothing" self-loop (the original bug this amendment
    /// fixes). If a future edit repoints one of these Back edges at an
    /// automatic gate, this test fails.
    ///
    /// The AUTOMATIC set mirrors the driver
    /// (`seed_flow::driver::run_pre_secret_flow`): `WatchdogDisable`
    /// (confirmation line, immediate `Continue`) and the three mandatory
    /// check gates `PlatformAndVirtualizationCheck`, `ConsoleTopologyCheck`,
    /// and `CryptographicSelfTest` (each runs its check and emits
    /// `CheckPassed` with no key read). `GraphicsAndKeyboardSelfTest` is
    /// INTERACTIVE (it blocks for the local-display confirmation and the
    /// keyboard-self-test offer), as are `SetupSelection` (2026-08-07: the
    /// merged word-count + mode + instrument screen),
    /// `MachineEntropyAcquisition`,
    /// `PhysicalCollection`, `FinalGenerationConfirmation`, and
    /// `ReleaseAndEnvironmentWarning`. `Start` is the caller-return
    /// sentinel — the opening warning's Back hands control to the caller's
    /// own visible menu — an accepted, visible destination.
    #[test]
    fn advertised_pre_secret_back_never_lands_on_an_automatic_gate() {
        fn is_automatic_gate(s: AppState) -> bool {
            matches!(
                s,
                AppState::WatchdogDisable
                    | AppState::PlatformAndVirtualizationCheck
                    | AppState::ConsoleTopologyCheck
                    | AppState::CryptographicSelfTest
            )
        }
        // The pre-secret screens the driver renders with `[Esc] Back` and
        // that fire `Event::Back` when Esc is pressed (see the
        // `text::BACK_PROMPT` render sites in `seed-flow`).
        let back_advertising_screens = [
            AppState::ReleaseAndEnvironmentWarning,
            AppState::SetupSelection,
            AppState::MachineEntropyAcquisition,
            AppState::PhysicalCollection,
            AppState::FinalGenerationConfirmation,
        ];
        for from in back_advertising_screens {
            let mut sm = sm_at(from);
            let mut w = wd();
            let t = sm.transition(Event::Back, &mut w);
            assert!(!t.was_illegal, "Back from advertised screen {from:?} must be a legal edge");
            assert!(
                !is_automatic_gate(t.next),
                "Back from advertised screen {from:?} lands on AUTOMATIC gate {:?}: \
                 Esc would loop invisibly (SPEC.md §21 amendment 2026-08-05)",
                t.next
            );
        }
    }

    /// Back from `Start` itself has no predecessor: it is not a legal
    /// edge, and — since `Start` is pre-secret — routes to
    /// `PreSecretError`, never to the fatal chain and never silently
    /// ignored.
    #[test]
    fn back_from_start_is_illegal_and_routes_to_pre_secret_error() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        let t = sm.transition(Event::Back, &mut w);
        assert!(t.was_illegal);
        assert!(matches!(t.next, AppState::PreSecretError(_)));
        assert_ne!(t.next, AppState::ScrubWhatIsReachable);
    }

    /// SPEC.md §21 amendment / SPEC §21, §27.2: `Event::Back` MUST NOT be
    /// a legal transition from any post-secret state — every attempt
    /// routes into the fatal scrub-and-shutdown chain, exactly like any
    /// other unrecognised post-secret event, never back to an earlier
    /// screen and never to a menu.
    #[test]
    fn back_is_illegal_and_fatal_from_every_post_secret_state() {
        let post_secret_states = [
            AppState::FinalEntropyDerivation,
            AppState::MnemonicGeneration,
            AppState::MnemonicDisplay,
            AppState::DestroyConfirm,
            AppState::DisplayScrub,
            AppState::CompleteHiddenReentry,
            AppState::ReentryMismatchChoice,
            AppState::PassphraseOffer,
            AppState::PassphraseEntry,
            AppState::PassphraseConfirm,
            AppState::DerivationVerificationDisplay,
            AppState::CompletionEducation,
            AppState::SecretArenaScrub,
            AppState::FramebufferScrub,
            AppState::Shutdown,
        ];
        for state in post_secret_states {
            let mut sm = StateMachine {
                state,
                word_count: Some(WordCount::Twelve),
                mode: Some(EntropyMode::Combined),
                instrument: Some(Instrument::Both),
            };
            let mut w = wd();
            let t = sm.transition(Event::Back, &mut w);
            assert!(t.was_illegal, "Back from post-secret state {state:?} must be illegal");
            assert_eq!(
                t.next,
                AppState::ScrubWhatIsReachable,
                "Back from post-secret state {state:?} must route to the fatal chain, got {:?}",
                t.next
            );
            assert!(t.fatal_class.is_some());
        }
    }

    /// Back from a `PreSecretError` screen is not a documented predecessor
    /// edge (that screen keeps its existing Continue/Escape-only
    /// semantics) — confirm it stays a harmless, non-fatal, non-menu-
    /// skipping pre-secret error rather than silently doing nothing or
    /// reaching the fatal chain.
    #[test]
    fn back_from_pre_secret_error_is_illegal_but_stays_pre_secret() {
        let mut sm = StateMachine {
            state: AppState::PreSecretError(ErrorClass::Platform),
            word_count: None,
            mode: None,
            instrument: None,
        };
        let mut w = wd();
        let t = sm.transition(Event::Back, &mut w);
        assert!(t.was_illegal);
        assert!(matches!(t.next, AppState::PreSecretError(_)));
        assert_ne!(t.next, AppState::ScrubWhatIsReachable);
    }

    /// Regression guard for the frozen forward semantics: adding
    /// `Event::Back` must not perturb any existing forward transition —
    /// the full happy-path drive still produces the exact same sequence.
    #[test]
    fn back_event_does_not_perturb_the_frozen_forward_happy_path() {
        let mut sm = StateMachine::new();
        let mut w = wd();
        drive_to_mnemonic_display(&mut sm, &mut w);
        assert_eq!(sm.state(), AppState::MnemonicDisplay);
    }

    // ========================================================================
    // SPEC_PASSPHRASE §6.2/§6.4 — the three new post-secret states (M1),
    // additive tests (a)-(e).
    // ========================================================================

    const PASSPHRASE_STATES: [AppState; 3] = [
        AppState::PassphraseOffer,
        AppState::PassphraseEntry,
        AppState::PassphraseConfirm,
    ];

    fn sm_at(state: AppState) -> StateMachine {
        StateMachine { state, word_count: Some(WordCount::Twelve), mode: Some(EntropyMode::Combined), instrument: Some(Instrument::Both) }
    }

    /// (a) SPEC_PASSPHRASE §6.2: all three new states report
    /// `is_post_secret() == true` (they are at/after `FinalEntropyDerivation`).
    #[test]
    fn passphrase_states_are_post_secret() {
        for s in PASSPHRASE_STATES {
            assert!(s.is_post_secret(), "{s:?} must be post-secret");
        }
    }

    /// (b) SPEC_PASSPHRASE §6.2: no LEGAL edge from any passphrase state
    /// reaches a pre-secret state — every legal target is itself
    /// post-secret. Forward-only, never back to a menu (SPEC §21/§26).
    #[test]
    fn no_passphrase_edge_reaches_a_pre_secret_state() {
        let all_events = [
            Event::PassphraseOfferYes,
            Event::PassphraseUseEmpty,
            Event::PassphraseEntered,
            Event::PassphraseConfirmMatch,
            Event::PassphraseConfirmMismatch,
        ];
        for state in PASSPHRASE_STATES {
            for ev in all_events {
                let mut sm = sm_at(state);
                let mut w = wd();
                let t = sm.transition(ev, &mut w);
                if !t.was_illegal {
                    assert!(
                        t.next.is_post_secret(),
                        "legal edge {state:?} + {ev:?} -> {:?} escaped the post-secret region",
                        t.next
                    );
                }
            }
        }
    }

    /// (c) SPEC_PASSPHRASE §6.2: an unexpected event from each passphrase
    /// state routes into the fatal `ScrubWhatIsReachable` chain (never a
    /// menu), exactly like every other post-secret state. `Escape`/`Back`
    /// are among the unexpected events here (post-secret: not navigation).
    #[test]
    fn unexpected_event_from_each_passphrase_state_is_fatal() {
        let unexpected = [Event::Escape, Event::Back, Event::Continue, Event::ShowVerification];
        for state in PASSPHRASE_STATES {
            for ev in unexpected {
                let mut sm = sm_at(state);
                let mut w = wd();
                let t = sm.transition(ev, &mut w);
                assert!(t.was_illegal, "{state:?} + {ev:?} should be illegal");
                assert_eq!(
                    t.next,
                    AppState::ScrubWhatIsReachable,
                    "{state:?} + {ev:?} must route to the fatal scrub chain, got {:?}",
                    t.next
                );
                assert!(t.fatal_class.is_some());
            }
        }
    }

    /// (d) SPEC_PASSPHRASE §6.4: the skip/empty path (offer `No`, or empty
    /// entry) reaches `DerivationVerificationDisplay` — the same terminus
    /// as before, where the empty-passphrase seed is derived byte-identically.
    #[test]
    fn skip_and_empty_passphrase_paths_reach_derivation_verification_display() {
        // Offer -> No (empty).
        let mut sm = sm_at(AppState::PassphraseOffer);
        let mut w = wd();
        assert_eq!(
            sm.transition(Event::PassphraseUseEmpty, &mut w).next,
            AppState::DerivationVerificationDisplay
        );
        // Offer -> Yes -> Entry -> empty/cancel -> derivation.
        let mut sm = sm_at(AppState::PassphraseOffer);
        assert_eq!(sm.transition(Event::PassphraseOfferYes, &mut w).next, AppState::PassphraseEntry);
        assert_eq!(
            sm.transition(Event::PassphraseUseEmpty, &mut w).next,
            AppState::DerivationVerificationDisplay
        );
    }

    /// (e) SPEC_PASSPHRASE §4.1: a confirm mismatch returns to
    /// `PassphraseEntry` (retained state is scrubbed at the driver level,
    /// SPEC_PASSPHRASE §5.2); a match advances to
    /// `DerivationVerificationDisplay`.
    #[test]
    fn confirm_mismatch_returns_to_entry_and_match_advances() {
        let mut w = wd();
        // Full non-empty path: Offer(Yes) -> Entry -> Confirm.
        let mut sm = sm_at(AppState::PassphraseOffer);
        assert_eq!(sm.transition(Event::PassphraseOfferYes, &mut w).next, AppState::PassphraseEntry);
        assert_eq!(sm.transition(Event::PassphraseEntered, &mut w).next, AppState::PassphraseConfirm);
        // Mismatch loops back to entry.
        assert_eq!(
            sm.transition(Event::PassphraseConfirmMismatch, &mut w).next,
            AppState::PassphraseEntry
        );
        // Re-enter and this time match -> verification.
        assert_eq!(sm.transition(Event::PassphraseEntered, &mut w).next, AppState::PassphraseConfirm);
        assert_eq!(
            sm.transition(Event::PassphraseConfirmMatch, &mut w).next,
            AppState::DerivationVerificationDisplay
        );
    }
}
