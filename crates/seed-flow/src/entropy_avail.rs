//! SPEC §22.5 entropy-mode gating.
//!
//! > Unavailable modes are disabled with a specific reason. Mode 3
//! > displays the §18.2 warning before proceeding.
//!
//! and SPEC §18.2:
//!
//! > Machine-only generation is enabled only when at least one source is
//! > approved as a sole source by the current compiled-in policy. ... RDRAND
//! > alone never enables this mode in version 1.
//!
//! and SPEC §18.3:
//!
//! > Physical-only generation is always available when the keyboard,
//! > display and platform security gates pass.
//!
//! and SPEC §18.2's required disclosure ([`MachineOnlyDisclosure`]):
//!
//! > The user must see: source class; algorithm identifier; CPU and
//! > microcode policy result where relevant; policy version; and this
//! > warning: ...

use crate::flow_secret::physical::Instrument;
use crate::keys::{read_menu_choice, MenuChoice, MenuKeySource};
use crate::output::TextOutput;
use crate::text::{self, ENTROPY_MODE_TITLE};
use seed_protocol::policy::AlgoId;
use seed_protocol::state::EntropyMode;

/// One machine source's (EFI RNG or RDSEED64) approval status under the
/// current compiled-in entropy policy (SPEC §15, §18.2), independent of which
/// concrete mechanism backs it. RDRAND is deliberately not represented
/// here: SPEC §15.3 "RDRAND alone never enables this mode in version 1"
/// and a valid policy's `RdrandPolicy::sole_source_allowed` is always
/// `false`, so it never changes the computation below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceAvailability {
    /// Detected on this platform AND approved by policy for use at all
    /// (SPEC §15, §18.4) — not necessarily as a sole source.
    pub approved: bool,
    /// SPEC §18.2: "approved as a sole source by the current compiled-in
    /// policy." Only meaningful when `approved` is also `true`.
    pub sole_source_allowed: bool,
}

/// SPEC §18.2's required disclosure for the machine-only warning screen:
/// "The user must see: source class; algorithm identifier; CPU and
/// microcode policy result where relevant; policy version".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineOnlyDisclosure {
    /// SPEC §18.2 "source class": which mechanism is the policy-approved
    /// sole source enabling this mode — `"EFI RNG"` or `"RDSEED64"`.
    /// Never `"RDRAND"` (SPEC §15.3/§18.2: RDRAND alone never enables
    /// this mode).
    pub source_class: &'static str,
    /// SPEC §18.2 "algorithm identifier": for `"EFI RNG"`, the first
    /// policy-approved algorithm identifier
    /// (`EfiRngPolicy::allowed_algorithms`); for `"RDSEED64"`, a fixed
    /// label noting RDSEED is a CPU instruction with no negotiated
    /// algorithm identifier, so the CPU/microcode fields below carry the
    /// equivalent disclosure instead.
    pub algorithm_identifier: AlgoId,
    /// SPEC §18.2 "CPU and microcode policy result where relevant":
    /// `Some(verdict)` for `"RDSEED64"` (the real
    /// `RdseedPolicy::is_cpu_allowed_with_microcode` result for this
    /// platform's detected vendor/family/model/stepping); `None` for
    /// `"EFI RNG"`, whose SPEC §15.1 approval is protocol/algorithm-based,
    /// not CPU-identity-based, so no CPU/microcode result is relevant.
    pub cpu_microcode_result: Option<bool>,
    /// SPEC §15/§18.2 "policy version": `Policy::version` of the
    /// compiled-in policy that approved this source.
    pub policy_version: u16,
}

/// SPEC §22.5 mode-availability provider seam. Production wiring computes
/// this from the compiled-in entropy policy (WP-12) plus runtime detection
/// (EFI RNG protocol location, RDSEED CPUID gate — WP-24); host tests
/// supply canned values directly.
pub trait MachineAvailabilityGate {
    /// `EFI_RNG_PROTOCOL` availability (SPEC §15.1).
    fn efi_rng(&mut self) -> SourceAvailability;
    /// RDSEED64 availability (SPEC §15.2).
    fn rdseed(&mut self) -> SourceAvailability;

    /// SPEC §18.2's required machine-only disclosure (source class,
    /// algorithm identifier, CPU/microcode result, policy version) for
    /// whichever source is currently sole-source-eligible, or `None` if
    /// none is (defensive — [`show_mode_warning_if_any`] only reaches
    /// this for [`EntropyMode::MachineOnly`], which
    /// [`compute_mode_availability`] never offers unless one source's
    /// [`SourceAvailability::sole_source_allowed`] is `true`).
    ///
    /// Defaults to `None`: any implementer that never offers
    /// `MachineOnly` in the first place (e.g. `seed-desktop-test`'s
    /// `DesktopGates`, whose `efi_rng`/`rdseed` always report
    /// unavailable per SPEC §4.3) has nothing to disclose and does not
    /// need to override this. Real firmware wiring (`ProdPolicyGates` in
    /// both UEFI editions) overrides it with the genuine computation.
    fn machine_only_disclosure(&mut self) -> Option<MachineOnlyDisclosure> {
        None
    }
}

/// SPEC §22.5: "No approved machine entropy source is present or
/// policy-approved on this platform." — reason shown when mode 1
/// (Combined) is disabled.
pub const NO_MACHINE_SOURCE_REASON: &str =
    "No approved machine entropy source is present or policy-approved on this platform.";

/// SPEC §18.2/§22.5 — reason shown when mode 3 (MachineOnly) is disabled.
pub const NO_SOLE_SOURCE_REASON: &str =
    "No source is approved as a sole source by the current compiled-in entropy policy.";

/// Which of the three SPEC §22.5 modes are available, each `Err` carrying
/// the specific disabling reason (SPEC §22.5: "Unavailable modes are
/// disabled with a specific reason").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeAvailability {
    /// SPEC §22.5 `[1]`: approved machine source + physical dice/coins.
    pub combined: Result<(), &'static str>,
    /// SPEC §22.5 `[2]` / §18.3: physical dice/coins only.
    pub dice_only: Result<(), &'static str>,
    /// SPEC §22.5 `[3]` / §18.2: approved machine source only.
    pub machine_only: Result<(), &'static str>,
}

/// Compute [`ModeAvailability`] from the two machine-source queries (SPEC
/// §18.2, §18.3, §18.4, §22.5).
pub fn compute_mode_availability<G: MachineAvailabilityGate + ?Sized>(gate: &mut G) -> ModeAvailability {
    let rng = gate.efi_rng();
    let seed = gate.rdseed();
    let any_approved = rng.approved || seed.approved;
    let any_sole = (rng.approved && rng.sole_source_allowed) || (seed.approved && seed.sole_source_allowed);
    ModeAvailability {
        combined: if any_approved {
            Ok(())
        } else {
            Err(NO_MACHINE_SOURCE_REASON)
        },
        // SPEC §18.3: "Physical-only generation is always available when
        // the keyboard, display and platform security gates pass" — by
        // the time this screen is shown, this crate's driver has already
        // confirmed those gates passed, so dice-only is unconditionally
        // available (SPEC §18.4: "There is no weak fallback" applies to
        // the *absence* of any acceptable entropy, not to disabling this
        // legitimate explicit choice).
        dice_only: Ok(()),
        machine_only: if any_sole {
            Ok(())
        } else {
            Err(NO_SOLE_SOURCE_REASON)
        },
    }
}

/// Render the SPEC §22.5 entropy-mode selection screen, showing each
/// mode's fixed label and, for a disabled mode, its specific reason
/// instead of a bare "[N] ..." line.
pub fn render_entropy_mode_screen(out: &mut dyn TextOutput, avail: &ModeAvailability) {
    out.clear();
    out.write_line(ENTROPY_MODE_TITLE);
    out.write_line("");

    match avail.combined {
        Ok(()) => out.write_line(
            "[1] Approved machine source + physical dice/coins   Recommended",
        ),
        Err(reason) => {
            out.write_line("[1] Approved machine source + physical dice/coins   UNAVAILABLE");
            out.write_line(reason);
        }
    }

    match avail.dice_only {
        Ok(()) => out.write_line("[2] Physical dice/coins only"),
        Err(reason) => {
            out.write_line("[2] Physical dice/coins only   UNAVAILABLE");
            out.write_line(reason);
        }
    }

    match avail.machine_only {
        Ok(()) => out.write_line("[3] Approved machine source only"),
        Err(reason) => {
            out.write_line("[3] Approved machine source only   UNAVAILABLE");
            out.write_line(reason);
        }
    }

    out.write_line("");
    out.write_line(crate::text::BACK_PROMPT);
}

/// The user's choice at the SPEC §22.5 entropy-mode selection screen
/// (SPEC.md §21 amendment, 2026-08-04: "pre-secret Back navigation" adds
/// the `Back` arm — Escape now goes back one step, consistently, on every
/// pre-secret screen, rather than being unavailable here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyModeChoice {
    /// One of the available modes was picked.
    Picked(EntropyMode),
    /// `[Esc]`: go back one step (SPEC.md §21 amendment) — the caller
    /// is handled by the driver as a move back one PANEL inside the
    /// merged `AppState::SetupSelection` state — no event is fired
    /// (2026-08-07 ceremony redesign; before the merge this fired
    /// `Event::Back` from the then-separate `EntropyModeSelection`).
    Back,
}

/// Block until the user picks an *available* mode or presses Escape (SPEC
/// §22.5: a disabled option is never selectable — its key is simply not
/// offered to [`crate::keys::read_menu_choice`]).
pub fn read_entropy_mode_choice(keys: &mut dyn MenuKeySource, avail: &ModeAvailability) -> EntropyModeChoice {
    let mut allowed = [' '; 3];
    let mut n = 0;
    if avail.combined.is_ok() {
        allowed[n] = '1';
        n += 1;
    }
    if avail.dice_only.is_ok() {
        allowed[n] = '2';
        n += 1;
    }
    if avail.machine_only.is_ok() {
        allowed[n] = '3';
        n += 1;
    }
    debug_assert!(n > 0, "SPEC §18.3: dice-only is always available once gates pass");

    loop {
        match read_menu_choice(keys, &allowed[..n], true) {
            MenuChoice::Picked('1') => return EntropyModeChoice::Picked(EntropyMode::Combined),
            MenuChoice::Picked('2') => return EntropyModeChoice::Picked(EntropyMode::DiceOnly),
            MenuChoice::Picked('3') => return EntropyModeChoice::Picked(EntropyMode::MachineOnly),
            MenuChoice::Escape => return EntropyModeChoice::Back,
            _ => {}
        }
    }
}

/// Render (if applicable) and require acknowledgement of the SPEC
/// §18.2/§18.3/§6 mode-specific warning(s) for `mode`, before the driver
/// commits to `Event::SetupCommitted { .., mode, .. }`.
///
/// `Combined` and `DiceOnly` both use physical dice/coins (SPEC §18.1
/// modes 1 and 2), so both additionally show the SPEC §6 warning that
/// dice/coins do not protect against malicious firmware recording
/// keystrokes or altering execution — distinct from `DiceOnly`'s §18.3
/// warning about the fairness of the rolls/flips themselves. `MachineOnly`
/// uses no physical randomness, so it never shows the §6 warning.
///
/// `gate` supplies [`MachineAvailabilityGate::machine_only_disclosure`]
/// for the `MachineOnly` case (SPEC §18.2's source class/algorithm
/// identifier/CPU-microcode-result/policy-version disclosure); unused for
/// the other two modes.
pub fn show_mode_warning_if_any(
    out: &mut dyn TextOutput,
    keys: &mut dyn MenuKeySource,
    mode: EntropyMode,
    gate: &mut dyn MachineAvailabilityGate,
) {
    match mode {
        EntropyMode::MachineOnly => {
            let disclosure = gate.machine_only_disclosure();
            text::render_machine_only_warning(out, disclosure.as_ref());
            crate::keys::read_enter(keys);
        }
        EntropyMode::DiceOnly => {
            text::render_physical_only_warning(out);
            crate::keys::read_enter(keys);
            text::render_dice_coins_firmware_warning(out);
            crate::keys::read_enter(keys);
        }
        EntropyMode::Combined => {
            text::render_dice_coins_firmware_warning(out);
            crate::keys::read_enter(keys);
        }
    }
}

// ============================================================================
// SPEC_DICE_COIN_VISUAL.md §2.2/§22.5a: physical-instrument sub-selection
// ============================================================================

/// SPEC_DICE_COIN_VISUAL.md §2.2 title for the §22.5a instrument screen.
pub const INSTRUMENT_SELECT_TITLE: &str = "Choose your physical randomness source";

/// The user's choice at the §22.5a physical-instrument selection screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentChoice {
    /// One of Dice / Coins / Both was picked.
    Picked(Instrument),
    /// `[Esc]`: re-loop the §22.5 mode screen, firing NO event (there is
    /// no new state edge -- SPEC_DICE_COIN_VISUAL.md §2.2/m1).
    Back,
}

/// Render the SPEC_DICE_COIN_VISUAL.md §2.2 §22.5a "physical instrument"
/// sub-selection screen. Presentation-only: it chooses which instrument's
/// UI leads the entry screen; both key families stay accepted regardless
/// (§2.3). This is a driver-owned screen shown *before*
/// `Event::SetupCommitted` is fired -- it adds no new state-machine edge.
pub fn render_instrument_selection_screen(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line(INSTRUMENT_SELECT_TITLE);
    out.write_line("");
    out.write_line("[1] Dice     -- roll a six-sided die");
    out.write_line("[2] Coins    -- flip a coin");
    out.write_line("[3] Both     -- mix dice and coin in one session");
    out.write_line("");
    out.write_line("You can switch at any time while entering.");
    out.write_line(crate::text::BACK_PROMPT);
}

/// Block until the user picks Dice/Coins/Both or presses Escape at the
/// §22.5a screen.
pub fn read_instrument_choice(keys: &mut dyn MenuKeySource) -> InstrumentChoice {
    loop {
        match read_menu_choice(keys, &['1', '2', '3'], true) {
            MenuChoice::Picked('1') => return InstrumentChoice::Picked(Instrument::Dice),
            MenuChoice::Picked('2') => return InstrumentChoice::Picked(Instrument::Coins),
            MenuChoice::Picked('3') => return InstrumentChoice::Picked(Instrument::Both),
            MenuChoice::Escape => return InstrumentChoice::Back,
            _ => {}
        }
    }
}

/// SPEC_DICE_COIN_VISUAL.md §2.2/§22.5a: for a physical-bearing mode
/// (`Combined`/`DiceOnly`), show the instrument sub-selection screen and
/// return the chosen [`Instrument`], or `None` if the user pressed Escape
/// (the caller re-loops the §22.5 mode screen, firing nothing -- no new
/// state edge, m1). For `MachineOnly` (no physical entry), the screen is
/// skipped and `Some(Instrument::Both)` is returned unused.
pub fn select_physical_instrument(
    out: &mut dyn TextOutput,
    keys: &mut dyn MenuKeySource,
    mode: EntropyMode,
) -> Option<Instrument> {
    match mode {
        EntropyMode::MachineOnly => Some(Instrument::default()),
        EntropyMode::Combined | EntropyMode::DiceOnly => {
            render_instrument_selection_screen(out);
            match read_instrument_choice(keys) {
                InstrumentChoice::Picked(instr) => Some(instr),
                InstrumentChoice::Back => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::test_support::ScriptedMenuKeys;
    use crate::keys::MenuKey;
    use crate::output::test_support::MockTerminal;

    struct FixedAvailability {
        efi_rng: SourceAvailability,
        rdseed: SourceAvailability,
    }
    impl MachineAvailabilityGate for FixedAvailability {
        fn efi_rng(&mut self) -> SourceAvailability {
            self.efi_rng
        }
        fn rdseed(&mut self) -> SourceAvailability {
            self.rdseed
        }
    }

    #[test]
    fn no_machine_source_disables_combined_and_machine_only_but_not_dice() {
        let mut gate = FixedAvailability {
            efi_rng: SourceAvailability::default(),
            rdseed: SourceAvailability::default(),
        };
        let avail = compute_mode_availability(&mut gate);
        assert_eq!(avail.combined, Err(NO_MACHINE_SOURCE_REASON));
        assert_eq!(avail.machine_only, Err(NO_SOLE_SOURCE_REASON));
        assert_eq!(avail.dice_only, Ok(()));
    }

    #[test]
    fn approved_but_not_sole_enables_combined_not_machine_only() {
        let mut gate = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: false },
            rdseed: SourceAvailability::default(),
        };
        let avail = compute_mode_availability(&mut gate);
        assert_eq!(avail.combined, Ok(()));
        assert_eq!(avail.machine_only, Err(NO_SOLE_SOURCE_REASON));
    }

    #[test]
    fn sole_source_via_rdseed_enables_machine_only() {
        let mut gate = FixedAvailability {
            efi_rng: SourceAvailability::default(),
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let avail = compute_mode_availability(&mut gate);
        assert_eq!(avail.combined, Ok(()));
        assert_eq!(avail.machine_only, Ok(()));
    }

    #[test]
    fn both_sources_approved_and_sole_still_yields_ok_not_double_counted() {
        let mut gate = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: true },
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        let avail = compute_mode_availability(&mut gate);
        assert_eq!(avail.combined, Ok(()));
        assert_eq!(avail.machine_only, Ok(()));
    }

    #[test]
    fn dice_only_is_always_available_regardless_of_machine_state() {
        let mut gate = FixedAvailability {
            efi_rng: SourceAvailability::default(),
            rdseed: SourceAvailability::default(),
        };
        assert_eq!(compute_mode_availability(&mut gate).dice_only, Ok(()));
        let mut gate2 = FixedAvailability {
            efi_rng: SourceAvailability { approved: true, sole_source_allowed: true },
            rdseed: SourceAvailability { approved: true, sole_source_allowed: true },
        };
        assert_eq!(compute_mode_availability(&mut gate2).dice_only, Ok(()));
    }

    #[test]
    fn render_shows_specific_reason_for_disabled_modes() {
        let avail = ModeAvailability {
            combined: Err(NO_MACHINE_SOURCE_REASON),
            dice_only: Ok(()),
            machine_only: Err(NO_SOLE_SOURCE_REASON),
        };
        let mut term = MockTerminal::new();
        render_entropy_mode_screen(&mut term, &avail);
        assert!(term.contains(NO_MACHINE_SOURCE_REASON));
        assert!(term.contains(NO_SOLE_SOURCE_REASON));
        assert!(term.contains("UNAVAILABLE"));
    }

    #[test]
    fn read_choice_never_returns_a_disabled_mode() {
        // Mode 3 is disabled; script an attempt to pick it followed by a
        // valid pick of mode 1. The disabled '3' must be silently
        // ignored, not accepted.
        let avail = ModeAvailability {
            combined: Ok(()),
            dice_only: Ok(()),
            machine_only: Err(NO_SOLE_SOURCE_REASON),
        };
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Char('3'), MenuKey::Char('1')]);
        let chosen = read_entropy_mode_choice(&mut keys, &avail);
        assert_eq!(chosen, EntropyModeChoice::Picked(EntropyMode::Combined));
    }

    // ---- SPEC.md §21 amendment: Back at entropy-mode selection ----

    #[test]
    fn read_choice_returns_back_on_escape() {
        let avail = ModeAvailability { combined: Ok(()), dice_only: Ok(()), machine_only: Ok(()) };
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Escape]);
        assert_eq!(read_entropy_mode_choice(&mut keys, &avail), EntropyModeChoice::Back);
    }

    #[test]
    fn entropy_mode_screen_shows_the_back_prompt() {
        let avail = ModeAvailability { combined: Ok(()), dice_only: Ok(()), machine_only: Ok(()) };
        let mut term = MockTerminal::new();
        render_entropy_mode_screen(&mut term, &avail);
        assert!(term.contains(crate::text::BACK_PROMPT));
    }

    /// A [`FixedAvailability`]-like gate whose `machine_only_disclosure`
    /// override is itself fixed, for tests that need to assert on the
    /// SPEC §18.2 disclosure content rather than just its absence.
    struct FixedDisclosureGate {
        disclosure: Option<MachineOnlyDisclosure>,
    }
    impl MachineAvailabilityGate for FixedDisclosureGate {
        fn efi_rng(&mut self) -> SourceAvailability {
            SourceAvailability::default()
        }
        fn rdseed(&mut self) -> SourceAvailability {
            SourceAvailability::default()
        }
        fn machine_only_disclosure(&mut self) -> Option<MachineOnlyDisclosure> {
            self.disclosure
        }
    }

    #[test]
    fn machine_only_mode_shows_18_2_warning_verbatim() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        let mut gate = FixedDisclosureGate { disclosure: None };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::MachineOnly, &mut gate);
        assert!(term.contains_wrapped(text::MACHINE_ONLY_WARNING_18_2, text::PROSE_WRAP_COLS));
    }

    /// SPEC §18.2: "The user must see: source class; algorithm
    /// identifier; CPU and microcode policy result where relevant;
    /// policy version" — `show_mode_warning_if_any` must pull this from
    /// the gate and pass it through to the render function, not just
    /// default it to absent.
    #[test]
    fn machine_only_mode_shows_the_gates_spec_18_2_disclosure() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        let mut gate = FixedDisclosureGate {
            disclosure: Some(MachineOnlyDisclosure {
                source_class: "EFI RNG",
                algorithm_identifier: AlgoId::from_str("CTR-DRBG").unwrap(),
                cpu_microcode_result: None,
                policy_version: 3,
            }),
        };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::MachineOnly, &mut gate);
        assert!(term.contains("EFI RNG"));
        assert!(term.contains("CTR-DRBG"));
        assert!(term.contains("3"));
    }

    #[test]
    fn dice_only_mode_shows_18_3_warning_verbatim() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter, MenuKey::Enter]);
        let mut gate = FixedDisclosureGate { disclosure: None };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::DiceOnly, &mut gate);
        assert!(term.contains_wrapped(text::PHYSICAL_ONLY_WARNING_18_3, text::PROSE_WRAP_COLS));
    }

    #[test]
    fn dice_only_mode_also_shows_6_dice_coins_firmware_warning_verbatim() {
        // SPEC §6: dice/coins are used in mode 2 (`DiceOnly`), so the
        // firmware-does-not-protect-you warning MUST also appear, in
        // addition to (and distinct from) the §18.3 fairness warning.
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter, MenuKey::Enter]);
        let mut gate = FixedDisclosureGate { disclosure: None };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::DiceOnly, &mut gate);
        assert!(term.contains_wrapped(text::DICE_COINS_FIRMWARE_WARNING_6, text::PROSE_WRAP_COLS));
    }

    #[test]
    fn machine_only_mode_never_shows_6_dice_coins_firmware_warning() {
        // MachineOnly uses no physical dice/coins at all, so the §6
        // warning (which is specifically about dice/coins) must not
        // appear.
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        let mut gate = FixedDisclosureGate { disclosure: None };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::MachineOnly, &mut gate);
        assert!(!term.contains(text::DICE_COINS_FIRMWARE_WARNING_6));
    }

    #[test]
    fn combined_mode_shows_6_dice_coins_firmware_warning_verbatim() {
        // SPEC §6: mode 1 ("Approved machine source + physical
        // dice/coins") also uses physical dice/coins, so it MUST show the
        // same warning even though it has no §18.2/§18.3 mode-specific
        // warning of its own.
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        let mut gate = FixedDisclosureGate { disclosure: None };
        show_mode_warning_if_any(&mut term, &mut keys, EntropyMode::Combined, &mut gate);
        assert!(term.contains_wrapped(text::DICE_COINS_FIRMWARE_WARNING_6, text::PROSE_WRAP_COLS));
    }

    // ---- SPEC_DICE_COIN_VISUAL.md §2.2/§22.5a: instrument sub-selection ----

    #[test]
    fn instrument_screen_lists_dice_coins_both_and_back() {
        let mut term = MockTerminal::new();
        render_instrument_selection_screen(&mut term);
        assert!(term.contains(INSTRUMENT_SELECT_TITLE));
        assert!(term.contains("[1] Dice"));
        assert!(term.contains("[2] Coins"));
        assert!(term.contains("[3] Both"));
        assert!(term.contains(text::BACK_PROMPT));
        for line in term.current_screen() {
            assert!(line.len() <= 79, "instrument screen line exceeds 79 cols: {line:?}");
        }
    }

    #[test]
    fn instrument_choice_reads_each_option() {
        for (key, want) in [('1', Instrument::Dice), ('2', Instrument::Coins), ('3', Instrument::Both)] {
            let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Char(key)]);
            assert_eq!(read_instrument_choice(&mut keys), InstrumentChoice::Picked(want));
        }
    }

    #[test]
    fn instrument_choice_escape_returns_back() {
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Escape]);
        assert_eq!(read_instrument_choice(&mut keys), InstrumentChoice::Back);
    }

    /// §2.2/m1: Esc on §22.5a re-loops the mode screen (returns `None`);
    /// no event is fired, so there is no new state edge for the caller.
    #[test]
    fn select_physical_instrument_esc_reloops_for_physical_modes() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![MenuKey::Escape]);
        assert_eq!(select_physical_instrument(&mut term, &mut keys, EntropyMode::DiceOnly), None);

        let mut term2 = MockTerminal::new();
        let mut keys2 = ScriptedMenuKeys::new(std::vec![MenuKey::Char('3')]);
        assert_eq!(
            select_physical_instrument(&mut term2, &mut keys2, EntropyMode::Combined),
            Some(Instrument::Both)
        );
    }

    /// §22.5a is skipped for MachineOnly (no physical entry); it consumes
    /// no key and returns the unused default.
    #[test]
    fn select_physical_instrument_skips_machine_only() {
        let mut term = MockTerminal::new();
        let mut keys = ScriptedMenuKeys::new(std::vec![]); // never read
        assert_eq!(
            select_physical_instrument(&mut term, &mut keys, EntropyMode::MachineOnly),
            Some(Instrument::default())
        );
        assert!(!term.contains(INSTRUMENT_SELECT_TITLE), "no §22.5a screen for MachineOnly");
    }
}
