//! SPEC §22.3 platform-diagnostics gate.
//!
//! > Machine-checked items are displayed separately from user
//! > attestations, with explicit non-proof wording. Bare "Passed"
//! > language is prohibited for checks a deliberate adversary can spoof.
//!
//! Provider traits here are the seam that makes the four mandatory
//! startup gates (SPEC §11.2-§11.6) host-testable: production wiring
//! (`seed-uefi-test::flow_pre`) implements each trait against real
//! firmware (reusing WP-19/20/21/24's own modules, never re-implementing
//! their classification logic); host tests implement them against
//! scripted doubles. This module never re-derives a Clean/Failed/
//! Inconclusive verdict itself — every [`CheckOutcome`] is set by the
//! provider, which already owns the real classification logic (e.g.
//! `seed_platform_x86::virt::report::VirtReport`,
//! `seed_platform_x86::console::TopologyReport`,
//! `seed_gop_ui::gop::mode::select_mode`).
//!
//! "Inconclusive" (SPEC §22.3: "'Inconclusive' on a mandatory item
//! disables generation") and "Failed" both disable generation identically
//! from this crate's point of view — the distinction exists purely so the
//! diagnostics/error screens can say the honest thing (a device path this
//! module could not classify is not the same claim as "a serial console
//! was detected"), never to let a mandatory item pass silently.

use seed_platform_x86::input::SelfTestExpectation;
use seed_protocol::state::ErrorClass;

use crate::output::{LineBuf, TextOutput};
use core::fmt::Write as _;

// ============================================================================
// Outcome
// ============================================================================

/// One machine-checked item's outcome (SPEC §22.3). Never rendered as a
/// bare "Passed" for a spoofable item — every render function in this
/// module pairs `Clean` with the not-proof/spoofable wording the provider
/// supplied, never with the word "Passed" alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check ran and found nothing wrong.
    Clean,
    /// The check ran and found a disqualifying condition.
    Failed,
    /// The check could not reach a definite result (SPEC §22.3:
    /// "'Inconclusive' on a mandatory item disables generation").
    Inconclusive,
}

impl CheckOutcome {
    /// SPEC §22.3: `Failed` and `Inconclusive` both disable generation;
    /// only `Clean` allows the gate to advance.
    #[must_use]
    pub const fn blocks_generation(self) -> bool {
        !matches!(self, CheckOutcome::Clean)
    }

    const fn label(self) -> &'static str {
        match self {
            CheckOutcome::Clean => "Clean",
            CheckOutcome::Failed => "Failed",
            CheckOutcome::Inconclusive => "Inconclusive",
        }
    }
}

// ============================================================================
// SPEC §11.2 / §22.3 — architecture + virtualization gate
// ============================================================================

/// SPEC §11.2/§22.3 architecture + virtualization-indicator gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformCheckResult {
    pub outcome: CheckOutcome,
    /// `Platform` (unsupported architecture) or `Virtualization`
    /// (indicators detected), meaningful only when `outcome != Clean`.
    pub error_class: ErrorClass,
    /// Fixed architecture label (SPEC §5/§6: `X86_64` is the only
    /// version-1 architecture) — always `"x86-64"` in this crate's own
    /// scope, kept as data so a future architecture doesn't need a code
    /// change here.
    pub architecture_line: &'static str,
    /// The exact not-proof wording for this result (SPEC §11.2: "MUST
    /// state that absence of these indicators does not prove that no
    /// hidden hypervisor exists"). Production wiring passes through
    /// `seed_platform_x86::virt::report::VirtReport::summary()` verbatim.
    pub virt_summary: &'static str,
}

pub trait PlatformGate {
    fn check(&mut self) -> PlatformCheckResult;
}

// ============================================================================
// SPEC §11.3 / §22.3 — console-topology gate
// ============================================================================

/// SPEC §11.3/§22.3 console-topology gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleCheckResult {
    pub outcome: CheckOutcome,
    /// Always `ConsoleTopology` when `outcome != Clean`.
    pub error_class: ErrorClass,
    /// Number of accepted output-capable console paths (SPEC §22.3:
    /// "Console output paths ... N supported path").
    pub con_out_paths: u8,
    /// Number of accepted input-capable console paths.
    pub con_in_paths: u8,
    /// Human-readable summary (SPEC §11.3: "MUST show a human-readable
    /// summary without exposing secret data"). Production wiring passes
    /// through `seed_platform_x86::console::RefuseReason::describe()` on
    /// refusal, or a fixed "accepted" line otherwise.
    pub summary_line: &'static str,
}

pub trait ConsoleGate {
    fn check(&mut self) -> ConsoleCheckResult;
}

// ============================================================================
// SPEC §11.4 / §22.3 — graphics gate
// ============================================================================

/// A usable GOP mode's resolution + device path (SPEC §11.4: "Display its
/// resolution and device path before generation").
#[derive(Debug, Clone, Copy)]
pub struct GraphicsInfo {
    pub width: u32,
    pub height: u32,
    pub device_path: seed_gop_ui::gop::device_path::DevicePathText,
}

/// SPEC §11.4 graphics gate result. Refusal reasons are the fixed SPEC
/// §11.4 wording (`PIXEL_BLT_ONLY_REFUSAL_REASON` /
/// `BELOW_RESOLUTION_FLOOR_REASON` from `seed_gop_ui::gop::mode`, or "no
/// GOP available" when the protocol itself is missing).
#[derive(Debug, Clone, Copy)]
pub enum GraphicsCheckResult {
    Available(GraphicsInfo),
    Refused(&'static str),
}

pub trait GraphicsGate {
    fn check(&mut self) -> GraphicsCheckResult;
}

/// SPEC.md amendment (2026-08-06): the SPEC §11.4 "MUST name this as the
/// reason" wording for the one path the real-firmware `HeldGopGraphicsGate`
/// (`crate::firmware_wiring`) never had to cover before: the previously-
/// captured session GOP mode no longer matches what firmware currently
/// reports. Not observed in practice (nothing in this ceremony's own
/// control flow changes the GOP mode after the session GOP is opened
/// once), but this crate fails closed and names the reason honestly
/// rather than reusing the unrelated `PixelBltOnly` wording for a mismatch
/// that is not that condition.
pub const GRAPHICS_MODE_CHANGED_REFUSAL_REASON: &str =
    "Graphics mode changed since startup. Restart and run the full startup sequence again.";

/// Pure re-verification rule for the real-firmware `HeldGopGraphicsGate`
/// (SPEC.md amendment 2026-08-06 / SPEC §11.4), factored out here so the
/// fail-closed Available/Refused mapping is host-testable without
/// cross-compiling to `x86_64-unknown-uefi` — `crate::firmware_wiring` is
/// `#[cfg(target_os = "uefi")]` in its entirety (see that module's own doc
/// comment), so nothing defined there can ever run under `cargo test`.
///
/// `current` is `None` when the `GraphicsOutput` handle could no longer be
/// located at all (treated identically to a `PixelBltOnly` refusal — both
/// mean "cannot prove a linear framebuffer is still available"); otherwise
/// `Some((width, height, is_linear))`, where `is_linear` is `false` exactly
/// when the firmware-reported *current* pixel format is
/// `PixelFormat::BltOnly` (the real caller reads this straight off the
/// already-held session protocol's `current_mode_info()` — see that
/// module's own doc comment for why no second protocol open is involved).
///
/// Three fail-closed arms, in priority order: a non-linear current format
/// refuses with the same `PixelBltOnly` wording `open_session_gop` itself
/// uses (checked *before* the dimension comparison, since a `BltOnly` mode
/// change is the specific condition that wording names); a dimension
/// mismatch on an otherwise-linear mode refuses with
/// [`GRAPHICS_MODE_CHANGED_REFUSAL_REASON`]; an exact dimension match on a
/// linear mode returns `Available(captured)` — the gate always echoes back
/// the *captured* [`GraphicsInfo`] (SPEC §11.4's displayed resolution/
/// device path), never a freshly-read one, since only `captured` carries
/// the device-path text.
#[must_use]
pub fn classify_held_graphics_check(
    current: Option<(u32, u32, bool)>,
    captured: GraphicsInfo,
) -> GraphicsCheckResult {
    match current {
        None => GraphicsCheckResult::Refused(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON),
        Some((_, _, false)) => GraphicsCheckResult::Refused(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON),
        Some((width, height, true)) if width == captured.width && height == captured.height => {
            GraphicsCheckResult::Available(captured)
        }
        Some(_) => GraphicsCheckResult::Refused(GRAPHICS_MODE_CHANGED_REFUSAL_REASON),
    }
}

// ============================================================================
// SPEC §11.6 / §22.3 — cryptographic self-test gate
// ============================================================================

/// SPEC §11.6 cryptographic self-test gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoCheckResult {
    /// `Clean` or `Failed` in practice — a KAT either matches or it does
    /// not, so `Inconclusive` is not expected here, but the shared
    /// [`CheckOutcome`] type is used for uniformity with the other three
    /// gates.
    pub outcome: CheckOutcome,
}

pub trait CryptoSelfTestGate {
    fn check(&mut self) -> CryptoCheckResult;
}

// ============================================================================
// SPEC §22.3 informational-only items (never gate generation)
// ============================================================================

/// SPEC §22.3: "Secure Boot Enabled / Disabled / Unknown" — informational
/// only. Nothing in SPEC §11 lists Secure Boot state as a mandatory
/// startup gate, so `Unknown` here does *not* disable generation the way
/// an `Inconclusive` mandatory-gate result does; it is shown, honestly,
/// as itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootStatus {
    Enabled,
    Disabled,
    Unknown,
}

impl SecureBootStatus {
    const fn label(self) -> &'static str {
        match self {
            SecureBootStatus::Enabled => "Enabled",
            SecureBootStatus::Disabled => "Disabled",
            SecureBootStatus::Unknown => "Unknown",
        }
    }
}

/// Informational SPEC §22.3 row data that never blocks generation on its
/// own: Secure Boot state, the entropy policy version shown per SPEC
/// §15's "UI MUST show the policy version used", and production build
/// policy markers (WP-27/WP-30's own concern; shown here only for the
/// SPEC §22.3 screen's sake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformInfo {
    pub secure_boot: SecureBootStatus,
    /// `None` when no entropy policy could be loaded at all — this alone
    /// does not disable generation (see `crate::entropy_avail`): it just
    /// means no machine source will ever show as available.
    pub entropy_policy_version: Option<u16>,
    pub production_markers_verified: bool,
}

pub trait PlatformInfoGate {
    fn info(&mut self) -> PlatformInfo;
}

// ============================================================================
// SPEC §22.3 recap data (2026-08-07 ceremony redesign)
// ============================================================================

/// The condensed subset of [`render_diagnostics_summary`]'s SPEC §22.3
/// data that the merged Stage-3 Setup screen's inline recap block
/// (`crate::screens::setup`, design doc §4 Stage 3: "The §22.3
/// diagnostics recap becomes a `CAPTION` block on this screen") shows,
/// bundled into one `Copy` value so that screen reads it from a single
/// source instead of taking four separate gate-result parameters like
/// [`render_diagnostics_summary`] does. Building this from the same
/// [`PlatformCheckResult`]/[`ConsoleCheckResult`]/[`CryptoCheckResult`]/
/// [`PlatformInfo`] values a caller already collected for
/// `render_diagnostics_summary` guarantees the recap can never show a
/// different verdict than the full §22.3 screen did — see
/// [`Self::from_parts`].
///
/// `render_diagnostics_summary` itself is unchanged: this struct is a
/// pure call-site convenience added alongside it, not a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagRecap {
    pub architecture_line: &'static str,
    pub con_out_paths: u8,
    pub con_in_paths: u8,
    pub secure_boot: SecureBootStatus,
    pub entropy_policy_version: Option<u16>,
    pub production_markers_verified: bool,
    /// `true` exactly when the SPEC §11.6 cryptographic self-test's
    /// outcome was [`CheckOutcome::Clean`].
    pub crypto_clean: bool,
}

impl DiagRecap {
    /// Bundle the four gate results a caller already holds (the same ones
    /// [`render_diagnostics_summary`] takes) into one [`DiagRecap`].
    #[must_use]
    pub fn from_parts(
        platform: &PlatformCheckResult,
        console: &ConsoleCheckResult,
        crypto: &CryptoCheckResult,
        info: &PlatformInfo,
    ) -> Self {
        Self {
            architecture_line: platform.architecture_line,
            con_out_paths: console.con_out_paths,
            con_in_paths: console.con_in_paths,
            secure_boot: info.secure_boot,
            entropy_policy_version: info.entropy_policy_version,
            production_markers_verified: info.production_markers_verified,
            crypto_clean: crypto.outcome == CheckOutcome::Clean,
        }
    }

    /// A recap that claims nothing: every machine-checked item reported as
    /// unknown/not-verified. Used only as the carried value of a
    /// [`crate::driver::FlowResult`] that never reached the diagnostics
    /// recap at all (an early refusal, or Back at the first screen), so a
    /// caller can never mistake an un-run ceremony's recap for a passing
    /// one — it is deliberately the *pessimistic* reading of every field.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            architecture_line: "unknown",
            con_out_paths: 0,
            con_in_paths: 0,
            secure_boot: SecureBootStatus::Unknown,
            entropy_policy_version: None,
            production_markers_verified: false,
            crypto_clean: false,
        }
    }
}

// ============================================================================
// Rendering
// ============================================================================

/// SPEC §27.1/§22.3 generic pre-secret error/recovery screen — used for
/// every `AppState::PreSecretError(class)` the driver lands on, whether it
/// came from an explicit `CheckFailed` this crate sent or from a
/// watchdog-reassert failure the state machine injected on its own (SPEC
/// §11.1). Never renders secret data (no `ErrorClass` variant carries
/// any).
pub fn render_pre_secret_error_screen(out: &mut dyn TextOutput, class: ErrorClass) {
    out.clear();
    out.write_line("CANNOT CONTINUE");
    out.write_line("");
    out.write_line(error_class_description(class));
    out.write_line("");
    out.write_line("[Enter] Retry   [Esc] Exit before generation");
}

/// Fixed, non-secret human explanation for every [`ErrorClass`] variant
/// (SPEC §27.3: "no error may carry secret values" — none of these
/// strings are built from runtime data).
const fn error_class_description(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Platform => "The platform/architecture check did not pass.",
        ErrorClass::Watchdog => "The UEFI watchdog could not be confirmed disabled.",
        ErrorClass::ConsoleTopology => "The console input/output topology check did not pass.",
        ErrorClass::Virtualization => "Virtualization indicators were detected on this platform.",
        ErrorClass::GraphicsOrKeyboard => "The graphics or keyboard self-test did not pass.",
        ErrorClass::EntropyPolicy => "The entropy policy could not be loaded or verified.",
        ErrorClass::MachineSource => "The machine entropy source failed.",
        ErrorClass::PhysicalEntryState => "The physical dice/coin entry state failed.",
        ErrorClass::Derivation => "Wallet derivation failed.",
        ErrorClass::Cryptographic => "A cryptographic self-test did not pass.",
        ErrorClass::StateMachine => "An unexpected internal state was reached.",
        ErrorClass::Integrity => "An internal integrity check failed.",
        ErrorClass::Shutdown => "The shutdown sequence failed.",
    }
}

/// A named refusal screen (SPEC §11.4: "The refusal screen MUST name this
/// as the reason" — used for the GOP `PixelBltOnly`/below-resolution
/// refusal, whose specific text the generic
/// [`render_pre_secret_error_screen`] does not carry).
pub fn render_named_refusal(out: &mut dyn TextOutput, title: &str, reason: &str) {
    out.clear();
    out.write_line(title);
    out.write_line("");
    out.write_line(reason);
}

/// Render one SPEC §11.5 keyboard self-test prompt step.
pub fn render_self_test_step(
    out: &mut dyn TextOutput,
    index: usize,
    total: usize,
    expected: SelfTestExpectation,
) {
    out.clear();
    out.write_line("KEYBOARD SELF-TEST");
    out.write_line("");
    let mut line = LineBuf::new();
    let _ = write!(line, "Step {} of {}: press ", index + 1, total);
    match expected {
        SelfTestExpectation::Char(c) => {
            let _ = write!(line, "'{c}'");
        }
        SelfTestExpectation::Backspace => {
            let _ = write!(line, "Backspace");
        }
        SelfTestExpectation::Enter => {
            let _ = write!(line, "Enter");
        }
    }
    out.write_line(line.as_str());
}

/// SPEC §22.3 combined platform-diagnostics screen, shown once all four
/// mandatory gates have passed (SPEC §11: "No secret entropy may be
/// collected until every mandatory startup gate passes"), immediately
/// before word-count selection. Every machine-checked line pairs its
/// result with the exact not-proof/spoofable wording the owning module
/// already produced — never a bare "Passed" (SPEC §22.3).
#[allow(clippy::too_many_arguments)]
pub fn render_diagnostics_summary(
    out: &mut dyn TextOutput,
    platform: &PlatformCheckResult,
    console: &ConsoleCheckResult,
    graphics: &GraphicsInfo,
    crypto: &CryptoCheckResult,
    info: &PlatformInfo,
) {
    out.clear();
    out.write_line("PLATFORM CHECKS  (machine-checked; can be fooled by malicious firmware)");
    out.write_line("");

    let mut line = LineBuf::new();
    let _ = write!(line, "Architecture             {}", platform.architecture_line);
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    let _ = write!(line, "Physical-platform check  {}", platform.virt_summary);
    out.write_line(line.as_str());

    out.write_line("UEFI watchdog            Disable call succeeded; re-asserted each step");

    let mut line = LineBuf::new();
    let _ = write!(
        line,
        "Graphics output          Linear framebuffer {}x{}; local path confirmed by user",
        graphics.width, graphics.height
    );
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    let _ = write!(line, "Console output paths     {} supported path", console.con_out_paths);
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    let _ = write!(line, "Console input paths      {} supported path", console.con_in_paths);
    out.write_line(line.as_str());

    out.write_line(console.summary_line);

    let mut line = LineBuf::new();
    let _ = write!(line, "Secure Boot              {}", info.secure_boot.label());
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    match info.entropy_policy_version {
        Some(v) => {
            let _ = write!(line, "Entropy policy           v{v}");
        }
        None => {
            let _ = write!(line, "Entropy policy           unavailable");
        }
    }
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    let _ = write!(
        line,
        "Production build policy  {}",
        if info.production_markers_verified {
            "Markers verified"
        } else {
            "Markers NOT verified"
        }
    );
    out.write_line(line.as_str());

    let mut line = LineBuf::new();
    let _ = write!(
        line,
        "Cryptographic self-test  {}",
        if crypto.outcome == CheckOutcome::Clean {
            "KATs matched"
        } else {
            crypto.outcome.label()
        }
    );
    out.write_line(line.as_str());

    out.write_line("");
    out.write_line("[Enter] Continue");
    out.write_line(crate::text::BACK_PROMPT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::MockTerminal;
    use seed_gop_ui::gop::device_path::DevicePathText;

    #[test]
    fn check_outcome_blocks_generation_matches_spec_22_3() {
        assert!(!CheckOutcome::Clean.blocks_generation());
        assert!(CheckOutcome::Failed.blocks_generation());
        assert!(CheckOutcome::Inconclusive.blocks_generation());
    }

    // ------------------------------------------------------------------
    // `classify_held_graphics_check` (SPEC.md amendment 2026-08-06 /
    // SPEC §11.4): host-testable pin of the real `HeldGopGraphicsGate`'s
    // fail-closed Available/Refused mapping, factored out here specifically
    // because `crate::firmware_wiring` itself never compiles on the host.
    // ------------------------------------------------------------------

    fn captured() -> GraphicsInfo {
        GraphicsInfo { width: 1024, height: 768, device_path: DevicePathText::unavailable() }
    }

    #[test]
    fn classify_held_graphics_check_matches_dims_and_linear_format_returns_available() {
        let result = classify_held_graphics_check(Some((1024, 768, true)), captured());
        match result {
            GraphicsCheckResult::Available(info) => {
                assert_eq!(info.width, 1024);
                assert_eq!(info.height, 768);
            }
            GraphicsCheckResult::Refused(r) => panic!("expected Available, got Refused({r})"),
        }
    }

    #[test]
    fn classify_held_graphics_check_dimension_mismatch_refuses_with_mode_changed_reason() {
        let result = classify_held_graphics_check(Some((800, 600, true)), captured());
        assert_eq!(result_reason(result), Some(GRAPHICS_MODE_CHANGED_REFUSAL_REASON));
    }

    #[test]
    fn classify_held_graphics_check_non_linear_current_format_refuses_pixel_blt_only_even_on_dims_match() {
        // Same dims as captured, but the current mode is no longer linear
        // (BltOnly) -- must refuse with the PixelBltOnly wording, not
        // report Available just because the dimensions still match.
        let result = classify_held_graphics_check(Some((1024, 768, false)), captured());
        assert_eq!(result_reason(result), Some(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON));
    }

    #[test]
    fn classify_held_graphics_check_lookup_failure_refuses_pixel_blt_only() {
        let result = classify_held_graphics_check(None, captured());
        assert_eq!(result_reason(result), Some(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON));
    }

    fn result_reason(r: GraphicsCheckResult) -> Option<&'static str> {
        match r {
            GraphicsCheckResult::Available(_) => None,
            GraphicsCheckResult::Refused(reason) => Some(reason),
        }
    }

    #[test]
    fn error_class_description_is_exhaustive_and_non_empty() {
        let classes = [
            ErrorClass::Platform,
            ErrorClass::Watchdog,
            ErrorClass::ConsoleTopology,
            ErrorClass::Virtualization,
            ErrorClass::GraphicsOrKeyboard,
            ErrorClass::EntropyPolicy,
            ErrorClass::MachineSource,
            ErrorClass::PhysicalEntryState,
            ErrorClass::Derivation,
            ErrorClass::Cryptographic,
            ErrorClass::StateMachine,
            ErrorClass::Integrity,
            ErrorClass::Shutdown,
        ];
        for c in classes {
            assert!(!error_class_description(c).is_empty());
        }
    }

    #[test]
    fn pre_secret_error_screen_offers_retry_and_exit() {
        let mut term = MockTerminal::new();
        render_pre_secret_error_screen(&mut term, ErrorClass::Virtualization);
        assert!(term.contains("[Enter] Retry"));
        assert!(term.contains("Virtualization indicators"));
    }

    fn sample_graphics_info() -> GraphicsInfo {
        GraphicsInfo {
            width: 1920,
            height: 1080,
            device_path: DevicePathText::unavailable(),
        }
    }

    fn clean_platform() -> PlatformCheckResult {
        PlatformCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: ErrorClass::Platform,
            architecture_line: "x86-64",
            virt_summary: "No virtualization indicators detected -- not proof",
        }
    }

    fn clean_console() -> ConsoleCheckResult {
        ConsoleCheckResult {
            outcome: CheckOutcome::Clean,
            error_class: ErrorClass::ConsoleTopology,
            con_out_paths: 1,
            con_in_paths: 1,
            summary_line: "Remote/serial paths      None detected -- not proof",
        }
    }

    fn clean_info() -> PlatformInfo {
        PlatformInfo {
            secure_boot: SecureBootStatus::Enabled,
            entropy_policy_version: Some(1),
            production_markers_verified: true,
        }
    }

    #[test]
    fn named_refusal_screen_shows_the_specific_reason() {
        let mut term = MockTerminal::new();
        render_named_refusal(
            &mut term,
            "GRAPHICS OUTPUT REFUSED",
            seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON,
        );
        assert!(term.contains(seed_gop_ui::gop::mode::PIXEL_BLT_ONLY_REFUSAL_REASON));
    }

    #[test]
    fn self_test_step_screen_shows_expected_key() {
        let mut term = MockTerminal::new();
        render_self_test_step(&mut term, 0, 34, SelfTestExpectation::Char('A'));
        assert!(term.contains("'A'"));
        render_self_test_step(&mut term, 32, 34, SelfTestExpectation::Backspace);
        assert!(term.contains("Backspace"));
    }

    #[test]
    fn diagnostics_summary_never_shows_bare_passed_for_virt_or_console() {
        let mut term = MockTerminal::new();
        render_diagnostics_summary(
            &mut term,
            &clean_platform(),
            &clean_console(),
            &sample_graphics_info(),
            &CryptoCheckResult { outcome: CheckOutcome::Clean },
            &clean_info(),
        );
        for line in &term.lines {
            assert_ne!(
                line.trim(),
                "Passed",
                "bare 'Passed' is prohibited for spoofable checks (SPEC §22.3)"
            );
        }
        assert!(term.contains("not proof"));
        assert!(term.contains("v1"));
        assert!(term.contains("Markers verified"));
    }
}
