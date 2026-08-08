//! Stage 3 — Setup screen (design doc §4 Stage 3,
//! `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md`):
//! folds the former SPEC §22.4 word-count screen, SPEC §22.5 entropy-mode
//! screen and SPEC §22.5a physical-instrument screen into three stacked
//! pickers on one screen, with the selected mode's mandated warning
//! (§18.2/§18.3/§6) inline in a `WARN` panel that swaps with the
//! selection, and the SPEC §22.3 diagnostics recap folded in as a
//! `CAPTION` block (its own Enter-gate removed — this screen's own single
//! `[Enter]` covers the whole assembled setup).
//!
//! # Deviation: no Up/Down/Left/Right keys exist yet
//!
//! `seed_platform_x86::input::InputEvent` (this crate's [`MenuKey`]) has
//! exactly five variants: `Char`, `Backspace`, `Enter`, `Escape`, `Other`.
//! Every non-Escape special scan code — including real arrow keys —
//! collapses into the single `Other` bucket
//! (`uefi_backend::FirmwareKeySource::read_key_blocking`:
//! `Ok(Some(Key::Special(_))) => return InputEvent::Other`), so four
//! *distinguishable* directions cannot be read from this input layer as
//! it stands: `Other` cannot tell Up from Down from Left from Right.
//! Extending `InputEvent` itself is out of this task's scope (the
//! parallel-merge protocol restricts this task to this file and one line
//! in `screens/mod.rs`, and other Wave-4 tasks may depend on the enum's
//! current shape).
//!
//! This screen therefore maps the design doc's Up/Down/Left/Right
//! semantics onto `[W]`/`[S]`/`[A]`/`[D]` — the usual up/left/down/right
//! keyboard-gaming convention, and (unlike real arrow scan codes) actual
//! letters that the existing SPEC §11.5 self-test already validates
//! end-to-end (`self_test_sequence` covers the full `A..=Z` range). The
//! footer hints advertise `[W/S]`/`[A/D]` accordingly. Reconciling this
//! with a future real arrow-key input layer, should one land, is a
//! follow-up concern noted in this task's report.

use core::fmt::Write as _;

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text, draw_text_scaled, scrub_fill, GLYPH_HEIGHT, GLYPH_WIDTH};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X, MAX_COLS_AT_FLOOR};
use seed_gop_ui::{panel, theme};
use seed_protocol::state::EntropyMode;

use crate::chrome::{content_top, draw_footer, draw_header, Chrome, KeyHint};
use crate::diagnostics::{DiagRecap, SecureBootStatus};
use crate::entropy_avail::ModeAvailability;
use crate::flow_secret::machine::MachineExtras;
use crate::flow_secret::physical::Instrument;
use crate::keys::MenuKey;
use crate::output::LineBuf;
use crate::text::{
    wrap_words, DICE_COINS_FIRMWARE_WARNING_6, MACHINE_ONLY_WARNING_18_2, PHYSICAL_ONLY_WARNING_18_3,
    PROSE_WRAP_COLS,
};

/// Screen title (design doc §4 Stage 3, matching the "Choose ..."
/// convention `text::WORD_COUNT_TITLE`/`text::ENTROPY_MODE_TITLE` already
/// use for the two screens this one merges).
pub const TITLE: &str = "Choose your setup";

/// 0-based index of the word-count row.
const ROW_WORDS: u8 = 0;
/// 0-based index of the entropy-mode row.
const ROW_MODE: u8 = 1;
/// 0-based index of the physical-instrument row — inert unless
/// [`is_physical`] is true for the current mode.
const ROW_INSTRUMENT: u8 = 2;
/// 0-based index of the §22.5b machine-extras row (SPEC_TPM_ENTROPY.md
/// §11a) — present only when at least one optional source is offerable
/// ([`ModeAvailability::extras`]) AND the current mode uses machine
/// sources at all; with zero offerable extras the row does not exist
/// (never a greyed promise).
const ROW_EXTRAS: u8 = 3;

/// This screen's entire mutable state (design doc §4 Stage 3: "Three
/// stacked pickers on one screen"). Every field is `pub` — like every
/// sibling screen's state struct (`DeviceState`, `VerifyState`) — since
/// this is plain, non-secret UI state a test can construct directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupState {
    /// Which row is active: `0..=2`, see [`ROW_WORDS`]/[`ROW_MODE`]/
    /// [`ROW_INSTRUMENT`].
    pub row: u8,
    /// `false` = 12 words, `true` = 24 words (SPEC §22.4).
    pub words24: bool,
    /// SPEC §22.5 entropy-source mode.
    pub mode: EntropyMode,
    /// SPEC §22.5a physical-instrument choice. Presentation only when
    /// `mode` is not physical (inert row).
    pub instrument: Instrument,
    /// §22.5b optional-source opt-ins (SPEC_TPM_ENTROPY.md §11a). Every
    /// flag defaults OFF; only flags whose source is offerable
    /// ([`ModeAvailability::extras`]) are togglable or committed.
    pub extras: MachineExtras,
}

impl SetupState {
    /// A fresh screen: word count row active, 12 words, `Combined` mode
    /// (the SPEC §22.5 "Recommended" option), the compatibility-default
    /// instrument, every §22.5b extra OFF (opt-in).
    #[must_use]
    pub fn new() -> Self {
        Self {
            row: ROW_WORDS,
            words24: false,
            mode: EntropyMode::Combined,
            instrument: Instrument::default(),
            extras: MachineExtras::default(),
        }
    }

    /// Feed one keystroke. `avail` is the current [`ModeAvailability`]
    /// (recomputed by the caller once per screen entry, exactly as
    /// `crate::entropy_avail::read_entropy_mode_choice` already takes it)
    /// — needed here, not just by [`render`], because both row navigation
    /// (skip the inert instrument row) and mode cycling/direct-select
    /// (skip unavailable modes) and the final commit (never commit an
    /// unavailable mode) all depend on it.
    ///
    /// See the module doc comment for why `[W]`/`[S]`/`[A]`/`[D]` stand
    /// in for Up/Down/Left/Right.
    pub fn handle_key(&mut self, k: MenuKey, avail: &ModeAvailability) -> Option<SetupOutcome> {
        match k {
            MenuKey::Escape => Some(SetupOutcome::Back),
            MenuKey::Enter => {
                if mode_result(avail, self.mode).is_ok() {
                    Some(SetupOutcome::Committed {
                        words24: self.words24,
                        mode: self.mode,
                        instrument: self.instrument,
                        extras: effective_extras(self.extras, self.mode, avail),
                    })
                } else {
                    None
                }
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'w') => {
                self.row = prev_row(self.row, self.mode, avail);
                None
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'s') => {
                self.row = next_row(self.row, self.mode, avail);
                None
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'a') => {
                self.cycle_active(avail, false);
                None
            }
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'d') => {
                self.cycle_active(avail, true);
                None
            }
            MenuKey::Char(c @ '1'..='4') => {
                self.direct_select(c, avail);
                None
            }
            _ => None,
        }
    }

    /// `[A]`/`[D]`: cycle the active row's own options, wrapping, and (for
    /// the mode row) skipping unavailable modes. On the extras row both
    /// directions toggle the first offerable extra (a toggle has no
    /// direction; digits address individual extras, [`Self::direct_select`]).
    fn cycle_active(&mut self, avail: &ModeAvailability, forward: bool) {
        match self.row {
            ROW_WORDS => self.words24 = !self.words24,
            ROW_MODE => self.mode = cycle_mode(self.mode, avail, forward),
            ROW_INSTRUMENT if is_physical(self.mode) => {
                self.instrument = cycle_instrument(self.instrument, forward);
            }
            ROW_EXTRAS if extras_row_active(self.mode, avail) => {
                if avail.extras.tpm {
                    self.extras.tpm = !self.extras.tpm;
                } else if avail.extras.usb_trng {
                    self.extras.usb_trng = !self.extras.usb_trng;
                }
            }
            _ => {}
        }
    }

    /// `[1]`-`[4]`: direct-select on the active row (plan: "'1'..'4'
    /// direct-select on the active row where meaningful" — `[4]` has no
    /// meaning on any row today and is silently ignored, kept accepted at
    /// the match level for parity with the digit range other screens in
    /// this crate already read).
    fn direct_select(&mut self, c: char, avail: &ModeAvailability) {
        match self.row {
            ROW_WORDS => match c {
                '1' => self.words24 = false,
                '2' => self.words24 = true,
                _ => {}
            },
            ROW_MODE => {
                let candidate = match c {
                    '1' => Some(EntropyMode::Combined),
                    '2' => Some(EntropyMode::DiceOnly),
                    '3' => Some(EntropyMode::MachineOnly),
                    _ => None,
                };
                if let Some(m) = candidate {
                    if mode_result(avail, m).is_ok() {
                        self.mode = m;
                    }
                }
            }
            ROW_INSTRUMENT if is_physical(self.mode) => {
                let candidate = match c {
                    '1' => Some(Instrument::Dice),
                    '2' => Some(Instrument::Coins),
                    '3' => Some(Instrument::Both),
                    _ => None,
                };
                if let Some(i) = candidate {
                    self.instrument = i;
                }
            }
            ROW_EXTRAS if extras_row_active(self.mode, avail) => {
                // `[1]`/`[2]` toggle the nth OFFERABLE extra, in the
                // fixed TPM-then-USB order the row renders in.
                let mut n = 0u8;
                if avail.extras.tpm {
                    n += 1;
                    if c == char::from(b'0' + n) {
                        self.extras.tpm = !self.extras.tpm;
                        return;
                    }
                }
                if avail.extras.usb_trng {
                    n += 1;
                    if c == char::from(b'0' + n) {
                        self.extras.usb_trng = !self.extras.usb_trng;
                    }
                }
            }
            _ => {}
        }
    }
}

/// The extras this commit actually carries (SPEC_TPM_ENTROPY.md §11a):
/// each opt-in is masked to sources that are still offerable, and a mode
/// that samples no machine sources at all (`DiceOnly`) always commits
/// all-OFF — a stale toggle from an earlier mode choice must never leak a
/// machine probe into a physical-only ceremony.
fn effective_extras(chosen: MachineExtras, mode: EntropyMode, avail: &ModeAvailability) -> MachineExtras {
    if !uses_machine_sources(mode) {
        return MachineExtras::default();
    }
    MachineExtras {
        tpm: chosen.tpm && avail.extras.tpm,
        usb_trng: chosen.usb_trng && avail.extras.usb_trng,
    }
}

impl Default for SetupState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of [`SetupState::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupOutcome {
    /// `[Enter]`, mode available: the whole assembled setup, ready for
    /// the caller to fold into `Event::SetupCommitted { word_count,
    /// mode, instrument }` (SPEC §22.4/§22.5/§22.5a — `word_count` is a
    /// `seed_core::contracts::WordCount`, not this screen's own concern:
    /// the caller converts `words24` at the call site). `extras` is the
    /// §22.5b opt-in set, already masked by [`effective_extras`] — the
    /// caller hands it to `MachineSourceGate::acquire` untouched.
    Committed { words24: bool, mode: EntropyMode, instrument: Instrument, extras: MachineExtras },
    /// `[Esc]`.
    Back,
}

// ============================================================================
// Mode / instrument helpers
// ============================================================================

/// Does `mode` use physical dice/coins at all (SPEC §18.1 modes 1 and 2)?
/// The instrument row is only meaningful — and only reachable by
/// row-navigation — when this is true.
fn is_physical(mode: EntropyMode) -> bool {
    matches!(mode, EntropyMode::Combined | EntropyMode::DiceOnly)
}

/// Does `mode` sample machine sources at all (SPEC §18.1 modes 1 and 3)?
/// The §22.5b extras row is only meaningful when this is true — a
/// physical-only ceremony samples nothing an extra could add to.
fn uses_machine_sources(mode: EntropyMode) -> bool {
    matches!(mode, EntropyMode::Combined | EntropyMode::MachineOnly)
}

/// Whether the §22.5b extras row exists and is live: at least one extra
/// offerable AND the mode machine-using (SPEC_TPM_ENTROPY.md §11a).
fn extras_row_active(mode: EntropyMode, avail: &ModeAvailability) -> bool {
    uses_machine_sources(mode) && !avail.extras.is_empty()
}

/// This mode's [`ModeAvailability`] result, mirroring
/// `crate::entropy_avail::read_entropy_mode_choice`'s own field mapping.
fn mode_result(avail: &ModeAvailability, mode: EntropyMode) -> Result<(), &'static str> {
    match mode {
        EntropyMode::Combined => avail.combined,
        EntropyMode::DiceOnly => avail.dice_only,
        EntropyMode::MachineOnly => avail.machine_only,
    }
}

/// Fixed display/cycle order for the mode row (SPEC §22.5's own `[1]`/
/// `[2]`/`[3]` order).
fn mode_order() -> [EntropyMode; 3] {
    [EntropyMode::Combined, EntropyMode::DiceOnly, EntropyMode::MachineOnly]
}

/// Fixed display/cycle order for the instrument row (SPEC_DICE_COIN_VISUAL
/// §2.2's own `[1]`/`[2]`/`[3]` order).
fn instrument_order() -> [Instrument; 3] {
    [Instrument::Dice, Instrument::Coins, Instrument::Both]
}

/// Cycle `current` to the next (`forward`) or previous (`!forward`)
/// *available* mode in [`mode_order`], wrapping. SPEC §18.3 guarantees
/// `dice_only` is always available, so this can never loop forever with
/// nothing to land on.
fn cycle_mode(current: EntropyMode, avail: &ModeAvailability, forward: bool) -> EntropyMode {
    let order = mode_order();
    let n = order.len();
    let cur = order.iter().position(|&m| m == current).unwrap_or(0);
    let mut idx = cur;
    for _ in 0..n {
        idx = if forward { (idx + 1) % n } else { (idx + n - 1) % n };
        if mode_result(avail, order[idx]).is_ok() {
            return order[idx];
        }
    }
    current
}

/// Cycle `current` to the next/previous instrument in [`instrument_order`],
/// wrapping. Instruments carry no availability concept (presentation
/// only, SPEC_DICE_COIN_VISUAL.md §2.3).
fn cycle_instrument(current: Instrument, forward: bool) -> Instrument {
    let order = instrument_order();
    let n = order.len();
    let cur = order.iter().position(|&i| i == current).unwrap_or(0);
    let idx = if forward { (cur + 1) % n } else { (cur + n - 1) % n };
    order[idx]
}

/// The rows navigable for `mode`, in a fixed buffer (`n` slots used):
/// words and mode always; the instrument row when physical; the §22.5b
/// extras row when [`extras_row_active`].
fn valid_rows(mode: EntropyMode, avail: &ModeAvailability) -> ([u8; 4], usize) {
    let mut rows = [0u8; 4];
    let mut n = 0;
    rows[n] = ROW_WORDS;
    n += 1;
    rows[n] = ROW_MODE;
    n += 1;
    // Directly after the mode row (user decision 2026-08-09): the extras
    // are machine-entropy sub-options, so they navigate — and render —
    // inside the machine-entropy part of the screen, not after the
    // instrument row.
    if extras_row_active(mode, avail) {
        rows[n] = ROW_EXTRAS;
        n += 1;
    }
    if is_physical(mode) {
        rows[n] = ROW_INSTRUMENT;
        n += 1;
    }
    (rows, n)
}

/// `[S]`: the next valid row after `current`, wrapping and skipping
/// inert rows.
fn next_row(current: u8, mode: EntropyMode, avail: &ModeAvailability) -> u8 {
    let (rows, n) = valid_rows(mode, avail);
    let valid = &rows[..n];
    let idx = valid.iter().position(|&r| r == current).unwrap_or(0);
    valid[(idx + 1) % valid.len()]
}

/// `[W]`: the previous valid row before `current`, wrapping and skipping
/// inert rows.
fn prev_row(current: u8, mode: EntropyMode, avail: &ModeAvailability) -> u8 {
    let (rows, n) = valid_rows(mode, avail);
    let valid = &rows[..n];
    let idx = valid.iter().position(|&r| r == current).unwrap_or(0);
    valid[(idx + valid.len() - 1) % valid.len()]
}

// ============================================================================
// Copy: mode/instrument labels, mandated warnings, summary line
// ============================================================================

fn mode_label(mode: EntropyMode) -> &'static str {
    match mode {
        EntropyMode::Combined => "Combined",
        EntropyMode::DiceOnly => "Dice only",
        EntropyMode::MachineOnly => "Machine only",
    }
}

fn instrument_label(instrument: Instrument) -> &'static str {
    match instrument {
        Instrument::Dice => "Dice",
        Instrument::Coins => "Coins",
        Instrument::Both => "Both",
    }
}

/// The mandated warning const for `mode` (design doc §4 Stage 3: "The
/// selected mode's mandated warning text (§18.2/§18.3/§6) renders inline
/// ... the panel swaps with the selection"). Each mode shows exactly one
/// warning here — never a duplicate of `crate::entropy_avail::
/// show_mode_warning_if_any`'s own (separate-screen) two-warning form for
/// `DiceOnly`/`Combined`; folding both a §6 and a §18.3 acknowledgement
/// into one inline panel per mode would not fit this single screen, so
/// each mode is assigned the one warning the task brief specifies:
/// `MachineOnly` -> §18.2, `DiceOnly` -> §18.3, `Combined` -> §6.
fn warning_text(mode: EntropyMode) -> &'static str {
    match mode {
        EntropyMode::Combined => DICE_COINS_FIRMWARE_WARNING_6,
        EntropyMode::DiceOnly => PHYSICAL_ONLY_WARNING_18_3,
        EntropyMode::MachineOnly => MACHINE_ONLY_WARNING_18_2,
    }
}

/// Upper bound on wrapped warning-panel lines: the longest mandated
/// warning const wraps to well under this at [`PROSE_WRAP_COLS`]
/// (asserted by `tests::warning_lines_fit_the_fixed_bound`).
const WARN_MAX_LINES: usize = 6;

/// Word-wrap `mode`'s mandated warning to [`PROSE_WRAP_COLS`], returning a
/// fixed-capacity line list (no allocation) plus how many of its slots
/// are used. Shared by [`render`] and every warning-content test, so a
/// test can never assert against a rendering-side copy of the wrap logic.
fn warning_lines(mode: EntropyMode) -> ([&'static str; WARN_MAX_LINES], usize) {
    let mut lines = [""; WARN_MAX_LINES];
    let mut n = 0usize;
    for line in wrap_words(warning_text(mode), PROSE_WRAP_COLS) {
        if n < WARN_MAX_LINES {
            lines[n] = line;
            n += 1;
        }
    }
    (lines, n)
}

/// SPEC §22.5's disabled-mode reason strings, reused verbatim (never
/// duplicated) from whichever of `avail.combined`/`avail.machine_only` is
/// currently `Err`. `dice_only` is never included: SPEC §18.3 guarantees
/// it is always available. Returned as a fixed 0..=2 slice — at most one
/// reason per disableable mode.
fn disabled_mode_reasons(avail: &ModeAvailability) -> ([&'static str; 2], usize) {
    let mut reasons = [""; 2];
    let mut n = 0;
    if let Err(reason) = avail.combined {
        reasons[n] = reason;
        n += 1;
    }
    if let Err(reason) = avail.machine_only {
        reasons[n] = reason;
        n += 1;
    }
    (reasons, n)
}

/// The design doc §4 Stage 3 one-line recap: `Your setup:  {12|24} words
/// - {mode}[ - {instrument}]`. Uses a plain hyphen rather than the design
/// doc's own middle-dot separator — like every other screen in this
/// crate (see e.g. `screens::verify`'s module doc comment), the embedded
/// font only covers ASCII `0x20..=0x7E`, so a non-ASCII glyph would
/// render as a blank cell.
fn build_summary_line(
    words24: bool,
    mode: EntropyMode,
    instrument: Instrument,
    extras: MachineExtras,
    avail: &ModeAvailability,
) -> LineBuf {
    let mut buf = LineBuf::new();
    let words = if words24 { 24 } else { 12 };
    let _ = write!(buf, "Your setup:  {words} words - {}", mode_label(mode));
    if is_physical(mode) {
        let _ = write!(buf, " - {}", instrument_label(instrument));
    }
    // §22.5b: recap exactly what would be committed — the masked set,
    // never a stale toggle (SPEC_TPM_ENTROPY.md §11a).
    let effective = effective_extras(extras, mode, avail);
    if effective.tpm {
        let _ = write!(buf, " + TPM");
    }
    if effective.usb_trng {
        let _ = write!(buf, " + USB TRNG");
    }
    buf
}

/// The SPEC §22.3 recap's condensed `CAPTION` block (design doc §4 Stage
/// 3: "content preserved, own Enter-gate removed"). Every value drawn
/// here comes straight from `recap`'s fields, so it can never show
/// anything the full `diagnostics::render_diagnostics_summary` screen
/// (which built the very same [`DiagRecap`] via [`DiagRecap::from_parts`])
/// did not already show.
fn recap_lines(recap: &DiagRecap) -> [LineBuf; 2] {
    let mut l1 = LineBuf::new();
    // "TPM {status}" lives on this (shorter) line: the SPEC §22.3 recap
    // must fit the 800x600 floor (`output::screens_fit_audit`), and line 2
    // is already near the right margin. Status labels are deliberately
    // compact (SPEC_TPM_ENTROPY.md §7.1 probe stages).
    let _ = write!(
        l1,
        "Diagnostics: Architecture {}   Console {} in / {} out   Secure Boot {}   TPM {}",
        recap.architecture_line,
        recap.con_in_paths,
        recap.con_out_paths,
        secure_boot_label(recap.secure_boot),
        recap.tpm_status,
    );

    let mut l2 = LineBuf::new();
    match recap.entropy_policy_version {
        Some(v) => {
            let _ = write!(l2, "Entropy policy v{v}   ");
        }
        None => {
            let _ = write!(l2, "Entropy policy unavailable   ");
        }
    }
    let _ = write!(
        l2,
        "Production build {}   Crypto self-test {}",
        if recap.production_markers_verified { "markers verified" } else { "markers NOT verified" },
        if recap.crypto_clean { "Clean" } else { "not Clean" },
    );

    [l1, l2]
}

fn secure_boot_label(status: SecureBootStatus) -> &'static str {
    match status {
        SecureBootStatus::Enabled => "Enabled",
        SecureBootStatus::Disabled => "Disabled",
        SecureBootStatus::Unknown => "Unknown",
    }
}

// ============================================================================
// Rendering
// ============================================================================

/// Width, in glyph cells, reserved for a picker row's label field (widest
/// label is `"Entropy mode"`, 12 cells).
const LABEL_FIELD_COLS: u32 = 14;

/// Color for one picker-row option: dimmed when the whole row is inert or
/// this specific option is unavailable, `ACCENT` for the current
/// selection, `CAPTION` otherwise.
fn option_color(selected: bool, available: bool, row_dim: bool) -> u32 {
    if row_dim || !available {
        theme::ACCENT_DIM
    } else if selected {
        theme::ACCENT
    } else {
        theme::CAPTION
    }
}

/// Draw one picker row: an active-row marker, a label, then every option
/// in `options` (`(text, available)`) as `"[text]"`, colored per
/// [`option_color`]. `row_dim` additionally dims the label itself (used
/// for the inert instrument row).
fn draw_picker_row(
    fb: &mut dyn Framebuffer,
    y: u32,
    active_row: bool,
    row_dim: bool,
    label: &str,
    options: &[(&str, bool)],
    selected: usize,
) {
    let marker_color = if active_row { theme::ACCENT } else { theme::CAPTION };
    draw_text(fb, MARGIN_X, y, if active_row { ">" } else { " " }, theme::on_bg(marker_color));

    let label_x = MARGIN_X + 2 * GLYPH_WIDTH;
    draw_text(fb, label_x, y, label, theme::on_bg(if row_dim { theme::ACCENT_DIM } else { theme::TEXT }));

    let mut x = label_x + LABEL_FIELD_COLS * GLYPH_WIDTH;
    for (i, &(text, available)) in options.iter().enumerate() {
        let mut buf = LineBuf::new();
        let _ = write!(buf, "[{text}]");
        let color = option_color(i == selected, available, row_dim);
        draw_text(fb, x, y, buf.as_str(), theme::on_bg(color));
        x += (buf.as_str().len() as u32 + 1) * GLYPH_WIDTH;
    }
}

fn mode_idx(mode: EntropyMode) -> usize {
    mode_order().iter().position(|&m| m == mode).unwrap_or(0)
}

fn instrument_idx(instrument: Instrument) -> usize {
    instrument_order().iter().position(|&i| i == instrument).unwrap_or(0)
}

/// Render the Stage 3 Setup screen: [`crate::chrome`] header/footer, the
/// 2x [`TITLE`], the three stacked picker rows (design doc §4 Stage 3),
/// any disabled-mode reason lines, the mandated warning panel for
/// `st.mode`, the SPEC §22.3 recap `CAPTION` block, and the assembled
/// summary line.
///
/// Clears the framebuffer first: unlike `screens::prepare`/`screens::
/// device` (whose rows never change width between renders), several rows
/// here vary in drawn width from one keystroke to the next (a longer mode
/// label replacing a shorter one, the warning panel's line count changing
/// with `st.mode`, disabled-reason lines appearing/disappearing) — a
/// front-to-back scrub is the same discipline `screens::verify` already
/// uses for its own re-rendered, content-varying screen.
pub fn render(fb: &mut dyn Framebuffer, st: &SetupState, avail: &ModeAvailability, recap: &DiagRecap, build: &'static str) {
    scrub_fill(fb, theme::BG);
    draw_header(fb, &Chrome { stage: 3, sub: None, build });

    let mut y = content_top();

    draw_text_scaled(fb, MARGIN_X, y, TITLE, theme::on_bg(theme::TEXT), 2);
    y += GLYPH_HEIGHT * 2 + LINE_PITCH;

    let words_options = [("12 words", true), ("24 words", true)];
    let words_selected = usize::from(st.words24);
    draw_picker_row(fb, y, st.row == ROW_WORDS, false, "Word count", &words_options, words_selected);
    y += LINE_PITCH;

    let mode_options = [
        ("Combined", avail.combined.is_ok()),
        ("Dice only", avail.dice_only.is_ok()),
        ("Machine only", avail.machine_only.is_ok()),
    ];
    draw_picker_row(fb, y, st.row == ROW_MODE, false, "Entropy mode", &mode_options, mode_idx(st.mode));
    y += LINE_PITCH;

    // §22.5b extras row (SPEC_TPM_ENTROPY.md §11a), drawn DIRECTLY under
    // the mode row (user decision 2026-08-09: these are machine-entropy
    // sub-options, so they live inside the machine-entropy part of the
    // screen). Rendered ONLY when at least one optional source is
    // offerable — zero offerable extras means no row at all, not a
    // dimmed one. Dimmed (like the inert instrument row) when the mode
    // samples no machine sources. Each offerable extra renders as one
    // toggle option showing its own state; the "selected" highlight
    // follows the ON state.
    if !avail.extras.is_empty() {
        let extras_dim = !uses_machine_sources(st.mode);
        let mut options: [(&str, bool); 2] = [("", true); 2];
        let mut selected = usize::MAX;
        let mut n = 0usize;
        if avail.extras.tpm {
            options[n] = (if st.extras.tpm { "Add TPM entropy: ON" } else { "Add TPM entropy: off" }, true);
            if st.extras.tpm {
                selected = n;
            }
            n += 1;
        }
        if avail.extras.usb_trng {
            options[n] =
                (if st.extras.usb_trng { "Add USB TRNG: ON" } else { "Add USB TRNG: off" }, true);
            if st.extras.usb_trng && selected == usize::MAX {
                selected = n;
            }
            n += 1;
        }
        draw_picker_row(fb, y, st.row == ROW_EXTRAS, extras_dim, "Machine extras", &options[..n], selected);
        y += LINE_PITCH;
    }

    let (reasons, reason_n) = disabled_mode_reasons(avail);
    for reason in &reasons[..reason_n] {
        draw_text(fb, MARGIN_X + 2 * GLYPH_WIDTH, y, reason, theme::on_bg(theme::CAPTION));
        y += LINE_PITCH;
    }

    let physical = is_physical(st.mode);
    let instrument_options = [("Dice", true), ("Coins", true), ("Both", true)];
    draw_picker_row(
        fb,
        y,
        st.row == ROW_INSTRUMENT,
        !physical,
        "Instrument",
        &instrument_options,
        instrument_idx(st.instrument),
    );
    y += LINE_PITCH + LINE_PITCH / 2;

    let (lines, n) = warning_lines(st.mode);
    let panel_w = (MAX_COLS_AT_FLOOR as u32) * GLYPH_WIDTH;
    let panel_h = (n as u32) * LINE_PITCH + LINE_PITCH / 2;
    panel::warn_panel(fb, MARGIN_X, y, panel_w, panel_h);
    let mut line_y = y + LINE_PITCH / 4;
    for line in &lines[..n] {
        draw_text(fb, MARGIN_X + GLYPH_WIDTH, line_y, line, theme::on_panel(theme::TEXT));
        line_y += LINE_PITCH;
    }
    y += panel_h + LINE_PITCH;

    for line in recap_lines(recap) {
        draw_text(fb, MARGIN_X, y, line.as_str(), theme::on_bg(theme::CAPTION));
        y += LINE_PITCH;
    }
    y += LINE_PITCH / 2;

    let summary = build_summary_line(st.words24, st.mode, st.instrument, st.extras, avail);
    draw_text(fb, MARGIN_X, y, summary.as_str(), theme::on_bg(theme::TEXT));

    let committable = mode_result(avail, st.mode).is_ok();
    let hints = [
        KeyHint { key: "W/S", label: "Row", enabled: true, danger: false },
        KeyHint { key: "A/D", label: "Change", enabled: true, danger: false },
        KeyHint { key: "1-3", label: "Direct select", enabled: true, danger: false },
        KeyHint {
            key: "Enter",
            label: if committable { "Continue" } else { "Continue - mode unavailable" },
            enabled: committable,
            danger: false,
        },
        KeyHint { key: "Esc", label: "Back", enabled: true, danger: false },
    ];
    draw_footer(fb, &hints);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};

    /// Host-only `Vec<u32>` `Framebuffer` test double — this module's own
    /// copy of the pattern every sibling screen test module uses.
    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }

    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
        }

        fn contains(&self, color: u32) -> bool {
            self.buf.iter().any(|&p| p == color)
        }
    }

    impl Framebuffer for VecFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            if y >= self.h || x >= self.w {
                return;
            }
            let n = px.len().min((self.w - x) as usize);
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + n].copy_from_slice(&px[..n]);
        }
    }

    const BUILD: &str = "test-build";

    fn all_available() -> ModeAvailability {
        ModeAvailability { combined: Ok(()), dice_only: Ok(()), machine_only: Ok(()), extras: Default::default() }
    }

    fn machine_only_unavailable() -> ModeAvailability {
        ModeAvailability { combined: Ok(()), dice_only: Ok(()), machine_only: Err("no sole source"), extras: Default::default() }
    }

    fn sample_recap() -> DiagRecap {
        DiagRecap {
            architecture_line: "x86-64",
            con_out_paths: 1,
            con_in_paths: 1,
            secure_boot: SecureBootStatus::Enabled,
            entropy_policy_version: Some(3),
            production_markers_verified: true,
            crypto_clean: true,
            tpm_status: "detected",
        }
    }

    // -- SetupState::new ------------------------------------------------

    #[test]
    fn new_state_defaults_to_word_count_row_12_words_combined_both() {
        let st = SetupState::new();
        assert_eq!(st.row, ROW_WORDS);
        assert!(!st.words24);
        assert_eq!(st.mode, EntropyMode::Combined);
        assert_eq!(st.instrument, Instrument::Both);
        assert_eq!(st, SetupState::default());
    }

    // -- Esc / Enter ------------------------------------------------------

    #[test]
    fn escape_always_returns_back() {
        let mut st = SetupState::new();
        assert_eq!(st.handle_key(MenuKey::Escape, &all_available()), Some(SetupOutcome::Back));
    }

    // -- §22.5b extras row (SPEC_TPM_ENTROPY.md §11a) ---------------------

    fn avail_with_tpm() -> ModeAvailability {
        ModeAvailability {
            combined: Ok(()),
            dice_only: Ok(()),
            machine_only: Ok(()),
            extras: crate::entropy_avail::ExtrasAvailability { tpm: true, usb_trng: false },
        }
    }

    /// With zero offerable extras, `[S]` from the instrument row wraps
    /// straight back to words: `ROW_EXTRAS` does not exist (§11a: no row,
    /// not a dimmed row).
    #[test]
    fn extras_row_is_unreachable_when_no_extra_is_offerable() {
        let mut st = SetupState::new();
        st.row = ROW_INSTRUMENT;
        st.handle_key(MenuKey::Char('s'), &all_available());
        assert_eq!(st.row, ROW_WORDS);
    }

    /// With TPM offerable and a machine-using mode, `[S]` from the mode
    /// row reaches the extras row DIRECTLY (user decision 2026-08-09:
    /// extras nest inside the machine-entropy part, before the
    /// instrument row) and `[A]`/`[D]`/`[1]` toggle the opt-in
    /// (default OFF).
    #[test]
    fn extras_row_reachable_and_toggles_tpm_when_offerable() {
        let avail = avail_with_tpm();
        let mut st = SetupState::new();
        assert!(!st.extras.tpm, "opt-in MUST default OFF");
        st.row = ROW_MODE;
        st.handle_key(MenuKey::Char('s'), &avail);
        assert_eq!(st.row, ROW_EXTRAS);
        st.handle_key(MenuKey::Char('s'), &avail);
        assert_eq!(st.row, ROW_INSTRUMENT, "instrument row follows the extras row");
        st.row = ROW_EXTRAS;
        st.handle_key(MenuKey::Char('d'), &avail);
        assert!(st.extras.tpm);
        st.handle_key(MenuKey::Char('a'), &avail);
        assert!(!st.extras.tpm);
        st.handle_key(MenuKey::Char('1'), &avail);
        assert!(st.extras.tpm);
    }

    /// The committed outcome carries the toggled extras for a
    /// machine-using mode.
    #[test]
    fn commit_carries_toggled_extras_for_combined_mode() {
        let avail = avail_with_tpm();
        let mut st = SetupState::new();
        st.extras.tpm = true;
        let outcome = st.handle_key(MenuKey::Enter, &avail);
        assert_eq!(
            outcome,
            Some(SetupOutcome::Committed {
                words24: false,
                mode: EntropyMode::Combined,
                instrument: Instrument::Both,
                extras: MachineExtras { tpm: true, usb_trng: false },
            })
        );
    }

    /// §11a: a `DiceOnly` commit always carries all-OFF extras — a stale
    /// toggle from an earlier mode choice must never leak a machine probe
    /// into a physical-only ceremony.
    #[test]
    fn dice_only_commit_masks_extras_to_all_off() {
        let avail = avail_with_tpm();
        let mut st = SetupState::new();
        st.extras.tpm = true;
        st.mode = EntropyMode::DiceOnly;
        let outcome = st.handle_key(MenuKey::Enter, &avail);
        assert_eq!(
            outcome,
            Some(SetupOutcome::Committed {
                words24: false,
                mode: EntropyMode::DiceOnly,
                instrument: Instrument::Both,
                extras: MachineExtras::default(),
            })
        );
    }

    /// A toggle whose source is no longer offerable is masked out of the
    /// commit (availability is live, §11a).
    #[test]
    fn commit_masks_extras_no_longer_offerable() {
        let mut st = SetupState::new();
        st.extras.tpm = true;
        let outcome = st.handle_key(MenuKey::Enter, &all_available());
        assert_eq!(
            outcome,
            Some(SetupOutcome::Committed {
                words24: false,
                mode: EntropyMode::Combined,
                instrument: Instrument::Both,
                extras: MachineExtras::default(),
            })
        );
    }

    /// The summary line appends " + TPM" exactly when the effective
    /// (masked) extras include it.
    #[test]
    fn summary_line_reflects_effective_tpm_extra() {
        let with = build_summary_line(
            false,
            EntropyMode::Combined,
            Instrument::Both,
            MachineExtras { tpm: true, usb_trng: false },
            &avail_with_tpm(),
        );
        assert_eq!(with.as_str(), "Your setup:  12 words - Combined - Both + TPM");
        let masked = build_summary_line(
            false,
            EntropyMode::Combined,
            Instrument::Both,
            MachineExtras { tpm: true, usb_trng: false },
            &all_available(),
        );
        assert_eq!(masked.as_str(), "Your setup:  12 words - Combined - Both");
    }

    #[test]
    fn enter_commits_the_assembled_setup_when_mode_available() {
        let mut st = SetupState { row: ROW_MODE, words24: true, mode: EntropyMode::DiceOnly, instrument: Instrument::Dice, extras: MachineExtras::default() };
        let outcome = st.handle_key(MenuKey::Enter, &all_available());
        assert_eq!(
            outcome,
            Some(SetupOutcome::Committed {
                words24: true,
                mode: EntropyMode::DiceOnly,
                instrument: Instrument::Dice,
                extras: MachineExtras::default(),
            })
        );
    }

    /// Brief's added test: Enter on an unavailable mode is a no-op (never
    /// commits an unavailable mode even if state somehow reached it).
    #[test]
    fn enter_on_an_unavailable_mode_is_a_no_op() {
        let mut st = SetupState::new();
        st.mode = EntropyMode::MachineOnly;
        let before = st;
        let outcome = st.handle_key(MenuKey::Enter, &machine_only_unavailable());
        assert_eq!(outcome, None);
        assert_eq!(st, before, "state must be unchanged by a no-op Enter");
    }

    // -- row navigation (W/S) --------------------------------------------

    #[test]
    fn down_skips_the_inert_instrument_row_for_machine_only() {
        let mut st = SetupState { row: ROW_MODE, words24: false, mode: EntropyMode::MachineOnly, instrument: Instrument::Both, extras: MachineExtras::default() };
        assert_eq!(st.handle_key(MenuKey::Char('s'), &all_available()), None);
        assert_eq!(st.row, ROW_WORDS, "Down from the mode row must skip the inert instrument row");
    }

    #[test]
    fn up_skips_the_inert_instrument_row_for_machine_only() {
        let mut st = SetupState { row: ROW_WORDS, words24: false, mode: EntropyMode::MachineOnly, instrument: Instrument::Both, extras: MachineExtras::default() };
        assert_eq!(st.handle_key(MenuKey::Char('W'), &all_available()), None);
        assert_eq!(st.row, ROW_MODE, "Up from the word-count row must skip the inert instrument row");
    }

    #[test]
    fn instrument_row_is_reachable_and_wraps_for_a_physical_mode() {
        let mut st = SetupState { row: ROW_MODE, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Both, extras: MachineExtras::default() };
        assert_eq!(st.handle_key(MenuKey::Char('s'), &all_available()), None);
        assert_eq!(st.row, ROW_INSTRUMENT);
        assert_eq!(st.handle_key(MenuKey::Char('s'), &all_available()), None);
        assert_eq!(st.row, ROW_WORDS, "Down from the instrument row wraps back to word count");
    }

    // -- option cycling (A/D) --------------------------------------------

    #[test]
    fn left_right_wraps_the_word_count_row() {
        let mut st = SetupState { row: ROW_WORDS, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Both, extras: MachineExtras::default() };
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert!(st.words24);
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert!(!st.words24, "Right wraps back to 12 words");
        st.handle_key(MenuKey::Char('a'), &all_available());
        assert!(st.words24, "Left wraps to 24 words");
    }

    #[test]
    fn left_right_on_the_mode_row_skips_unavailable_modes_and_wraps() {
        let mut st = SetupState { row: ROW_MODE, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Both, extras: MachineExtras::default() };
        let avail = machine_only_unavailable();
        st.handle_key(MenuKey::Char('d'), &avail);
        assert_eq!(st.mode, EntropyMode::DiceOnly);
        st.handle_key(MenuKey::Char('d'), &avail);
        assert_eq!(st.mode, EntropyMode::Combined, "MachineOnly is unavailable, so Right must skip it and wrap");
    }

    #[test]
    fn left_right_wraps_the_instrument_row() {
        let mut st = SetupState { row: ROW_INSTRUMENT, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Dice, extras: MachineExtras::default() };
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert_eq!(st.instrument, Instrument::Coins);
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert_eq!(st.instrument, Instrument::Both);
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert_eq!(st.instrument, Instrument::Dice, "Right wraps back to Dice");
        st.handle_key(MenuKey::Char('a'), &all_available());
        assert_eq!(st.instrument, Instrument::Both, "Left wraps to Both");
    }

    #[test]
    fn cycling_the_instrument_row_is_a_no_op_when_mode_is_not_physical() {
        let mut st = SetupState { row: ROW_INSTRUMENT, words24: false, mode: EntropyMode::MachineOnly, instrument: Instrument::Dice, extras: MachineExtras::default() };
        st.handle_key(MenuKey::Char('d'), &all_available());
        assert_eq!(st.instrument, Instrument::Dice, "instrument row is inert for MachineOnly");
    }

    // -- digit direct-select ----------------------------------------------

    #[test]
    fn digits_direct_select_on_the_word_count_row() {
        let mut st = SetupState { row: ROW_WORDS, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Both, extras: MachineExtras::default() };
        st.handle_key(MenuKey::Char('2'), &all_available());
        assert!(st.words24);
        st.handle_key(MenuKey::Char('1'), &all_available());
        assert!(!st.words24);
    }

    #[test]
    fn digits_direct_select_on_the_mode_row_ignore_unavailable() {
        let mut st = SetupState { row: ROW_MODE, words24: false, mode: EntropyMode::Combined, instrument: Instrument::Both, extras: MachineExtras::default() };
        let avail = machine_only_unavailable();
        st.handle_key(MenuKey::Char('3'), &avail);
        assert_eq!(st.mode, EntropyMode::Combined, "digit 3 (MachineOnly) must be ignored while unavailable");
        st.handle_key(MenuKey::Char('2'), &avail);
        assert_eq!(st.mode, EntropyMode::DiceOnly);
    }

    #[test]
    fn digits_direct_select_on_the_instrument_row() {
        let mut st = SetupState { row: ROW_INSTRUMENT, words24: false, mode: EntropyMode::DiceOnly, instrument: Instrument::Both, extras: MachineExtras::default() };
        st.handle_key(MenuKey::Char('1'), &all_available());
        assert_eq!(st.instrument, Instrument::Dice);
        st.handle_key(MenuKey::Char('2'), &all_available());
        assert_eq!(st.instrument, Instrument::Coins);
    }

    #[test]
    fn unrecognized_keys_are_ignored() {
        let mut st = SetupState::new();
        let before = st;
        for k in [MenuKey::Other, MenuKey::Backspace, MenuKey::Char('z'), MenuKey::Char('4')] {
            assert_eq!(st.handle_key(k, &all_available()), None);
        }
        assert_eq!(st, before);
    }

    // -- mandated warning text --------------------------------------------

    #[test]
    fn warning_lines_reconstruct_the_mandated_const_for_each_mode() {
        for (mode, want) in [
            (EntropyMode::Combined, DICE_COINS_FIRMWARE_WARNING_6),
            (EntropyMode::DiceOnly, PHYSICAL_ONLY_WARNING_18_3),
            (EntropyMode::MachineOnly, MACHINE_ONLY_WARNING_18_2),
        ] {
            let (lines, n) = warning_lines(mode);
            let joined: std::string::String =
                lines[..n].iter().copied().collect::<std::vec::Vec<_>>().join(" ");
            assert_eq!(joined, want, "warning for {mode:?} must equal the mandated const verbatim");
        }
    }

    #[test]
    fn warning_lines_fit_the_fixed_bound() {
        for mode in [EntropyMode::Combined, EntropyMode::DiceOnly, EntropyMode::MachineOnly] {
            let (_lines, n) = warning_lines(mode);
            assert!(n > 0 && n < WARN_MAX_LINES, "{mode:?} warning wrapped to {n} lines");
        }
    }

    // -- summary line -------------------------------------------------------

    #[test]
    fn summary_line_includes_instrument_for_a_physical_mode() {
        let line = build_summary_line(false, EntropyMode::Combined, Instrument::Both, MachineExtras::default(), &all_available());
        assert_eq!(line.as_str(), "Your setup:  12 words - Combined - Both");
    }

    #[test]
    fn summary_line_omits_instrument_for_machine_only() {
        let line = build_summary_line(true, EntropyMode::MachineOnly, Instrument::Both, MachineExtras::default(), &all_available());
        assert_eq!(line.as_str(), "Your setup:  24 words - Machine only");
    }

    #[test]
    fn summary_line_reflects_dice_only_and_words() {
        let line = build_summary_line(false, EntropyMode::DiceOnly, Instrument::Dice, MachineExtras::default(), &all_available());
        assert_eq!(line.as_str(), "Your setup:  12 words - Dice only - Dice");
    }

    // -- disabled-mode reasons ---------------------------------------------

    #[test]
    fn disabled_mode_reasons_reuses_the_avail_err_strings() {
        let avail = machine_only_unavailable();
        let (reasons, n) = disabled_mode_reasons(&avail);
        assert_eq!(n, 1);
        assert_eq!(reasons[0], "no sole source");
    }

    #[test]
    fn disabled_mode_reasons_empty_when_all_available() {
        let (_reasons, n) = disabled_mode_reasons(&all_available());
        assert_eq!(n, 0);
    }

    // -- rendering ------------------------------------------------------

    #[test]
    fn render_does_not_panic_at_floor_resolution() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &SetupState::new(), &all_available(), &sample_recap(), BUILD);
    }

    #[test]
    fn render_every_mode_does_not_panic() {
        for mode in [EntropyMode::Combined, EntropyMode::DiceOnly, EntropyMode::MachineOnly] {
            let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
            let st = SetupState { row: ROW_MODE, words24: false, mode, instrument: Instrument::Both, extras: MachineExtras::default() };
            render(&mut fb, &st, &machine_only_unavailable(), &sample_recap(), BUILD);
        }
    }

    #[test]
    fn render_shows_accent_dim_for_the_inert_instrument_row() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st = SetupState { row: ROW_WORDS, words24: false, mode: EntropyMode::MachineOnly, instrument: Instrument::Both, extras: MachineExtras::default() };
        render(&mut fb, &st, &all_available(), &sample_recap(), BUILD);
        assert!(fb.contains(theme::ACCENT_DIM), "inert instrument row must render dimmed");
    }

    #[test]
    fn render_warn_panel_border_is_present() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, &SetupState::new(), &all_available(), &sample_recap(), BUILD);
        assert!(fb.contains(theme::WARN), "warning panel border must render in WARN");
    }

    #[test]
    fn render_disabled_enter_hint_uses_accent_dim() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st = SetupState { row: ROW_WORDS, words24: false, mode: EntropyMode::MachineOnly, instrument: Instrument::Both, extras: MachineExtras::default() };
        render(&mut fb, &st, &machine_only_unavailable(), &sample_recap(), BUILD);
        assert!(fb.contains(theme::ACCENT_DIM), "Enter hint must render dimmed while the mode is unavailable");
    }
}
