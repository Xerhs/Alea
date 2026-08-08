//! Stage 5 -- GENERATE (design doc
//! `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md` §
//! "Stage 5 — GENERATE (was 4 screens -> 1; the arm key)"): one screen
//! composed of the composition summary (including, when any claimed
//! source is present, the SPEC_EDU_UI.md §4.1/§7.1-mandated
//! `MACHINE_HEALTH_CHECK_DISCLAIMER_16`, verbatim), the SPEC §8.4 required
//! warning, and the `[G]` arm confirm.
//!
//! This is the product's most dangerous gate (the one screen after which
//! entropy is irrevocably committed and a seed is generated), so its
//! keystroke contract is deliberately narrow: `[G]`/`[g]` is the ONLY key
//! that arms generation, `[Esc]` returns to entropy entry, and -- unlike
//! every other confirm screen in this crate -- `[Enter]` is a silent
//! no-op ([`handle_key`]'s own doc comment; design doc: "This converts
//! finding 2's Enter-mash hazard into a physical impossibility and
//! *strengthens* the §22.6 gate.").
//!
//! The composition summary is a condensed, single-screen re-layout of the
//! SAME data `crate::flow_secret::composition::CompositionModel` already
//! carries (dice/coin counts, present machine tags, target bits, policy
//! version) -- this module reads that model, it does not redefine or
//! duplicate it, and it never modifies `composition.rs` (that module's
//! own paginated `TextOutput` renderer is unrelated and untouched; T13
//! only adds this GOP single-page layout over the same struct).

use core::fmt::Write as _;

use seed_core::contracts::{Framebuffer, SourceTag, TargetBits};
use seed_gop_ui::font::{draw_text, draw_text_scaled, scrub_fill};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::{panel, theme};
use seed_protocol::accounting::{counted_milli_bits, fmt_milli_bits_1dp, meets_floor};
use seed_protocol::state::EntropyMode;

use crate::chrome::{content_top, draw_footer, draw_header, Chrome, KeyHint};
use crate::flow_secret::composition::CompositionModel;
use crate::keys::MenuKey;
use crate::output::LineBuf;
use crate::text::{wrap_words, MACHINE_HEALTH_CHECK_DISCLAIMER_16, PROSE_WRAP_COLS, REQUIRED_WARNING_8_4};

/// The §8.4 warning panel's title. ASCII only: the embedded 8x16 font
/// (`seed_gop_ui::font`) only covers `0x20..=0x7E` and silently
/// blank-renders anything outside that range (see
/// `crate::chrome::FILLED_DOT`'s doc comment for the same rationale
/// applied to the stage-rail dots) -- `§` (U+00A7) is not in that range,
/// so every GOP-rendered screen in this crate spells section references
/// out in ASCII (`"SPEC 8.4"`, not `"SPEC §8.4"`) or omits them entirely;
/// the handful of literal `§` characters that DO appear in this codebase
/// are either Rust doc-comments/test-panic messages (never drawn) or
/// `seed-desktop-test/src/launcher/compat.rs`'s own `TextOutput`-backed
/// screens, which render through a host terminal, not this GOP font, and
/// so are not bound by the same constraint.
const WARN_TITLE: &str = "REQUIRED WARNING - SPEC 8.4";

/// 2x-scale arm prompt (design doc: "3. The confirm: 2x 'Press [G] to
/// generate your seed'").
const ARM_PROMPT: &str = "Press [G] to generate your seed";

/// Caption under the arm prompt (design doc, verbatim).
const IRREVERSIBLE_CAPTION: &str = "Irreversible. Enter is deliberately ignored on this screen.";

/// Vertical padding inside the warning panel border, above/below its text
/// rows.
const WARN_PANEL_PAD: u32 = LINE_PITCH / 2;

/// The user's choice at the Stage-5 arm gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateOutcome {
    /// `[G]`/`[g]` was pressed: proceed to generation.
    Generate,
    /// `[Esc]` was pressed: return to entropy entry.
    Back,
}

/// Stage 5 keystroke handling. `Key` here is [`MenuKey`] (=
/// `seed_platform_x86::input::InputEvent`) -- the exact type every other
/// `flow_secret` blocking-read loop already consumes via
/// `crate::keys::MenuKeySource::read_menu_key`.
///
/// `[G]`/`[g]` (case-insensitive) arms generation; `[Esc]` returns to
/// entropy entry; **`[Enter]` is deliberately ignored -- it returns
/// `None`, same as every other unrecognized key** (design doc: "`[Enter]`
/// is ignored", converting the finding-2 Enter-mash hazard into a
/// physical impossibility). This is the exact contract
/// `enter_never_generates` below regression-tests.
pub fn handle_key(k: MenuKey) -> Option<GenerateOutcome> {
    match k {
        MenuKey::Char(c) if c.eq_ignore_ascii_case(&'g') => Some(GenerateOutcome::Generate),
        MenuKey::Escape => Some(GenerateOutcome::Back),
        _ => None,
    }
}

/// Draw the Stage 5 screen: chrome (header/footer) + the single-page
/// composition summary + §8.4 warning panel + arm confirm.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this screen
/// follows Stage 4's dice/coin entry, whose live progress/history strip
/// would otherwise stay on screen underneath the product's most dangerous
/// gate — an arm prompt must be surrounded by nothing but its own content.
pub fn render(fb: &mut dyn Framebuffer, comp: &CompositionModel, build: &'static str) {
    scrub_fill(fb, theme::BG);
    draw_header(fb, &Chrome { stage: 5, sub: None, build });

    layout(fb, comp);

    let hints = [
        KeyHint { key: "G", label: "Generate", enabled: true, danger: true },
        KeyHint { key: "Esc", label: "Back", enabled: true, danger: false },
    ];
    draw_footer(fb, &hints);
}

/// A no-op [`Framebuffer`] sink: every [`Framebuffer::put_row`] call is
/// discarded. Used only by [`layout_lines`] to *measure* [`layout`]'s
/// content height without a real caller-supplied framebuffer -- `dims()`
/// reports the SPEC §11.4 800x600 floor, the exact resolution the
/// fit-budget test cares about.
///
/// Test-only, like [`layout_lines`] itself: `cargo test -p seed-flow`
/// builds this library twice — once with `cfg(test)` for the unit tests,
/// once without, as `tests/keystroke_budget.rs`'s dependency — and an
/// ungated measurement helper is dead code in the second build.
#[cfg(test)]
struct NullFb;

#[cfg(test)]
impl Framebuffer for NullFb {
    fn dims(&self) -> (u32, u32) {
        (seed_gop_ui::gop::mode::MIN_WIDTH, seed_gop_ui::gop::mode::MIN_HEIGHT)
    }

    fn put_row(&mut self, _x: u32, _y: u32, _px: &[u32]) {}
}

/// Total whole-[`LINE_PITCH`] rows [`layout`] consumes for `comp`'s
/// content (composition summary + warning panel + arm confirm), NOT
/// counting the chrome header/footer bands -- used only by
/// `worst_case_composition_fits_floor_budget` below. Not part of this
/// module's public interface (the brief's `Produces` block lists only
/// [`GenerateOutcome`]/[`handle_key`]/[`render`]). Test-only — see
/// [`NullFb`]'s own doc comment for why the gate is needed.
#[cfg(test)]
fn layout_lines(comp: &CompositionModel) -> usize {
    let mut null = NullFb;
    let end_y = layout(&mut null, comp);
    let content_px = end_y.saturating_sub(content_top());
    ((content_px + LINE_PITCH - 1) / LINE_PITCH) as usize
}

/// Draws this screen's full content area (composition summary + warning
/// panel + arm confirm) into `fb`, returning the final `y` reached.
/// [`render`] and [`layout_lines`] both call this ONE function -- the
/// latter via [`NullFb`] -- so the fit-budget test can never silently
/// drift from what actually gets drawn.
fn layout(fb: &mut dyn Framebuffer, comp: &CompositionModel) -> u32 {
    let x = MARGIN_X;
    let mut y = content_top();

    y = draw_composition_summary(fb, x, y, comp);
    y += LINE_PITCH / 2;
    y = draw_warning_panel(fb, x, y);
    y += LINE_PITCH / 2;
    y = draw_confirm(fb, x, y);

    y
}

/// Row 1 of the composition summary: word/bit-length, mode, policy
/// version -- from [`CompositionModel::target`]/`mode`/`policy_version`.
fn target_words(t: TargetBits) -> u32 {
    match t {
        TargetBits::Bits128 => 12,
        TargetBits::Bits256 => 24,
    }
}

fn mode_label(mode: EntropyMode) -> &'static str {
    match mode {
        EntropyMode::Combined => "Combined",
        EntropyMode::DiceOnly => "Dice-only",
        EntropyMode::MachineOnly => "Machine-only",
    }
}

/// Short claimed-source label, mirroring (not reusing -- that helper is
/// private to `composition.rs`) the "short" column of that module's own
/// `claimed_row_text`.
fn short_tag_name(tag: SourceTag) -> &'static str {
    match tag {
        SourceTag::ApprovedEfiRng => "EFI RNG",
        SourceTag::X86Rdseed64 => "RDSEED",
        SourceTag::X86RdrandSupplementary => "RDRAND",
        SourceTag::ApprovedUsbTrng => "USB TRNG",
        SourceTag::DiceRolls | SourceTag::CoinFlips => "",
    }
}

/// The single-screen composition summary (design doc: "Composition
/// summary panel — sources, claim ticks, conditioning, result shape.
/// Content from today's composition pages, laid out to fit one screen").
/// Condensed relative to `composition.rs`'s own paginated prose panel --
/// one line per fact, not a multi-page explainer -- so the worst case
/// (Combined + all 4 possible claimed tags) fits this screen alongside
/// the §8.4 warning and the arm confirm.
fn draw_composition_summary(fb: &mut dyn Framebuffer, x: u32, mut y: u32, comp: &CompositionModel) -> u32 {
    let mut header = LineBuf::new();
    let _ = write!(
        header,
        "COMPOSITION -- {} words / {} bits -- {} -- policy v{}",
        target_words(comp.target),
        comp.target as u32,
        mode_label(comp.mode),
        comp.policy_version
    );
    draw_text(fb, x, y, header.as_str(), theme::on_bg(theme::TEXT));
    y += LINE_PITCH;

    if comp.dice_rolls > 0 {
        let mut line = LineBuf::new();
        let _ = write!(line, "COUNTED  dice: {} rolls", comp.dice_rolls);
        draw_text(fb, x, y, line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;
    }
    if comp.coin_flips > 0 {
        let mut line = LineBuf::new();
        let _ = write!(line, "COUNTED  coin: {} flips", comp.coin_flips);
        draw_text(fb, x, y, line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;
    }

    if comp.dice_rolls == 0 && comp.coin_flips == 0 {
        draw_text(fb, x, y, "COUNTED  nothing witnessed (machine-only mode)", theme::on_bg(theme::CAPTION));
        y += LINE_PITCH;
    } else {
        let total_milli = counted_milli_bits(comp.dice_rolls, comp.coin_flips);
        let mut num_buf = [0u8; 24];
        let total_str = fmt_milli_bits_1dp(total_milli, &mut num_buf);
        let target_num = comp.target as u32;
        let mut line = LineBuf::new();
        if meets_floor(total_milli, comp.target) {
            let _ = write!(line, "COUNTED TOTAL: {total_str} bits >= {target_num} bits floor");
        } else {
            // Defensive-only (mirrors composition.rs's own defensive
            // branch): unreachable on a real path, but must never claim a
            // passing verdict it did not earn.
            let _ = write!(line, "COUNTED TOTAL: {total_str} bits < {target_num} bits floor (BELOW FLOOR)");
        }
        draw_text(fb, x, y, line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;
    }

    if !comp.machine_tags.is_empty() {
        let mut line = LineBuf::new();
        let _ = write!(line, "CLAIMED (not counted):");
        for (i, tag) in comp.machine_tags.iter().enumerate() {
            if i > 0 {
                let _ = write!(line, ",");
            }
            let _ = write!(line, " {}", short_tag_name(tag));
        }
        draw_text(fb, x, y, line.as_str(), theme::on_bg(theme::CAPTION));
        y += LINE_PITCH;

        draw_text(
            fb,
            x,
            y,
            "Claimed sources help but add 0 counted bits (health-checked, not proven).",
            theme::on_bg(theme::CAPTION),
        );
        y += LINE_PITCH;

        // SPEC_EDU_UI.md §4.1/§7.1: whenever a claimed source is present,
        // the composition panel MUST show MACHINE_HEALTH_CHECK_DISCLAIMER_16
        // verbatim, accompanying the claimed list -- gated on the exact
        // same `!comp.machine_tags.is_empty()` condition composition.rs's
        // own `render_notices_page`/`has_claimed` uses. Reused by
        // reference (never duplicated), same discipline as
        // REQUIRED_WARNING_8_4 above.
        for line in wrap_words(MACHINE_HEALTH_CHECK_DISCLAIMER_16, PROSE_WRAP_COLS) {
            draw_text(fb, x, y, line, theme::on_bg(theme::CAPTION));
            y += LINE_PITCH;
        }
    }

    y
}

/// The SPEC §8.4 required warning, in a `WARN`-bordered panel (design
/// doc: "The §8.4 required warning in a `WARN` panel."). Text is
/// [`REQUIRED_WARNING_8_4`] verbatim, by reference -- this module never
/// copies that string, it reuses `crate::text`'s single source of truth
/// (the same const `crate::text::render_required_warning` draws).
fn draw_warning_panel(fb: &mut dyn Framebuffer, x: u32, y: u32) -> u32 {
    let wrapped_count = wrap_words(REQUIRED_WARNING_8_4, PROSE_WRAP_COLS).count();
    let content_rows = 1 + wrapped_count; // title + wrapped body
    let h = WARN_PANEL_PAD * 2 + (content_rows as u32) * LINE_PITCH;

    let (fb_w, _fb_h) = fb.dims();
    let w = fb_w.saturating_sub(2 * x);
    panel::warn_panel(fb, x, y, w, h);

    let tx = x + WARN_PANEL_PAD;
    let mut ty = y + WARN_PANEL_PAD;
    draw_text(fb, tx, ty, WARN_TITLE, theme::on_panel(theme::WARN));
    ty += LINE_PITCH;

    for line in wrap_words(REQUIRED_WARNING_8_4, PROSE_WRAP_COLS) {
        draw_text(fb, tx, ty, line, theme::on_panel(theme::TEXT));
        ty += LINE_PITCH;
    }

    y + h
}

/// The arm confirm: [`ARM_PROMPT`] at 2x scale in `WARN` (irreversibility
/// role, `theme::WARN`'s own doc comment), then [`IRREVERSIBLE_CAPTION`]
/// at 1x in `CAPTION`.
fn draw_confirm(fb: &mut dyn Framebuffer, x: u32, y: u32) -> u32 {
    draw_text_scaled(fb, x, y, ARM_PROMPT, theme::on_bg(theme::WARN), 2);
    let y = y + LINE_PITCH * 2;

    draw_text(fb, x, y, IRREVERSIBLE_CAPTION, theme::on_bg(theme::CAPTION));
    y + LINE_PITCH
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::chrome::content_bottom;
    use crate::flow_secret::composition::MachineTagSet;

    /// Host-only `Vec<u32>` `Framebuffer` test double, same pattern as
    /// `chrome`'s/`panel`'s own copies (each module keeps its own since
    /// it's `#[cfg(test)]`-private).
    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }

    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
        }

        fn cell_contains(&self, x: u32, y: u32, w: u32, h: u32, color: u32) -> bool {
            (y..y + h).any(|py| (x..x + w).any(|px| px < self.w && py < self.h && self.at(px, py) == color))
        }

        fn at(&self, x: u32, y: u32) -> u32 {
            self.buf[(y as usize) * (self.w as usize) + (x as usize)]
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

    // ------------------------------------------------------------------
    // SPEC §12.2 "Fixed layouts" -- CRITICAL bleed-through regression.
    // ------------------------------------------------------------------

    /// Stage 5 is drawn straight over Stage 4's dice/coin entry screen,
    /// whose live counters and history strip are considerably taller than
    /// this screen's content. Before the fix this screen did not clear, so
    /// that strip stayed on screen underneath the product's most dangerous
    /// gate -- an arm prompt must be surrounded by nothing but its own
    /// content.
    ///
    /// Stage 4 paints through `FbTextOutput` (it is a `TextOutput` screen —
    /// `flow_secret::physical::render_physical_screen`), so its pixel
    /// footprint is exactly a stack of text rows; this test lays down that
    /// same footprint, through that same path, tall enough to cover the rows
    /// Stage 5 leaves blank. (`StripRing`, which backs the history strip, is
    /// deliberately private to `physical` — it is secret-typed — so the real
    /// renderer is not constructible from here, and widening it for a test
    /// would be exactly the wrong trade.)
    ///
    /// Then asserted exactly: rendering Stage 5 over it must produce a
    /// pixel-for-pixel identical framebuffer to rendering it on a blank one.
    /// That is the whole property, and only clearing first can satisfy it.
    #[test]
    fn generate_clears_the_entropy_entry_history_strip_instead_of_letting_it_bleed_through() {
        use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};

        let comp = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);

        let mut dirty = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        {
            use crate::output::TextOutput as _;
            let mut out = crate::output::FbTextOutput::new(&mut dirty);
            out.write_line("Roll dice   Rolls 24   Flips 0   62.0 of 128.0 bits");
            out.write_line("");
            for _ in 0..22 {
                // The history strip plus the live counters and controls:
                // every row Stage 5's shorter content leaves untouched.
                out.write_line("[4][4][4][4][4][4][4][4][4][4][4][4][4][4][4][4][4][4][4][4]");
            }
        }
        assert!(
            dirty.buf.iter().any(|&p| p != 0),
            "sanity: the simulated Stage-4 entry screen must have drawn something"
        );

        let mut clean = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut dirty, &comp, "b1");
        render(&mut clean, &comp, "b1");

        assert!(
            dirty.buf == clean.buf,
            "the Stage-5 GENERATE screen must clear the entropy-entry history strip, \
             not composite the arm prompt over it"
        );
    }

    // ------------------------------------------------------------------
    // handle_key -- THE regression test the brief names, plus arm/back
    // ------------------------------------------------------------------

    /// THE regression test named by the brief: Enter is deliberately a
    /// no-op on this screen (design doc: "`[Enter]` is ignored" -- the
    /// finding-2 Enter-mash hazard becomes a physical impossibility).
    #[test]
    fn enter_never_generates() {
        assert_eq!(handle_key(MenuKey::Enter), None);
    }

    #[test]
    fn lowercase_g_arms_generation() {
        assert_eq!(handle_key(MenuKey::Char('g')), Some(GenerateOutcome::Generate));
    }

    #[test]
    fn uppercase_g_arms_generation() {
        assert_eq!(handle_key(MenuKey::Char('G')), Some(GenerateOutcome::Generate));
    }

    #[test]
    fn escape_returns_back() {
        assert_eq!(handle_key(MenuKey::Escape), Some(GenerateOutcome::Back));
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        assert_eq!(handle_key(MenuKey::Other), None);
        assert_eq!(handle_key(MenuKey::Backspace), None);
        assert_eq!(handle_key(MenuKey::Char('x')), None);
        assert_eq!(handle_key(MenuKey::Char('1')), None);
    }

    // ------------------------------------------------------------------
    // Fit budget: worst case (Combined, max claimed tags) must fit
    // MAX_LINES_AT_FLOOR minus the chrome header/footer rows.
    // ------------------------------------------------------------------

    /// Lines the header+footer bands themselves occupy, derived from
    /// `content_top`/`content_bottom`/`LINE_PITCH` exactly as the brief
    /// directs -- not a hand-guessed constant.
    fn chrome_rows() -> usize {
        let content_px = content_bottom() - content_top();
        let available_lines = (content_px / LINE_PITCH) as usize;
        seed_gop_ui::layout::MAX_LINES_AT_FLOOR - available_lines
    }

    fn worst_case_composition() -> CompositionModel {
        // Combined mode (dice + coin both present) with every possible
        // claimed machine tag present -- `MachineTagSet` caps at exactly
        // 4 (that type's own doc comment), so this IS the worst case,
        // not just a large one.
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedEfiRng);
        tags.insert(SourceTag::X86Rdseed64);
        tags.insert(SourceTag::X86RdrandSupplementary);
        tags.insert(SourceTag::ApprovedUsbTrng);
        let comp = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 7);
        assert_eq!(comp.mode, EntropyMode::Combined);
        assert_eq!(comp.machine_tags.len(), 4);
        comp
    }

    #[test]
    fn worst_case_composition_fits_floor_budget() {
        let comp = worst_case_composition();
        let lines = layout_lines(&comp);
        let budget = seed_gop_ui::layout::MAX_LINES_AT_FLOOR - chrome_rows();
        assert!(lines <= budget, "worst-case composition needs {lines} lines, budget is {budget}");
    }

    #[test]
    fn sparser_composition_uses_fewer_lines_than_the_worst_case() {
        let sparse = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        assert_eq!(sparse.mode, EntropyMode::DiceOnly);
        assert!(layout_lines(&sparse) < layout_lines(&worst_case_composition()));
    }

    // ------------------------------------------------------------------
    // render: smoke tests across modes, chrome + panel + arm content
    // ------------------------------------------------------------------

    #[test]
    fn render_does_not_panic_for_every_mode() {
        let combined = worst_case_composition();
        let dice_only = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::ApprovedEfiRng);
        let machine_only = CompositionModel::new(0, 0, tags, TargetBits::Bits256, 2);

        for comp in [&combined, &dice_only, &machine_only] {
            let mut fb = VecFb::new(800, 600);
            render(&mut fb, comp, "b1");
            assert!(fb.buf.iter().any(|&p| p != 0), "render must draw something");
        }
    }

    #[test]
    fn render_draws_warn_panel_border_and_footer_key_hints() {
        let comp = worst_case_composition();
        let mut fb = VecFb::new(800, 600);
        render(&mut fb, &comp, "b1");

        assert!(
            fb.cell_contains(0, content_top(), 800, content_bottom() - content_top(), theme::WARN),
            "the §8.4 warning must render inside a WARN-bordered panel"
        );

        let band_y = 600 - LINE_PITCH * 2;
        assert!(
            fb.cell_contains(0, band_y, 800, LINE_PITCH * 2, theme::DANGER),
            "the [G] footer hint must render DANGER (irreversible action)"
        );
    }

    /// `draw_confirm` in isolation, byte-for-byte against a directly-built
    /// expected buffer -- proves the arm prompt is drawn via
    /// `draw_text_scaled(.., 2)` (not plain `draw_text`) and the caption
    /// follows it exactly `LINE_PITCH * 2` rows down (the scale-2 row
    /// height), matching the global "2x scale for ... the arm prompt"
    /// constraint precisely rather than by loose pixel-presence probing.
    #[test]
    fn draw_confirm_renders_arm_prompt_at_2x_scale() {
        let w = 800u32;
        let h = LINE_PITCH * 4;

        let mut actual = VecFb::new(w, h);
        let end_y = draw_confirm(&mut actual, MARGIN_X, 0);

        let mut expected = VecFb::new(w, h);
        draw_text_scaled(&mut expected, MARGIN_X, 0, ARM_PROMPT, theme::on_bg(theme::WARN), 2);
        draw_text(&mut expected, MARGIN_X, LINE_PITCH * 2, IRREVERSIBLE_CAPTION, theme::on_bg(theme::CAPTION));

        assert_eq!(actual.buf, expected.buf);
        assert_eq!(end_y, LINE_PITCH * 3, "confirm section must be exactly 2 (scale-2 prompt) + 1 (caption) rows tall");
    }

    // ------------------------------------------------------------------
    // layout_lines: pure sanity on the shared measure/draw function.
    // ------------------------------------------------------------------

    #[test]
    fn layout_lines_is_positive_for_every_mode() {
        let dice_only = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        assert!(layout_lines(&dice_only) > 0);
        assert!(layout_lines(&worst_case_composition()) > 0);
    }

    // ------------------------------------------------------------------
    // Fix (task-review "Needs fixes"): SPEC_EDU_UI.md §4.1/§7.1 mandates
    // MACHINE_HEALTH_CHECK_DISCLAIMER_16 verbatim, accompanying the
    // claimed list, whenever a claimed source is present. Gated exactly
    // like composition.rs's own `has_claimed` check.
    // ------------------------------------------------------------------

    /// Byte-exact: `draw_composition_summary` for a claimed-bearing
    /// Combined model draws EXACTLY header, dice, coin, total, claimed
    /// list, claimed caption, then [`MACHINE_HEALTH_CHECK_DISCLAIMER_16`]
    /// wrapped, in that order, each via the same `draw_text`/`wrap_words`
    /// primitives -- proving the §16 disclaimer is drawn verbatim
    /// alongside the claimed list, not merely that *some* extra content
    /// appears.
    #[test]
    fn draw_composition_summary_appends_claimed_list_caption_and_16_disclaimer_when_claimed_present() {
        let mut tags = MachineTagSet::new();
        tags.insert(SourceTag::X86Rdseed64);
        let comp = CompositionModel::new(128, 40, tags, TargetBits::Bits256, 7);
        assert_eq!(comp.mode, EntropyMode::Combined);

        let w = 800u32;
        let h = LINE_PITCH * 20;

        let mut actual = VecFb::new(w, h);
        let y_end = draw_composition_summary(&mut actual, MARGIN_X, content_top(), &comp);

        let mut expected = VecFb::new(w, h);
        let mut y = content_top();

        let mut header = LineBuf::new();
        let _ = write!(header, "COMPOSITION -- 24 words / 256 bits -- Combined -- policy v7");
        draw_text(&mut expected, MARGIN_X, y, header.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;

        let mut dice_line = LineBuf::new();
        let _ = write!(dice_line, "COUNTED  dice: 128 rolls");
        draw_text(&mut expected, MARGIN_X, y, dice_line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;

        let mut coin_line = LineBuf::new();
        let _ = write!(coin_line, "COUNTED  coin: 40 flips");
        draw_text(&mut expected, MARGIN_X, y, coin_line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;

        let total_milli = counted_milli_bits(128, 40);
        let mut num_buf = [0u8; 24];
        let total_str = fmt_milli_bits_1dp(total_milli, &mut num_buf);
        let mut total_line = LineBuf::new();
        let _ = write!(total_line, "COUNTED TOTAL: {total_str} bits >= 256 bits floor");
        draw_text(&mut expected, MARGIN_X, y, total_line.as_str(), theme::on_bg(theme::TEXT));
        y += LINE_PITCH;

        let mut claimed_line = LineBuf::new();
        let _ = write!(claimed_line, "CLAIMED (not counted): RDSEED");
        draw_text(&mut expected, MARGIN_X, y, claimed_line.as_str(), theme::on_bg(theme::CAPTION));
        y += LINE_PITCH;

        draw_text(
            &mut expected,
            MARGIN_X,
            y,
            "Claimed sources help but add 0 counted bits (health-checked, not proven).",
            theme::on_bg(theme::CAPTION),
        );
        y += LINE_PITCH;

        // The §16 disclaimer, wrapped -- built via the SAME primitives
        // (`wrap_words`, `MACHINE_HEALTH_CHECK_DISCLAIMER_16`)
        // `draw_composition_summary` itself uses, so this test can never
        // silently drift from a hand-typed copy of the disclaimer text.
        for line in wrap_words(MACHINE_HEALTH_CHECK_DISCLAIMER_16, PROSE_WRAP_COLS) {
            draw_text(&mut expected, MARGIN_X, y, line, theme::on_bg(theme::CAPTION));
            y += LINE_PITCH;
        }

        assert_eq!(y, y_end, "draw_composition_summary must return exactly this many consumed rows");
        assert_eq!(actual.buf, expected.buf, "composition summary + §16 disclaimer must render exactly as built here");
    }

    /// No claimed sources present: `draw_composition_summary` draws
    /// nothing beyond header/dice/coin/total -- no claimed list, no
    /// caption, and critically no §16 disclaimer either.
    #[test]
    fn draw_composition_summary_omits_16_disclaimer_when_no_claimed_source() {
        let dice_only = CompositionModel::new(128, 40, MachineTagSet::new(), TargetBits::Bits256, 7);
        assert!(dice_only.machine_tags.is_empty());

        let w = 800u32;
        let h = LINE_PITCH * 20;
        let mut fb = VecFb::new(w, h);
        let y_end = draw_composition_summary(&mut fb, MARGIN_X, content_top(), &dice_only);

        // header + dice + coin + total = exactly 4 rows.
        assert_eq!((y_end - content_top()) / LINE_PITCH, 4);

        // Absolute pixel-row offset (see the sibling test's comment on
        // why this is `y_end` directly, not `y_end - content_top()`).
        let consumed_px = (y_end as usize) * (w as usize);
        assert!(fb.buf[consumed_px..].iter().all(|&p| p == theme::BG), "nothing may render past the 4-row prefix when there is no claimed source");
    }

    /// The fit-budget test above (`worst_case_composition_fits_floor_budget`)
    /// already re-covers the worst case now that it includes the §16
    /// disclaimer's wrapped rows (that test was re-run, unchanged, as
    /// part of this fix and still passes -- see the fix report for the
    /// exact before/after line counts).
    #[test]
    fn worst_case_still_uses_strictly_more_lines_than_a_claimed_free_composition() {
        let worst = worst_case_composition();
        let claimed_free = CompositionModel::new(24, 0, MachineTagSet::new(), TargetBits::Bits128, 1);
        assert!(layout_lines(&worst) > layout_lines(&claimed_free));
    }
}
