//! Mnemonic display (SPEC §22.7, `AppState::MnemonicDisplay` /
//! `AppState::DestroyConfirm`).
//!
//! Requirements enforced here:
//! - Every word is rendered **individually** via
//!   [`seed_gop_ui::font::draw_word`], by index, into the linear GOP
//!   framebuffer — this module never builds, formats or holds a
//!   concatenated mnemonic string anywhere (SPEC §12.2). Its own render
//!   function takes `indexes: &[u16]` and draws each slot in a loop; no
//!   local variable in this file is ever a joined phrase.
//! - No timeout: [`read_display_choice`] blocks forever until `H` or `D`
//!   is pressed (SPEC §22.7: "no automatic timeout after watchdog
//!   disablement" — the watchdog is re-asserted by the caller's state-
//!   machine transitions around this screen, never by a timer here).
//! - `[D]` destroy requires a second confirmation
//!   ([`read_destroy_double_confirm`]) before the caller may transition
//!   to the scrub-and-shutdown chain (SPEC §22.7: "Destroy requires a
//!   second confirmation and then scrub-and-shutdown").
//!
//! Post-secret input goes through `seed_platform_x86::input::KeySource`
//! (the same no-echo-capable primitive SPEC §12.3 hidden re-entry uses,
//! `crate::flow_secret::reentry`) rather than this crate's pre-secret
//! `MenuKeySource` — one live keyboard borrow threads through every
//! screen from here to shutdown, and using the same trait as re-entry
//! keeps that borrow uniform.

use seed_core::contracts::{Framebuffer, Style};
use seed_gop_ui::font::draw_word;
use seed_gop_ui::{panel, theme};
use seed_platform_x86::input::{InputEvent, KeySource};

use crate::flow_secret::gop_screen::SCREEN_STYLE;

/// Style used to render mnemonic words (same fixed style as every other
/// post-secret screen; SPEC §12.2 "Fixed layouts"). Kept as the plain
/// on-screen-ground style (not the panel-background variant the restyled
/// word slots actually draw with below) because its `.fg` value is a
/// cross-crate leakage-test signal (`tests/leakage/tests/scrub_points.rs`
/// looks for this exact foreground color to prove a word was drawn, then
/// scrubbed) — [`theme::TEXT`] is that shared `.fg` value either way, so
/// the leakage check's assumption holds regardless of which background
/// role a given render call pairs it with.
pub const WORD_STYLE: Style = SCREEN_STYLE;

/// Fixed row (below the 4-row/24-slot word grid `seed_gop_ui::font`
/// lays out internally) where this screen's control prompts are drawn.
/// `seed_gop_ui::font`'s own slot-grid constants are private, so this is
/// a conservative independent bound (4 rows at `2 * GLYPH_HEIGHT` each,
/// SPEC §12.2 "Fixed layouts" — any legitimate change to that grid is a
/// WP-10-owned layout change, not a secret-handling one).
const CONTROLS_Y: u32 = seed_gop_ui::layout::WORD_GRID_TOP
    + 4 * (seed_gop_ui::font::GLYPH_HEIGHT * 2)
    + seed_gop_ui::font::GLYPH_HEIGHT;

// ============================================================================
// Design doc §4 Stage 6: "word-slot panels with CAPTION indexes"
// ============================================================================
//
// `seed_gop_ui::font::draw_word`'s own slot grid (`WORD_SLOT_COLUMNS`/
// `_ROWS`/`_CELL_W`/`_CELL_H`, `slot_origin`) is private — this module
// already independently mirrors its geometry for `CONTROLS_Y` above (see
// that constant's own doc comment for why that's the established,
// intentional pattern here rather than a layout change to `font.rs`).
// The constants/`slot_origin` below extend that same mirroring so this
// restyle can draw a themed panel behind the word grid and recolor each
// slot's own "NN. " index label, without touching `font.rs` at all —
// `draw_word` itself (and the one call to it below) is unchanged.

const WORD_SLOT_COLUMNS: u32 = 6;
const WORD_SLOT_ROWS: u32 = 4;
const WORD_SLOT_CELL_W: u32 = seed_gop_ui::font::GLYPH_WIDTH * 12;
const WORD_SLOT_CELL_H: u32 = seed_gop_ui::font::GLYPH_HEIGHT * 2;

/// Mirrors `seed_gop_ui::font`'s private `slot_origin` exactly (see this
/// section's own doc comment).
fn slot_origin(slot: u8) -> (u32, u32) {
    let slot = u32::from(slot) % (WORD_SLOT_COLUMNS * WORD_SLOT_ROWS);
    let col = slot % WORD_SLOT_COLUMNS;
    let row = slot / WORD_SLOT_COLUMNS;
    // Grid offset mirror (Stage-6 shell restyle, 2026-08-09): keep in
    // lockstep with `seed_gop_ui::font::slot_origin`, which now places
    // the grid at the shared `layout::WORD_GRID_LEFT/TOP` origin inside
    // the chrome shell's content area.
    (
        seed_gop_ui::layout::WORD_GRID_LEFT + col * WORD_SLOT_CELL_W,
        seed_gop_ui::layout::WORD_GRID_TOP + row * WORD_SLOT_CELL_H,
    )
}

/// The "NN. " slot-index label `draw_word` itself draws as the first 4
/// glyphs of each slot (1-based `slot + 1`, always 2 digits + ". ") —
/// duplicated here (not exported by `font.rs`) purely so this module can
/// redraw just those glyph cells in [`theme::CAPTION`] afterward.
fn slot_label(slot: u8) -> [u8; 4] {
    let n = u32::from(slot) + 1;
    [b'0' + ((n / 10) % 10) as u8, b'0' + (n % 10) as u8, b'.', b' ']
}

pub const HIDE_PROMPT: &str = "[H] Hide words and begin complete re-entry";
pub const DESTROY_PROMPT: &str = "[D] Destroy phrase and shut down";

/// Render every mnemonic word (SPEC §22.7: "words are numbered; all
/// words visible simultaneously") plus the two control prompts. `count`
/// is 12 or 24; only `indexes[..count]` is drawn.
///
/// Design doc §4 Stage 6 restyle: the word grid draws on a
/// [`theme::PANEL`] background (word text in [`theme::TEXT`], unchanged
/// from the pre-restyle [`WORD_STYLE`] foreground — see that constant's
/// own doc comment), with each slot's own "NN. " index label recolored to
/// [`theme::CAPTION`] afterward. `draw_word` itself is called exactly
/// once per slot, unchanged (SPEC §12.2: no concatenated mnemonic
/// string) — only the surrounding panel fill and the label-recolor pass
/// are new.
/// Stage-6 BACKUP screen title (design doc §4 Stage 6 shell,
/// 2026-08-09 restyle: the mnemonic screen joins the redesigned shell —
/// chrome header/footer, 2x title — with the word-grid security contract
/// untouched).
pub const BACKUP_TITLE: &str = "Write down your recovery phrase";

pub fn render_mnemonic_display(fb: &mut dyn Framebuffer, indexes: &[u16], count: usize, build: &'static str) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    crate::chrome::draw_header(fb, &crate::chrome::Chrome { stage: 6, sub: None, build });

    let title_y = crate::chrome::content_top() + seed_gop_ui::layout::LINE_PITCH / 2;
    seed_gop_ui::font::draw_text_scaled(
        fb,
        seed_gop_ui::layout::MARGIN_X,
        title_y,
        BACKUP_TITLE,
        theme::on_bg(theme::TEXT),
        2,
    );

    let rows = (count as u32).div_ceil(WORD_SLOT_COLUMNS).max(1);
    let pad = seed_gop_ui::font::GLYPH_WIDTH;
    panel::panel(
        fb,
        seed_gop_ui::layout::WORD_GRID_LEFT - pad,
        seed_gop_ui::layout::WORD_GRID_TOP - pad,
        WORD_SLOT_COLUMNS * WORD_SLOT_CELL_W + 2 * pad,
        rows * WORD_SLOT_CELL_H + 2 * pad,
    );

    for (slot, &index) in indexes.iter().take(count).enumerate() {
        draw_word(fb, slot as u8, index, theme::on_panel(theme::TEXT));

        let (ox, oy) = slot_origin(slot as u8);
        let label = slot_label(slot as u8);
        let label_str = core::str::from_utf8(&label).unwrap_or("");
        seed_gop_ui::font::draw_text(fb, ox, oy, label_str, theme::on_panel(theme::CAPTION));
    }

    let x = seed_gop_ui::layout::MARGIN_X;
    seed_gop_ui::font::draw_text(fb, x, CONTROLS_Y, HIDE_PROMPT, SCREEN_STYLE);
    seed_gop_ui::font::draw_text(
        fb,
        x,
        CONTROLS_Y + seed_gop_ui::font::GLYPH_HEIGHT + seed_gop_ui::font::GLYPH_HEIGHT / 2,
        DESTROY_PROMPT,
        SCREEN_STYLE,
    );

    crate::chrome::draw_footer(
        fb,
        &[
            crate::chrome::KeyHint { key: "H", label: "Hide & re-enter", enabled: true, danger: false },
            crate::chrome::KeyHint { key: "D", label: "Destroy", enabled: true, danger: true },
        ],
    );
}

/// The user's choice on the mnemonic-display screen (SPEC §22.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayChoice {
    /// `[H]`.
    Hide,
    /// `[D]`, first press — the caller must still run
    /// [`read_destroy_double_confirm`] before destroying anything.
    DestroyRequested,
}

/// Block (no timeout, SPEC §22.7) until `H` or `D` is pressed. Every
/// other key is ignored.
pub fn read_display_choice<K: KeySource + ?Sized>(keys: &mut K) -> DisplayChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'h') => return DisplayChoice::Hide,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'d') => return DisplayChoice::DestroyRequested,
            _ => {}
        }
    }
}

pub const DESTROY_CONFIRM_LINES: &[&str] = &[
    "Destroy the phrase?",
    "This cannot be undone.",
    "",
    "[M] Wipe and return to the menu",
    "[P] Wipe and power off (safest: clears RAM)",
    "[N] Cancel, show the phrase again",
];

/// How the operator chose to leave the ceremony from the second destroy
/// confirmation (SPEC §22.7, extended by the SPEC §26 amendment
/// 2026-08-08). Both destructive choices run the identical full scrub
/// first (`crate::flow_secret::shutdown::scrub_secrets`); they differ only
/// in what happens *after* every secret is already gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyDecision {
    /// `[M]` — wipe every secret, then return to the launcher main menu.
    /// The SPEC §26 amendment (2026-08-08) permits this in place of the
    /// forced power-off precisely because the scrub has already zeroed the
    /// whole secret arena; the trade-off (RAM is not power-cycled) is
    /// surfaced to the operator on the post-destroy notice screen.
    ReturnToMenu,
    /// `[P]` — wipe every secret, then power the machine off: the original
    /// SPEC §26 scrub-and-shutdown. Safest, because power-off also lets
    /// RAM decay, closing the cold-boot-read window the menu path leaves.
    PowerOff,
    /// `[N]` — cancel and redisplay the phrase.
    Cancel,
}

/// Render the SPEC §22.7 second destroy confirmation.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this
/// screen follows the mnemonic-display screen's full word grid, which
/// this screen's own (shorter) lines would otherwise be drawn on top of,
/// leaving garbled overlapping text.
///
/// Design doc §4 Stage 6 restyle ("second confirmation ... `DANGER`-
/// styled"): [`DESTROY_CONFIRM_LINES`]'s title row (`"Destroy the phrase
/// and shut down?"`) renders in [`theme::DANGER`] — the role SPEC §3.1
/// reserves exclusively for the destroy path and the fatal-failure
/// chain. Every other line keeps the ordinary screen style; the copy
/// itself is untouched.
pub fn render_destroy_confirm(fb: &mut dyn Framebuffer, build: &'static str) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    crate::chrome::draw_header(fb, &crate::chrome::Chrome { stage: 6, sub: None, build });

    let margin = seed_gop_ui::layout::MARGIN_X;
    let pitch = seed_gop_ui::layout::LINE_PITCH;
    // Design doc §4 Stage 6: destroy's second confirmation is
    // DANGER-styled — the mandated lines render inside a warn panel, the
    // heading in `theme::DANGER`, wording verbatim (SPEC §22.7 / §26
    // amendment).
    let panel_y = crate::chrome::content_top() + pitch;
    let panel_h = (DESTROY_CONFIRM_LINES.len() as u32) * pitch + pitch;
    let (fb_w, _) = fb.dims();
    panel::warn_panel(fb, margin, panel_y, fb_w.saturating_sub(2 * margin), panel_h);
    let mut y = panel_y + pitch / 2;
    for (i, line) in DESTROY_CONFIRM_LINES.iter().enumerate() {
        let style = if i == 0 {
            theme::on_panel(theme::DANGER)
        } else {
            theme::on_panel(theme::TEXT)
        };
        seed_gop_ui::font::draw_text(fb, margin + seed_gop_ui::font::GLYPH_WIDTH, y, line, style);
        y += pitch;
    }

    crate::chrome::draw_footer(
        fb,
        &[
            crate::chrome::KeyHint { key: "M", label: "Wipe, menu", enabled: true, danger: true },
            crate::chrome::KeyHint { key: "P", label: "Wipe, power off", enabled: true, danger: true },
            crate::chrome::KeyHint { key: "N", label: "Cancel", enabled: true, danger: false },
        ],
    );
}

/// Block until the second destroy confirmation is answered: `M`/`m` wipes
/// and returns to the menu, `P`/`p` wipes and powers off, `N`/`n` cancels
/// back to the mnemonic display. Every other key — including a bare
/// `Enter` — is ignored: the two destructive choices each require their
/// own explicit letter so a stray keystroke can never irreversibly wipe
/// the phrase, and there is no bare Escape post-secret (SPEC §21).
pub fn read_destroy_double_confirm<K: KeySource + ?Sized>(keys: &mut K) -> DestroyDecision {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'m') => return DestroyDecision::ReturnToMenu,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'p') => return DestroyDecision::PowerOff,
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'n') => return DestroyDecision::Cancel,
            _ => {}
        }
    }
}

/// Post-destroy notice shown once, on the freshly-scrubbed (blank)
/// framebuffer, after the operator chose [`DestroyDecision::ReturnToMenu`]
/// and `scrub_secrets` has already run (SPEC §26 amendment 2026-08-08).
/// Carries no secret content — every secret is gone by the time this
/// draws — and states the cold-boot trade-off the menu path accepts.
pub const DESTROYED_RETURN_NOTICE_LINES: &[&str] = &[
    "Keys destroyed.",
    "Every secret has been wiped from memory.",
    "",
    "For maximum safety, power this machine",
    "off before leaving it unattended.",
    "",
    "[Enter] Return to the menu",
];

/// Render the post-destroy "returned to menu" notice. Clears the
/// framebuffer first (it was scrubbed blank by `scrub_secrets`, but this
/// keeps the draw self-contained and matches every other screen's SPEC
/// §12.2 fixed-layout discipline). The heading row states the destructive
/// action in [`theme::DANGER`]; the remaining rows use the ordinary
/// screen style.
pub fn render_destroyed_return_notice(fb: &mut dyn Framebuffer) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let margin = seed_gop_ui::layout::MARGIN_X;
    let pitch = seed_gop_ui::layout::LINE_PITCH;
    let mut y = margin;
    for (i, line) in DESTROYED_RETURN_NOTICE_LINES.iter().enumerate() {
        let style = if i == 0 { theme::on_bg(theme::DANGER) } else { SCREEN_STYLE };
        seed_gop_ui::font::draw_text(fb, margin, y, line, style);
        y += pitch;
    }
}

/// Block until the operator acknowledges the post-destroy notice with
/// `Enter` (SPEC §26 amendment 2026-08-08). Every other key is ignored:
/// the secrets are already gone so there is nothing left to protect, but
/// the same "only Enter advances" discipline the rest of the ceremony
/// uses keeps a stray keypress from silently dropping back to the menu.
pub fn read_return_notice_ack<K: KeySource + ?Sized>(keys: &mut K) {
    loop {
        if matches!(keys.read_key_blocking(), InputEvent::Enter) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }
    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
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

    struct ScriptedKeys {
        events: std::vec::Vec<InputEvent>,
        pos: usize,
    }
    impl ScriptedKeys {
        fn new(events: std::vec::Vec<InputEvent>) -> Self {
            Self { events, pos: 0 }
        }
    }
    impl KeySource for ScriptedKeys {
        fn read_key_blocking(&mut self) -> InputEvent {
            let ev = self.events.get(self.pos).copied().expect("read past scripted keystream");
            self.pos += 1;
            ev
        }
    }

    #[test]
    fn render_draws_every_word_slot() {
        let mut fb = VecFb::new(1024, 768);
        let indexes = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        render_mnemonic_display(&mut fb, &indexes, 12, "test-build");
        assert!(fb.buf.iter().any(|&p| p == WORD_STYLE.fg));
    }

    #[test]
    fn render_only_draws_count_slots_not_full_24_buffer() {
        // A 12-word display must not touch pixels belonging only to
        // slots 12..24; sanity check by rendering 12 vs 24 into
        // identically-sized buffers with the same first 12 indexes and
        // confirming the 12-word render is a strict subset in coverage
        // (fewer nonzero pixels than the 24-word render of the same
        // prefix plus 12 more real words).
        let mut fb12 = VecFb::new(1024, 768);
        let mut indexes = [0u16; 24];
        for (i, v) in indexes.iter_mut().enumerate() {
            *v = (i as u16) + 1;
        }
        render_mnemonic_display(&mut fb12, &indexes, 12, "test-build");
        let count12 = fb12.buf.iter().filter(|&&p| p != 0).count();

        let mut fb24 = VecFb::new(1024, 768);
        render_mnemonic_display(&mut fb24, &indexes, 24, "test-build");
        let count24 = fb24.buf.iter().filter(|&&p| p != 0).count();

        assert!(count24 > count12, "24-word render must draw strictly more than the 12-word render");
    }

    /// Extends the individual-per-slot rendering property this module's
    /// own doc comment asserts (SPEC §12.2: "It MUST NOT create one
    /// concatenated mnemonic string" — no function in this module ever
    /// builds or formats a joined phrase). If word text were ever routed
    /// through a concatenated/formatted string instead of per-slot
    /// `draw_word` calls, changing ONE slot's index could shift or alter
    /// pixels belonging to OTHER slots (e.g. a different word length
    /// reflowing what follows it). Rendering with only slot 5's index
    /// changed must touch pixels in slot 5's own cell only — every other
    /// slot's cell must be pixel-identical, proving each word is still
    /// drawn independently by its own fixed-grid slot, not assembled
    /// from a shared string. This assertion must survive the panel/
    /// caption restyle unweakened.
    #[test]
    fn changing_one_word_index_only_touches_that_slots_own_cell() {
        let mut indexes_a = [0u16; 12];
        for (i, v) in indexes_a.iter_mut().enumerate() {
            *v = i as u16;
        }
        let mut indexes_b = indexes_a;
        indexes_b[5] = 2000; // a maximally different word at slot 5 only

        let mut fb_a = VecFb::new(1024, 768);
        let mut fb_b = VecFb::new(1024, 768);
        render_mnemonic_display(&mut fb_a, &indexes_a, 12, "test-build");
        render_mnemonic_display(&mut fb_b, &indexes_b, 12, "test-build");

        let (cx, cy) = slot_origin(5);
        for y in 0..768u32 {
            for x in 0..1024u32 {
                let in_slot5 = (cx..cx + WORD_SLOT_CELL_W).contains(&x) && (cy..cy + WORD_SLOT_CELL_H).contains(&y);
                if in_slot5 {
                    continue;
                }
                let idx = (y as usize) * 1024 + (x as usize);
                assert_eq!(
                    fb_a.buf[idx], fb_b.buf[idx],
                    "pixel ({x},{y}) outside slot 5's cell changed when only slot 5's index changed"
                );
            }
        }
        // Sanity: slot 5's own cell DID change (the word is genuinely
        // drawn there, not skipped).
        let mut slot5_differs = false;
        for y in cy..cy + WORD_SLOT_CELL_H {
            for x in cx..cx + WORD_SLOT_CELL_W {
                let idx = (y as usize) * 1024 + (x as usize);
                if fb_a.buf[idx] != fb_b.buf[idx] {
                    slot5_differs = true;
                }
            }
        }
        assert!(slot5_differs, "sanity: slot 5's own cell must actually differ between the two renders");
    }

    /// Design doc §4 Stage 6: "word-slot panels with CAPTION indexes" —
    /// each slot's "NN. " label renders in `theme::CAPTION`, distinct
    /// from the word text's `theme::TEXT`.
    #[test]
    fn word_slot_index_labels_render_in_caption_color() {
        let mut fb = VecFb::new(1024, 768);
        let indexes = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        render_mnemonic_display(&mut fb, &indexes, 12, "test-build");
        assert!(fb.buf.iter().any(|&p| p == theme::CAPTION), "no slot label was drawn in CAPTION");
    }

    /// Design doc §4 Stage 6: "word-slot panels" — the grid draws on a
    /// `theme::PANEL` background.
    #[test]
    fn word_grid_draws_on_a_panel_background() {
        let mut fb = VecFb::new(1024, 768);
        let indexes = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        render_mnemonic_display(&mut fb, &indexes, 12, "test-build");
        assert!(fb.buf.iter().any(|&p| p == theme::PANEL), "no panel background was drawn behind the word grid");
    }

    #[test]
    fn read_display_choice_h() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Other, InputEvent::Char('h')]);
        assert_eq!(read_display_choice(&mut k), DisplayChoice::Hide);
    }

    #[test]
    fn read_display_choice_d_case_insensitive() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('D')]);
        assert_eq!(read_display_choice(&mut k), DisplayChoice::DestroyRequested);
    }

    #[test]
    fn read_destroy_double_confirm_p_powers_off() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('P')]);
        assert_eq!(read_destroy_double_confirm(&mut k), DestroyDecision::PowerOff);
    }

    #[test]
    fn read_destroy_double_confirm_m_returns_to_menu() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('m')]);
        assert_eq!(read_destroy_double_confirm(&mut k), DestroyDecision::ReturnToMenu);
    }

    #[test]
    fn read_destroy_double_confirm_n_cancels() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('n')]);
        assert_eq!(read_destroy_double_confirm(&mut k), DestroyDecision::Cancel);
    }

    #[test]
    fn read_destroy_double_confirm_ignores_bare_enter() {
        // Enter no longer destroys: an explicit [M]/[P] is required so a
        // stray Enter cannot irreversibly wipe the phrase. The Enter is
        // skipped; the following [P] is what resolves the screen.
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Enter, InputEvent::Char('p')]);
        assert_eq!(read_destroy_double_confirm(&mut k), DestroyDecision::PowerOff);
    }

    #[test]
    fn destroy_confirm_offers_both_menu_and_power_off() {
        let joined = DESTROY_CONFIRM_LINES.join("\n");
        assert!(joined.contains("[M]") && joined.to_lowercase().contains("menu"));
        assert!(joined.contains("[P]") && joined.to_lowercase().contains("power off"));
        assert!(joined.contains("[N]"));
    }

    #[test]
    fn return_notice_acknowledges_only_on_enter_and_warns_about_power_off() {
        // Copy must warn the operator to power off for maximum safety.
        let joined = DESTROYED_RETURN_NOTICE_LINES.join("\n").to_lowercase();
        assert!(joined.contains("wiped from memory"));
        assert!(joined.contains("power this machine"));
        // Only Enter advances.
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('x'), InputEvent::Enter]);
        read_return_notice_ack(&mut k); // returns iff Enter was seen
    }

    #[test]
    fn return_notice_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(640, 480);
        let far_right_row: std::vec::Vec<u32> = std::vec![0x00FF_FFFFu32; 40];
        fb.put_row(600, 0, &far_right_row);
        assert!(fb.buf.iter().any(|&p| p == 0x00FF_FFFF), "sanity: residue present");
        render_destroyed_return_notice(&mut fb);
        for x in 600..640 {
            assert_eq!(fb.buf[x as usize], 0, "residual pixel at x={x} not cleared");
        }
    }

    /// Regression test for the confirmed WP-26 finding (SPEC §12.2
    /// "Fixed layouts"): `render_destroy_confirm` must clear residual
    /// content from the prior mnemonic-display word grid before drawing
    /// its own (shorter) lines.
    #[test]
    fn render_destroy_confirm_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(640, 480);
        let far_right_row: std::vec::Vec<u32> = std::vec![0x00FF_FFFFu32; 40];
        fb.put_row(600, 0, &far_right_row);
        assert!(fb.buf.iter().any(|&p| p == 0x00FF_FFFF), "sanity: residue is present before rendering");

        render_destroy_confirm(&mut fb, "test-build");

        // Row 0 now sits inside the chrome header band (Stage-6 shell,
        // 2026-08-09): the residue must be REPLACED (scrub_fill + band
        // fill), never survive.
        for x in 600..640 {
            assert_ne!(fb.buf[x as usize], 0x00FF_FFFF, "residual prior-screen pixel at x={x} was not cleared");
        }
    }

    #[test]
    fn hide_and_destroy_prompts_present_in_source_text() {
        assert!(HIDE_PROMPT.starts_with("[H]"));
        assert!(DESTROY_PROMPT.starts_with("[D]"));
    }

    /// Design doc §4 Stage 6: the destroy-confirm screen's second
    /// confirmation renders "DANGER-styled" (SPEC §3.1: `DANGER` is
    /// "reserved exclusively for the destroy path and the fatal-failure
    /// chain"). The title row (`DESTROY_CONFIRM_LINES[0]`, the
    /// irreversibility question itself) must use `theme::DANGER`; no
    /// other row may.
    #[test]
    fn render_destroy_confirm_title_row_uses_danger_fg() {
        let mut fb = VecFb::new(800, 600);
        render_destroy_confirm(&mut fb, "test-build");

        let pitch = seed_gop_ui::layout::LINE_PITCH;
        let glyph_h = seed_gop_ui::font::GLYPH_HEIGHT;

        let band_has_danger = |y0: u32| -> bool {
            (y0..y0 + glyph_h).any(|y| (0..800u32).any(|x| fb.buf[(y as usize) * 800 + x as usize] == theme::DANGER))
        };

        // Stage-6 shell (2026-08-09): the mandated lines render inside a
        // warn panel starting one pitch below the chrome header, heading
        // first at half-pitch inset — mirror `render_destroy_confirm`'s
        // own layout.
        let heading_y = crate::chrome::content_top() + pitch + pitch / 2;
        assert!(band_has_danger(heading_y), "title row must render in DANGER");
        for i in 1..DESTROY_CONFIRM_LINES.len() as u32 {
            assert!(!band_has_danger(heading_y + i * pitch), "only the title row should render in DANGER (row {i})");
        }
    }
}
