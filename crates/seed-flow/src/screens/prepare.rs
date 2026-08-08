//! Stage 1 — Prepare screen (design doc §4 Stage 1,
//! `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md`):
//! folds the old SPEC §22.1 opening warning and the three SPEC §22.2
//! environment acknowledgements into one screen — the §22.1 warning body
//! shown once, then the three commitments as a checklist, each requiring
//! its own distinct keypress (SPEC amendment §22.2: "three
//! acknowledgements, each requiring a distinct confirmation keypress" —
//! the screen count is not load-bearing, the "no single keypress
//! acknowledges everything" security intent is).
//!
//! [`WARNING_BODY`] is the single source for the SPEC §22.1 warning body
//! text — moved here from `crate::text` (which used to define its own
//! `OPENING_BODY` const with the identical string data). `crate::text`
//! now re-exports this same constant under its old name so the
//! pre-redesign `render_opening_warning` call site is unaffected.

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text, draw_text_scaled, scrub_fill, GLYPH_HEIGHT, GLYPH_WIDTH};
use seed_gop_ui::layout::{MARGIN_X, MAX_COLS_AT_FLOOR};
use seed_gop_ui::{panel, theme};

use crate::chrome::{content_top, draw_footer, draw_header, Chrome, KeyHint};
use crate::keys::MenuKey;

/// SPEC §22.1 warning body, verbatim (single source — see the module doc
/// comment for the `crate::text::OPENING_BODY` re-export).
pub const WARNING_BODY: &[&str] = &[
    "This application generates BIP39 recovery words before your normal",
    "operating system loads.",
    "",
    "It cannot prove that your firmware, processor, memory, keyboard,",
    "display path or physical environment are trustworthy.",
];

/// Screen title (design doc §4 Stage 1 mockup: "Before we begin").
pub const TITLE: &str = "Before we begin";

/// The three SPEC §22.2 commitments, folded into this one screen's
/// checklist, verbatim from the mockup.
pub const ITEMS: [&str; 3] = [
    "1  I verified this release's hash against a second source",
    "2  This machine is offline - no network cable, no radios, no USB storage",
    "3  No cameras, windows, or other people face this screen",
];

/// Result of [`PrepareState::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareOutcome {
    /// All three commitments are checked and Enter was pressed.
    Continue,
    /// Escape was pressed.
    Exit,
}

/// Stage 1 screen state: which of the three commitments the user has
/// checked so far.
pub struct PrepareState {
    checked: [bool; 3],
}

impl PrepareState {
    /// A fresh screen: nothing checked.
    pub fn new() -> Self {
        Self { checked: [false; 3] }
    }

    /// Have all three commitments been checked?
    pub fn all_checked(&self) -> bool {
        self.checked.iter().all(|&c| c)
    }

    /// Handle one keystroke. `'1'`/`'2'`/`'3'` each toggle their own
    /// commitment (a repeat of the SAME key toggles the SAME item back
    /// off — key-repeat of one key can never check all three). `Enter`
    /// only yields [`PrepareOutcome::Continue`] once [`Self::all_checked`]
    /// is true; otherwise it (like every other unrecognized key) yields
    /// `None` and leaves state unchanged. `Escape` always yields
    /// [`PrepareOutcome::Exit`].
    pub fn handle_key(&mut self, k: MenuKey) -> Option<PrepareOutcome> {
        match k {
            MenuKey::Char('1') => {
                self.checked[0] = !self.checked[0];
                None
            }
            MenuKey::Char('2') => {
                self.checked[1] = !self.checked[1];
                None
            }
            MenuKey::Char('3') => {
                self.checked[2] = !self.checked[2];
                None
            }
            MenuKey::Enter if self.all_checked() => Some(PrepareOutcome::Continue),
            MenuKey::Escape => Some(PrepareOutcome::Exit),
            _ => None,
        }
    }
}

impl Default for PrepareState {
    fn default() -> Self {
        Self::new()
    }
}

/// Gap (in glyph cells) between a checkbox's `"[x]"`/`"[ ]"` glyphs and
/// the item text that follows it: 3 glyphs for the checkbox itself, 1
/// blank cell of breathing room.
const CHECKBOX_TEXT_GAP: u32 = GLYPH_WIDTH * 4;

/// Footer key hints (design doc §4 Stage 1): `[1] [2] [3] Confirm each`
/// is built as a single [`KeyHint`] whose `key` field is the literal
/// `"1] [2] [3"` -- `chrome::draw_footer` always wraps a hint's `key` in
/// `"[...]"`, so this yields exactly the mockup's `"[1] [2] [3]"` without
/// `chrome` needing a second, multi-key hint shape. `[Enter] Begin` is
/// enabled only once every commitment is checked (disabled label per the
/// brief); `[Esc] Exit` is always available.
fn footer_hints(st: &PrepareState) -> [KeyHint; 3] {
    let all = st.all_checked();
    [
        KeyHint {
            key: "1] [2] [3",
            label: "Confirm each",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "Enter",
            label: if all { "Begin" } else { "Begin - confirm all three first" },
            enabled: all,
            danger: false,
        },
        KeyHint {
            key: "Esc",
            label: "Exit",
            enabled: true,
            danger: false,
        },
    ]
}

/// Render the Stage 1 Prepare screen: [`crate::chrome`] header/footer,
/// the 2x-scale [`TITLE`], the [`WARNING_BODY`] in a
/// [`panel::warn_panel`], then the three [`ITEMS`] as
/// [`panel::checkbox`] rows reflecting `st`.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this is the
/// first ceremony screen, drawn over whatever the edition's startup banner
/// and landing launcher left on the framebuffer, which would otherwise
/// bleed through around this screen's content.
pub fn render(fb: &mut dyn Framebuffer, st: &PrepareState, build: &'static str) {
    scrub_fill(fb, theme::BG);
    draw_header(
        fb,
        &Chrome {
            stage: 1,
            sub: None,
            build,
        },
    );
    draw_footer(fb, &footer_hints(st));

    let line_pitch = seed_gop_ui::layout::LINE_PITCH;
    let mut y = content_top();

    draw_text_scaled(fb, MARGIN_X, y, TITLE, theme::on_bg(theme::TEXT), 2);
    y += GLYPH_HEIGHT * 2 + line_pitch;

    let panel_w = (MAX_COLS_AT_FLOOR as u32) * GLYPH_WIDTH;
    let panel_h = (WARNING_BODY.len() as u32) * line_pitch + line_pitch / 2;
    panel::warn_panel(fb, MARGIN_X, y, panel_w, panel_h);
    let mut line_y = y + line_pitch / 4;
    for line in WARNING_BODY {
        draw_text(fb, MARGIN_X + GLYPH_WIDTH, line_y, line, theme::on_panel(theme::TEXT));
        line_y += line_pitch;
    }
    y += panel_h + line_pitch;

    for (i, item) in ITEMS.iter().enumerate() {
        panel::checkbox(fb, MARGIN_X, y, st.checked[i]);
        draw_text(fb, MARGIN_X + CHECKBOX_TEXT_GAP, y, item, theme::on_bg(theme::TEXT));
        y += line_pitch;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};

    /// Host-only `Vec<u32>` `Framebuffer` test double -- this module's own
    /// local copy (the pattern used throughout `seed-gop-ui`/`seed-flow`
    /// tests, since each crate/module's existing double is private).
    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }

    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self {
                w,
                h,
                buf: std::vec![0u32; (w as usize) * (h as usize)],
            }
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

    // -- PrepareState::handle_key ----------------------------------------

    #[test]
    fn enter_before_all_checked_returns_none_and_leaves_state_unchanged() {
        let mut st = PrepareState::new();
        st.checked = [true, true, false];
        let outcome = st.handle_key(MenuKey::Enter);
        assert_eq!(outcome, None);
        assert_eq!(st.checked, [true, true, false]);
    }

    #[test]
    fn same_key_pressed_twice_toggles_that_item_back_off() {
        let mut st = PrepareState::new();
        assert_eq!(st.handle_key(MenuKey::Char('1')), None);
        assert!(st.checked[0]);
        assert_eq!(st.handle_key(MenuKey::Char('1')), None);
        assert!(!st.checked[0]);
    }

    #[test]
    fn all_three_distinct_keys_then_enter_yields_continue() {
        let mut st = PrepareState::new();
        assert_eq!(st.handle_key(MenuKey::Char('1')), None);
        assert_eq!(st.handle_key(MenuKey::Char('2')), None);
        assert_eq!(st.handle_key(MenuKey::Char('3')), None);
        assert!(st.all_checked());
        assert_eq!(st.handle_key(MenuKey::Enter), Some(PrepareOutcome::Continue));
    }

    #[test]
    fn escape_always_yields_exit() {
        let mut st = PrepareState::new();
        assert_eq!(st.handle_key(MenuKey::Escape), Some(PrepareOutcome::Exit));
    }

    /// Multi-keypress arming (brief): key-repeat of a single key must not
    /// be able to check all three -- each of `[1]`/`[2]`/`[3]` must be a
    /// genuinely distinct keypress.
    #[test]
    fn key_repeat_of_a_single_key_cannot_check_all_three() {
        let mut st = PrepareState::new();
        for _ in 0..7 {
            st.handle_key(MenuKey::Char('1'));
        }
        assert!(!st.all_checked());
        assert!(!st.checked[1]);
        assert!(!st.checked[2]);
        assert_eq!(st.handle_key(MenuKey::Enter), None);
    }

    #[test]
    fn unrecognized_key_is_ignored() {
        let mut st = PrepareState::new();
        assert_eq!(st.handle_key(MenuKey::Other), None);
        assert_eq!(st.checked, [false, false, false]);
    }

    // -- copy content -------------------------------------------------------

    #[test]
    fn items_are_the_verbatim_commitment_strings() {
        assert_eq!(ITEMS[0], "1  I verified this release's hash against a second source");
        assert_eq!(
            ITEMS[1],
            "2  This machine is offline - no network cable, no radios, no USB storage"
        );
        assert_eq!(ITEMS[2], "3  No cameras, windows, or other people face this screen");
    }

    /// SPEC §12.2/§20-style hygiene: this pre-secret screen must never
    /// carry any leaked key-material vocabulary, even accidentally.
    #[test]
    fn no_banned_leak_strings_anywhere_in_screen_text() {
        const BANNED: [&str; 5] = ["xprv", "private key", "chain code", "pubkey", "xpub"];
        let mut lines: std::vec::Vec<&str> = std::vec![TITLE];
        lines.extend_from_slice(WARNING_BODY);
        lines.extend_from_slice(&ITEMS);
        for line in &lines {
            let lower = line.to_lowercase();
            for banned in BANNED {
                assert!(!lower.contains(banned), "banned leak string {banned:?} found in {line:?}");
            }
        }
    }

    // -- render ---------------------------------------------------------------

    /// SPEC §12.2 "Fixed layouts" — CRITICAL bleed-through regression.
    /// Stage 1 is drawn straight over whatever the edition's startup banner
    /// and landing launcher left on the framebuffer. Before the fix this
    /// screen did not clear, so banner text composited through around its
    /// (much shorter) content.
    ///
    /// Simulated with the REAL banner path — `FbTextOutput` writing lines
    /// onto the same buffer, exactly as `print_banner` does — and asserted
    /// exactly: rendering Stage 1 over the banner must produce a
    /// pixel-for-pixel identical framebuffer to rendering it on a blank one.
    /// That is the whole property ("no stale content survives") and it
    /// cannot be satisfied by anything except clearing first.
    #[test]
    fn stage_one_clears_the_startup_banner_instead_of_letting_it_bleed_through() {
        let mut dirty = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        {
            use crate::output::TextOutput as _;
            let mut banner = crate::output::FbTextOutput::new(&mut dirty);
            // Long enough to reach well below Stage 1's own content.
            for _ in 0..24 {
                banner.write_line("ALEA EXPERIMENTAL SECURITY SOFTWARE -- BUILD 0123456789abcdef");
            }
        }
        assert!(
            dirty.buf.iter().any(|&p| p != 0),
            "sanity: the simulated banner must have drawn something"
        );

        let mut clean = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut dirty, &PrepareState::new(), "build-1");
        render(&mut clean, &PrepareState::new(), "build-1");

        assert!(
            dirty.buf == clean.buf,
            "the Stage-1 Prepare screen must clear the startup banner, not composite over it"
        );
    }

    #[test]
    fn render_does_not_panic_at_floor_resolution() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st = PrepareState::new();
        render(&mut fb, &st, "build-1");
    }

    #[test]
    fn render_shows_ok_glyph_color_when_an_item_is_checked() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let mut st = PrepareState::new();
        st.handle_key(MenuKey::Char('1'));
        render(&mut fb, &st, "build-1");
        assert!(fb.buf.iter().any(|&p| p == theme::OK));
    }

    #[test]
    fn render_shows_no_ok_glyph_color_when_nothing_is_checked() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st = PrepareState::new();
        render(&mut fb, &st, "build-1");
        assert!(!fb.buf.iter().any(|&p| p == theme::OK));
    }

    /// The disabled `[Enter] Begin` footer hint must render in
    /// `ACCENT_DIM` (brief requirement); once all three are checked it
    /// must not.
    #[test]
    fn disabled_begin_hint_uses_accent_dim_enabled_does_not() {
        let mut fb_disabled = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let st_disabled = PrepareState::new();
        render(&mut fb_disabled, &st_disabled, "build-1");
        assert!(
            fb_disabled.buf.iter().any(|&p| p == theme::ACCENT_DIM),
            "disabled Begin hint must render in ACCENT_DIM"
        );

        let mut fb_enabled = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let mut st_enabled = PrepareState::new();
        st_enabled.handle_key(MenuKey::Char('1'));
        st_enabled.handle_key(MenuKey::Char('2'));
        st_enabled.handle_key(MenuKey::Char('3'));
        render(&mut fb_enabled, &st_enabled, "build-1");
        assert!(
            !fb_enabled.buf.iter().any(|&p| p == theme::ACCENT_DIM),
            "enabled Begin hint must not render in ACCENT_DIM"
        );
    }
}
