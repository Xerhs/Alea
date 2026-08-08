//! Stage-7 Finish screen (design doc §4 "Stage 7 — VERIFY & FINISH":
//! "`[Enter] Finish` -> final screen: `RE-ENTRY MATCHED` heading + the
//! completion-education reminders ... -> `[Enter] Shut down` -> scrub
//! chain, byte-for-byte unchanged").
//!
//! This screen absorbs the SPEC §23.3 completion-education screen: its
//! *display* is SPEC-mandated, its dedicated screen is not. Every line of
//! that content is referenced from [`crate::flow_secret::education`]
//! rather than restated here, so the two can never drift and
//! `education.rs`'s own topic-coverage and no-false-claim tests keep
//! covering the copy this screen draws.
//!
//! Nothing on this screen is derived from, or can reach, secret material:
//! it draws four `&'static str` sets and nothing else. It is also the
//! last screen before the §26 scrub-and-shutdown chain, which this module
//! does not touch — the driver owns that edge.

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text_scaled, GLYPH_HEIGHT};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::theme;
use seed_platform_x86::input::InputEvent;

use crate::chrome::{self, Chrome, KeyHint};
use crate::flow_secret::education::{HEADER, MATCHED_LINE, REMINDER_LINES};

/// 1-based ceremony stage this screen belongs to (design doc §4: Finish
/// is the second of Stage 7's two screens).
pub const STAGE: u8 = 7;

/// The two ways to leave the finished ceremony (design doc §4 "`[Enter]
/// Shut down`", extended by the SPEC §26 amendment 2026-08-08 with a
/// wipe-and-return-to-menu alternative). Both run the identical SPEC §26
/// scrub first; only what follows differs.
pub const HINTS: [KeyHint; 2] = [
    KeyHint { key: "Enter", label: "Power off", enabled: true, danger: false },
    KeyHint { key: "M", label: "Wipe & menu", enabled: true, danger: false },
];

/// Height of one 2x heading row: the 2x glyph box plus the leading a 1x
/// row already carries, so both scales share one vertical rhythm.
const ROW_2X: u32 = GLYPH_HEIGHT * 2 + (LINE_PITCH - GLYPH_HEIGHT);

/// Height of a blank separator row.
const GAP: u32 = LINE_PITCH / 2;

/// How the operator chose to leave the finished ceremony. Both wipe every
/// secret via the SPEC §26 scrub; they differ only in what follows (SPEC
/// §26 amendment 2026-08-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishChoice {
    /// `[Enter]` — scrub, then power the machine off (RAM decays; safest).
    PowerOff,
    /// `[M]` — scrub, then return to the launcher main menu.
    ReturnToMenu,
}

/// Map a keystroke on the Finish screen to a [`FinishChoice`], or `None`
/// for any other key. Every other key is ignored (the same discipline
/// `flow_secret::verification::read_acknowledged` applies), so no stray
/// keystroke can shortcut into the scrub chain — only these two do.
#[must_use]
pub fn finish_choice(k: InputEvent) -> Option<FinishChoice> {
    match k {
        InputEvent::Enter => Some(FinishChoice::PowerOff),
        InputEvent::Char(c) if c.eq_ignore_ascii_case(&'m') => Some(FinishChoice::ReturnToMenu),
        _ => None,
    }
}

/// Render the Finish screen: chrome shell, the `RE-ENTRY MATCHED`
/// heading (2x, [`theme::OK`]), the SPEC §23.3 matched line and reminder
/// lines, and the single-hint footer.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this screen
/// follows the Verify screen, whose (differently laid out) content would
/// otherwise show through.
pub fn render(fb: &mut dyn Framebuffer, build: &'static str) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    chrome::draw_header(fb, &Chrome { stage: STAGE, sub: None, build });
    draw_content(fb);
    chrome::draw_footer(fb, &HINTS);
}

/// Draw this screen's content rows from [`chrome::content_top`]
/// downwards, returning the y pixel row immediately below the last one.
///
/// The fit audit calls exactly this function and checks its return value,
/// so the budget the test measures is the budget that ships: there is no
/// mirrored copy of the layout arithmetic to drift out of step, and no
/// `debug_assert` panic path in a firmware render routine.
fn draw_content(fb: &mut dyn Framebuffer) -> u32 {
    let mut y = chrome::content_top();
    draw_text_scaled(fb, MARGIN_X, y, HEADER, theme::on_bg(theme::OK), 2);
    y += ROW_2X;
    draw_text_scaled(fb, MARGIN_X, y, MATCHED_LINE, theme::on_bg(theme::TEXT), 1);
    y += LINE_PITCH + GAP;
    for line in REMINDER_LINES {
        draw_text_scaled(fb, MARGIN_X, y, line, theme::on_bg(theme::CAPTION), 1);
        y += LINE_PITCH;
    }
    y
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::string::{String, ToString};
    use std::vec::Vec;

    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};
    use seed_gop_ui::layout::MAX_COLS_AT_FLOOR;

    const BUILD: &str = "test-build";

    struct VecFb {
        w: u32,
        h: u32,
        buf: Vec<u32>,
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
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + px.len()].copy_from_slice(px);
        }
    }

    /// Every string this screen draws, in draw order.
    fn screen_lines() -> Vec<String> {
        let mut out = std::vec![HEADER.to_string(), MATCHED_LINE.to_string()];
        out.extend(REMINDER_LINES.iter().map(|l| l.to_string()));
        out
    }

    #[test]
    fn finish_screen_carries_the_completion_education_reminders() {
        let joined = screen_lines().join("\n");
        assert!(joined.contains(HEADER), "RE-ENTRY MATCHED heading missing");
        assert_eq!(HEADER, "RE-ENTRY MATCHED");
        for reminder in REMINDER_LINES {
            assert!(joined.contains(reminder), "reminder {reminder:?} missing");
        }
        // The SPEC §23.3 topics survive the screen merge.
        let lower = joined.to_lowercase();
        for topic in [
            "memorized",
            "responsibility",
            "signing device",
            "independently confirm",
            "small test amount",
        ] {
            assert!(lower.contains(topic), "required topic {topic:?} missing");
        }
    }

    #[test]
    fn footer_offers_power_off_and_menu() {
        assert_eq!(HINTS.len(), 2);
        assert_eq!(std::format!("[{}] {}", HINTS[0].key, HINTS[0].label), "[Enter] Power off");
        assert_eq!(std::format!("[{}] {}", HINTS[1].key, HINTS[1].label), "[M] Wipe & menu");
    }

    #[test]
    fn enter_powers_off_and_m_returns_to_menu() {
        assert_eq!(finish_choice(InputEvent::Enter), Some(FinishChoice::PowerOff));
        assert_eq!(finish_choice(InputEvent::Char('m')), Some(FinishChoice::ReturnToMenu));
        assert_eq!(finish_choice(InputEvent::Char('M')), Some(FinishChoice::ReturnToMenu));
    }

    #[test]
    fn other_keys_do_not_leave_the_finish_screen() {
        for k in [
            InputEvent::Other,
            InputEvent::Escape,
            InputEvent::Backspace,
            InputEvent::Char('x'),
        ] {
            assert_eq!(finish_choice(k), None, "{k:?} must not leave the screen");
        }
    }

    #[test]
    fn never_mentions_xpub_xprv_or_seed() {
        let forbidden = ["xpub", "xprv", "private key", "chain code", "pubkey", "seed"];
        let mut all = screen_lines();
        all.push(HINTS[0].key.to_string());
        all.push(HINTS[0].label.to_string());
        for line in &all {
            let lower = line.to_lowercase();
            for bad in forbidden {
                assert!(!lower.contains(bad), "line {line:?} must never mention {bad:?}");
            }
        }
    }

    #[test]
    fn all_copy_is_printable_ascii_and_fits_the_floor() {
        let mut all = screen_lines();
        all.push(HINTS[0].label.to_string());
        for line in &all {
            for ch in line.chars() {
                assert!(
                    (' '..='~').contains(&ch),
                    "line {line:?} has non-renderable character {ch:?}"
                );
            }
        }
        // The heading draws at 2x, everything else at 1x.
        assert!(HEADER.chars().count() * 2 <= MAX_COLS_AT_FLOOR);
        for line in screen_lines().iter().skip(1) {
            assert!(
                line.chars().count() <= MAX_COLS_AT_FLOOR,
                "line {line:?} exceeds the {MAX_COLS_AT_FLOOR}-col floor"
            );
        }
    }

    #[test]
    fn content_fits_between_the_chrome_bands() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let end = draw_content(&mut fb);
        assert!(
            end <= chrome::content_bottom(),
            "content ends at y={end}, footer starts at {}",
            chrome::content_bottom()
        );
    }

    #[test]
    fn render_draws_the_shell_and_the_heading_in_ok() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, BUILD);
        assert!(fb.contains(theme::OK), "heading must render in the OK role");
        assert!(fb.contains(theme::PANEL), "chrome bands must render");
        assert!(fb.contains(theme::ACCENT), "footer key glyphs must render");
        assert!(fb.contains(theme::CAPTION), "reminder lines must render");
    }

    #[test]
    fn render_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let residue: Vec<u32> = std::vec![theme::WATERMARK.fg; 40];
        let mid = MIN_HEIGHT / 2;
        fb.put_row(MIN_WIDTH - 40, mid, &residue);
        assert!(fb.contains(theme::WATERMARK.fg), "sanity: residue present");

        render(&mut fb, BUILD);
        for x in (MIN_WIDTH - 40)..MIN_WIDTH {
            assert_eq!(
                fb.buf[(mid as usize) * (MIN_WIDTH as usize) + (x as usize)],
                theme::BG,
                "residual pixel at x={x} was not cleared"
            );
        }
    }
}
