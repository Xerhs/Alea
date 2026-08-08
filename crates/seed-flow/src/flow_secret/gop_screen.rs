//! Shared GOP text-layout helper for every screen from
//! `AppState::MnemonicDisplay` onward (SPEC §12.2: once a secret exists,
//! rendering MUST go through the application-owned bitmap-font path into
//! the linear framebuffer, never firmware text output).
//!
//! This module draws only fixed, non-secret UI copy (labels, prompts,
//! hex fingerprints, addresses, education text) with [`draw_lines`]. It
//! is never used to render the mnemonic itself — [`crate::flow_secret::display`]
//! calls `seed_gop_ui::font::draw_word` directly, per index, exactly as
//! SPEC §12.2 requires ("MUST NOT create one concatenated mnemonic
//! string").

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::draw_text;

/// Default fixed left margin, line pitch and style used by every
/// post-secret screen in this module tree — hoisted to
/// `seed_gop_ui::layout` (SPEC.md amendment 2026-08-06) so
/// `crate::output::FbTextOutput` and `seed-desktop-test`'s
/// `shared_screen::WindowTextOutput` agree with this module on the exact
/// same numbers instead of each maintaining its own copy. Re-exported
/// under their original names here so every existing `crate::
/// flow_secret::gop_screen::{MARGIN_X, LINE_PITCH, SCREEN_STYLE}` import
/// in this module tree (`display.rs` in particular, which re-exports
/// `SCREEN_STYLE` again as `WORD_STYLE`) keeps working unchanged.
pub use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X, SCREEN_STYLE};

/// Draw `lines` top-to-bottom starting at `(MARGIN_X, MARGIN_X)`, one
/// call to [`draw_text`] per line, [`LINE_PITCH`] pixels apart. Does not
/// clear the framebuffer first — callers that need a fresh screen call
/// `seed_gop_ui::font::scrub_fill` (or the full SPEC §12.4
/// `seed_gop_ui::gop::scrub_sequence`) themselves before drawing, exactly
/// like every other screen-transition scrub in this crate.
pub fn draw_lines(fb: &mut dyn Framebuffer, lines: &[&str]) {
    let mut y = MARGIN_X;
    for line in lines {
        draw_text(fb, MARGIN_X, y, line, SCREEN_STYLE);
        y += LINE_PITCH;
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

    #[test]
    fn draw_lines_places_each_line_at_a_distinct_row() {
        let mut fb = VecFb::new(800, 600);
        draw_lines(&mut fb, &["one", "two"]);
        assert!(fb.buf.iter().any(|&p| p == SCREEN_STYLE.fg));
    }

    #[test]
    fn draw_lines_empty_slice_draws_nothing_and_does_not_panic() {
        let mut fb = VecFb::new(80, 60);
        draw_lines(&mut fb, &[]);
        assert!(fb.buf.iter().all(|&p| p == 0));
    }
}
