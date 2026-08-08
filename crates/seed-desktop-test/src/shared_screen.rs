//! The desktop `Framebuffer` backend (SPEC §12.2) plus a `TextOutput`
//! adapter over the exact same pixel storage (SPEC §12.1), so every
//! pre-secret text screen and every post-secret GOP-style screen render
//! into one shared buffer that `crate::window`'s presentation loop then
//! composites onto the real OS window every frame — see that module's
//! doc comment for why the SPEC §4.3 permanent watermark lives there
//! (compositing time), not here.
//!
//! `SharedFramebuffer` is an `Arc<Mutex<..>>` handle rather than an owned
//! buffer specifically so the worker thread that drives the whole
//! ceremony (`crate::ceremony`, `crate::window`) and the main thread that
//! owns the actual OS window and `softbuffer` surface can each hold their
//! own cheap clone of the same underlying pixels: the worker thread only
//! ever writes (`Framebuffer::put_row`/`dims`), the main thread only ever
//! reads (to composite + present), and `Mutex` makes the interleaving
//! safe without either thread blocking the other for more than a
//! `memcpy`.

use std::sync::{Arc, Mutex};

use seed_core::contracts::Framebuffer;
use seed_flow::output::TextOutput;
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X, SCREEN_STYLE as TEXT_STYLE};

/// Logical (pre-watermark) canvas size every screen in this rehearsal
/// renders into — generous enough for the widest fixed layout
/// (`seed_gop_ui::font`'s 24-word slot grid, and every pre-secret text
/// screen's longest line) with comfortable margin. `crate::window` adds
/// its own fixed watermark bands above and below this canvas when sizing
/// the real OS window.
pub const CANVAS_WIDTH: u32 = 1024;
pub const CANVAS_HEIGHT: u32 = 768;

/// A cloneable handle to one shared pixel buffer (SPEC §12.2). Every
/// clone refers to the same underlying storage.
#[derive(Clone)]
pub struct SharedFramebuffer {
    width: u32,
    height: u32,
    buf: Arc<Mutex<Vec<u32>>>,
}

impl SharedFramebuffer {
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height, buf: Arc::new(Mutex::new(vec![0u32; (width as usize) * (height as usize)])) }
    }

    /// Copy the current pixel contents out (used by `crate::window`'s
    /// per-frame presentation step; never by ceremony logic itself).
    #[must_use]
    pub fn snapshot(&self) -> Vec<u32> {
        self.buf.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

impl Framebuffer for SharedFramebuffer {
    fn dims(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        if y >= self.height || x >= self.width {
            return;
        }
        let visible = core::cmp::min(px.len(), (self.width - x) as usize);
        if visible == 0 {
            return;
        }
        let mut guard = self.buf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let start = (y as usize) * (self.width as usize) + (x as usize);
        guard[start..start + visible].copy_from_slice(&px[..visible]);
    }
}

/// SPEC §12.1 `TextOutput` implementation for the desktop rehearsal:
/// every "firmware text console" line WP-25's pre-secret screens write is
/// instead rendered, one full-screen redraw per call (this UI is small
/// and not performance-sensitive), into the same [`SharedFramebuffer`]
/// every post-secret GOP screen uses — there is no separate text console
/// on a desktop OS, only this one window.
pub struct WindowTextOutput {
    fb: SharedFramebuffer,
    lines: Vec<String>,
}

impl WindowTextOutput {
    #[must_use]
    pub fn new(fb: SharedFramebuffer) -> Self {
        Self { fb, lines: Vec::new() }
    }

    fn redraw(&mut self) {
        seed_gop_ui::font::scrub_fill(&mut self.fb, 0);
        let mut y = MARGIN_X;
        for line in &self.lines {
            seed_gop_ui::font::draw_text(&mut self.fb, MARGIN_X, y, line, TEXT_STYLE);
            y += LINE_PITCH;
        }
    }
}

impl TextOutput for WindowTextOutput {
    fn write_line(&mut self, line: &str) {
        self.lines.push(line.to_string());
        self.redraw();
    }

    fn clear(&mut self) {
        self.lines.clear();
        self.redraw();
    }
}

/// 2026-08-07 ceremony redesign: the same shared pixel storage, handed to
/// `seed_flow::screens::*`, which draw full chrome-shell layouts rather
/// than lines of text.
///
/// The accumulated line list is dropped first: a screen drawn through this
/// view owns every pixel it needs, and a later [`TextOutput::write_line`]
/// must not re-composite text screens that are no longer on screen over
/// the top of it. Dropping the lines here makes the next text screen start
/// from a blank surface exactly as [`TextOutput::clear`] does — the
/// contract `seed_flow::output::FlowSurface` states.
impl seed_flow::output::FlowSurface for WindowTextOutput {
    fn framebuffer(&mut self) -> &mut dyn Framebuffer {
        self.lines.clear();
        &mut self.fb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_framebuffer_put_row_writes_expected_pixels() {
        let mut fb = SharedFramebuffer::new(8, 4);
        fb.put_row(2, 1, &[1, 2, 3]);
        let snap = fb.snapshot();
        assert_eq!(snap[1 * 8 + 2], 1);
        assert_eq!(snap[1 * 8 + 3], 2);
        assert_eq!(snap[1 * 8 + 4], 3);
    }

    #[test]
    fn shared_framebuffer_put_row_clips_without_panicking() {
        let mut fb = SharedFramebuffer::new(4, 4);
        fb.put_row(2, 0, &[9, 9, 9, 9]); // only 2 columns actually fit
        fb.put_row(100, 0, &[1]); // fully off-screen
        fb.put_row(0, 100, &[1]); // fully off-screen (row)
        let snap = fb.snapshot();
        assert_eq!(snap[2], 9);
        assert_eq!(snap[3], 9);
    }

    #[test]
    fn clone_shares_the_same_underlying_pixels() {
        let fb_a = SharedFramebuffer::new(4, 4);
        let mut fb_b = fb_a.clone();
        fb_b.put_row(0, 0, &[42]);
        assert_eq!(fb_a.snapshot()[0], 42);
    }

    #[test]
    fn window_text_output_write_line_renders_something() {
        let fb = SharedFramebuffer::new(200, 100);
        let mut out = WindowTextOutput::new(fb.clone());
        out.write_line("hello");
        assert!(fb.snapshot().iter().any(|&p| p == TEXT_STYLE.fg));
    }

    #[test]
    fn window_text_output_clear_blanks_the_screen() {
        let fb = SharedFramebuffer::new(200, 100);
        let mut out = WindowTextOutput::new(fb.clone());
        out.write_line("hello");
        out.clear();
        assert!(fb.snapshot().iter().all(|&p| p == 0));
    }
}
