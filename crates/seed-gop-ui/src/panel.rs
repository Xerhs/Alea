//! Panel/rule/checkbox rendering primitives (SPEC §3.1 role-palette
//! layout building blocks). Built directly over
//! [`seed_core::contracts::Framebuffer::put_row`] with a fixed on-stack
//! row buffer -- no allocation -- and the same edge-clipping discipline
//! as [`crate::font::draw_glyph`]: any geometry (zero width/height,
//! fully off-screen `x`/`y`, a rect that only partially overlaps the
//! framebuffer) is clipped silently, never panics.
//!
//! Colors are named roles only ([`crate::theme`]) -- enforced workspace-
//! wide by the `no_raw_colors` host test.

use seed_core::contracts::Framebuffer;

use crate::font::draw_text;
use crate::theme;

/// Row buffer chunk size for [`fill_rect`], matching
/// [`crate::font::scrub_fill`]'s fixed on-stack buffer discipline.
const ROW_CHUNK: usize = 256;

/// Fill the `w`x`h` rectangle whose top-left corner is `(x, y)` with a
/// flat `color`, clipped to the framebuffer's actual dimensions.
///
/// Zero `w`/`h`, and a rect fully or partially off either edge, are all
/// handled without panicking: the drawn region is simply the
/// intersection of the requested rect with `(0, 0)..fb.dims()`. Uses a
/// fixed `[u32; 256]` row buffer emitted in chunks -- no allocation, no
/// per-pixel `put_row` calls.
pub fn fill_rect(fb: &mut dyn Framebuffer, x: u32, y: u32, w: u32, h: u32, color: u32) {
    if w == 0 || h == 0 {
        return;
    }
    let (fb_w, fb_h) = fb.dims();
    if x >= fb_w || y >= fb_h {
        return;
    }
    // Clip to the framebuffer edges exactly once, like `draw_glyph`'s
    // `visible_w` computation -- both bounds are known up front here
    // since a flat fill (unlike a glyph) has no per-row shape.
    let visible_w = core::cmp::min(w, fb_w - x);
    let visible_h = core::cmp::min(h, fb_h - y);

    let mut row = [0u32; ROW_CHUNK];
    for px in row.iter_mut() {
        *px = color;
    }

    for row_y in y..y + visible_h {
        let end = x + visible_w;
        let mut cx = x;
        while cx < end {
            let n = core::cmp::min(ROW_CHUNK as u32, end - cx) as usize;
            fb.put_row(cx, row_y, &row[..n]);
            cx += n as u32;
        }
    }
}

/// Draw a single 1px-tall horizontal rule at `(x, y)`, `w` pixels wide,
/// in the [`theme::RULE`] role.
pub fn hrule(fb: &mut dyn Framebuffer, x: u32, y: u32, w: u32) {
    fill_rect(fb, x, y, w, 1, theme::RULE);
}

/// Shared implementation for [`panel`]/[`warn_panel`]: a [`theme::PANEL`]
/// fill with a 1px border in `border_color` drawn on top (so the border
/// always wins at the four edge pixels, even for a 1-wide or 1-tall
/// panel where top/bottom or left/right borders coincide).
fn draw_panel(fb: &mut dyn Framebuffer, x: u32, y: u32, w: u32, h: u32, border_color: u32) {
    fill_rect(fb, x, y, w, h, theme::PANEL);
    if w == 0 || h == 0 {
        // Nothing to border -- and computing `x + w - 1`/`y + h - 1`
        // below would underflow for a zero-size panel.
        return;
    }
    let x1 = x.saturating_add(w).saturating_sub(1);
    let y1 = y.saturating_add(h).saturating_sub(1);
    fill_rect(fb, x, y, w, 1, border_color); // top
    fill_rect(fb, x, y1, w, 1, border_color); // bottom
    fill_rect(fb, x, y, 1, h, border_color); // left
    fill_rect(fb, x1, y, 1, h, border_color); // right
}

/// A `w`x`h` panel at `(x, y)`: [`theme::PANEL`] fill, 1px
/// [`theme::RULE`]-colored border (SPEC §3.1 panel styling).
pub fn panel(fb: &mut dyn Framebuffer, x: u32, y: u32, w: u32, h: u32) {
    draw_panel(fb, x, y, w, h, theme::RULE);
}

/// A `w`x`h` panel at `(x, y)` like [`panel`], but with a
/// [`theme::WARN`]-colored border instead of [`theme::RULE`] (SPEC §3.1:
/// irreversibility/warning notices).
pub fn warn_panel(fb: &mut dyn Framebuffer, x: u32, y: u32, w: u32, h: u32) {
    draw_panel(fb, x, y, w, h, theme::WARN);
}

/// Draw a checkbox glyph at `(x, y)`: `"[x]"` in [`theme::OK`] when
/// `checked`, `"[ ]"` in [`theme::CAPTION`] otherwise, both on
/// [`theme::BG`] (SPEC §3.1: `CAPTION` for de-emphasized/unset state,
/// `OK` for a confirmed/checked state).
pub fn checkbox(fb: &mut dyn Framebuffer, x: u32, y: u32, checked: bool) {
    let (glyphs, fg) = if checked {
        ("[x]", theme::OK)
    } else {
        ("[ ]", theme::CAPTION)
    };
    draw_text(fb, x, y, glyphs, theme::on_bg(fg));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::font::{GLYPH_HEIGHT, GLYPH_WIDTH};

    /// Host-only `Vec<u32>` `Framebuffer` test double, same pattern as
    /// `font::tests::VecFb` (this module's own copy, since that one is
    /// private to `font`).
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

        fn at(&self, x: u32, y: u32) -> u32 {
            self.buf[(y as usize) * (self.w as usize) + (x as usize)]
        }
    }

    impl Framebuffer for VecFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            assert!(y < self.h, "put_row y out of bounds");
            assert!(x + px.len() as u32 <= self.w, "put_row x run out of bounds");
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + px.len()].copy_from_slice(px);
        }
    }

    // -- fill_rect ----------------------------------------------------

    /// A 10x10 fill positioned so only its bottom-right 7x7 corner
    /// overlaps the framebuffer must paint exactly 49 pixels, all
    /// `color`, and nothing outside that 7x7 region.
    #[test]
    fn fill_rect_clips_10x10_at_corner_to_7x7() {
        let mut fb = VecFb::new(20, 20);
        let color = theme::ACCENT;
        // Positioned so exactly 7 columns/rows (of the requested 10)
        // land inside the 20x20 framebuffer before running off the
        // right/bottom edge.
        fill_rect(&mut fb, 13, 13, 10, 10, color);

        let mut painted = 0u32;
        for py in 0..20u32 {
            for px in 0..20u32 {
                let in_region = px >= 13 && px < 20 && py >= 13 && py < 20;
                let want = if in_region { color } else { 0 };
                assert_eq!(fb.at(px, py), want, "mismatch at ({px},{py})");
                if fb.at(px, py) == color {
                    painted += 1;
                }
            }
        }
        assert_eq!(painted, 49, "expected exactly 7x7 = 49 colored pixels");
    }

    #[test]
    fn fill_rect_zero_width_or_height_is_noop() {
        let mut fb = VecFb::new(10, 10);
        fill_rect(&mut fb, 2, 2, 0, 5, theme::ACCENT);
        fill_rect(&mut fb, 2, 2, 5, 0, theme::ACCENT);
        assert!(fb.buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn fill_rect_fully_off_screen_is_noop_without_panic() {
        let mut fb = VecFb::new(10, 10);
        fill_rect(&mut fb, 100, 0, 5, 5, theme::ACCENT);
        fill_rect(&mut fb, 0, 100, 5, 5, theme::ACCENT);
        assert!(fb.buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn fill_rect_larger_than_row_chunk_fills_every_pixel() {
        // Exercises the chunked-emission path (ROW_CHUNK = 256).
        let mut fb = VecFb::new(300, 2);
        fill_rect(&mut fb, 0, 0, 300, 2, theme::PANEL);
        assert!(fb.buf.iter().all(|&p| p == theme::PANEL));
    }

    // -- hrule ----------------------------------------------------------

    #[test]
    fn hrule_draws_one_pixel_tall_rule_line() {
        let mut fb = VecFb::new(10, 5);
        hrule(&mut fb, 1, 2, 8);
        for py in 0..5u32 {
            for px in 0..10u32 {
                let on_rule = py == 2 && (1..9).contains(&px);
                let want = if on_rule { theme::RULE } else { 0 };
                assert_eq!(fb.at(px, py), want, "mismatch at ({px},{py})");
            }
        }
    }

    // -- panel / warn_panel ----------------------------------------------

    #[test]
    fn panel_border_is_rule_interior_is_panel() {
        let mut fb = VecFb::new(10, 8);
        panel(&mut fb, 0, 0, 10, 8);
        for py in 0..8u32 {
            for px in 0..10u32 {
                let is_border = px == 0 || px == 9 || py == 0 || py == 7;
                let want = if is_border { theme::RULE } else { theme::PANEL };
                assert_eq!(fb.at(px, py), want, "mismatch at ({px},{py})");
            }
        }
    }

    #[test]
    fn warn_panel_border_is_warn_interior_is_panel() {
        let mut fb = VecFb::new(10, 8);
        warn_panel(&mut fb, 0, 0, 10, 8);
        for py in 0..8u32 {
            for px in 0..10u32 {
                let is_border = px == 0 || px == 9 || py == 0 || py == 7;
                let want = if is_border { theme::WARN } else { theme::PANEL };
                assert_eq!(fb.at(px, py), want, "mismatch at ({px},{py})");
            }
        }
    }

    #[test]
    fn panel_offset_from_origin_borders_correct_edges() {
        // A panel not anchored at (0,0): border pixels must be at the
        // panel's own edges, not the framebuffer's.
        let mut fb = VecFb::new(12, 10);
        panel(&mut fb, 2, 1, 6, 5);
        for py in 0..10u32 {
            for px in 0..12u32 {
                let in_panel = (2..8).contains(&px) && (1..6).contains(&py);
                let is_border = in_panel && (px == 2 || px == 7 || py == 1 || py == 5);
                let want = if is_border {
                    theme::RULE
                } else if in_panel {
                    theme::PANEL
                } else {
                    0
                };
                assert_eq!(fb.at(px, py), want, "mismatch at ({px},{py})");
            }
        }
    }

    #[test]
    fn panel_degenerate_1xh_and_wx1_do_not_panic() {
        let mut fb = VecFb::new(5, 5);
        panel(&mut fb, 0, 0, 1, 5);
        let mut fb2 = VecFb::new(5, 5);
        panel(&mut fb2, 0, 0, 5, 1);
    }

    #[test]
    fn panel_zero_size_is_noop_without_panic() {
        let mut fb = VecFb::new(5, 5);
        panel(&mut fb, 0, 0, 0, 0);
        assert!(fb.buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn panel_clips_at_framebuffer_edge_without_panic() {
        let mut fb = VecFb::new(5, 5);
        panel(&mut fb, 3, 3, 10, 10);
    }

    // -- checkbox ---------------------------------------------------------

    #[test]
    fn checkbox_checked_renders_ok_colored_x_glyphs() {
        let w = GLYPH_WIDTH * 3;
        let mut fb = VecFb::new(w, GLYPH_HEIGHT);
        checkbox(&mut fb, 0, 0, true);

        let mut fb_expected = VecFb::new(w, GLYPH_HEIGHT);
        draw_text(&mut fb_expected, 0, 0, "[x]", theme::on_bg(theme::OK));
        assert_eq!(fb.buf, fb_expected.buf);

        // Sanity: the OK color actually appears (glyph isn't blank).
        assert!(fb.buf.iter().any(|&p| p == theme::OK));
    }

    #[test]
    fn checkbox_unchecked_renders_caption_colored_bracket_glyphs() {
        let w = GLYPH_WIDTH * 3;
        let mut fb = VecFb::new(w, GLYPH_HEIGHT);
        checkbox(&mut fb, 0, 0, false);

        let mut fb_expected = VecFb::new(w, GLYPH_HEIGHT);
        draw_text(&mut fb_expected, 0, 0, "[ ]", theme::on_bg(theme::CAPTION));
        assert_eq!(fb.buf, fb_expected.buf);

        assert!(fb.buf.iter().any(|&p| p == theme::CAPTION));
        // Unchecked must not use the OK color anywhere.
        assert!(fb.buf.iter().all(|&p| p != theme::OK));
    }

    #[test]
    fn checkbox_checked_and_unchecked_render_differently() {
        let w = GLYPH_WIDTH * 3;
        let mut fb_checked = VecFb::new(w, GLYPH_HEIGHT);
        let mut fb_unchecked = VecFb::new(w, GLYPH_HEIGHT);
        checkbox(&mut fb_checked, 0, 0, true);
        checkbox(&mut fb_unchecked, 0, 0, false);
        assert_ne!(fb_checked.buf, fb_unchecked.buf);
    }
}
