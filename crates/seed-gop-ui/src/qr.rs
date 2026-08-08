//! QR symbol rendering for the opt-in wallet-export screen
//! (`docs/superpowers/specs/2026-08-07-wallet-export-design.md` §4.1, "QR
//! renderer"): integer module scaling onto a white quiet-zone panel,
//! built on [`crate::panel::fill_rect`] like every other primitive in
//! this crate.
//!
//! # What may be drawn here
//!
//! A [`seed_qr::Matrix`] is a bitmap; this module cannot tell what it
//! encodes. The rule that only *public export values* (an account
//! extended public key, an output descriptor) are ever encoded is
//! enforced where the matrix is built — `seed_flow::screens::export`'s
//! `compute_export`, whose own tests pin the encoded bytes to exactly the
//! artifact string shown on screen. Wallet-export spec D5 ("no SeedQR, no
//! QR of any secret, ever") is a property of that call site, not of this
//! renderer.
//!
//! # Rendering rules
//!
//! * **Integer scaling only.** Each module becomes an exact
//!   `module_px` x `module_px` square of flat color. There is no
//!   anti-aliasing, no filtering and no fractional scaling anywhere:
//!   a camera binarizes the symbol, and a half-lit boundary pixel is
//!   exactly the ambiguity that makes a decode fail.
//! * **Quiet zone.** [`QUIET_MODULES`] (4, the ISO/IEC 18004 minimum) of
//!   light margin on all four sides, painted as part of the panel, so the
//!   symbol never relies on whatever the surrounding screen happens to
//!   draw.
//! * **Two colors only**, [`theme::QR_LIGHT`] and [`theme::QR_DARK`].
//!
//! # Panic-freedom
//!
//! Every geometry computation below is saturating, and `fill_rect` clips
//! to the framebuffer, so no `(x, y, module_px)` combination — including
//! deliberately absurd ones — can panic or index out of bounds. A symbol
//! drawn partly off-screen is simply clipped (SPEC §13, §27.3).

use seed_core::contracts::Framebuffer;

use crate::panel::fill_rect;
use crate::theme;

/// Width of the light margin around a symbol, in modules. ISO/IEC 18004
/// requires 4 for a QR Code symbol; the wallet-export design restates it
/// as the floor ("white quiet-zone panel (>= 4 modules)").
pub const QUIET_MODULES: u32 = 4;

/// Side of the drawn block, in modules: the symbol plus a
/// [`QUIET_MODULES`]-wide quiet zone on each side.
///
/// Saturating, so an absurd `side` cannot overflow (the real bound is
/// [`seed_qr::MAX_SIDE`] = 69).
#[must_use]
pub const fn block_modules(side: usize) -> u32 {
    (side as u32).saturating_add(QUIET_MODULES.saturating_mul(2))
}

/// Side of the drawn block in *pixels* for a symbol of `side` modules
/// rendered at `module_px` — what a caller must reserve in its layout.
#[must_use]
pub const fn block_px(side: usize, module_px: u32) -> u32 {
    block_modules(side).saturating_mul(module_px)
}

/// The largest integer `module_px` at which a `side`-module symbol (quiet
/// zone included) still fits `width_px`, or `0` if even one pixel per
/// module would not fit.
///
/// Callers use this to keep a *fixed* layout box while the symbol's
/// version varies with the payload: the block is at most `width_px` wide
/// whatever the encoder chose, and `draw_qr` is a no-op if the result is
/// `0` rather than drawing a symbol too small to mean anything.
#[must_use]
pub const fn module_px_for_width(side: usize, width_px: u32) -> u32 {
    let modules = block_modules(side);
    if modules == 0 {
        return 0;
    }
    width_px / modules
}

/// Draw `m` at `(x, y)`: a [`theme::QR_LIGHT`] panel of
/// [`block_px`]`(m.side(), module_px)` on a side, with every dark module
/// painted as a `module_px`-square of [`theme::QR_DARK`] inset by the
/// [`QUIET_MODULES`]-wide quiet zone.
///
/// A no-op for an empty matrix (`side == 0`, i.e. nothing was ever
/// encoded) or `module_px == 0` — both would otherwise paint a blank
/// white box that reads as "a QR that failed to scan" rather than
/// "no QR here".
///
/// Consecutive dark modules in a row are emitted as one `fill_rect` run,
/// so a version-13 symbol costs on the order of a few hundred fills
/// rather than 4761.
pub fn draw_qr(fb: &mut dyn Framebuffer, x: u32, y: u32, m: &seed_qr::Matrix, module_px: u32) {
    if m.side() == 0 || module_px == 0 {
        return;
    }

    let block = block_px(m.side(), module_px);
    fill_rect(fb, x, y, block, block, theme::QR_LIGHT);

    let quiet_px = QUIET_MODULES.saturating_mul(module_px);
    let origin_x = x.saturating_add(quiet_px);
    let origin_y = y.saturating_add(quiet_px);

    for my in 0..m.side() {
        let row_y = origin_y.saturating_add((my as u32).saturating_mul(module_px));
        let mut mx = 0usize;
        while mx < m.side() {
            if !m.get(mx, my) {
                mx += 1;
                continue;
            }
            // Coalesce this run of dark modules into a single fill.
            let start = mx;
            while mx < m.side() && m.get(mx, my) {
                mx += 1;
            }
            let run = (mx - start) as u32;
            fill_rect(
                fb,
                origin_x.saturating_add((start as u32).saturating_mul(module_px)),
                row_y,
                run.saturating_mul(module_px),
                module_px,
                theme::QR_DARK,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Host-only `Vec<u32>` `Framebuffer` test double — same pattern as
    /// `crate::panel`'s own `VecFb`.
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

    /// A real symbol (version 1, 21 modules) from the encoder itself, so
    /// these tests measure what actually ships rather than a hand-built
    /// bitmap.
    fn sample() -> seed_qr::Matrix {
        let mut m = seed_qr::Matrix::new();
        let version = seed_qr::encode(b"HELLO WORLD", &mut m).expect("encodes");
        assert_eq!(version, 1);
        assert_eq!(m.side(), 21);
        m
    }

    // -- geometry -------------------------------------------------------

    #[test]
    fn block_geometry_adds_four_quiet_modules_on_every_side() {
        assert_eq!(QUIET_MODULES, 4);
        assert_eq!(block_modules(21), 29);
        assert_eq!(block_px(21, 4), 116);
        assert_eq!(block_px(seed_qr::MAX_SIDE, 4), (69 + 8) * 4);
    }

    #[test]
    fn module_px_for_width_never_overflows_the_box() {
        for side in [1usize, 21, 45, seed_qr::MAX_SIDE] {
            for width in [0u32, 7, 100, 352, 1024] {
                let px = module_px_for_width(side, width);
                assert!(
                    block_px(side, px) <= width,
                    "side {side} at width {width}: {px}px/module overflows the box"
                );
                // And one more pixel per module would not fit.
                assert!(block_px(side, px + 1) > width);
            }
        }
    }

    // -- rendering ------------------------------------------------------

    #[test]
    fn quiet_zone_is_four_modules_of_light_on_all_four_sides() {
        let m = sample();
        let px = 3u32;
        let block = block_px(m.side(), px);
        let mut fb = VecFb::new(block, block);
        draw_qr(&mut fb, 0, 0, &m, px);

        let quiet = QUIET_MODULES * px;
        for i in 0..block {
            for q in 0..quiet {
                assert_eq!(fb.at(i, q), theme::QR_LIGHT, "top quiet zone at ({i},{q})");
                assert_eq!(fb.at(i, block - 1 - q), theme::QR_LIGHT, "bottom quiet zone");
                assert_eq!(fb.at(q, i), theme::QR_LIGHT, "left quiet zone");
                assert_eq!(fb.at(block - 1 - q, i), theme::QR_LIGHT, "right quiet zone");
            }
        }
    }

    /// Every module is a solid `module_px` square of one of exactly two
    /// colors: integer scaling, no anti-aliasing, no intermediate shades.
    #[test]
    fn every_module_is_a_solid_square_matching_the_matrix() {
        let m = sample();
        let px = 5u32;
        let block = block_px(m.side(), px);
        let mut fb = VecFb::new(block, block);
        draw_qr(&mut fb, 0, 0, &m, px);

        let quiet = QUIET_MODULES * px;
        for my in 0..m.side() {
            for mx in 0..m.side() {
                let want = if m.get(mx, my) { theme::QR_DARK } else { theme::QR_LIGHT };
                let x0 = quiet + (mx as u32) * px;
                let y0 = quiet + (my as u32) * px;
                for dy in 0..px {
                    for dx in 0..px {
                        assert_eq!(
                            fb.at(x0 + dx, y0 + dy),
                            want,
                            "module ({mx},{my}) pixel ({dx},{dy}) is not solid"
                        );
                    }
                }
            }
        }

        // Two colors, and both actually present.
        assert!(fb.buf.iter().all(|&p| p == theme::QR_LIGHT || p == theme::QR_DARK));
        assert!(fb.buf.iter().any(|&p| p == theme::QR_DARK));
        assert!(fb.buf.iter().any(|&p| p == theme::QR_LIGHT));
    }

    #[test]
    fn drawing_at_an_offset_leaves_the_rest_of_the_screen_untouched() {
        let m = sample();
        let px = 2u32;
        let block = block_px(m.side(), px);
        let mut fb = VecFb::new(block + 20, block + 20);
        draw_qr(&mut fb, 10, 6, &m, px);

        for y in 0..fb.h {
            for x in 0..fb.w {
                let inside = (10..10 + block).contains(&x) && (6..6 + block).contains(&y);
                if !inside {
                    assert_eq!(fb.at(x, y), 0, "pixel ({x},{y}) outside the block was painted");
                }
            }
        }
    }

    #[test]
    fn empty_matrix_or_zero_module_size_draws_nothing() {
        let mut fb = VecFb::new(64, 64);
        draw_qr(&mut fb, 0, 0, &seed_qr::Matrix::new(), 4);
        assert!(fb.buf.iter().all(|&p| p == 0), "an empty matrix must draw nothing");

        draw_qr(&mut fb, 0, 0, &sample(), 0);
        assert!(fb.buf.iter().all(|&p| p == 0), "module_px == 0 must draw nothing");
    }

    #[test]
    fn off_screen_and_oversized_geometry_clip_without_panicking() {
        let m = sample();
        let mut fb = VecFb::new(40, 40);
        draw_qr(&mut fb, 0, 0, &m, 7); // overflows both edges
        draw_qr(&mut fb, 35, 35, &m, 2); // starts near the corner
        draw_qr(&mut fb, 5000, 5000, &m, 2); // fully off-screen
        draw_qr(&mut fb, 0, 0, &m, u32::MAX); // saturating geometry
    }

    #[test]
    fn a_max_version_symbol_renders_at_the_export_screens_box_width() {
        // The widest payload the export screen can produce still gets an
        // integer scale >= 3 in a 352px box.
        let px = module_px_for_width(seed_qr::MAX_SIDE, 352);
        assert!(px >= 3, "max-version symbol would render at only {px}px/module");
        let block = block_px(seed_qr::MAX_SIDE, px);
        assert!(block <= 352);
    }
}
