//! Owned by WP-10 (SPEC §12.2). 8x16 embedded bitmap font and the
//! `draw_text`/`draw_word`/`scrub_fill` rendering routines against
//! `seed_core::contracts::Framebuffer`.
//!
//! This module is `#![no_std]` (inherited from the crate root) and
//! allocation-free: every routine draws directly into the caller-owned
//! framebuffer one glyph row at a time via [`Framebuffer::put_row`], using
//! a fixed-size on-stack row buffer. No firmware text output and no
//! external font files are used anywhere in this module (SPEC §12.2).

mod glyphs;

pub use glyphs::{GLYPHS, GLYPH_HEIGHT, GLYPH_WIDTH, LAST_CHAR};

use seed_core::contracts::{Framebuffer, Style};

/// Maximum glyphs drawn by a single [`draw_text`]/[`draw_word`] call.
///
/// Derivation: the widest fixed-layout line in the UI (SPEC §12.2 "Fixed
/// layouts") is well under 128 printable characters; 128 is a generous,
/// still-fixed bound that keeps the on-stack row buffer small. Callers
/// that pass a longer string simply have it truncated at this bound
/// rather than panicking (no dynamic formatting of secret-bearing text,
/// SPEC §12.2).
pub const MAX_TEXT_LEN: usize = 128;

/// Render one glyph (`GLYPH_WIDTH` x `GLYPH_HEIGHT` pixels) with its
/// top-left corner at `(x, y)` (SPEC §12.2: fixed, application-owned
/// rendering routine over the embedded bitmap font).
///
/// Codepoints outside `0x20..=LAST_CHAR` (space through `~`) are rendered
/// as a blank cell rather than panicking, since firmware code must never
/// panic on untrusted/edge-case display input.
pub fn draw_glyph(fb: &mut dyn Framebuffer, x: u32, y: u32, ch: u8, style: Style) {
    draw_glyph_scaled(fb, x, y, ch, style, 1);
}

/// Render one glyph like [`draw_glyph`], but each source font pixel
/// becomes a `scale`x`scale` block of solid color (nearest-neighbor
/// scaling by construction). `scale` is clamped to `1..=2` — no caller
/// input, however large, can grow the on-stack row buffer or the drawn
/// area beyond 2x.
///
/// Follows the exact row-loop, right/bottom clipping, and
/// blank-cell-for-invalid-codepoint discipline of `draw_glyph` (this
/// function IS that discipline — `draw_glyph` is the `scale = 1` case of
/// this one). Never panics on display input.
pub fn draw_glyph_scaled(fb: &mut dyn Framebuffer, x: u32, y: u32, ch: u8, style: Style, scale: u32) {
    let scale = scale.clamp(1, 2);
    let glyph: &[u8; 16] = if (glyphs::FIRST_CHAR..=LAST_CHAR).contains(&ch) {
        &GLYPHS[(ch - glyphs::FIRST_CHAR) as usize]
    } else {
        // Blank cell for control chars / non-ASCII bytes / DEL.
        &[0u8; 16]
    };

    let (fb_w, fb_h) = fb.dims();
    let mut row_px = [0u32; GLYPH_WIDTH as usize * 2];
    let row_width = GLYPH_WIDTH * scale;
    // Clip the row on the right edge of the framebuffer (fixed for every
    // glyph row, since x/fb_w don't change during the draw).
    let visible_w = if x >= fb_w {
        0
    } else {
        core::cmp::min(row_width, fb_w - x) as usize
    };

    'rows: for (row_idx, bits) in glyph.iter().enumerate() {
        for col in 0..GLYPH_WIDTH {
            let set = (bits >> col) & 1 != 0;
            let px = if set { style.fg } else { style.bg };
            for s in 0..scale {
                row_px[(col * scale + s) as usize] = px;
            }
        }
        // Emit this glyph row `scale` times (nearest-neighbor row
        // repetition), stopping at the bottom edge exactly like
        // `draw_glyph`: once one output row falls off the framebuffer,
        // every later one does too (py is monotonically increasing).
        for sub in 0..scale {
            let py = y + (row_idx as u32) * scale + sub;
            if py >= fb_h {
                break 'rows;
            }
            if visible_w > 0 {
                fb.put_row(x, py, &row_px[..visible_w]);
            }
        }
    }
}

/// Render `s` as a horizontal line of glyphs starting at `(x, y)`, one
/// glyph cell (`GLYPH_WIDTH` px) per byte, left to right (SPEC §12.2:
/// fixed, application-owned rendering routine; no firmware text output).
///
/// `s` is treated as a fixed-layout UI string (menu text, labels,
/// addresses, fingerprints) — NOT as a vehicle for concatenating secret
/// mnemonic words (see [`draw_word`] for that path, SPEC §12.2: "MUST NOT
/// create one concatenated mnemonic string"). Only the first
/// [`MAX_TEXT_LEN`] bytes are drawn; bytes are interpreted 1:1 as ASCII
/// (non-ASCII bytes render as a blank cell via [`draw_glyph`]).
pub fn draw_text(fb: &mut dyn Framebuffer, x: u32, y: u32, s: &str, style: Style) {
    draw_text_scaled(fb, x, y, s, style, 1);
}

/// Render `s` like [`draw_text`], but every glyph is drawn via
/// [`draw_glyph_scaled`] at the given `scale` (clamped to `1..=2`), with
/// cells spaced `GLYPH_WIDTH * scale` px apart so scaled glyphs never
/// overlap. Same [`MAX_TEXT_LEN`] truncation bound as `draw_text`.
pub fn draw_text_scaled(fb: &mut dyn Framebuffer, x: u32, y: u32, s: &str, style: Style, scale: u32) {
    let scale = scale.clamp(1, 2);
    for (i, &b) in s.as_bytes().iter().take(MAX_TEXT_LEN).enumerate() {
        draw_glyph_scaled(fb, x + (i as u32) * GLYPH_WIDTH * scale, y, b, style, scale);
    }
}

/// Render ASCII bytes (not necessarily a `&str`) as a horizontal line of
/// glyphs, used internally by [`draw_word`] so a caller-owned byte buffer
/// never needs to be validated/copied into a `&str` first.
fn draw_ascii(fb: &mut dyn Framebuffer, x: u32, y: u32, bytes: &[u8], style: Style) {
    for (i, &b) in bytes.iter().take(MAX_TEXT_LEN).enumerate() {
        draw_glyph(fb, x + (i as u32) * GLYPH_WIDTH, y, b, style);
    }
}

/// A single fixed BIP39 word slot's on-screen origin (SPEC §12.2 fixed
/// layout). `WORD_SLOT_ORIGINS[slot as usize]` gives the `(x, y)` top-left
/// pixel of that slot's text baseline; slots beyond the 24-word maximum
/// mnemonic length are unused. This is a conservative fixed grid (6
/// columns x 4 rows) that any 12/15/18/21/24-word layout maps onto by
/// using a prefix of the slots; the exact on-screen grid is otherwise the
/// GOP backend's (WP-21) concern, so this module only guarantees *some*
/// fixed, non-overlapping origin per slot rather than dictating final UI
/// pixel geometry.
const WORD_SLOT_COLUMNS: u32 = 6;
const WORD_SLOT_ROWS: u32 = 4;
const WORD_SLOT_CELL_W: u32 = GLYPH_WIDTH * 12; // room for "24. " + up to 8-char word
const WORD_SLOT_CELL_H: u32 = GLYPH_HEIGHT * 2;

/// Resolve fixed slot index (0..24) to a top-left pixel origin in a
/// 6-column x 4-row grid (SPEC §12.2 "Fixed layouts").
fn slot_origin(slot: u8) -> (u32, u32) {
    let slot = slot as u32 % (WORD_SLOT_COLUMNS * WORD_SLOT_ROWS);
    let col = slot % WORD_SLOT_COLUMNS;
    let row = slot / WORD_SLOT_COLUMNS;
    // Grid offset (2026-08-09 Stage-6 shell restyle, a WP-10 layout
    // change): the grid now sits inside the redesigned chrome shell's
    // content area instead of the raw framebuffer origin. Mirrored by
    // `seed-flow`'s `flow_secret::display` — keep the two in lockstep.
    (
        crate::layout::WORD_GRID_LEFT + col * WORD_SLOT_CELL_W,
        crate::layout::WORD_GRID_TOP + row * WORD_SLOT_CELL_H,
    )
}

/// Render exactly ONE BIP39 mnemonic word, identified only by its
/// `index` (0..2047) into the fixed English wordlist, into the fixed
/// screen slot `slot` (SPEC §12.2: "The application MUST render words
/// individually from fixed word indexes. It MUST NOT create one
/// concatenated mnemonic string."; SPEC §22.7/§23.1: the words shown here
/// are what the user must be able to read and later re-type during
/// hidden re-entry).
///
/// This function never accepts a full-phrase string and never builds one
/// internally: it draws a slot label (`"NN. "`, NN = slot+1, two ASCII
/// digits max) followed by the single word's glyphs, resolved via
/// [`seed_core::bip39::word`] (the frozen `contracts.rs` accessor, SPEC
/// §4) and drawn straight from that `&'static str`'s bytes into the
/// framebuffer — no local copy of the word text is ever made.
///
/// # Panics
///
/// Panics if `index >= 2048` — [`seed_core::bip39::word`]'s own
/// documented invariant. Every caller in this codebase only ever passes
/// indexes produced by `entropy_to_indexes`/read back from
/// `SecretArena::mnemonic_indexes()`, both always in range by
/// construction (the same invariant `seed_core::bip39::word` itself
/// documents); this is not a user-input or platform-failure path.
pub fn draw_word(fb: &mut dyn Framebuffer, slot: u8, index: u16, style: Style) {
    let (ox, oy) = slot_origin(slot);

    // "NN. " label, NN = 1-based slot number, always 2 digits + ". ".
    let n = (slot as u32) + 1;
    let label = [
        b'0' + ((n / 10) % 10) as u8,
        b'0' + (n % 10) as u8,
        b'.',
        b' ',
    ];
    draw_ascii(fb, ox, oy, &label, style);
    let word_x = ox + (label.len() as u32) * GLYPH_WIDTH;

    draw_ascii(fb, word_x, oy, seed_core::bip39::word(index).as_bytes(), style);
}

/// Fill the entire visible framebuffer with a single flat pixel `pattern`
/// (SPEC §12.2 secret-display scrub path: overwriting the screen with a
/// pattern before/after showing secret text). Uses a fixed on-stack row
/// buffer, no allocation.
pub fn scrub_fill(fb: &mut dyn Framebuffer, pattern: u32) {
    let (w, h) = fb.dims();
    if w == 0 || h == 0 {
        return;
    }
    const CHUNK: u32 = 256;
    let mut row = [0u32; CHUNK as usize];
    for v in row.iter_mut() {
        *v = pattern;
    }
    for y in 0..h {
        let mut x = 0u32;
        while x < w {
            let n = core::cmp::min(CHUNK, w - x) as usize;
            fb.put_row(x, y, &row[..n]);
            x += n as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Host-only `Vec<u32>` double implementing `Framebuffer`, as directed
    /// by the WP-10 Definition of Done ("host tests render into a
    /// `Vec<u32>` test double and snapshot-hash the output").
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

        fn hash(&self) -> u64 {
            // FNV-1a 64-bit over the raw pixel buffer, good enough for a
            // deterministic snapshot without pulling in a hash crate.
            let mut h: u64 = 0xcbf29ce484222325;
            for &px in &self.buf {
                for b in px.to_le_bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
            }
            h
        }
    }

    impl seed_core::contracts::Framebuffer for VecFb {
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

    const STYLE: Style = Style {
        fg: crate::theme::TEXT,
        bg: crate::theme::BG,
    };

    #[test]
    fn draw_glyph_space_is_blank() {
        let mut fb = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        draw_glyph(&mut fb, 0, 0, b' ', STYLE);
        assert!(fb.buf.iter().all(|&p| p == STYLE.bg));
    }

    #[test]
    fn draw_glyph_control_char_is_blank() {
        let mut fb = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        draw_glyph(&mut fb, 0, 0, 0x01, STYLE);
        assert!(fb.buf.iter().all(|&p| p == STYLE.bg));
    }

    #[test]
    fn draw_glyph_non_space_has_foreground_pixels() {
        let mut fb = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        draw_glyph(&mut fb, 0, 0, b'A', STYLE);
        assert!(fb.buf.iter().any(|&p| p == STYLE.fg));
    }

    #[test]
    fn draw_glyph_clips_at_framebuffer_edge_without_panic() {
        // 4px wide fb, glyph is 8px wide: right half must clip silently.
        let mut fb = VecFb::new(4, GLYPH_HEIGHT);
        draw_glyph(&mut fb, 0, 0, b'A', STYLE);
        // 8px wide fb but glyph placed 4px from origin also clips.
        let mut fb2 = VecFb::new(8, GLYPH_HEIGHT);
        draw_glyph(&mut fb2, 4, 0, b'A', STYLE);
        // x fully off-screen: no panic, no writes.
        let mut fb3 = VecFb::new(8, GLYPH_HEIGHT);
        draw_glyph(&mut fb3, 100, 0, b'A', STYLE);
        assert!(fb3.buf.iter().all(|&p| p == STYLE.bg));
    }

    #[test]
    fn draw_glyph_clips_at_bottom_edge_without_panic() {
        let mut fb = VecFb::new(GLYPH_WIDTH, 4);
        draw_glyph(&mut fb, 0, 0, b'A', STYLE);
    }

    #[test]
    fn draw_text_places_glyphs_left_to_right() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 3, GLYPH_HEIGHT);
        draw_text(&mut fb, 0, 0, "A B", STYLE);
        // Middle cell (space) must be entirely background.
        for row in 0..GLYPH_HEIGHT {
            for col in GLYPH_WIDTH..GLYPH_WIDTH * 2 {
                let idx = (row as usize) * (fb.w as usize) + col as usize;
                assert_eq!(fb.buf[idx], STYLE.bg);
            }
        }
        // First and last cells ('A') have some foreground pixels.
        let has_fg = |x0: u32| {
            (0..GLYPH_HEIGHT).any(|row| {
                (x0..x0 + GLYPH_WIDTH).any(|col| {
                    let idx = (row as usize) * (fb.w as usize) + col as usize;
                    fb.buf[idx] == STYLE.fg
                })
            })
        };
        assert!(has_fg(0));
        assert!(has_fg(GLYPH_WIDTH * 2));
    }

    #[test]
    fn draw_text_truncates_at_max_len_without_panic() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 4, GLYPH_HEIGHT);
        let long: std::string::String = core::iter::repeat('X').take(1000).collect();
        draw_text(&mut fb, 0, 0, &long, STYLE);
    }

    #[test]
    fn draw_word_never_takes_a_phrase_string() {
        // Compile-time contract check: draw_word's signature only accepts
        // (Framebuffer, slot: u8, index: u16, Style) — there is no way to
        // pass a full mnemonic string to it. This test exercises the call
        // shape to keep the contract pinned.
        let mut fb = VecFb::new(
            crate::layout::WORD_GRID_LEFT + WORD_SLOT_COLUMNS * WORD_SLOT_CELL_W,
            crate::layout::WORD_GRID_TOP + WORD_SLOT_ROWS * WORD_SLOT_CELL_H,
        );
        draw_word(&mut fb, 0, 0, STYLE);
        draw_word(&mut fb, 11, 2047, STYLE);
        draw_word(&mut fb, 23, 1, STYLE);
    }

    #[test]
    fn draw_word_distinct_slots_do_not_overlap() {
        let w = WORD_SLOT_COLUMNS * WORD_SLOT_CELL_W;
        let h = WORD_SLOT_ROWS * WORD_SLOT_CELL_H;
        let mut fb_a = VecFb::new(w, h);
        let mut fb_b = VecFb::new(w, h);
        draw_word(&mut fb_a, 0, 5, STYLE);
        draw_word(&mut fb_b, 1, 5, STYLE);
        assert_ne!(fb_a.buf, fb_b.buf);
    }

    /// Regression test for the confirmed WP-26 finding: `draw_word` MUST
    /// render the actual BIP39 word text (SPEC §22.7/§23.1: the user
    /// reads the words on screen, then re-types them from memory during
    /// hidden re-entry), not a numeric `"#<index>"` placeholder. Index 0
    /// is the BIP39 English wordlist's first entry, "abandon".
    #[test]
    fn draw_word_renders_the_real_bip39_word_not_a_numeric_placeholder() {
        assert_eq!(seed_core::bip39::word(0), "abandon");

        // Slot 0 renders at the grid origin (Stage-6 shell restyle,
        // 2026-08-09) — compare against draw_text at that same offset.
        let (ox, oy) = slot_origin(0);
        let w = ox + WORD_SLOT_CELL_W;
        let h = oy + WORD_SLOT_CELL_H;

        let mut fb_word = VecFb::new(w, h);
        draw_word(&mut fb_word, 0, 0, STYLE);

        let mut fb_expected = VecFb::new(w, h);
        draw_text(&mut fb_expected, ox, oy, "01. abandon", STYLE);
        assert_eq!(fb_word.buf, fb_expected.buf, "draw_word must render the real word \"abandon\"");

        // The old numeric placeholder ("01. #0") must be gone: rendering
        // it would produce different pixels than the real word.
        let mut fb_placeholder = VecFb::new(w, h);
        draw_text(&mut fb_placeholder, ox, oy, "01. #0", STYLE);
        assert_ne!(fb_word.buf, fb_placeholder.buf, "draw_word must not render a numeric placeholder");
    }

    /// A second index, away from the boundary, also renders its real
    /// word (not just index 0): BIP39 English index 2047 is "zoo".
    #[test]
    fn draw_word_renders_the_real_word_at_the_last_wordlist_index() {
        assert_eq!(seed_core::bip39::word(2047), "zoo");

        let w = WORD_SLOT_CELL_W;
        let h = WORD_SLOT_CELL_H;
        let mut fb_word = VecFb::new(w, h);
        draw_word(&mut fb_word, 11, 2047, STYLE);

        let (ox, oy) = slot_origin(11);
        let mut fb_expected = VecFb::new(w, h);
        draw_text(&mut fb_expected, ox, oy, "12. zoo", STYLE);
        assert_eq!(fb_word.buf, fb_expected.buf);
    }

    /// Longest BIP39 English wordlist entry, in ASCII bytes: the room
    /// `WORD_SLOT_CELL_W` reserves for a word (see that constant's own
    /// comment, "up to 8-char word") must actually be enough for every
    /// real wordlist entry.
    const MAX_BIP39_WORD_LEN: usize = 8;

    #[test]
    fn longest_word_fits_buffer() {
        // BIP39 English wordlist longest entries are 8 letters (e.g.
        // "abstract"); verify every real wordlist entry fits the
        // documented bound directly against `seed_core::bip39::word`,
        // since `draw_word` now renders that text straight from the
        // wordlist with no intermediate copy buffer to size separately.
        for i in 0..2048u16 {
            assert!(seed_core::bip39::word(i).len() <= MAX_BIP39_WORD_LEN);
        }
    }

    #[test]
    fn scrub_fill_sets_every_pixel() {
        let mut fb = VecFb::new(37, 13); // deliberately not chunk-aligned
        scrub_fill(&mut fb, 0xdead_beef);
        assert!(fb.buf.iter().all(|&p| p == 0xdead_beef));
    }

    #[test]
    fn scrub_fill_zero_dims_no_panic() {
        let mut fb = VecFb::new(0, 0);
        scrub_fill(&mut fb, 0x1234);
    }

    // -- draw_glyph_scaled / draw_text_scaled (Task 2: integer-scaled
    // glyph rendering, 1x/2x) --------------------------------------------

    /// Every set/unset font pixel of 'A' at scale 2 must map to an exact
    /// 2x2 block of style.fg / style.bg respectively — nearest-neighbor
    /// scaling by construction.
    #[test]
    fn draw_glyph_scaled_2x_produces_exact_2x2_blocks() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 2, GLYPH_HEIGHT * 2);
        draw_glyph_scaled(&mut fb, 0, 0, b'A', STYLE, 2);

        let glyph = &GLYPHS[(b'A' - glyphs::FIRST_CHAR) as usize];
        for row in 0..GLYPH_HEIGHT {
            let bits = glyph[row as usize];
            for col in 0..GLYPH_WIDTH {
                let set = (bits >> col) & 1 != 0;
                let expected = if set { STYLE.fg } else { STYLE.bg };
                for sy in 0..2u32 {
                    for sx in 0..2u32 {
                        let px = col * 2 + sx;
                        let py = row * 2 + sy;
                        let idx = (py as usize) * (fb.w as usize) + px as usize;
                        assert_eq!(
                            fb.buf[idx], expected,
                            "mismatch at glyph row {row} col {col} sub ({sx},{sy})"
                        );
                    }
                }
            }
        }
    }

    /// The drawn area at scale 2 is exactly 16x32 pixels: nothing outside
    /// that box is touched (untouched pixels stay at the buffer's initial
    /// value, distinguishable here from a real bg write since bg != 0).
    #[test]
    fn draw_glyph_scaled_2x_drawn_area_is_exactly_16x32() {
        const STYLE2: Style = Style {
            // Theme roles (SPEC §3.1): PANEL is nonzero, preserving this
            // test's requirement that bg differ from the buffer's 0 init.
            fg: crate::theme::TEXT,
            bg: crate::theme::PANEL,
        };
        let mut fb = VecFb::new(GLYPH_WIDTH * 3, GLYPH_HEIGHT * 3);
        // Draw offset from the origin so the drawn box has untouched
        // buffer on every side to check against.
        draw_glyph_scaled(&mut fb, GLYPH_WIDTH, GLYPH_HEIGHT, b'A', STYLE2, 2);

        let box_x0 = GLYPH_WIDTH;
        let box_x1 = GLYPH_WIDTH + GLYPH_WIDTH * 2;
        let box_y0 = GLYPH_HEIGHT;
        let box_y1 = GLYPH_HEIGHT + GLYPH_HEIGHT * 2;
        assert_eq!(box_x1 - box_x0, 16);
        assert_eq!(box_y1 - box_y0, 32);

        for py in 0..fb.h {
            for px in 0..fb.w {
                let idx = (py as usize) * (fb.w as usize) + px as usize;
                let in_box = px >= box_x0 && px < box_x1 && py >= box_y0 && py < box_y1;
                if in_box {
                    assert!(fb.buf[idx] == STYLE2.fg || fb.buf[idx] == STYLE2.bg);
                } else {
                    assert_eq!(fb.buf[idx], 0, "pixel outside the drawn 16x32 box was written");
                }
            }
        }
    }

    /// Right-edge clipping at scale 2 matches `draw_glyph`'s discipline:
    /// silently truncate the row, never panic.
    #[test]
    fn draw_glyph_scaled_clips_at_right_edge_without_panic() {
        // Scaled glyph is 16px wide; fb is only 10px wide.
        let mut fb = VecFb::new(10, GLYPH_HEIGHT * 2);
        draw_glyph_scaled(&mut fb, 0, 0, b'A', STYLE, 2);

        // x fully off-screen: no panic, no writes (buffer stays all bg).
        let mut fb2 = VecFb::new(20, GLYPH_HEIGHT * 2);
        draw_glyph_scaled(&mut fb2, 100, 0, b'A', STYLE, 2);
        assert!(fb2.buf.iter().all(|&p| p == STYLE.bg));
    }

    /// Bottom-edge clipping at scale 2 matches `draw_glyph`'s discipline:
    /// silently stop, never panic.
    #[test]
    fn draw_glyph_scaled_clips_at_bottom_edge_without_panic() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 2, 4);
        draw_glyph_scaled(&mut fb, 0, 0, b'A', STYLE, 2);
    }

    /// Scale is clamped to 1..=2: 0 behaves like 1, and anything above 2
    /// behaves like 2 (never panics, never draws a larger block).
    #[test]
    fn draw_glyph_scaled_clamps_scale_to_1_and_2() {
        let mut fb_zero = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        let mut fb_one = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        draw_glyph_scaled(&mut fb_zero, 0, 0, b'A', STYLE, 0);
        draw_glyph_scaled(&mut fb_one, 0, 0, b'A', STYLE, 1);
        assert_eq!(fb_zero.buf, fb_one.buf);

        let mut fb_big = VecFb::new(GLYPH_WIDTH * 2, GLYPH_HEIGHT * 2);
        let mut fb_two = VecFb::new(GLYPH_WIDTH * 2, GLYPH_HEIGHT * 2);
        draw_glyph_scaled(&mut fb_big, 0, 0, b'A', STYLE, 9);
        draw_glyph_scaled(&mut fb_two, 0, 0, b'A', STYLE, 2);
        assert_eq!(fb_big.buf, fb_two.buf);
    }

    /// `draw_glyph` (scale-1 caller) must render identically to
    /// `draw_glyph_scaled(.., 1)` — it is a delegating wrapper, not a
    /// separate code path.
    #[test]
    fn draw_glyph_matches_draw_glyph_scaled_at_scale_1() {
        let mut fb_a = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        let mut fb_b = VecFb::new(GLYPH_WIDTH, GLYPH_HEIGHT);
        draw_glyph(&mut fb_a, 0, 0, b'A', STYLE);
        draw_glyph_scaled(&mut fb_b, 0, 0, b'A', STYLE, 1);
        assert_eq!(fb_a.buf, fb_b.buf);
    }

    /// `draw_text_scaled` places glyph cells `GLYPH_WIDTH * scale` px
    /// apart, and clips/truncates the same way `draw_text` does.
    #[test]
    fn draw_text_scaled_places_glyphs_with_scaled_spacing() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 2 * 3, GLYPH_HEIGHT * 2);
        draw_text_scaled(&mut fb, 0, 0, "A B", STYLE, 2);

        // Middle cell (space, scaled) must be entirely background.
        for row in 0..GLYPH_HEIGHT * 2 {
            for col in GLYPH_WIDTH * 2..GLYPH_WIDTH * 2 * 2 {
                let idx = (row as usize) * (fb.w as usize) + col as usize;
                assert_eq!(fb.buf[idx], STYLE.bg);
            }
        }
        let has_fg = |x0: u32| {
            (0..GLYPH_HEIGHT * 2).any(|row| {
                (x0..x0 + GLYPH_WIDTH * 2).any(|col| {
                    let idx = (row as usize) * (fb.w as usize) + col as usize;
                    fb.buf[idx] == STYLE.fg
                })
            })
        };
        assert!(has_fg(0));
        assert!(has_fg(GLYPH_WIDTH * 2 * 2));
    }

    /// `draw_text_scaled` truncates at `MAX_TEXT_LEN` bytes without
    /// panicking, same bound as `draw_text`.
    #[test]
    fn draw_text_scaled_truncates_at_max_len_without_panic() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 2 * 4, GLYPH_HEIGHT * 2);
        let long: std::string::String = core::iter::repeat('X').take(1000).collect();
        draw_text_scaled(&mut fb, 0, 0, &long, STYLE, 2);
    }

    /// `draw_text` (scale-1 caller) must render identically to
    /// `draw_text_scaled(.., 1)`.
    #[test]
    fn draw_text_matches_draw_text_scaled_at_scale_1() {
        let mut fb_a = VecFb::new(GLYPH_WIDTH * 3, GLYPH_HEIGHT);
        let mut fb_b = VecFb::new(GLYPH_WIDTH * 3, GLYPH_HEIGHT);
        draw_text(&mut fb_a, 0, 0, "A B", STYLE);
        draw_text_scaled(&mut fb_b, 0, 0, "A B", STYLE, 1);
        assert_eq!(fb_a.buf, fb_b.buf);
    }

    /// Snapshot-hash test per the WP-10 Definition of Done: renders a
    /// fixed known string into a fixed-size framebuffer and checks the
    /// resulting pixel buffer hashes to a pinned constant. If this ever
    /// legitimately changes (e.g. a glyph fix), recompute and update the
    /// constant deliberately — a silent change here means rendering
    /// output changed.
    #[test]
    fn snapshot_hash_known_text() {
        let mut fb = VecFb::new(GLYPH_WIDTH * 11, GLYPH_HEIGHT);
        draw_text(&mut fb, 0, 0, "Hello, WP10", STYLE);
        // Pinned snapshot hash captured from the reference render of
        // "Hello, WP10" at (0,0) with `STYLE`. If this legitimately
        // changes (e.g. a glyph fix), recompute deliberately — a silent
        // change here means rendering output changed.
        assert_eq!(fb.hash(), SNAPSHOT_HELLO_WP10);
    }

    /// Pinned snapshot hash for `snapshot_hash_known_text`. Recomputed for
    /// the SPEC §3.1 role-palette change: `STYLE`'s foreground moved from
    /// pure white (`0x00FF_FFFF`) to `theme::TEXT` (`0x00E6_EDF3`), which
    /// legitimately changes every pixel's hashed byte value even though
    /// no glyph data changed.
    const SNAPSHOT_HELLO_WP10: u64 = 8587353845688648205;

    #[test]
    fn snapshot_hash_known_word_slot() {
        let mut fb = VecFb::new(WORD_SLOT_CELL_W, WORD_SLOT_CELL_H);
        draw_word(&mut fb, 0, 42, STYLE);
        let h = fb.hash();
        assert_ne!(h, 0xcbf2_9ce4_8422_2325); // not the empty-buffer hash
    }
}
