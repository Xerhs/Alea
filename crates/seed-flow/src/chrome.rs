//! Shared screen chrome (design doc §3.3/§3.4,
//! `docs/superpowers/specs/2026-08-07-ceremony-ux-redesign-design.md`):
//! the header band (product name + build ID left, seven-dot stage rail +
//! current stage label right) and the footer key bar (the *only* place
//! key hints live, per §3.3) that every ceremony screen composes on top
//! of.
//!
//! This module renders for all three UI editions (`seed-uefi-production`,
//! `seed-uefi-test`, `seed-desktop-test`) via the same `Framebuffer`
//! trait every other `seed-gop-ui`/`seed-flow` renderer already targets
//! (§3.4: "identical by construction, same as today"). It draws with
//! `seed_gop_ui::panel::{fill_rect, hrule}` for the two bands and
//! `seed_gop_ui::font::{draw_text, draw_glyph}` for their content — no
//! new rendering primitive, no allocation, and every color reached only
//! through a [`seed_gop_ui::theme`] role (enforced workspace-wide by the
//! `no_raw_colors` host test, which scans this crate's `src/` tree too).
//!
//! `Chrome::build` is caller-supplied (`&'static str`): this crate takes
//! no dependency on any release/build-id constant. Production passes its
//! existing `release::BUILD_ID` (already shown on the launcher's About
//! screen); other editions pass whatever build string they track, or a
//! fixed placeholder.

use core::fmt::Write as _;

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_glyph, draw_text, GLYPH_HEIGHT, GLYPH_WIDTH};
use seed_gop_ui::gop::mode::MIN_HEIGHT;
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::{panel, theme};

use crate::output::LineBuf;
use crate::text::OPENING_TITLE;

/// The seven ceremony stage names, in order (design doc §4: PREPARE,
/// DEVICE, SETUP, ENTROPY, GENERATE, BACKUP, VERIFY). [`Chrome::stage`]
/// is 1-based (`1..=7`) and indexes here as `stage - 1`.
pub const STAGE_NAMES: [&str; 7] = ["PREPARE", "DEVICE", "SETUP", "ENTROPY", "GENERATE", "BACKUP", "VERIFY"];

/// Number of stages — always `STAGE_NAMES.len()`, hoisted to a `u8`
/// constant so every clamp/index computation below shares one source of
/// truth instead of re-deriving it.
const NUM_STAGES: u8 = STAGE_NAMES.len() as u8;

/// Header/footer band height (design doc §3.3/§3.4): both bands share
/// the same height for visual symmetry. Two [`LINE_PITCH`]s tall —
/// comfortably more than the single text row each band actually draws —
/// so [`content_top`]/[`content_bottom`] leave real breathing room below
/// the header and above the footer rather than hugging that one line.
const BAND_HEIGHT: u32 = LINE_PITCH * 2;

/// Vertical offset of each band's one text row: centers a `GLYPH_HEIGHT`
/// glyph row within [`BAND_HEIGHT`].
const ROW_Y: u32 = (BAND_HEIGHT - GLYPH_HEIGHT) / 2;

/// Horizontal pitch between consecutive stage-rail dots: one glyph cell
/// per dot plus one glyph cell of gap.
const DOT_PITCH: u32 = GLYPH_WIDTH * 2;

/// Total pixel width of the seven-dot stage rail, measured from the
/// first dot's left edge to the last dot's right edge.
const RAIL_WIDTH: u32 = DOT_PITCH * (NUM_STAGES as u32 - 1) + GLYPH_WIDTH;

/// Gap between the stage rail and the stage-name label that follows it.
const RAIL_LABEL_GAP: u32 = GLYPH_WIDTH;

/// The stage rail's "filled" (completed/current stage) dot glyph.
///
/// The embedded 8x16 font only covers ASCII `0x20..=0x7E` — no
/// bullet/circle codepoint is available (`draw_text`/`draw_glyph` render
/// anything outside that range as a blank cell, never a real bullet), so
/// the rail uses these two plain ASCII characters as stand-ins,
/// distinguished by color ([`theme::ACCENT`] filled, [`theme::CAPTION`]
/// upcoming) exactly as the design doc's `\u{25cf}`/`\u{25cb}` sketch
/// intended. Named constants (not inlined literals) so a later change to
/// a richer glyph — e.g. once the font gains a real bullet — is a
/// one-line edit with no effect on the rail's layout math.
const FILLED_DOT: u8 = b'o';
/// The stage rail's "upcoming" (not yet reached) dot glyph — see
/// [`FILLED_DOT`]'s doc comment for the ASCII-only rationale.
const UPCOMING_DOT: u8 = b'.';

/// Separator drawn between consecutive footer key hints.
const HINT_SEP: &str = " | ";

/// One screen's chrome identity: which stage the rail highlights, an
/// optional sub-label for a screen that branches off the main ceremony
/// (e.g. `"EXPORT"` for the Stage-7 `[X]` export branch), and the
/// caller-supplied build string (see the module doc comment — this crate
/// never imports a release/build-id constant itself).
pub struct Chrome {
    /// 1-based stage number. Clamped to `1..=7` by every rendering
    /// function in this module — an out-of-range value never panics and
    /// never indexes [`STAGE_NAMES`] out of bounds.
    pub stage: u8,
    /// Optional sub-label appended to the stage name, e.g. `"EXPORT"`.
    pub sub: Option<&'static str>,
    /// Caller-supplied build identifier string, shown in the header's
    /// left-hand block.
    pub build: &'static str,
}

/// One footer key hint: a key glyph, its verb-phrase label, whether the
/// action is currently reachable, and whether it is destructive (design
/// doc §3.3: "`ACCENT` `[K]` + 1x `TEXT` verb phrase. Disabled actions
/// render dimmed... Key hints are the only place key hints live").
pub struct KeyHint {
    /// The key glyph shown in brackets, e.g. `"Enter"`, `"V"`, `"Esc"`.
    pub key: &'static str,
    /// The verb-phrase label, e.g. `"Continue"`, `"Show/Hide addresses"`.
    pub label: &'static str,
    /// Whether this action can currently be taken. A disabled hint's key
    /// glyph renders in [`theme::ACCENT_DIM`] regardless of [`Self::danger`].
    pub enabled: bool,
    /// Whether this action is destructive (SPEC role palette:
    /// [`theme::DANGER`] "reserved exclusively for the destroy path and
    /// the fatal-failure chain"). Only visible when `enabled` is true —
    /// see [`draw_footer`]'s color selection.
    pub danger: bool,
}

/// Clamp a possibly out-of-range `stage` to the valid `1..=NUM_STAGES`
/// range and return its 0-based [`STAGE_NAMES`] index. Every entry point
/// in this module goes through this instead of indexing `stage - 1`
/// directly, so no caller-supplied `stage` value (including `0`) can
/// ever panic.
fn stage_index(stage: u8) -> usize {
    (stage.clamp(1, NUM_STAGES) - 1) as usize
}

/// Build the header's right-hand stage label, e.g. `"3/7 SETUP"`, or
/// `"7/7 VERIFY - EXPORT"` when [`Chrome::sub`] is `Some`.
fn stage_label(stage: u8, sub: Option<&str>) -> LineBuf {
    let idx = stage_index(stage);
    let mut buf = LineBuf::new();
    let _ = write!(buf, "{}/{} {}", idx + 1, NUM_STAGES, STAGE_NAMES[idx]);
    if let Some(sub) = sub {
        let _ = write!(buf, " - {sub}");
    }
    buf
}

/// The x origin of the stage rail's first dot, given the framebuffer
/// width and the already-built label's length: the whole
/// rail-gap-label block is right-aligned with [`MARGIN_X`] padding from
/// the right edge, computed dynamically (not a fixed reservation) so it
/// stays flush regardless of how long the stage name/sub-label is.
fn rail_x(fb_w: u32, label_len: usize) -> u32 {
    let label_w = (label_len as u32) * GLYPH_WIDTH;
    let block_w = RAIL_WIDTH + RAIL_LABEL_GAP + label_w;
    fb_w.saturating_sub(MARGIN_X + block_w)
}

/// The x origin of stage-rail dot `i` (`0..NUM_STAGES`), given the
/// rail's own origin from [`rail_x`].
fn dot_x(rail_x: u32, i: u32) -> u32 {
    rail_x + i * DOT_PITCH
}

/// Draw the header band: a full-width [`theme::PANEL`] fill,
/// [`theme::RULE`] hrule immediately under it, product name + build ID
/// left, seven-dot stage rail + current stage label right (design doc
/// §3.3).
pub fn draw_header(fb: &mut dyn Framebuffer, c: &Chrome) {
    let (fb_w, _fb_h) = fb.dims();

    panel::fill_rect(fb, 0, 0, fb_w, BAND_HEIGHT, theme::PANEL);
    panel::hrule(fb, 0, BAND_HEIGHT, fb_w);

    let mut left = LineBuf::new();
    let _ = write!(left, "{OPENING_TITLE}  {}", c.build);
    draw_text(fb, MARGIN_X, ROW_Y, left.as_str(), theme::on_panel(theme::TEXT));

    let label = stage_label(c.stage, c.sub);
    let rx = rail_x(fb_w, label.as_str().len());

    let stage = u32::from(c.stage.clamp(1, NUM_STAGES));
    for i in 0..u32::from(NUM_STAGES) {
        let (glyph, color) = if i < stage {
            (FILLED_DOT, theme::ACCENT)
        } else {
            (UPCOMING_DOT, theme::CAPTION)
        };
        draw_glyph(fb, dot_x(rx, i), ROW_Y, glyph, theme::on_panel(color));
    }

    draw_text(
        fb,
        rx + RAIL_WIDTH + RAIL_LABEL_GAP,
        ROW_Y,
        label.as_str(),
        theme::on_panel(theme::TEXT),
    );
}

/// Draw the footer key bar: a full-width [`theme::PANEL`] fill,
/// [`theme::RULE`] hrule immediately over it, and every hint in `hints`
/// left to right as `"[KEY] label"` separated by [`HINT_SEP`] (design
/// doc §3.3: "the *only* place key hints live"). A hint's key glyphs
/// render in [`theme::ACCENT_DIM`] when disabled, [`theme::DANGER`] when
/// enabled and destructive, [`theme::ACCENT`] otherwise; labels always
/// render in [`theme::CAPTION`].
pub fn draw_footer(fb: &mut dyn Framebuffer, hints: &[KeyHint]) {
    let (fb_w, fb_h) = fb.dims();
    let band_y = fb_h.saturating_sub(BAND_HEIGHT);
    let rule_y = band_y.saturating_sub(1);

    panel::hrule(fb, 0, rule_y, fb_w);
    panel::fill_rect(fb, 0, band_y, fb_w, BAND_HEIGHT, theme::PANEL);

    let text_y = band_y + ROW_Y;
    let mut x = MARGIN_X;
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            draw_text(fb, x, text_y, HINT_SEP, theme::on_panel(theme::CAPTION));
            x += (HINT_SEP.len() as u32) * GLYPH_WIDTH;
        }

        let key_color = if !hint.enabled {
            theme::ACCENT_DIM
        } else if hint.danger {
            theme::DANGER
        } else {
            theme::ACCENT
        };

        let mut key_buf = LineBuf::new();
        let _ = write!(key_buf, "[{}]", hint.key);
        draw_text(fb, x, text_y, key_buf.as_str(), theme::on_panel(key_color));
        x += (key_buf.as_str().len() as u32) * GLYPH_WIDTH;

        draw_text(fb, x, text_y, " ", theme::on_panel(theme::CAPTION));
        x += GLYPH_WIDTH;

        draw_text(fb, x, text_y, hint.label, theme::on_panel(theme::CAPTION));
        x += (hint.label.len() as u32) * GLYPH_WIDTH;
    }
}

/// Draw a "plain" header band for non-ceremony surfaces (design doc §5:
/// the production/desktop launcher landing menus, About, Self-check,
/// Learn, and the compat tools) where [`Chrome`]'s seven-dot ceremony
/// stage rail would be meaningless — none of those screens has a stage
/// to count toward. Same header band construction as [`draw_header`]
/// (full-width [`theme::PANEL`] fill, [`theme::RULE`] hrule immediately
/// under it, one text row vertically centered in [`BAND_HEIGHT`]) except
/// the right-hand block is `build` drawn flush right (no rail, no stage
/// label) instead of [`Chrome::sub`]/the stage rail, and the left-hand
/// block is caller-supplied `title` instead of the fixed
/// `OPENING_TITLE`/build pairing [`draw_header`] always uses — so a
/// launcher screen can show its own title (e.g. `"ALEA -- main menu"`)
/// rather than the ceremony's opening title.
pub fn draw_header_plain(fb: &mut dyn Framebuffer, title: &str, build: &str) {
    let (fb_w, _fb_h) = fb.dims();

    panel::fill_rect(fb, 0, 0, fb_w, BAND_HEIGHT, theme::PANEL);
    panel::hrule(fb, 0, BAND_HEIGHT, fb_w);

    draw_text(fb, MARGIN_X, ROW_Y, title, theme::on_panel(theme::TEXT));

    // Right-aligned with the same MARGIN_X padding from the right edge
    // draw_header's stage-rail block uses (see rail_x), computed
    // dynamically so it stays flush regardless of `build`'s length.
    let build_x = fb_w.saturating_sub(MARGIN_X + (build.len() as u32) * GLYPH_WIDTH);
    draw_text(fb, build_x, ROW_Y, build, theme::on_panel(theme::CAPTION));
}

/// First y pixel row below the header band (and its separating rule) —
/// every screen's own content starts here or later.
pub fn content_top() -> u32 {
    BAND_HEIGHT + 1
}

/// Last y pixel row above the footer band (and its separating rule) at
/// the SPEC §11.4 resolution floor ([`MIN_HEIGHT`]) — every screen's own
/// content must end at or before this row to avoid the footer.
pub fn content_bottom() -> u32 {
    MIN_HEIGHT - BAND_HEIGHT - 2
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Host-only `Vec<u32>` `Framebuffer` test double — same pattern as
    /// `seed_gop_ui::panel`'s own `VecFb`.
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

        /// Does any pixel in the `w`x`h` cell at `(x, y)` equal `color`?
        fn cell_contains(&self, x: u32, y: u32, w: u32, h: u32, color: u32) -> bool {
            (y..y + h).any(|py| {
                (x..x + w).any(|px| px < self.w && py < self.h && self.at(px, py) == color)
            })
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

    // -- draw_header: stage rail coloring -----------------------------

    #[test]
    fn header_stage_rail_marks_stage_dots_accent_rest_caption() {
        let stage = 3u8;
        let mut fb = VecFb::new(800, BAND_HEIGHT);
        let c = Chrome {
            stage,
            sub: None,
            build: "b1",
        };
        draw_header(&mut fb, &c);

        let label = stage_label(c.stage, c.sub);
        let rx = rail_x(800, label.as_str().len());

        for i in 0..u32::from(NUM_STAGES) {
            let x = dot_x(rx, i);
            let filled = fb.cell_contains(x, ROW_Y, GLYPH_WIDTH, GLYPH_HEIGHT, theme::ACCENT);
            let upcoming = fb.cell_contains(x, ROW_Y, GLYPH_WIDTH, GLYPH_HEIGHT, theme::CAPTION);
            if i < u32::from(stage) {
                assert!(filled, "dot {i} should be ACCENT (filled)");
                assert!(!upcoming, "dot {i} should not be CAPTION");
            } else {
                assert!(upcoming, "dot {i} should be CAPTION (upcoming)");
                assert!(!filled, "dot {i} should not be ACCENT");
            }
        }
    }

    #[test]
    fn header_stage_clamps_zero_and_above_max_without_panic() {
        let mut fb = VecFb::new(800, BAND_HEIGHT);
        draw_header(
            &mut fb,
            &Chrome {
                stage: 0,
                sub: None,
                build: "b",
            },
        );
        let mut fb2 = VecFb::new(800, BAND_HEIGHT);
        draw_header(
            &mut fb2,
            &Chrome {
                stage: 255,
                sub: None,
                build: "b",
            },
        );
    }

    #[test]
    fn header_sub_label_is_appended() {
        let mut fb_no_sub = VecFb::new(800, BAND_HEIGHT);
        draw_header(
            &mut fb_no_sub,
            &Chrome {
                stage: 7,
                sub: None,
                build: "b",
            },
        );
        let mut fb_sub = VecFb::new(800, BAND_HEIGHT);
        draw_header(
            &mut fb_sub,
            &Chrome {
                stage: 7,
                sub: Some("EXPORT"),
                build: "b",
            },
        );
        // Different sub-labels shift the right-aligned block to a
        // different x origin, so the two framebuffers must differ.
        assert_ne!(fb_no_sub.buf, fb_sub.buf);
    }

    // -- draw_header_plain: launcher/tool surfaces (no stage rail) -----

    #[test]
    fn header_plain_draws_the_panel_band_and_rule() {
        let mut fb = VecFb::new(800, BAND_HEIGHT + 4);
        draw_header_plain(&mut fb, "ALEA -- main menu", "b1");
        assert!(fb.cell_contains(0, 0, 800, BAND_HEIGHT, theme::PANEL));
        assert!(fb.cell_contains(0, BAND_HEIGHT, 800, 1, theme::RULE));
    }

    #[test]
    fn header_plain_title_renders_flush_left() {
        let mut fb = VecFb::new(800, BAND_HEIGHT);
        draw_header_plain(&mut fb, "ALEA -- main menu", "b1");
        // The title starts at MARGIN_X, in the on-PANEL TEXT role -- a
        // pixel of that color must appear at the left margin's glyph row.
        assert!(fb.cell_contains(MARGIN_X, ROW_Y, GLYPH_WIDTH, GLYPH_HEIGHT, theme::TEXT));
    }

    #[test]
    fn header_plain_build_renders_flush_right_and_shifts_with_its_length() {
        let mut fb_short = VecFb::new(800, BAND_HEIGHT);
        draw_header_plain(&mut fb_short, "Title", "b1");
        let mut fb_long = VecFb::new(800, BAND_HEIGHT);
        draw_header_plain(&mut fb_long, "Title", "build-0000000000");
        // A longer build string pushes its own left edge further left (it
        // stays right-aligned to the same margin), so the two
        // framebuffers must differ -- same property draw_header's own
        // header_sub_label_is_appended test pins for the stage label.
        assert_ne!(fb_short.buf, fb_long.buf);
    }

    #[test]
    fn header_plain_never_paints_accent_no_stage_rail_to_highlight() {
        // draw_header colors a "filled" rail dot in ACCENT for every
        // completed/current stage (header_stage_rail_marks_stage_dots_
        // accent_rest_caption, above). draw_header_plain has no stage
        // concept at all -- title is TEXT, build is CAPTION, band is
        // PANEL/RULE -- so ACCENT must never appear, proving there is no
        // rail (filled or otherwise) hiding in this header.
        let mut fb = VecFb::new(800, BAND_HEIGHT);
        draw_header_plain(&mut fb, "Title", "b1");
        assert!(!fb.cell_contains(0, 0, 800, BAND_HEIGHT, theme::ACCENT));
    }

    #[test]
    fn header_plain_does_not_panic_on_empty_strings_or_tiny_framebuffer() {
        let mut fb = VecFb::new(4, BAND_HEIGHT);
        draw_header_plain(&mut fb, "", "");
    }

    // -- draw_footer: key hint coloring --------------------------------

    #[test]
    fn footer_disabled_hint_key_glyphs_are_accent_dim() {
        let mut fb = VecFb::new(800, 600);
        let hints = [KeyHint {
            key: "Enter",
            label: "Begin",
            enabled: false,
            danger: false,
        }];
        draw_footer(&mut fb, &hints);

        let band_y = 600 - BAND_HEIGHT;
        assert!(
            fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT_DIM),
            "disabled hint must render its key glyphs in ACCENT_DIM"
        );
        assert!(
            !fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT),
            "disabled hint must not render in plain ACCENT"
        );
        assert!(
            !fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::DANGER),
            "disabled hint must not render in DANGER"
        );
    }

    #[test]
    fn footer_danger_hint_key_glyphs_are_danger() {
        let mut fb = VecFb::new(800, 600);
        let hints = [KeyHint {
            key: "X",
            label: "Destroy",
            enabled: true,
            danger: true,
        }];
        draw_footer(&mut fb, &hints);

        let band_y = 600 - BAND_HEIGHT;
        assert!(
            fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::DANGER),
            "enabled danger hint must render its key glyphs in DANGER"
        );
        assert!(
            !fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT),
            "enabled danger hint must not render in plain ACCENT"
        );
        assert!(
            !fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT_DIM),
            "enabled danger hint must not render in ACCENT_DIM"
        );
    }

    #[test]
    fn footer_enabled_non_danger_hint_key_glyphs_are_accent() {
        let mut fb = VecFb::new(800, 600);
        let hints = [KeyHint {
            key: "Enter",
            label: "Continue",
            enabled: true,
            danger: false,
        }];
        draw_footer(&mut fb, &hints);

        let band_y = 600 - BAND_HEIGHT;
        assert!(fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT));
        assert!(!fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::DANGER));
        assert!(!fb.cell_contains(0, band_y, 800, BAND_HEIGHT, theme::ACCENT_DIM));
    }

    #[test]
    fn footer_empty_hints_does_not_panic() {
        let mut fb = VecFb::new(800, 600);
        draw_footer(&mut fb, &[]);
    }

    // -- content_top / content_bottom -----------------------------------

    #[test]
    fn content_top_leaves_at_least_two_line_pitches() {
        assert!(content_top() >= LINE_PITCH * 2);
    }

    #[test]
    fn content_bottom_is_below_content_top_and_above_min_height() {
        assert!(content_bottom() > content_top());
        assert!(content_bottom() < MIN_HEIGHT);
    }

    // -- footer fit budget (Stage-7 hint set, design doc §4 Stage 7) ----

    /// `[Enter] Finish | [V] Show/Hide addresses | [M] Grid | [B] Custom
    /// path | [X] Export xpub` — the exact Stage-7 Verify-screen hint set
    /// from the design doc (§4, Stage 7 footer). Exercised here purely as
    /// a string-length budget check (this module doesn't own that
    /// screen's rendering — Task 15 does), matching the brief's "footer
    /// fits >= 5 hints in MAX_COLS_AT_FLOOR columns" requirement.
    const STAGE_7_HINTS: [KeyHint; 5] = [
        KeyHint {
            key: "Enter",
            label: "Finish",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "V",
            label: "Show/Hide addresses",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "M",
            label: "Grid",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "B",
            label: "Custom path",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "X",
            label: "Export xpub",
            enabled: true,
            danger: false,
        },
    ];

    /// Column width [`draw_footer`] actually consumes for `hints`: exact
    /// mirror of its `x`-advance arithmetic, so this test tracks the real
    /// rendering budget rather than a hand-maintained duplicate estimate.
    fn footer_cols(hints: &[KeyHint]) -> usize {
        let mut cols = 0usize;
        for (i, hint) in hints.iter().enumerate() {
            if i > 0 {
                cols += HINT_SEP.len();
            }
            cols += hint.key.len() + 2; // "[" + key + "]"
            cols += 1; // space
            cols += hint.label.len();
        }
        cols
    }

    #[test]
    fn stage_7_hint_set_fits_max_cols_at_floor() {
        assert!(STAGE_7_HINTS.len() >= 5);
        let cols = footer_cols(&STAGE_7_HINTS);
        assert!(
            cols <= seed_gop_ui::layout::MAX_COLS_AT_FLOOR,
            "Stage-7 footer hint set is {cols} columns, budget is {}",
            seed_gop_ui::layout::MAX_COLS_AT_FLOOR
        );
    }
}
