//! Shared screen-layout constants (SPEC §12.1, §12.2): the fixed left
//! margin, line pitch and foreground/background style every GOP-rendered
//! text screen in this workspace uses.
//!
//! Before this module existed, three call sites each hand-derived the
//! same pair of numbers from [`crate::font::GLYPH_WIDTH`]/
//! [`crate::font::GLYPH_HEIGHT`] independently: `seed-flow`'s
//! `flow_secret::gop_screen` (the post-secret screens, SPEC §12.2),
//! `seed-flow`'s `output::FbTextOutput` (SPEC.md amendment 2026-08-06:
//! every pre-secret AND secret-phase-pre-`MnemonicDisplay` screen, both
//! UEFI editions) and `seed-desktop-test`'s `shared_screen::
//! WindowTextOutput` (that edition's own equivalent, over a `std`-backed
//! framebuffer). Hoisting the numbers here means all three now agree by
//! construction rather than by three independently-maintained copies —
//! every screen in the whole product lays out identically regardless of
//! which of the three renders it.
use crate::font::{GLYPH_HEIGHT, GLYPH_WIDTH};
use crate::gop::mode::{MIN_HEIGHT, MIN_WIDTH};
use seed_core::contracts::Style;

/// Fixed left margin (and, for cursor-based renderers, the top margin
/// too — see each caller's own use) every screen in this workspace draws
/// text from.
pub const MARGIN_X: u32 = GLYPH_WIDTH * 2;

/// Left pixel origin of the fixed 6x4 BIP39 word-slot grid
/// (`font::draw_word`, SPEC §12.2 "Fixed layouts") — aligned with
/// [`MARGIN_X`] so the Stage-6 BACKUP screen's grid sits inside the
/// redesigned shell's content margins (design doc §4 Stage 6).
pub const WORD_GRID_LEFT: u32 = MARGIN_X;

/// Top pixel origin of the word-slot grid: clears the chrome header band
/// (`seed-flow`'s `chrome::BAND_HEIGHT` = 2 x [`LINE_PITCH`] = 48px, plus
/// its 1px rule) AND one 2x-scale title row with breathing room. A
/// reviewed fixed constant (SPEC §12.2), asserted against the chrome
/// geometry by `seed-flow`'s Stage-6 fit audit rather than imported from
/// it (dependency direction: `seed-flow` -> this crate).
pub const WORD_GRID_TOP: u32 = 112;

/// Vertical distance between consecutive text lines — one and a half
/// glyph cells, giving comfortable line spacing without wasting vertical
/// space at the 800x600 resolution floor.
pub const LINE_PITCH: u32 = GLYPH_HEIGHT + GLYPH_HEIGHT / 2;

/// Foreground/background style shared by every screen in this workspace
/// (SPEC §12.2: fixed rendering routines, no per-caller color logic).
/// Colors are named roles (SPEC §3.1) — see [`crate::theme`].
pub const SCREEN_STYLE: Style = Style {
    fg: crate::theme::TEXT,
    bg: crate::theme::BG,
};

/// Max text lines any GOP-rendered screen may emit without running off the
/// bottom edge of the SPEC §11.4 minimum resolution floor
/// ([`crate::gop::mode::MIN_WIDTH`]/[`MIN_HEIGHT`]) -- unlike firmware
/// `SimpleTextOut`, [`crate::gop::framebuffer::LinearFramebuffer::put_row`]
/// clips silently at the framebuffer edge rather than scrolling, so a
/// screen that emits more than this many lines loses content with no
/// error. Single source of truth for both the `seed-flow` fit-audit host
/// test and any renderer (e.g. the SPEC_EDU_UI composition panel) that
/// paginates its own content to this budget rather than relying on the
/// audit alone to catch an overflow after the fact.
pub const MAX_LINES_AT_FLOOR: usize = ((MIN_HEIGHT - 2 * MARGIN_X) / LINE_PITCH) as usize;

/// Max text columns (fixed-width glyph cells) any GOP-rendered screen may
/// emit without clipping at the right edge of the SPEC §11.4 minimum
/// resolution floor -- see [`MAX_LINES_AT_FLOOR`]'s own doc comment for why
/// this matters (silent clipping, not wrapping). Prose lines are expected
/// to already be word-wrapped to 80 columns (`seed-flow`'s own
/// `text::PROSE_WRAP_COLS`) before reaching a [`crate::font::draw_text`]
/// call, which comfortably fits this wider budget.
pub const MAX_COLS_AT_FLOOR: usize = ((MIN_WIDTH - 2 * MARGIN_X) / GLYPH_WIDTH) as usize;
