//! The role palette (SPEC §3.1): "Every drawn color is a named role.
//! Callers never pass raw pixel values, so SPEC §12.2's 'no per-caller
//! color logic' survives as 'color only via roles'."
//!
//! This module is the *only* place a `0x00RR_GGBB`-shaped color literal
//! may appear anywhere in `seed-gop-ui`, `seed-flow` or
//! `seed-desktop-test` — enforced by the `no_raw_colors` host test
//! (`crates/seed-gop-ui/tests/no_raw_colors.rs`), which walks all three
//! crates' `src/` trees. Every caller reaches these colors by name, not
//! by value.

use seed_core::contracts::Style;

/// Screen ground (SPEC §3.1: "screen ground (unchanged)"). Same value the
/// pre-redesign `layout::SCREEN_STYLE` used for its background.
pub const BG: u32 = 0x0000_0000;

/// Body text and values (SPEC §3.1). Replaces the pre-redesign
/// `layout::SCREEN_STYLE` foreground (`0x00FF_FFFF` pure white).
pub const TEXT: u32 = 0x00E6_EDF3;

/// Explainers, de-emphasis, slot numbers (SPEC §3.1).
pub const CAPTION: u32 = 0x007A_8794;

/// Key hints, selection, interactive affordances (SPEC §3.1). `ACCENT`-
/// on-`BG` exceeds WCAG-AA contrast at 8x16 (SPEC §3.1).
pub const ACCENT: u32 = 0x0053_D6E5;

/// Reduced-intensity `ACCENT`, for disabled footer-key-bar actions (SPEC
/// §3.3: "Disabled actions render dimmed (`ACCENT` at reduced intensity
/// constant, e.g. `0x002E_5B63`)").
pub const ACCENT_DIM: u32 = 0x002E_5B63;

/// Warnings, irreversibility notices (SPEC §3.1). `WARN`-on-`BG` exceeds
/// WCAG-AA contrast at 8x16 (SPEC §3.1).
pub const WARN: u32 = 0x00F2_B94E;

/// Destroy/failure paths only (SPEC §3.1): "`DANGER` is reserved
/// exclusively for the destroy path and the fatal-failure chain, so red
/// on screen always means 'destructive'."
pub const DANGER: u32 = 0x00F0_625D;

/// Checks passed, match confirmed (SPEC §3.1).
pub const OK: u32 = 0x0057_D98A;

/// Panel fills (SPEC §3.1). `TEXT`-on-`PANEL` exceeds WCAG-AA contrast at
/// 8x16 (SPEC §3.1).
pub const PANEL: u32 = 0x000D_1319;

/// Separators, panel borders (SPEC §3.1).
pub const RULE: u32 = 0x001E_2830;

/// Light modules and quiet zone of a rendered QR symbol
/// (`crate::qr::draw_qr`): pure white, deliberately outside the §3.1 role
/// palette above.
///
/// A QR symbol is not screen decoration — it is a machine-readable
/// artifact whose decode margin depends on maximum luminance contrast
/// between its two module colors and on a quiet zone that is the *same*
/// color as the light modules. The palette's `TEXT`/`BG` pair is tuned for
/// glyph legibility, not for a camera's binarization threshold, so the QR
/// renderer gets its own two-value pair. They live here, and only here,
/// because the raw-color-literal ban leaves nowhere else for them
/// (`no_raw_colors` host test).
pub const QR_LIGHT: u32 = 0x00FF_FFFF;

/// Dark modules of a rendered QR symbol — pure black; see [`QR_LIGHT`] for
/// why the QR renderer does not use the §3.1 roles. Numerically equal to
/// [`BG`] today, but semantically independent: `BG` may be re-tuned as a
/// screen ground without silently changing a scannability property.
pub const QR_DARK: u32 = 0x0000_0000;

/// The desktop test edition's permanent SPEC §4.3 watermark ("Watermarks
/// unchanged and permanent" — SPEC amendment 2026-08-07): bright yellow
/// on dark red, deliberately outside the §3.1 role palette above so the
/// watermark reads as a fixed alarm banner rather than part of the
/// ceremony's own visual language. Same numeric value the pre-redesign
/// `seed-desktop-test::window::WATERMARK_STYLE` literal used; kept here,
/// unrelated to any role, only because the raw-color-literal ban leaves
/// nowhere else for it to live.
pub const WATERMARK: Style = Style {
    fg: 0x00FF_FF00,
    bg: 0x0040_0000,
};

/// A style with the given foreground on the screen ground ([`BG`]).
pub const fn on_bg(fg: u32) -> Style {
    Style { fg, bg: BG }
}

/// A style with the given foreground on a panel fill ([`PANEL`]).
pub const fn on_panel(fg: u32) -> Style {
    Style { fg, bg: PANEL }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_bg_uses_screen_ground() {
        assert_eq!(on_bg(TEXT), Style { fg: TEXT, bg: BG });
    }

    #[test]
    fn on_panel_uses_panel_fill() {
        assert_eq!(on_panel(TEXT), Style { fg: TEXT, bg: PANEL });
    }
}
