//! The Stage-7 `[X]` export branch's **gate**: a full-screen `WARN` panel
//! that states, in plain language, what an account extended public key is
//! and what showing one costs, before any of it is rendered
//! (`docs/superpowers/specs/2026-08-07-wallet-export-design.md` D8/§3
//! step 2: "Entry is deliberate... Never ambient on any default screen").
//!
//! This screen exists so that the export is a *chosen act*. The design
//! considered making the xpub ambient on the verification screen and
//! rejected it; the consequence — an artifact that links every address in
//! one account, forever, to anyone who photographs it — is not something a
//! user can un-see, so it is spelled out before it appears, not after.
//!
//! # Leak posture
//!
//! This module holds **no values at all**: it has no fields, takes no
//! derived data, and every string it draws is a `const` in this file.
//! It is one of exactly two modules (with [`crate::screens::export`]) in
//! which the literal `xpub` is permitted in a rendered line — the
//! leak-scope test in `tests/leakage` enumerates that allowlist, and
//! `xprv`/`private key`/`chain code` remain banned here with no allowlist
//! at all, as they are everywhere else. Naming `xpub` here is the whole
//! point of the screen: a user who has never met the term cannot consent
//! to displaying one.
//!
//! All copy is plain ASCII (the embedded 8x16 font covers `0x20..=0x7E`).

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text, draw_text_scaled, GLYPH_HEIGHT};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::{panel, theme};
use seed_platform_x86::input::InputEvent;

use crate::chrome::{self, Chrome, KeyHint};

// ============================================================================
// Copy (wallet-export design §3, step 2)
// ============================================================================

/// 1-based ceremony stage this screen belongs to: it is a branch off
/// Stage 7, and the header's stage rail says so.
pub const STAGE: u8 = 7;

/// Header sub-label for the whole export branch.
pub const SUB: &str = "EXPORT";

/// The panel heading, drawn 2x in [`theme::WARN`].
pub const HEADING: &str = "BEFORE YOU EXPORT";

/// Body copy, in draw order. `""` is a half-height separator row.
///
/// Each line states one of the four things the design doc requires this
/// screen to say: what the artifact is, that it cannot spend, that it
/// links the whole account forever, and who it may be shared with. The
/// closing pair restates the one thing that is *not* on the next screen,
/// because "export" is exactly the word a user might fear means "my seed
/// leaves the device".
pub const BODY: [&str; 10] = [
    "The next screen shows an account extended public key (xpub) and an",
    "output descriptor built from it. Both are PUBLIC data.",
    "",
    "They contain no private key. Nobody can spend your coins with them.",
    "",
    "They link every address in this account. Anyone who scans or",
    "photographs them can watch your balance and history forever.",
    "",
    "Share them only with your own watch-only wallet or your multisig",
    "coordinator.",
];

/// The closing reassurance, drawn under the body in [`theme::OK`].
pub const REASSURANCE: &str =
    "Your seed words are never shown here, never encoded in a QR, and never leave this device.";

/// This screen's footer key set.
pub const HINTS: [KeyHint; 2] = [
    KeyHint { key: "Enter", label: "Show the export", enabled: true, danger: false },
    KeyHint { key: "Esc", label: "Back to verify", enabled: true, danger: false },
];

// ============================================================================
// State
// ============================================================================

/// What the user decided at the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningOutcome {
    /// `[Enter]` — proceed to [`crate::screens::export`].
    Proceed,
    /// `[Esc]` — return to the Verify screen; nothing is derived, nothing
    /// is shown.
    Back,
}

/// Fold one keystroke into the gate. Returns `None` for any key that is
/// neither of the two documented answers — in particular there is no
/// "any key continues" path, so a stray keypress cannot walk a user
/// through this screen without reading it.
///
/// Stateless by construction (no `self`): this screen has nothing to
/// remember, and having no state means there is no way to arrive at the
/// export screen with the gate "already answered".
#[must_use]
pub fn handle_key(k: InputEvent) -> Option<WarningOutcome> {
    match k {
        InputEvent::Enter => Some(WarningOutcome::Proceed),
        InputEvent::Escape => Some(WarningOutcome::Back),
        _ => None,
    }
}

// ============================================================================
// Layout
// ============================================================================

/// Height of one 1x content row.
const ROW_1X: u32 = LINE_PITCH;

/// Height of the 2x heading row (2x glyph box + the same leading a 1x row
/// carries, so both scales share one vertical rhythm).
const ROW_2X: u32 = GLYPH_HEIGHT * 2 + (LINE_PITCH - GLYPH_HEIGHT);

/// Height of a blank separator row.
const GAP: u32 = LINE_PITCH / 2;

/// Padding between the panel border and its content.
const PAD: u32 = LINE_PITCH / 2;

/// Total height of the panel: padding, heading, body, a gap, the
/// reassurance line, padding.
const PANEL_H: u32 = PAD * 2 + ROW_2X + body_height() + GAP + ROW_1X;

/// Vertical space [`BODY`] consumes (`""` entries are half-height).
const fn body_height() -> u32 {
    let mut total = 0;
    let mut i = 0;
    while i < BODY.len() {
        total += if BODY[i].is_empty() { GAP } else { ROW_1X };
        i += 1;
    }
    total
}

/// Draw the gate: the chrome shell, one full-width `WARN` panel holding
/// every line of copy, and the two-key footer.
///
/// Clears the framebuffer first (SPEC §12.2): the Verify screen's own
/// content would otherwise show through around the panel.
pub fn render(fb: &mut dyn Framebuffer, build: &'static str) {
    seed_gop_ui::font::scrub_fill(fb, theme::BG);
    chrome::draw_header(fb, &Chrome { stage: STAGE, sub: Some(SUB), build });

    let (fb_w, _) = fb.dims();
    let panel_w = fb_w.saturating_sub(MARGIN_X * 2);
    let panel_y = chrome::content_top();
    panel::warn_panel(fb, MARGIN_X, panel_y, panel_w, PANEL_H);

    let x = MARGIN_X + PAD;
    let mut y = panel_y + PAD;

    draw_text_scaled(fb, x, y, HEADING, theme::on_panel(theme::WARN), 2);
    y += ROW_2X;

    for line in BODY {
        if line.is_empty() {
            y += GAP;
            continue;
        }
        draw_text(fb, x, y, line, theme::on_panel(theme::TEXT));
        y += ROW_1X;
    }

    y += GAP;
    draw_text(fb, x, y, REASSURANCE, theme::on_panel(theme::OK));

    chrome::draw_footer(fb, &HINTS);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::path::PathBuf;
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
        let mut out = std::vec![HEADING.to_string()];
        for line in BODY {
            if !line.is_empty() {
                out.push(line.to_string());
            }
        }
        out.push(REASSURANCE.to_string());
        out
    }

    // -- key handling ---------------------------------------------------

    #[test]
    fn enter_proceeds_and_escape_goes_back() {
        assert_eq!(handle_key(InputEvent::Enter), Some(WarningOutcome::Proceed));
        assert_eq!(handle_key(InputEvent::Escape), Some(WarningOutcome::Back));
    }

    /// No "any key continues": the gate must be answered deliberately
    /// (wallet-export design D8).
    #[test]
    fn no_other_key_leaves_the_gate() {
        for k in [
            InputEvent::Backspace,
            InputEvent::Other,
            InputEvent::Char('x'),
            InputEvent::Char('y'),
            InputEvent::Char(' '),
            InputEvent::Char('\r'),
        ] {
            assert_eq!(handle_key(k), None, "{k:?} must not answer the gate");
        }
    }

    // -- copy -----------------------------------------------------------

    /// The four things the design doc (§3, step 2) requires this screen to
    /// say, each pinned to the phrase that says it.
    #[test]
    fn copy_states_every_required_consequence() {
        let joined = screen_lines().join(" ").to_lowercase();
        assert!(joined.contains("no private key"), "must say it holds no private key");
        assert!(joined.contains("spend"), "must say it cannot spend");
        assert!(
            joined.contains("link every address in this account"),
            "must say it links the whole account"
        );
        assert!(joined.contains("forever"), "must say the linkage is permanent");
        assert!(joined.contains("photograph"), "must name the photograph/scan threat");
        assert!(
            joined.contains("watch-only wallet") && joined.contains("coordinator"),
            "must say who it may be shared with"
        );
        assert!(joined.contains("seed words are never shown"), "must reassure about the seed");
    }

    /// This screen is one of the two places the literal `xpub` may be
    /// drawn — it has to name the thing to obtain consent. The
    /// xprv-class bans still apply here with no allowlist.
    #[test]
    fn names_xpub_but_never_an_xprv_class_artifact() {
        let joined = screen_lines().join(" ").to_lowercase();
        assert!(joined.contains("xpub"), "the gate must name what is about to be shown");
        for bad in ["xprv", "chain code", "pubkey", "seed phrase"] {
            assert!(!joined.contains(bad), "copy must never mention {bad:?}");
        }
        // "no private key" is the only permitted use of the phrase, and
        // it is a denial: assert the phrase never appears except negated.
        for line in screen_lines() {
            let lower = line.to_lowercase();
            if let Some(at) = lower.find("private key") {
                assert!(
                    lower[..at].ends_with("no "),
                    "line {line:?} mentions a private key other than to deny one"
                );
            }
        }
    }

    #[test]
    fn all_copy_is_printable_ascii_and_fits_the_floor() {
        let panel_cols =
            ((MIN_WIDTH - 2 * MARGIN_X - 2 * PAD) / seed_gop_ui::font::GLYPH_WIDTH) as usize;
        let mut all = screen_lines();
        for hint in &HINTS {
            all.push(hint.key.to_string());
            all.push(hint.label.to_string());
        }
        for line in &all {
            for ch in line.chars() {
                assert!((' '..='~').contains(&ch), "line {line:?} has non-renderable {ch:?}");
            }
        }
        // The heading renders 2x, everything else 1x.
        assert!(HEADING.len() * 2 <= panel_cols, "heading overflows the panel at 2x");
        for line in screen_lines().iter().skip(1) {
            assert!(line.len() <= panel_cols, "line {line:?} is {} cols, budget {panel_cols}", line.len());
        }
    }

    #[test]
    fn footer_fits_the_floor() {
        const HINT_SEP_LEN: usize = 3; // " | "
        let mut cols = 0usize;
        for (i, hint) in HINTS.iter().enumerate() {
            if i > 0 {
                cols += HINT_SEP_LEN;
            }
            cols += hint.key.len() + 2 + 1 + hint.label.len();
        }
        assert!(cols <= MAX_COLS_AT_FLOOR, "footer is {cols} columns");
    }

    // -- fit ------------------------------------------------------------

    #[test]
    fn panel_fits_between_the_chrome_bands() {
        let bottom = chrome::content_top() + PANEL_H;
        assert!(
            bottom <= chrome::content_bottom(),
            "panel ends at y={bottom}, footer starts at {}",
            chrome::content_bottom()
        );
    }

    // -- rendering ------------------------------------------------------

    #[test]
    fn render_draws_a_warn_panel_and_the_shell() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        render(&mut fb, BUILD);
        assert!(fb.contains(theme::WARN), "the panel border + heading must be WARN");
        assert!(fb.contains(theme::PANEL), "panel fill + chrome bands must render");
        assert!(fb.contains(theme::ACCENT), "footer key glyphs must render");
        assert!(fb.contains(theme::OK), "the reassurance line must render in OK");
    }

    #[test]
    fn render_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let residue: Vec<u32> = std::vec![theme::WATERMARK.fg; 40];
        let mid = MIN_HEIGHT / 2;
        fb.put_row(MIN_WIDTH - 40, mid, &residue);
        render(&mut fb, BUILD);
        for x in (MIN_WIDTH - 40)..MIN_WIDTH {
            assert_ne!(
                fb.buf[(mid as usize) * (MIN_WIDTH as usize) + (x as usize)],
                theme::WATERMARK.fg,
                "residual pixel at x={x} was not cleared"
            );
        }
    }

    /// Structural half of the leak posture: this module's production code
    /// names no secret-bearing type and no derived-value type at all, so
    /// nothing derived can reach a drawn line however the code is edited.
    #[test]
    fn module_never_names_a_value_bearing_type() {
        let this_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("screens")
            .join("export_warning.rs");
        let text = std::fs::read_to_string(&this_file).expect("read own source");
        let prod = &text[..text.find("#[cfg(test)]").expect("test module marker")];
        for banned in
            ["SecretArena", "WordCount", "mnemonic_indexes", "AccountPublic", "ExportValues"]
        {
            assert!(!prod.contains(banned), "export_warning.rs must never reference {banned}");
        }
    }
}
