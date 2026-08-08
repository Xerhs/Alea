//! Stage 2 — DEVICE (design doc §4.2, "Stage 2 — DEVICE (was 3 screens +
//! auto-gates -> 1 + test + 1 transient)"): the combined display-confirm
//! + keyboard-test-offer screen.
//!
//! Replaces the old three-screen sequence (display confirmation, keyboard
//! self-test offer, skip-acknowledgement) with one screen offering three
//! actions: `[Enter]` run the 34-step keyboard self-test (recommended),
//! `[S]` skip it (a first `[S]` arms an inline `WARN` line instead of a
//! separate acknowledgement screen; a second `[S]` confirms the skip —
//! any other key disarms), `[N]` decline ("not my display" — the SPEC
//! §11.4 decline path, which fails the graphics/keyboard gate closed).
//!
//! It also carries the SPEC §11.4 "display its resolution and device path
//! before generation" requirement: this module is the product's ONLY
//! renderer of those two lines.
//!
//! This module is pure state ([`DeviceState`]) plus renderers — no key
//! source, no I/O. The caller (the flow driver) owns the actual blocking
//! read loop and feeds each key to [`DeviceState::handle_key`].

use core::fmt::Write as _;

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text, scrub_fill};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::theme;
use seed_platform_x86::input::InputEvent as Key;

use crate::chrome::{content_top, draw_footer, draw_header, Chrome, KeyHint};
use crate::diagnostics::GraphicsInfo;
use crate::output::LineBuf;

/// SPEC §11.4's exact local-display confirmation question — the single
/// definition of it in the workspace (the firmware-text-console renderer
/// that used to carry its own copy is gone).
pub const DISPLAY_QUESTION: &str = "Does this correspond to your local physical display?";

/// Label prefix of the SPEC §11.4 resolution line. SPEC §11.4: "Display
/// its resolution and device path before generation" — re-ratified
/// verbatim by the 2026-08-06 amendment. This screen is the ONLY place
/// that requirement is now satisfied, so the two lines below are as
/// load-bearing as the question itself: the user is being asked to judge
/// whether this is their local display, and these are the machine-checked
/// facts they judge it with.
pub const RESOLUTION_LABEL: &str = "Resolution:";

/// Label prefix of the SPEC §11.4 device-path line — see
/// [`RESOLUTION_LABEL`].
pub const DEVICE_PATH_LABEL: &str = "Device path:";

/// Build the SPEC §11.4 resolution line, e.g. `"Resolution: 1920x1080"`.
/// Shared by [`render`] and its tests so no test can assert against a
/// second copy of the formatting.
#[must_use]
pub fn resolution_line(info: &GraphicsInfo) -> LineBuf {
    let mut buf = LineBuf::new();
    let _ = write!(buf, "{RESOLUTION_LABEL} {}x{}", info.width, info.height);
    buf
}

/// Build the SPEC §11.4 device-path line, e.g.
/// `"Device path: PciRoot(0x0)/Pci(0x2,0x0)"` — see [`resolution_line`].
#[must_use]
pub fn device_path_line(info: &GraphicsInfo) -> LineBuf {
    let mut buf = LineBuf::new();
    let _ = write!(buf, "{DEVICE_PATH_LABEL} {}", info.device_path.as_str());
    buf
}

/// Design doc §4.2 inline skip-acknowledgement copy, verbatim: shown
/// once the first `[S]` arms the skip (replacing the old full
/// skip-acknowledgement screen with this one inline line).
pub const SKIP_WARNING: &str =
    "Skipping leaves typos undetectable during re-entry - press [S] again to confirm";

/// First line of the keyboard-test-offer copy.
pub const OFFER_LINE_1: &str =
    "Recommended: run a quick 34-key keyboard-layout self-test before continuing,";
/// Second line of the keyboard-test-offer copy.
pub const OFFER_LINE_2: &str = "so a typo during hidden re-entry is caught now instead of then.";

/// What the user chose at this screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceOutcome {
    /// `[Enter]` — run the keyboard self-test now.
    RunTest,
    /// `[S]` pressed twice — skip the test, acknowledged.
    SkipConfirmed,
    /// `[N]` — this is not the local physical display (existing decline
    /// path, SPEC §11.4).
    NotMyDisplay,
}

/// Live state for this screen: whether the first `[S]` has armed the
/// inline skip-confirmation (design doc §4.2's two-press inline form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceState {
    pub skip_armed: bool,
}

impl DeviceState {
    /// A fresh, unarmed screen state.
    #[must_use]
    pub const fn new() -> Self {
        Self { skip_armed: false }
    }

    /// Feed one keystroke. Returns `Some` once the user has made a
    /// terminal choice (run the test, confirm the skip, or decline the
    /// display); returns `None` while the screen is still waiting
    /// (including the "armed, waiting for the confirming `[S]`" state).
    ///
    /// - `[Enter]` always returns [`DeviceOutcome::RunTest`] (and
    ///   disarms any pending skip-arm — Enter is not the confirming
    ///   keystroke for skip).
    /// - First `[S]`/`[s]`: arms (`skip_armed = true`), returns `None`.
    /// - Second consecutive `[S]`/`[s]` (while armed): returns
    ///   [`DeviceOutcome::SkipConfirmed`].
    /// - `[N]`/`[n]`: returns [`DeviceOutcome::NotMyDisplay`] (disarms).
    /// - Any other key: disarms without returning an outcome — design
    ///   doc §4.2's two-press form requires the *second* press to be
    ///   `[S]` specifically, so anything else resets the arm rather than
    ///   silently keeping it live.
    pub fn handle_key(&mut self, k: Key) -> Option<DeviceOutcome> {
        match k {
            Key::Enter => {
                self.skip_armed = false;
                Some(DeviceOutcome::RunTest)
            }
            Key::Char(c) if c.eq_ignore_ascii_case(&'s') => {
                if self.skip_armed {
                    self.skip_armed = false;
                    Some(DeviceOutcome::SkipConfirmed)
                } else {
                    self.skip_armed = true;
                    None
                }
            }
            Key::Char(c) if c.eq_ignore_ascii_case(&'n') => {
                self.skip_armed = false;
                Some(DeviceOutcome::NotMyDisplay)
            }
            _ => {
                self.skip_armed = false;
                None
            }
        }
    }
}

/// Render this screen (design doc §4.2): [`crate::chrome`] header for
/// Stage 2/DEVICE, the SPEC §11.4 resolution + device-path lines, the
/// display-confirm question, the keyboard-test-offer copy, the inline
/// [`SKIP_WARNING`] line when `st.skip_armed`, and the footer key bar for
/// all three actions.
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this screen
/// follows the transient auto-gate checklist and, on a Back from Stage 3,
/// the Setup screen — either would otherwise show through around this
/// screen's shorter content.
pub fn render(fb: &mut dyn Framebuffer, st: &DeviceState, info: &GraphicsInfo, build: &'static str) {
    scrub_fill(fb, theme::BG);
    let chrome = Chrome {
        stage: 2,
        sub: None,
        build,
    };
    draw_header(fb, &chrome);

    let mut y = content_top();
    // SPEC §11.4: "Display its resolution and device path before
    // generation." Drawn ABOVE the question so the facts precede the
    // judgement the user is being asked to make about them.
    draw_text(fb, MARGIN_X, y, resolution_line(info).as_str(), theme::on_bg(theme::TEXT));
    y += LINE_PITCH;
    draw_text(fb, MARGIN_X, y, device_path_line(info).as_str(), theme::on_bg(theme::TEXT));
    y += LINE_PITCH * 2;

    draw_text(fb, MARGIN_X, y, DISPLAY_QUESTION, theme::on_bg(theme::TEXT));
    y += LINE_PITCH * 2;

    draw_text(fb, MARGIN_X, y, OFFER_LINE_1, theme::on_bg(theme::CAPTION));
    y += LINE_PITCH;
    draw_text(fb, MARGIN_X, y, OFFER_LINE_2, theme::on_bg(theme::CAPTION));
    y += LINE_PITCH * 2;

    if st.skip_armed {
        draw_text(fb, MARGIN_X, y, SKIP_WARNING, theme::on_bg(theme::WARN));
    }

    let hints = [
        KeyHint {
            key: "Enter",
            label: "Run keyboard test",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "S",
            label: "Skip test",
            enabled: true,
            danger: false,
        },
        KeyHint {
            key: "N",
            label: "Not my display",
            enabled: true,
            danger: false,
        },
    ];
    draw_footer(fb, &hints);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Host-only `Vec<u32>` `Framebuffer` test double, same pattern as
    /// `crate::chrome`'s own `VecFb`.
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

        fn has_pixel(&self, color: u32) -> bool {
            self.buf.iter().any(|&p| p == color)
        }
    }

    impl Framebuffer for VecFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            if y >= self.h || x >= self.w {
                return;
            }
            let n = px.len().min((self.w - x) as usize);
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + n].copy_from_slice(&px[..n]);
        }
    }

    // -- DeviceState::handle_key -----------------------------------------

    #[test]
    fn single_s_arms_and_returns_none() {
        let mut st = DeviceState::new();
        let outcome = st.handle_key(Key::Char('S'));
        assert_eq!(outcome, None);
        assert!(st.skip_armed);
    }

    #[test]
    fn s_then_s_returns_skip_confirmed() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('S')), None);
        assert_eq!(st.handle_key(Key::Char('S')), Some(DeviceOutcome::SkipConfirmed));
    }

    #[test]
    fn s_then_enter_returns_run_test_disarmed() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('S')), None);
        assert!(st.skip_armed);
        assert_eq!(st.handle_key(Key::Enter), Some(DeviceOutcome::RunTest));
        assert!(!st.skip_armed, "any non-S key must disarm");
    }

    #[test]
    fn bare_enter_returns_run_test() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Enter), Some(DeviceOutcome::RunTest));
    }

    #[test]
    fn n_returns_not_my_display() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('N')), Some(DeviceOutcome::NotMyDisplay));
        assert_eq!(st.handle_key(Key::Char('n')), Some(DeviceOutcome::NotMyDisplay));
    }

    #[test]
    fn s_lowercase_also_arms_and_confirms() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('s')), None);
        assert_eq!(st.handle_key(Key::Char('s')), Some(DeviceOutcome::SkipConfirmed));
    }

    #[test]
    fn any_other_key_disarms_without_outcome() {
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('S')), None);
        assert!(st.skip_armed);
        assert_eq!(st.handle_key(Key::Char('x')), None);
        assert!(!st.skip_armed, "an unrelated key must disarm, not just leave the arm alone");
        assert_eq!(st.handle_key(Key::Other), None);
        assert_eq!(st.handle_key(Key::Backspace), None);
        assert_eq!(st.handle_key(Key::Escape), None);
    }

    #[test]
    fn s_s_s_stays_armed_after_reconfirm_arms_again() {
        // Re-arming after a fresh screen render is a plausible real
        // sequence (user backs out then reconsiders); the third `S`
        // starts a brand-new arm cycle rather than panicking/erroring.
        let mut st = DeviceState::new();
        assert_eq!(st.handle_key(Key::Char('S')), None);
        assert_eq!(st.handle_key(Key::Char('S')), Some(DeviceOutcome::SkipConfirmed));
        assert_eq!(st.handle_key(Key::Char('S')), None);
        assert!(st.skip_armed);
    }

    // -- SPEC §11.4 resolution + device path -----------------------------

    fn sample_info() -> GraphicsInfo {
        GraphicsInfo {
            width: 1920,
            height: 1080,
            device_path: seed_gop_ui::gop::device_path::DevicePathText::unavailable(),
        }
    }

    #[test]
    fn resolution_and_device_path_lines_format_the_spec_11_4_facts() {
        let info = sample_info();
        assert_eq!(resolution_line(&info).as_str(), "Resolution: 1920x1080");
        assert_eq!(
            device_path_line(&info).as_str(),
            std::format!("Device path: {}", info.device_path.as_str()).as_str()
        );
    }

    /// SPEC §11.4: "Display its resolution and device path before
    /// generation." This screen is the ONLY renderer of those two lines in
    /// the product, so this test is the whole of that requirement's
    /// coverage. Asserted by scanning the drawn pixels for the exact glyph
    /// runs the shared line builders produce — not by re-deriving the text.
    #[test]
    fn render_shows_the_spec_11_4_resolution_and_device_path() {
        let info = sample_info();
        let mut fb = VecFb::new(800, 600);
        render(&mut fb, &DeviceState::new(), &info, "b1");

        for line in [resolution_line(&info), device_path_line(&info)] {
            let mut probe = VecFb::new(800, 600);
            seed_gop_ui::font::draw_text(
                &mut probe,
                MARGIN_X,
                content_top(),
                line.as_str(),
                theme::on_bg(theme::TEXT),
            );
            let drawn: std::vec::Vec<usize> =
                probe.buf.iter().enumerate().filter(|(_, &p)| p != 0).map(|(i, _)| i).collect();
            assert!(
                !drawn.is_empty(),
                "probe render of {:?} drew nothing -- the test itself is broken",
                line.as_str()
            );
            // The rendered screen must contain the same glyph run somewhere:
            // search every row for a matching horizontal slice.
            let row_len = 800usize;
            let probe_row = drawn[0] / row_len;
            let probe_slice: std::vec::Vec<u32> =
                probe.buf[probe_row * row_len..(probe_row + 1) * row_len].to_vec();
            let found = (0..600usize).any(|row| {
                fb.buf[row * row_len..(row + 1) * row_len] == probe_slice[..]
            });
            assert!(found, "the SPEC §11.4 line {:?} is not on the DEVICE screen", line.as_str());
        }
    }

    // -- render ---------------------------------------------------------

    #[test]
    fn render_draws_something() {
        let mut fb = VecFb::new(800, 600);
        render(&mut fb, &DeviceState::new(), &sample_info(), "b1");
        assert!(fb.buf.iter().any(|&p| p != 0));
    }

    #[test]
    fn render_shows_warn_line_only_when_armed() {
        let mut fb_unarmed = VecFb::new(800, 600);
        render(&mut fb_unarmed, &DeviceState::new(), &sample_info(), "b1");
        assert!(
            !fb_unarmed.has_pixel(theme::WARN),
            "unarmed screen must not show the WARN skip line"
        );

        let mut fb_armed = VecFb::new(800, 600);
        render(&mut fb_armed, &DeviceState { skip_armed: true }, &sample_info(), "b1");
        assert!(
            fb_armed.has_pixel(theme::WARN),
            "armed screen must show the WARN skip line"
        );
    }

    #[test]
    fn render_does_not_panic_at_min_resolution_floor() {
        let mut fb = VecFb::new(800, 600);
        render(&mut fb, &DeviceState { skip_armed: true }, &sample_info(), "build-x");
    }

    /// Floor fit budget: the SPEC §11.4 resolution/device-path lines added
    /// two content rows to this screen, so pin that its worst case (skip
    /// armed, so the inline WARN line is present too) still ends above the
    /// footer band at the 800x600 floor.
    #[test]
    fn worst_case_content_fits_above_the_footer_at_the_floor() {
        // Row layout, mirroring `render`: resolution, device path, gap,
        // question, gap, offer 1, offer 2, gap, WARN.
        let last_row = content_top() + LINE_PITCH * 8;
        assert!(
            last_row + seed_gop_ui::font::GLYPH_HEIGHT <= crate::chrome::content_bottom(),
            "DEVICE content ends at y={last_row}, past content_bottom()={}",
            crate::chrome::content_bottom()
        );
    }

    /// SPEC §12.2 "Fixed layouts": this screen clears first, so nothing a
    /// previous screen drew can composite through around its content.
    #[test]
    fn render_clears_stale_pixels_from_a_previous_screen() {
        let mut fb = VecFb::new(800, 600);
        // A stale block in the content area, in a color this screen never
        // draws anywhere.
        let stale = theme::DANGER;
        for y in 300..320 {
            fb.put_row(400, y, &std::vec![stale; 200]);
        }
        assert!(fb.has_pixel(stale));
        render(&mut fb, &DeviceState::new(), &sample_info(), "b1");
        assert!(!fb.has_pixel(stale), "the DEVICE screen must clear before drawing");
    }
}
