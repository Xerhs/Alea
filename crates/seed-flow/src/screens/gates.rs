//! Stage 2 — transient auto-gate checklist (design doc §4.2: "The silent
//! auto-gates (platform, console topology, crypto self-test, watchdog)
//! render as one transient checklist screen with `OK` ticks appearing as
//! each passes — no keypress consumed.").
//!
//! Pure render-only, like [`super::device`]: no key source. The caller
//! (the flow driver, which actually runs the four gates) owns building
//! and updating a [`GateList`] as each check completes and re-rendering
//! between checks; this module only draws whatever [`GateList`] it is
//! handed.

use core::fmt::Write as _;

use seed_core::contracts::Framebuffer;
use seed_gop_ui::font::{draw_text, scrub_fill};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::theme;

use crate::chrome::{content_top, draw_footer, draw_header, Chrome};
use crate::output::LineBuf;

/// The four mandatory startup gates, in the fixed order they are drawn
/// (design doc §4.2's own listed order: "platform, console topology,
/// crypto self-test, watchdog"). `[`GateList::passed`]`'s indices line up
/// with this array 1:1.
pub const GATE_LABELS: [&str; 4] = [
    "Platform check",
    "Console topology",
    "Crypto self-test",
    "Watchdog",
];

/// Live pass/fail state of the four gates, indexed exactly like
/// [`GATE_LABELS`]. This screen never fails a gate itself closed (that
/// remains each gate's own owning module's job, unchanged by this
/// redesign) — it only reflects whichever gates have completed so far.
pub struct GateList {
    pub passed: [bool; 4],
}

impl GateList {
    /// All four gates not yet passed (the checklist's initial frame,
    /// before the first gate completes).
    #[must_use]
    pub const fn new() -> Self {
        Self { passed: [false; 4] }
    }
}

impl Default for GateList {
    fn default() -> Self {
        Self::new()
    }
}

/// Render this screen (design doc §4.2): [`crate::chrome`] header for
/// Stage 2/DEVICE, one row per [`GATE_LABELS`] entry with an `OK` tick
/// (in [`theme::OK`]) once [`GateList::passed`] is true for that index,
/// or a pending marker (in [`theme::CAPTION`]) otherwise, and the footer
/// key bar with no hints (this screen consumes no keypress).
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): it follows
/// the taller Stage-1 Prepare screen, whose warning panel and checklist
/// would otherwise show through under this short checklist.
pub fn render_gates(fb: &mut dyn Framebuffer, g: &GateList, build: &'static str) {
    scrub_fill(fb, theme::BG);
    let chrome = Chrome {
        stage: 2,
        sub: None,
        build,
    };
    draw_header(fb, &chrome);

    let mut y = content_top();
    draw_text(fb, MARGIN_X, y, "STARTUP CHECKS", theme::on_bg(theme::TEXT));
    y += LINE_PITCH * 2;

    for (i, label) in GATE_LABELS.iter().enumerate() {
        let (mark, color) = if g.passed[i] {
            ("OK", theme::OK)
        } else {
            ("..", theme::CAPTION)
        };
        let mut line = LineBuf::new();
        let _ = write!(line, "[{mark:2}] {label}");
        draw_text(fb, MARGIN_X, y, line.as_str(), theme::on_bg(color));
        y += LINE_PITCH;
    }

    draw_footer(fb, &[]);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// SPEC §12.2 "Fixed layouts" — bleed-through regression. The transient
    /// checklist follows the taller Stage-1 Prepare screen; before the fix
    /// it did not clear, so Prepare's warning panel and checkbox rows stayed
    /// on screen underneath it. Nothing is ticked in this `GateList`, so a
    /// surviving `OK` pixel can only have come from Prepare's checked box.
    #[test]
    fn gates_checklist_clears_the_previous_screen() {
        use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};
        let mut fb = VecFb::new(MIN_WIDTH, MIN_HEIGHT);
        let mut st = crate::screens::prepare::PrepareState::new();
        st.handle_key(crate::keys::MenuKey::Char('1'));
        crate::screens::prepare::render(&mut fb, &st, "b1");
        assert!(
            fb.buf.iter().any(|&p| p == theme::OK),
            "sanity: Prepare must have drawn its checked box in OK"
        );

        render_gates(&mut fb, &GateList::new(), "b1");
        assert!(
            !fb.buf.iter().any(|&p| p == theme::OK),
            "the auto-gate checklist must clear Prepare's content, not composite over it \
             (nothing is ticked yet, so no OK pixel may remain)"
        );
    }

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

    #[test]
    fn no_gates_passed_shows_no_ok_color() {
        let mut fb = VecFb::new(800, 600);
        render_gates(&mut fb, &GateList::new(), "b1");
        assert!(!fb.has_pixel(theme::OK), "no OK tick expected when nothing has passed");
        assert!(fb.has_pixel(theme::CAPTION), "pending gates must render in CAPTION");
    }

    #[test]
    fn all_gates_passed_renders_ok_ticks() {
        let mut fb = VecFb::new(800, 600);
        let g = GateList { passed: [true; 4] };
        render_gates(&mut fb, &g, "b1");
        assert!(fb.has_pixel(theme::OK), "OK tick expected once every gate has passed");
    }

    #[test]
    fn some_gates_passed_shows_both_ok_and_pending() {
        let mut fb = VecFb::new(800, 600);
        let g = GateList {
            passed: [true, false, true, false],
        };
        render_gates(&mut fb, &g, "b1");
        assert!(fb.has_pixel(theme::OK), "passed gates must show OK");
        assert!(fb.has_pixel(theme::CAPTION), "unpassed gates must still show pending");
    }

    #[test]
    fn render_draws_something_and_does_not_panic() {
        let mut fb = VecFb::new(800, 600);
        render_gates(&mut fb, &GateList::new(), "build-x");
        assert!(fb.buf.iter().any(|&p| p != 0));
    }
}
