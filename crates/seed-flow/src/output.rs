//! Narrow output trait so every pre-secret screen (SPEC §12.1: "Firmware
//! text output may be used for: opening warnings, diagnostics,
//! environment acknowledgements, release and build information, and
//! error reporting before secret generation") is host-testable against a
//! scripted mock terminal, never against the real UEFI console directly.
//!
//! Nothing in this module ever touches secret data (SPEC §12.1 scope is
//! pre-secret-only), and no caller in this crate may route secret-bearing
//! text through it (SPEC §12.2 requires the GOP framebuffer path for that,
//! owned by WP-26/`flow_secret`).

/// A single line-oriented text output surface (SPEC §12.1).
///
/// Implemented by a firmware text-console adapter in production
/// (`seed-uefi-test`'s `flow_pre` wiring) and by [`test_support::MockTerminal`]
/// in host tests, so every screen-rendering function in this crate is
/// exercised without a UEFI environment (IMPLEMENTATION_MAP.md WP-25:
/// "route everything through one narrow output trait").
pub trait TextOutput {
    /// Emit one line of text (no implicit wrapping/newline handling
    /// beyond "one line per call").
    fn write_line(&mut self, line: &str);

    /// Clear the console before the next screen, best-effort. A backend
    /// that cannot clear (or whose clear fails) simply leaves prior text
    /// in place; no screen's correctness in this crate depends on this
    /// succeeding — it is a presentation nicety, not a security property.
    fn clear(&mut self);

    /// Emit `s` as a machine-entropy-acquisition progress tick (real-
    /// hardware slow-RDSEED fix, SPEC §21): counts-only, no secret
    /// content ever passes through this call. Unlike [`Self::write_line`],
    /// a backend that can accumulate ticks on one visual row (no implicit
    /// line terminator) SHOULD override this to do so — the default
    /// implementation simply delegates to `write_line`, which is exactly
    /// right for [`test_support::MockTerminal`] and every other backend
    /// that has no such distinction to make.
    fn write_progress(&mut self, s: &str) {
        self.write_line(s);
    }
}

/// Write every line in `lines` to `out`, in order. A tiny helper so
/// screen-rendering functions read as a flat list of strings rather than
/// a hand-written loop at every call site.
pub fn write_screen(out: &mut dyn TextOutput, lines: &[&str]) {
    for line in lines {
        out.write_line(line);
    }
}

/// [`TextOutput`] backed by the GOP linear framebuffer (SPEC.md amendment
/// 2026-08-06 / SPEC §4.1, §11.4, §12.1: both UEFI editions now render
/// the ENTIRE ceremony — every pre-secret screen and every secret-phase
/// screen prior to `AppState::MnemonicDisplay` — through this same
/// application bitmap-font path the post-secret screens
/// (`crate::flow_secret::gop_screen`) already used, instead of firmware
/// text output. Firmware text output survives in the normal boot path
/// solely for the one refusal printed before a framebuffer exists at all
/// — see `crate::firmware_wiring::open_session_gop`).
///
/// Zero-storage, append-only cursor — deliberately mirrors
/// [`crate::firmware_wiring::FirmwareTextOutput`]'s own semantics exactly
/// ([`Self::write_line`] only ever appends at the current cursor row and
/// advances it; [`Self::clear`] only ever blanks the framebuffer and
/// resets the cursor to the top margin). Neither operation stores or
/// re-reads any prior line's text, so this type carries no secret-bearing
/// state of its own regardless of what a caller ever writes through it —
/// the same "no storage, no re-render" property [`write_screen`]'s other
/// callers already rely on, just against a pixel surface instead of a
/// firmware text console.
pub struct FbTextOutput<'a> {
    fb: &'a mut dyn seed_core::contracts::Framebuffer,
    y: u32,
}

impl<'a> FbTextOutput<'a> {
    /// Wrap `fb`. The cursor starts at the shared top/left margin
    /// (`seed_gop_ui::layout::MARGIN_X`, used for both axes — see that
    /// module's own doc comment), exactly where [`Self::clear`] resets it
    /// to.
    #[must_use]
    pub fn new(fb: &'a mut dyn seed_core::contracts::Framebuffer) -> Self {
        Self::at(fb, seed_gop_ui::layout::MARGIN_X)
    }

    /// Wrap `fb` with the cursor starting at `y` instead of the top
    /// margin — for a caller that has already drawn its own chrome
    /// (e.g. `seed_flow::chrome::draw_header_plain`) above `y` and wants
    /// this type's ordinary line-stepping `write_line` behavior for the
    /// content below it (Task 19: launcher/tool screens that wrap their
    /// `TextOutput` content in a header/footer band, the same pattern
    /// `seed_flow::screens`'s pixel-exact renderers already use via
    /// `chrome::content_top`).
    ///
    /// [`Self::clear`] still resets the cursor to [`Self::new`]'s
    /// [`seed_gop_ui::layout::MARGIN_X`] top margin, NOT back to this
    /// `y` — and it still wipes the WHOLE framebuffer, including
    /// anything a caller drew above `y` (a header band, say). A caller
    /// that wants to keep its own chrome across re-renders (e.g. a
    /// paging loop) must therefore never call `clear()` on an
    /// `at`-constructed instance; instead it should scrub the
    /// framebuffer and redraw its chrome itself each frame, then build a
    /// FRESH `FbTextOutput::at(fb, y)` for that frame's content — the
    /// same "clear, redraw chrome, fresh content cursor" sequence a
    /// screen using `chrome::draw_header`/`draw_footer` directly follows.
    #[must_use]
    pub fn at(fb: &'a mut dyn seed_core::contracts::Framebuffer, y: u32) -> Self {
        Self { fb, y }
    }
}

impl TextOutput for FbTextOutput<'_> {
    fn write_line(&mut self, line: &str) {
        seed_gop_ui::font::draw_text(
            self.fb,
            seed_gop_ui::layout::MARGIN_X,
            self.y,
            line,
            seed_gop_ui::layout::SCREEN_STYLE,
        );
        self.y += seed_gop_ui::layout::LINE_PITCH;
    }

    fn clear(&mut self) {
        seed_gop_ui::font::scrub_fill(self.fb, 0);
        self.y = seed_gop_ui::layout::MARGIN_X;
    }
}

/// A pre-secret rendering surface that is BOTH the SPEC §12.1 line-oriented
/// [`TextOutput`] every legacy pre-secret screen writes through AND the SPEC
/// §12.2 pixel [`Framebuffer`](seed_core::contracts::Framebuffer) the
/// 2026-08-07 redesign's [`crate::screens`] modules draw on.
///
/// # Why one trait rather than two parameters
///
/// The redesigned pre-secret ceremony draws most screens through
/// `crate::screens::*` (`&mut dyn Framebuffer`) while a handful of
/// still-line-oriented screens — the `PreSecretError` recovery screen, the
/// named-refusal screen, the keyboard self-test step screens — keep writing
/// through [`TextOutput`]. On every real edition both surfaces are *the same
/// pixels*: the UEFI editions hand [`run_pre_secret_flow`](crate::driver::run_pre_secret_flow)
/// an [`FbTextOutput`] over the one session framebuffer, and the desktop
/// edition hands it a `WindowTextOutput` over its one shared buffer. Passing
/// the framebuffer as a second `&mut` parameter alongside the text output is
/// therefore impossible without aliasing it — hence one trait that hands out
/// each view in turn.
///
/// Implementors MUST return a view of the same pixel surface their
/// [`TextOutput`] half writes to, and MUST reset any line cursor they keep,
/// so a screen drawn through [`Self::framebuffer`] followed by a
/// [`TextOutput::clear`] behaves exactly as two consecutive text screens do.
pub trait FlowSurface: TextOutput {
    /// Borrow this surface's pixel view.
    fn framebuffer(&mut self) -> &mut dyn seed_core::contracts::Framebuffer;
}

impl FlowSurface for FbTextOutput<'_> {
    fn framebuffer(&mut self) -> &mut dyn seed_core::contracts::Framebuffer {
        // The line cursor is meaningless once a full-screen chrome layout
        // owns the surface; reset it so a subsequent text screen starts at
        // the top margin exactly as it would after `clear()`.
        self.y = seed_gop_ui::layout::MARGIN_X;
        self.fb
    }
}

/// Fixed capacity of one interpolated diagnostic line built via
/// [`LineBuf`] (SPEC §13: fixed buffers, no `alloc`, anywhere in this
/// crate). Generously larger than any single diagnostic sentence this
/// crate builds (resolution/path-count/version lines).
pub const LINE_CAPACITY: usize = 160;

/// A fixed-capacity `core::fmt::Write` buffer used to build one display
/// line with interpolated (always non-secret) values — resolution
/// numbers, console-path counts, policy versions — without `alloc`.
///
/// Overlong content is silently truncated rather than propagating a
/// `core::fmt::Error` up through every `write!` call site: nothing built
/// with this type is secret or security-critical text whose exact
/// truncation point matters (unlike, e.g., the SPEC §8.4/§18.2/§18.3
/// verbatim warnings in [`crate::text`], which are always written as a
/// single already-fixed `&'static str`, never through this buffer).
pub struct LineBuf {
    buf: [u8; LINE_CAPACITY],
    len: usize,
}

impl LineBuf {
    /// An empty line buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; LINE_CAPACITY],
            len: 0,
        }
    }

    /// The valid contents built so far.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Default for LineBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = LINE_CAPACITY - self.len;
        let n = bytes.len().min(remaining);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

/// Host-test support: a [`TextOutput`] double that records every line
/// (and every `clear()` as a sentinel) into a `Vec<String>`, so tests can
/// assert on exact screen sequences.
#[cfg(test)]
pub(crate) mod test_support {
    use super::TextOutput;

    /// Sentinel line [`MockTerminal`] pushes on [`TextOutput::clear`], so
    /// tests can assert screen boundaries without a separate call log.
    pub(crate) const CLEAR_SENTINEL: &str = "\u{0}CLEAR\u{0}";

    /// Host-only `Vec<u32>` [`Framebuffer`](seed_core::contracts::Framebuffer)
    /// backing for [`MockTerminal`]'s [`super::FlowSurface`] half, so a
    /// driver test can drive screens that draw pixels while still asserting
    /// on the text screens' recorded lines. Sized at the SPEC §11.4 800x600
    /// floor — the smallest surface any screen must fit.
    pub(crate) struct MockFb {
        w: u32,
        h: u32,
        pub(crate) buf: std::vec::Vec<u32>,
    }

    impl MockFb {
        fn new() -> Self {
            let w = seed_gop_ui::gop::mode::MIN_WIDTH;
            let h = seed_gop_ui::gop::mode::MIN_HEIGHT;
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
        }
    }

    impl seed_core::contracts::Framebuffer for MockFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            if y >= self.h || x >= self.w {
                return;
            }
            let visible = core::cmp::min(px.len(), (self.w - x) as usize);
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + visible].copy_from_slice(&px[..visible]);
        }
    }

    pub(crate) struct MockTerminal {
        pub(crate) lines: std::vec::Vec<std::string::String>,
        pub(crate) fb: MockFb,
    }

    impl MockTerminal {
        pub(crate) fn new() -> Self {
            Self {
                lines: std::vec::Vec::new(),
                fb: MockFb::new(),
            }
        }

        /// All lines written since the last `clear()` (or since the
        /// start, if `clear()` was never called) — i.e. the current
        /// screen only.
        pub(crate) fn current_screen(&self) -> std::vec::Vec<&str> {
            self.lines
                .iter()
                .rev()
                .take_while(|l| l.as_str() != CLEAR_SENTINEL)
                .map(std::string::String::as_str)
                .collect::<std::vec::Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        }

        pub(crate) fn contains(&self, needle: &str) -> bool {
            self.lines.iter().any(|l| l.contains(needle))
        }

        /// True when `prose`, word-wrapped to `cols` by
        /// [`crate::text::wrap_words`], appears as consecutive recorded
        /// lines (each wrapped fragment present, in order). This is the
        /// wrapped-prose analogue of [`contains`](Self::contains): a prose
        /// paragraph that render functions now word-wrap for display can no
        /// longer be found as one contiguous line, but its reflowed
        /// fragments still appear in sequence.
        pub(crate) fn contains_wrapped(&self, prose: &str, cols: usize) -> bool {
            let frags: std::vec::Vec<&str> = crate::text::wrap_words(prose, cols).collect();
            if frags.is_empty() {
                return true;
            }
            self.lines.windows(frags.len()).any(|window| {
                window
                    .iter()
                    .zip(frags.iter())
                    .all(|(line, frag)| line.as_str() == *frag)
            })
        }
    }

    impl TextOutput for MockTerminal {
        fn write_line(&mut self, line: &str) {
            self.lines.push(std::string::String::from(line));
        }

        fn clear(&mut self) {
            self.lines.push(std::string::String::from(CLEAR_SENTINEL));
        }
    }

    impl super::FlowSurface for MockTerminal {
        fn framebuffer(&mut self) -> &mut dyn seed_core::contracts::Framebuffer {
            // Honor the `FlowSurface` contract that handing out the pixel
            // view resets the line cursor exactly as `clear()` does: the
            // recorded transcript gets the same screen-boundary sentinel, so
            // a test's `current_screen()` never spans a chrome screen.
            self.lines.push(std::string::String::from(CLEAR_SENTINEL));
            &mut self.fb
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockTerminal;
    use super::*;

    #[test]
    fn write_screen_writes_every_line_in_order() {
        let mut term = MockTerminal::new();
        write_screen(&mut term, &["one", "two", "three"]);
        assert_eq!(term.lines, std::vec!["one", "two", "three"]);
    }

    /// Real-hardware slow-RDSEED fix: `write_progress`'s default impl
    /// delegates to `write_line` unmodified — a backend that has no
    /// special "accumulate on one row" behavior (like `MockTerminal`)
    /// just gets the exact same text recorded either way.
    #[test]
    fn write_progress_default_impl_delegates_to_write_line() {
        let mut term = MockTerminal::new();
        term.write_progress(".");
        assert!(term.contains("."));
    }

    #[test]
    fn line_buf_builds_interpolated_text() {
        use core::fmt::Write as _;
        let mut buf = LineBuf::new();
        write!(buf, "Console output paths   {} supported path", 1).unwrap();
        assert_eq!(buf.as_str(), "Console output paths   1 supported path");
    }

    #[test]
    fn line_buf_truncates_without_panicking() {
        use core::fmt::Write as _;
        let mut buf = LineBuf::new();
        for _ in 0..LINE_CAPACITY {
            write!(buf, "x").unwrap();
        }
        // One more character over capacity must not panic or error.
        write!(buf, "y").unwrap();
        assert_eq!(buf.as_str().len(), LINE_CAPACITY);
    }

    #[test]
    fn mock_terminal_current_screen_resets_on_clear() {
        let mut term = MockTerminal::new();
        write_screen(&mut term, &["old screen line"]);
        term.clear();
        write_screen(&mut term, &["new screen line 1", "new screen line 2"]);
        assert_eq!(
            term.current_screen(),
            std::vec!["new screen line 1", "new screen line 2"]
        );
        assert!(term.contains("old screen line"));
    }
}

/// [`FbTextOutput`] host tests (Step 1: a fake `Framebuffer` mock — no
/// UEFI/real GOP needed, matching `flow_secret::gop_screen`'s own
/// `VecFb` test pattern).
#[cfg(test)]
mod fb_text_output_tests {
    use super::*;
    use seed_core::contracts::Framebuffer;

    /// A plain heap-backed `Framebuffer`, sized like the SPEC §11.4
    /// minimum resolution floor (800x600) unless a test asks for
    /// something else.
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

        fn is_blank(&self) -> bool {
            self.buf.iter().all(|&p| p == 0)
        }

        fn has_pixel(&self, value: u32) -> bool {
            self.buf.iter().any(|&p| p == value)
        }

        /// True if pixel row `y` contains `value` anywhere.
        fn row_has_pixel(&self, y: u32, value: u32) -> bool {
            let start = (y as usize) * (self.w as usize);
            self.buf[start..start + self.w as usize].iter().any(|&p| p == value)
        }

        /// True if `value` appears anywhere in the `height`-row band
        /// starting at `y0` — a glyph's own top/bottom rows are often
        /// blank (e.g. a lowercase letter's ascender-free top row), so a
        /// single-row check can miss real ink; this checks the whole
        /// glyph-height band instead.
        fn band_has_pixel(&self, y0: u32, height: u32, value: u32) -> bool {
            (y0..y0 + height).any(|y| self.row_has_pixel(y, value))
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
    fn write_line_draws_into_the_framebuffer() {
        let mut fb = VecFb::new(800, 600);
        let mut out = FbTextOutput::new(&mut fb);
        out.write_line("hello");
        assert!(fb.has_pixel(seed_gop_ui::layout::SCREEN_STYLE.fg));
    }

    #[test]
    fn write_line_never_stores_prior_text_only_advances_the_cursor() {
        // Zero-storage, append-only cursor (module doc comment): two
        // consecutive lines land at two different rows, and nothing about
        // `FbTextOutput` itself grows with the number of lines written
        // (no `Vec`, no buffer -- this is a compile-time property of the
        // struct, exercised here only behaviorally via distinct rows).
        let mut fb = VecFb::new(800, 600);
        {
            let mut out = FbTextOutput::new(&mut fb);
            out.write_line("one");
            out.write_line("two");
        }
        let fg = seed_gop_ui::layout::SCREEN_STYLE.fg;
        let first_band = seed_gop_ui::layout::MARGIN_X;
        let second_band = seed_gop_ui::layout::MARGIN_X + seed_gop_ui::layout::LINE_PITCH;
        let glyph_h = seed_gop_ui::font::GLYPH_HEIGHT;
        assert!(
            fb.band_has_pixel(first_band, glyph_h, fg),
            "first line must land at the top margin row"
        );
        assert!(
            fb.band_has_pixel(second_band, glyph_h, fg),
            "second line must land one LINE_PITCH below the first, not overwrite it"
        );
    }

    #[test]
    fn clear_blanks_the_framebuffer_and_resets_the_cursor_to_top_margin() {
        let mut fb = VecFb::new(800, 600);
        {
            let mut out = FbTextOutput::new(&mut fb);
            out.write_line("first screen, several lines");
            out.write_line("more content pushing the cursor down");
            out.write_line("even more, several rows deep by now");
            out.clear();
        }
        assert!(fb.is_blank());

        // After `clear()`, the cursor must be back at the top margin --
        // not wherever it had drifted to -- so the next line lands at the
        // same row `FbTextOutput::new` itself would have used.
        let mut fresh_fb = VecFb::new(800, 600);
        {
            let mut fresh_out = FbTextOutput::new(&mut fresh_fb);
            fresh_out.write_line("same line");
        }
        {
            let mut out = FbTextOutput::new(&mut fb);
            out.write_line("same line");
        }
        assert_eq!(fb.buf, fresh_fb.buf);
    }

    // ---- FbTextOutput::at (Task 19: content cursor starting below a
    // caller-drawn chrome band) ----

    #[test]
    fn at_starts_the_cursor_at_the_given_y_not_the_top_margin() {
        let mut fb = VecFb::new(800, 600);
        let start_y = 120;
        {
            let mut out = FbTextOutput::at(&mut fb, start_y);
            out.write_line("first content row, below the header band");
        }
        let fg = seed_gop_ui::layout::SCREEN_STYLE.fg;
        let glyph_h = seed_gop_ui::font::GLYPH_HEIGHT;
        assert!(
            fb.band_has_pixel(start_y, glyph_h, fg),
            "line must land at the caller-supplied y, not the top margin"
        );
        assert!(
            !fb.band_has_pixel(seed_gop_ui::layout::MARGIN_X, glyph_h, fg),
            "the top-margin row must stay untouched -- that's where a caller-drawn header lives"
        );
    }

    #[test]
    fn at_leaves_pixels_above_y_untouched_so_a_caller_drawn_header_survives() {
        let mut fb = VecFb::new(800, 600);
        // Simulate a caller's own chrome draw above the content cursor.
        let header_marker = 0x00AB_CDEF;
        for x in 0..fb.w {
            fb.put_row(x, 10, &[header_marker]);
        }
        {
            let mut out = FbTextOutput::at(&mut fb, 120);
            out.write_line("content below the simulated header");
        }
        assert!(
            fb.row_has_pixel(10, header_marker),
            "FbTextOutput::at must never touch pixels above its start y"
        );
    }

    #[test]
    fn at_second_line_advances_by_one_line_pitch_from_the_given_y() {
        let mut fb = VecFb::new(800, 600);
        {
            let mut out = FbTextOutput::at(&mut fb, 0);
            out.write_line("one");
            out.write_line("two");
        }
        let fg = seed_gop_ui::layout::SCREEN_STYLE.fg;
        let glyph_h = seed_gop_ui::font::GLYPH_HEIGHT;
        let pitch = seed_gop_ui::layout::LINE_PITCH;
        assert!(fb.band_has_pixel(0, glyph_h, fg), "first line at row 0");
        assert!(fb.band_has_pixel(pitch, glyph_h, fg), "second line one LINE_PITCH below row 0");
    }

    // ---- fit-audit harness (Step 1 acceptance: representative pre-secret
    // + secret-phase screens fit the SPEC §11.4 800x600 resolution floor)
    // ----

    /// Column/line budget derived from the same shared
    /// `seed_gop_ui::layout` constants `FbTextOutput` itself draws with,
    /// at the 800x600 floor, reserving an equal margin on the opposite
    /// edge from `MARGIN_X`/the top margin (SPEC §11.4's minimum
    /// resolution): `(800 - 2*MARGIN_X) / GLYPH_WIDTH` columns,
    /// `(600 - 2*MARGIN_X) / LINE_PITCH` lines.
    const FIT_AUDIT_FB_WIDTH: u32 = 800;
    const FIT_AUDIT_FB_HEIGHT: u32 = 600;

    // Single source of truth with `seed_gop_ui::layout` itself (and, in
    // turn, with any renderer -- e.g. the SPEC_EDU_UI composition panel --
    // that paginates its own content to the same budget) rather than a
    // second, independently-maintained derivation of the same numbers.
    fn fit_audit_max_cols() -> usize {
        seed_gop_ui::layout::MAX_COLS_AT_FLOOR
    }

    fn fit_audit_max_lines() -> usize {
        seed_gop_ui::layout::MAX_LINES_AT_FLOOR
    }

    /// Wraps [`FbTextOutput`] to count lines and track the widest one, so
    /// the fit-audit test below can assert against a screen's rendered
    /// shape without `FbTextOutput` itself needing to grow any bookkeeping
    /// of its own (it stays exactly the zero-storage type the module doc
    /// comment describes; this counter lives only in this test module).
    struct FitAuditRecorder<'a> {
        inner: FbTextOutput<'a>,
        lines: usize,
        max_cols: usize,
        /// Worst (tallest, widest) *completed* page seen so far, updated
        /// on every `clear()` (SPEC.md amendment 2026-08-06: pagination --
        /// a multi-page screen like the composition panel calls `clear()`
        /// once per page, and every page individually must fit the floor,
        /// not just whichever page happens to be open when the caller
        /// stops writing).
        worst_lines: usize,
        worst_max_cols: usize,
    }

    impl<'a> FitAuditRecorder<'a> {
        fn new(fb: &'a mut dyn Framebuffer) -> Self {
            Self { inner: FbTextOutput::new(fb), lines: 0, max_cols: 0, worst_lines: 0, worst_max_cols: 0 }
        }

        /// The worst (lines, cols) shape across every page rendered so
        /// far, including whatever page is still open (not yet
        /// `clear()`-ed) at call time -- the right thing to audit for a
        /// screen that may render across more than one page.
        fn worst(&self) -> (usize, usize) {
            (self.worst_lines.max(self.lines), self.worst_max_cols.max(self.max_cols))
        }
    }

    impl TextOutput for FitAuditRecorder<'_> {
        fn write_line(&mut self, line: &str) {
            self.lines += 1;
            self.max_cols = self.max_cols.max(line.chars().count());
            self.inner.write_line(line);
        }
        fn clear(&mut self) {
            self.worst_lines = self.worst_lines.max(self.lines);
            self.worst_max_cols = self.worst_max_cols.max(self.max_cols);
            self.lines = 0;
            self.max_cols = 0;
            self.inner.clear();
        }
    }

    fn assert_fits(screen: &str, lines: usize, max_cols: usize) {
        let max_lines = fit_audit_max_lines();
        let max_cols_budget = fit_audit_max_cols();
        assert!(
            lines <= max_lines,
            "{screen}: {lines} lines exceeds the {max_lines}-line budget at {FIT_AUDIT_FB_WIDTH}x{FIT_AUDIT_FB_HEIGHT}"
        );
        assert!(
            max_cols <= max_cols_budget,
            "{screen}: widest line is {max_cols} columns, exceeds the {max_cols_budget}-column budget at {FIT_AUDIT_FB_WIDTH}x{FIT_AUDIT_FB_HEIGHT}"
        );
    }

    /// SPEC.md amendment 2026-08-06 / Step 1 acceptance: representative
    /// pre-secret screens (`crate::text`) AND representative secret-phase
    /// screens rendered pre-`MnemonicDisplay` (`crate::flow_secret`,
    /// SPEC §12.1-scope, non-secret content) all fit the SPEC §11.4
    /// minimum 800x600 resolution floor through the exact same
    /// `FbTextOutput` adapter both UEFI editions now render through.
    #[test]
    fn fit_audit_pre_secret_and_secret_screens_fit_the_800x600_floor() {
        let mut fb = VecFb::new(FIT_AUDIT_FB_WIDTH, FIT_AUDIT_FB_HEIGHT);

        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_opening_warning(&mut r);
            assert_fits("opening_warning", r.worst().0, r.worst().1);
        }
        for (title, items) in crate::text::ACK_SCREENS {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_ack_screen(&mut r, title, items);
            assert_fits(title, r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_word_count_screen(&mut r);
            assert_fits("word_count", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_required_warning(&mut r);
            assert_fits("required_warning_8_4", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_physical_only_warning(&mut r);
            assert_fits("physical_only_warning_18_3", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::text::render_dice_coins_firmware_warning(&mut r);
            assert_fits("dice_coins_firmware_warning_6", r.worst().0, r.worst().1);
        }

        // Representative SECRET-PHASE screens rendered before
        // `AppState::MnemonicDisplay` (still non-secret content -- see
        // `crate::firmware_wiring::run_secret_phase`'s own doc comment for
        // exactly which screens these are).
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::flow_secret::machine::render_machine_failed(
                &mut r,
                crate::flow_secret::machine::MachineAcquisitionError::SourceTimedOut,
            );
            assert_fits("machine_failed_timed_out", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::flow_secret::machine::render_machine_failed(
                &mut r,
                crate::flow_secret::machine::MachineAcquisitionError::NoSourceAvailable,
            );
            assert_fits("machine_failed_no_source", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            let avail = crate::entropy_avail::ModeAvailability {
                combined: Ok(()),
                dice_only: Ok(()),
                machine_only: Ok(()),
            };
            crate::entropy_avail::render_entropy_mode_screen(&mut r, &avail);
            assert_fits("entropy_mode_screen", r.worst().0, r.worst().1);
        }
        {
            // SPEC.md amendment 2026-08-06 / blocking finding fix: the
            // SPEC_EDU_UI §22.5a composition panel now paginates (see
            // `crate::flow_secret::composition::render_composition_panel`'s
            // own doc comment) specifically because its worst-case content
            // -- dice AND coins counted, plus every present machine
            // source claimed -- does not fit the floor as one page.
            // `FitAuditRecorder::worst()` asserts every INDIVIDUAL page
            // this worst-case model produces fits, not just whichever
            // page happens to be open when rendering stops.
            use crate::flow_secret::composition::{CompositionModel, MachineTagSet};
            use seed_core::contracts::{SourceTag, TargetBits};

            let mut worst_tags = MachineTagSet::new();
            worst_tags.insert(SourceTag::ApprovedEfiRng);
            worst_tags.insert(SourceTag::X86Rdseed64);
            worst_tags.insert(SourceTag::X86RdrandSupplementary);
            worst_tags.insert(SourceTag::ApprovedUsbTrng);
            let worst_combined = CompositionModel::new(128, 40, worst_tags, TargetBits::Bits256, 65_535);

            let mut r = FitAuditRecorder::new(&mut fb);
            crate::flow_secret::composition::render_composition_panel(&mut r, &worst_combined);
            assert_fits("composition_panel_combined_worst_case", r.worst().0, r.worst().1);

            let mut machine_only_tags = MachineTagSet::new();
            machine_only_tags.insert(SourceTag::ApprovedEfiRng);
            machine_only_tags.insert(SourceTag::X86Rdseed64);
            let worst_machine_only = CompositionModel::new(0, 0, machine_only_tags, TargetBits::Bits256, 65_535);

            let mut r = FitAuditRecorder::new(&mut fb);
            crate::flow_secret::composition::render_composition_panel(&mut r, &worst_machine_only);
            assert_fits("composition_panel_machine_only_worst_case", r.worst().0, r.worst().1);
        }
        {
            let mut r = FitAuditRecorder::new(&mut fb);
            crate::flow_secret::machine::render_acquiring(&mut r);
            assert_fits("machine_acquiring", r.worst().0, r.worst().1);
        }
    }
}

/// The 2026-08-07 ceremony redesign's AUDIT-level floor sweep: every
/// screen in [`crate::screens`] rendered at the SPEC §11.4 800x600
/// resolution floor, in its worst case, checked for the two ways a
/// pixel-exact screen can overflow the content area
/// [`crate::chrome::content_top`]/[`crate::chrome::content_bottom`] carve
/// out between the header and footer bands.
///
/// The sibling module above audits the LINE-oriented screens (the ones
/// still written through [`TextOutput`]); those cannot collide with a
/// chrome band because they have none. This module audits the
/// [`Framebuffer`](seed_core::contracts::Framebuffer)-drawing screens the
/// redesign added, where "does it fit" is a pixel question, not a
/// line-count one.
///
/// # What the audit detects, and how
///
/// [`ChromeAuditFb`] records every `put_row` a render issues and flags:
///
/// 1. **Band collisions** — content drawn into the header band (above
///    `content_top()`) or the footer band (at or below `content_bottom()`
///    + its separating rule). The discriminator is the *pixel palette* of
///    the paint ([`screens_fit_audit::CHROME_BAND_PIXELS`]), which is
///    order-independent — and it has to be, since some screens draw their
///    footer before their content and some after, so "what got drawn
///    last" proves nothing. The one full-screen `scrub_fill(BG)` every
///    renderer opens with is excluded by [`ChromeAuditFb::armed`].
/// 2. **Right-margin overruns** — a content glyph cell (or QR module)
///    running past `MIN_WIDTH - MARGIN_X`. Only glyph-sized content
///    paints are eligible, for the reason given at the check itself; the
///    header's right-aligned stage block ends exactly ON the margin and
///    is chrome, not content, either way.
///
/// [`fit_audit_harness_flags_a_screen_that_overflows_its_content_area`]
/// proves the detector fires, so a passing sweep is evidence rather than
/// a tautology.
///
/// # Known blind spot, and what covers it
///
/// Content drawn as `theme::on_panel(theme::TEXT)` or
/// `theme::on_panel(theme::CAPTION)` inside a `theme::PANEL` fill is
/// indistinguishable, pixel-wise, from the chrome's own band. (A panel
/// with a `WARN` border, or any `OK`/`WARN`/`BG`-bearing pixel, is not —
/// those are caught.) Each screen that uses such a panel carries its own
/// analytic panel-geometry test, named per screen in the coverage table
/// on [`fit_audit_every_redesigned_screen_fits_the_800x600_floor`].
#[cfg(test)]
mod screens_fit_audit {
    use seed_core::contracts::{AddressBuf, Framebuffer, PathStandard, SourceTag, TargetBits, WordCount};
    use seed_gop_ui::gop::mode::{MIN_HEIGHT, MIN_WIDTH};
    use seed_gop_ui::layout::MARGIN_X;
    use seed_gop_ui::theme;

    use crate::chrome::{content_bottom, content_top};
    use crate::screens;

    /// Stand-in for an edition's `release::BUILD_ID`. Deliberately long —
    /// the header's right-aligned stage block is laid out relative to it,
    /// so a longer build string is the header's own worst case.
    const BUILD: &str = "alea-0.1.0-0000000";

    /// One recorded paint: `(y, x, len)`.
    type Paint = (u32, u32, usize);

    /// Every pixel value the chrome bands themselves can contain:
    /// [`crate::chrome::draw_header`]/[`crate::chrome::draw_footer`] fill
    /// with [`theme::PANEL`], rule with [`theme::RULE`], and draw their
    /// glyphs with `theme::on_panel(fg)` for exactly these foregrounds
    /// (stage dots: `ACCENT`/`CAPTION`; key hints: `ACCENT`/`ACCENT_DIM`/
    /// `DANGER`; labels: `CAPTION`; titles: `TEXT`).
    ///
    /// A paint inside a band carrying anything else — a `theme::BG`
    /// background (every content glyph is `theme::on_bg`), a `WARN`/`OK`
    /// role, a QR module — is content that escaped the content area.
    const CHROME_BAND_PIXELS: [u32; 7] = [
        theme::PANEL,
        theme::RULE,
        theme::ACCENT,
        theme::ACCENT_DIM,
        theme::DANGER,
        theme::CAPTION,
        theme::TEXT,
    ];

    /// Does this paint carry any pixel the chrome bands could never
    /// contain? See [`CHROME_BAND_PIXELS`].
    fn is_content_ink(px: &[u32]) -> bool {
        px.iter().any(|p| !CHROME_BAND_PIXELS.contains(p))
    }

    /// See the module doc comment.
    struct ChromeAuditFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
        /// `false` until the first paint that is not pure [`theme::BG`],
        /// i.e. until the opening full-screen `scrub_fill` is behind us.
        armed: bool,
        band_collisions: std::vec::Vec<Paint>,
        right_overruns: std::vec::Vec<Paint>,
        /// Set once content ink lands INSIDE the content area — proof the
        /// audited render actually drew a screen, so a case that silently
        /// stopped rendering cannot pass as "no violations found".
        saw_content: bool,
    }

    impl ChromeAuditFb {
        fn new() -> Self {
            Self {
                w: MIN_WIDTH,
                h: MIN_HEIGHT,
                buf: std::vec![0u32; (MIN_WIDTH as usize) * (MIN_HEIGHT as usize)],
                armed: false,
                band_collisions: std::vec::Vec::new(),
                right_overruns: std::vec::Vec::new(),
                saw_content: false,
            }
        }

        /// Start a fresh audit over the same buffer (a screen's own
        /// `scrub_fill` wipes it anyway, so only the findings reset).
        fn reset(&mut self) {
            self.armed = false;
            self.saw_content = false;
            self.band_collisions.clear();
            self.right_overruns.clear();
        }
    }

    impl Framebuffer for ChromeAuditFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            if !self.armed {
                if px.iter().any(|&p| p != theme::BG) {
                    self.armed = true;
                }
            } else {
                let in_band = y < content_top() || y > content_bottom();
                let is_content_ink = is_content_ink(px);
                if is_content_ink {
                    if in_band {
                        self.band_collisions.push((y, x, px.len()));
                    } else {
                        self.saw_content = true;
                    }
                }
                // Measured on glyph/QR-module-sized paints only. `fill_rect`
                // and `scrub_fill` emit their rows in 256-pixel chunks from a
                // fixed on-stack buffer, so a chunk's own `x` says nothing
                // about where its logical rectangle began — the tail chunk of
                // a full-width chrome band fill starts at x=768 and would
                // otherwise read as a content overrun.
                let cell = px.len() <= (seed_gop_ui::font::GLYPH_WIDTH * 2) as usize;
                if cell && is_content_ink && x + px.len() as u32 > MIN_WIDTH - MARGIN_X {
                    self.right_overruns.push((y, x, px.len()));
                }
            }

            if y >= self.h || x >= self.w {
                return;
            }
            let n = px.len().min((self.w - x) as usize);
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + n].copy_from_slice(&px[..n]);
        }
    }

    /// Render `draw` into a fresh audit and assert it stayed inside the
    /// chrome-bounded content area at the floor.
    fn audit(fb: &mut ChromeAuditFb, case: &str, draw: impl FnOnce(&mut ChromeAuditFb)) {
        fb.reset();
        draw(fb);
        assert!(
            fb.saw_content,
            "{case}: nothing was drawn in the content area — the audit had nothing to check"
        );
        assert!(
            fb.band_collisions.is_empty(),
            "{case}: content collides with a chrome band (content area is y={}..={} at \
             {MIN_WIDTH}x{MIN_HEIGHT}); offending (y, x, len) paints: {:?}",
            content_top(),
            content_bottom(),
            fb.band_collisions
        );
        assert!(
            fb.right_overruns.is_empty(),
            "{case}: content runs past the x={} right margin; offending (y, x, len) paints: {:?}",
            MIN_WIDTH - MARGIN_X,
            fb.right_overruns
        );
    }

    // ---- fixtures ----------------------------------------------------

    fn graphics_info(path: &str) -> crate::diagnostics::GraphicsInfo {
        crate::diagnostics::GraphicsInfo {
            width: MIN_WIDTH,
            height: MIN_HEIGHT,
            device_path: seed_gop_ui::gop::device_path::ascii_from_utf16(
                path.encode_utf16().collect::<std::vec::Vec<u16>>(),
            ),
        }
    }

    /// The §22.3 recap at its widest: a real architecture line, both path
    /// counts set, every informational item present.
    fn recap() -> crate::diagnostics::DiagRecap {
        crate::diagnostics::DiagRecap {
            architecture_line: "x86-64",
            con_out_paths: 3,
            con_in_paths: 2,
            secure_boot: crate::diagnostics::SecureBootStatus::Enabled,
            entropy_policy_version: Some(u16::MAX),
            production_markers_verified: true,
            crypto_clean: true,
        }
    }

    /// Every entropy mode available — the Setup screen's tallest shape
    /// (no row is disabled, and the instrument row is live for the
    /// physical modes).
    fn all_modes_available() -> crate::entropy_avail::ModeAvailability {
        crate::entropy_avail::ModeAvailability {
            combined: Ok(()),
            dice_only: Ok(()),
            machine_only: Ok(()),
        }
    }

    fn address(standard: PathStandard, s: &str) -> seed_core::pipeline::StandardAddress {
        let mut bytes = [0u8; AddressBuf::CAPACITY];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        seed_core::pipeline::StandardAddress {
            standard,
            address: AddressBuf::new(bytes, s.len()),
        }
    }

    /// The longest real mainnet addresses of each standard (the taproot
    /// one is the 62-character worst case), so the Verify screen's
    /// revealed state is audited at its true width.
    fn verification_values() -> seed_core::pipeline::VerificationValues {
        seed_core::pipeline::VerificationValues {
            master_fingerprint: [0xa1, 0xb2, 0xc3, 0xd4],
            addresses: [
                address(PathStandard::Bip44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
                address(PathStandard::Bip49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
                address(PathStandard::Bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
                address(
                    PathStandard::Bip86,
                    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                ),
            ],
        }
    }

    /// A descriptor-shaped payload of exactly `len` bytes — mirrors
    /// `screens::export::tests::descriptor_shaped` (duplicated rather
    /// than widened, since that one lives inside the screen's own private
    /// test module).
    fn synthetic_descriptor(len: usize) -> std::vec::Vec<u8> {
        const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut out = std::vec::Vec::with_capacity(len);
        out.extend_from_slice(b"wpkh([73c5da0a/84h/0h/0h]xpub");
        while out.len() + 14 < len {
            out.push(B58[out.len() % B58.len()]);
        }
        out.extend_from_slice(b"/0/*)#abcdefgh");
        out.truncate(len);
        out
    }

    /// An arena holding the canonical ceremony mnemonic ("abandon
    /// abandon ... about") — the fixture `screens::export`'s own tests
    /// use, so this sweep exports the same pinned artifacts.
    fn ceremony_arena() -> seed_core::arena::SecretArena {
        let word = |target: &str| {
            (0..2048u16).find(|&i| seed_core::bip39::word(i) == target).expect("word in list")
        };
        let mut arena = seed_core::arena::SecretArena::new();
        {
            let idx = arena.mnemonic_indexes();
            for slot in idx.iter_mut().take(11) {
                *slot = word("abandon");
            }
            idx[11] = word("about");
        }
        arena
    }

    // ---- the sweep ---------------------------------------------------

    /// Every redesigned screen, at its worst case, at the floor.
    ///
    /// # Coverage table
    ///
    /// | Screen | Worst case(s) audited here | Complementary module-local test |
    /// |---|---|---|
    /// | `prepare` | nothing checked (disabled `[Enter]` + reason) / all three checked | `prepare::tests::render_does_not_panic_at_floor_resolution` (no analytic height test — this sweep is its geometry coverage) |
    /// | `gates` | none passed / all four passed | `gates::tests::render_draws_something_and_does_not_panic` (likewise) |
    /// | `device` | §11.4 resolution + device-path lines, unarmed and skip-armed (the extra `WARN` line) | `device::tests::worst_case_content_fits_above_the_footer_at_the_floor` (analytic row math) |
    /// | `setup` | all three modes x 12/24 words, every mode available (instrument row live), widest recap — dice-only carries the longest mandated warning | `setup::tests::warning_lines_fit_the_fixed_bound`, `setup::tests::render_every_mode_does_not_panic` (no analytic height test — this sweep is its geometry coverage) |
    /// | `generate` | Combined with all four source tags claimed (the §16 disclaimer's trigger) + §8.4 warning + arm confirm; dice-only and machine-only too | `generate::tests::worst_case_composition_fits_floor_budget` (analytic line budget) |
    /// | `verify` | hidden / revealed (four addresses) x passphrase caveat on/off | `verify::tests::tallest_state_fits_between_the_chrome_bands` (analytic row math), `verify::tests::address_rows_fit_the_floor` |
    /// | `export_warning` | the fixed screen | `export_warning::tests::panel_fits_between_the_chrome_bands` |
    /// | `export` | all five kinds x SLIP-132 on/off (BIP49's `sh(wpkh(..))` is the longest *derivable* descriptor), plus two synthetic maxima: the longest holdable 180-byte descriptor and a version-13 symbol (69 modules a side) | `export::tests::the_longest_holdable_descriptor_renders_inside_the_layout_at_the_floor` and `a_version_13_symbol_still_fits_the_qr_block_at_the_floor` (module size >= 3px — the T16 floor — and the ISO 4-module quiet zone inside the QR box, plus lossless wrapping), `both_columns_end_above_the_privacy_panel`, `every_kind_fits_a_supported_qr_version`, `every_row_and_caption_fits_its_column_at_the_floor` |
    /// | `finish` | the fixed screen | `finish::tests::content_fits_between_the_chrome_bands` |
    ///
    /// Screens whose own module-local test is the *only* other geometry
    /// check are still swept here; nothing is covered by pointer alone.
    #[test]
    fn fit_audit_every_redesigned_screen_fits_the_800x600_floor() {
        let mut fb = ChromeAuditFb::new();

        // -- Stage 1 PREPARE ------------------------------------------
        {
            let mut st = screens::prepare::PrepareState::new();
            audit(&mut fb, "prepare_nothing_checked", |fb| {
                screens::prepare::render(fb, &st, BUILD);
            });
            for c in ['1', '2', '3'] {
                let _ = st.handle_key(crate::keys::MenuKey::Char(c));
            }
            assert!(st.all_checked());
            audit(&mut fb, "prepare_all_checked", |fb| {
                screens::prepare::render(fb, &st, BUILD);
            });
        }

        // -- Stage 2 auto-gate checklist ------------------------------
        {
            let none = screens::gates::GateList::new();
            audit(&mut fb, "gates_none_passed", |fb| {
                screens::gates::render_gates(fb, &none, BUILD);
            });
            let all = screens::gates::GateList { passed: [true; 4] };
            audit(&mut fb, "gates_all_passed", |fb| {
                screens::gates::render_gates(fb, &all, BUILD);
            });
        }

        // -- Stage 2 DEVICE (SPEC §11.4 lines + the armed skip warning)
        {
            let info = graphics_info("PciRoot(0x0)/Pci(0x2,0x0)");
            for (name, st) in [
                ("device_unarmed", screens::device::DeviceState { skip_armed: false }),
                ("device_skip_armed", screens::device::DeviceState { skip_armed: true }),
            ] {
                audit(&mut fb, name, |fb| screens::device::render(fb, &st, &info, BUILD));
            }
        }

        // -- Stage 3 SETUP --------------------------------------------
        {
            use seed_protocol::state::EntropyMode;
            let avail = all_modes_available();
            let recap = recap();
            for mode in [EntropyMode::Combined, EntropyMode::DiceOnly, EntropyMode::MachineOnly] {
                for words24 in [false, true] {
                    let st = screens::setup::SetupState {
                        row: 1,
                        words24,
                        mode,
                        instrument: crate::flow_secret::physical::Instrument::Both,
                        ..screens::setup::SetupState::new()
                    };
                    let case = std::format!("setup_{mode:?}_{}", if words24 { 24 } else { 12 });
                    audit(&mut fb, &case, |fb| {
                        screens::setup::render(fb, &st, &avail, &recap, BUILD);
                    });
                }
            }
        }

        // -- Stage 5 GENERATE -----------------------------------------
        {
            use crate::flow_secret::composition::{CompositionModel, MachineTagSet};

            // Worst case: Combined, every machine source claimed (which is
            // what puts the SPEC §16 "claimed, not measured" disclaimer on
            // screen), maximum policy version, both physical instruments.
            let mut all_tags = MachineTagSet::new();
            all_tags.insert(SourceTag::ApprovedEfiRng);
            all_tags.insert(SourceTag::X86Rdseed64);
            all_tags.insert(SourceTag::X86RdrandSupplementary);
            all_tags.insert(SourceTag::ApprovedUsbTrng);
            let worst = CompositionModel::new(128, 40, all_tags, TargetBits::Bits256, u16::MAX);
            audit(&mut fb, "generate_combined_all_tags_worst_case", |fb| {
                screens::generate::render(fb, &worst, BUILD);
            });

            let dice_only = CompositionModel::new(
                128,
                0,
                MachineTagSet::new(),
                TargetBits::Bits256,
                u16::MAX,
            );
            audit(&mut fb, "generate_dice_only", |fb| {
                screens::generate::render(fb, &dice_only, BUILD);
            });

            let mut machine_tags = MachineTagSet::new();
            machine_tags.insert(SourceTag::X86Rdseed64);
            let machine_only =
                CompositionModel::new(0, 0, machine_tags, TargetBits::Bits256, u16::MAX);
            audit(&mut fb, "generate_machine_only", |fb| {
                screens::generate::render(fb, &machine_only, BUILD);
            });
        }

        // -- Stage 7 VERIFY -------------------------------------------
        {
            let values = verification_values();
            for show in [false, true] {
                for passphrase_set in [false, true] {
                    let st = screens::verify::VerifyState { show_addresses: show };
                    let case = std::format!(
                        "verify_{}_{}",
                        if show { "revealed" } else { "hidden" },
                        if passphrase_set { "with_passphrase_caveat" } else { "no_passphrase" }
                    );
                    audit(&mut fb, &case, |fb| {
                        screens::verify::render(fb, &st, &values, passphrase_set, BUILD);
                    });
                }
            }
        }

        // -- Stage 7 [X] export branch --------------------------------
        {
            audit(&mut fb, "export_warning", |fb| {
                screens::export_warning::render(fb, BUILD);
            });

            use screens::export::{compute_export, ExportKind, ExportState, ExportValues};
            let mut arena = ceremony_arena();
            for kind in [
                ExportKind::Bip44,
                ExportKind::Bip49,
                ExportKind::Bip84,
                ExportKind::Bip86,
                ExportKind::Bip48Cosigner,
            ] {
                for slip132 in [false, true] {
                    let st = ExportState { kind, slip132, cosigner_account: 3 };
                    let mut values = ExportValues::new();
                    compute_export(&mut arena, WordCount::Twelve, &st, &mut values)
                        .expect("the ceremony fixture derives every export kind");
                    let case = std::format!("export_{kind:?}_slip132_{slip132}");
                    audit(&mut fb, &case, |fb| {
                        screens::export::render(fb, &st, &values, BUILD);
                    });
                    values.scrub();
                }
            }

            // The two synthetic maxima no derivable seed can reach: the
            // longest descriptor `ExportValues` can hold at all (180
            // bytes, 26 longer than the longest derivable one), and a
            // symbol at `seed_qr`'s version-13 ceiling (331 payload
            // bytes -> 69 modules a side, drawn at 4px/module with its
            // ISO 4-module quiet zone inside the 352px QR box).
            //
            // `screens::export`'s own
            // `the_longest_holdable_descriptor_renders_inside_the_layout_at_the_floor`
            // and `a_version_13_symbol_still_fits_the_qr_block_at_the_floor`
            // own the module-size / quiet-zone / wrap-losslessness
            // arithmetic — they can see that screen's private layout
            // constants. What this sweep adds, against the same two
            // fixtures, is the chrome-band and right-margin check.
            let printed = synthetic_descriptor(180);
            let xpub = std::vec![b'x'; 112];
            for (case, symbol_payload) in [
                ("export_synthetic_longest_holdable_descriptor", synthetic_descriptor(180)),
                ("export_synthetic_version_13_symbol", synthetic_descriptor(331)),
            ] {
                let st =
                    ExportState { kind: ExportKind::Bip84, slip132: false, cosigner_account: 0 };
                let values =
                    ExportValues::synthetic([0xff; 4], &xpub, &printed, &symbol_payload);
                audit(&mut fb, case, |fb| screens::export::render(fb, &st, &values, BUILD));
            }
        }

        // -- Stage 7 FINISH -------------------------------------------
        audit(&mut fb, "finish", |fb| screens::finish::render(fb, BUILD));
    }

    /// The audit above is only evidence if its detector can fail. This
    /// draws a synthetic "screen" whose content deliberately runs one
    /// line past [`content_bottom`] and one glyph past the right margin,
    /// and asserts both findings are reported.
    #[test]
    fn fit_audit_harness_flags_a_screen_that_overflows_its_content_area() {
        let mut fb = ChromeAuditFb::new();
        fb.reset();

        seed_gop_ui::font::scrub_fill(&mut fb, theme::BG);
        crate::chrome::draw_header(&mut fb, &crate::chrome::Chrome { stage: 1, sub: None, build: BUILD });
        // One content row below the content area (into the footer band).
        seed_gop_ui::font::draw_text(
            &mut fb,
            MARGIN_X,
            content_bottom() + seed_gop_ui::layout::LINE_PITCH,
            "this row belongs to the footer band",
            theme::on_bg(theme::TEXT),
        );
        // One content row that runs past the right margin.
        seed_gop_ui::font::draw_text(
            &mut fb,
            MIN_WIDTH - MARGIN_X - seed_gop_ui::font::GLYPH_WIDTH,
            content_top(),
            "over",
            theme::on_bg(theme::TEXT),
        );
        crate::chrome::draw_footer(&mut fb, &[]);

        assert!(!fb.band_collisions.is_empty(), "a row inside the footer band must be flagged");
        assert!(!fb.right_overruns.is_empty(), "a row past the right margin must be flagged");
    }

    /// SPEC §11.4's device-path line is built from a *runtime* string
    /// (`GraphicsInfo::device_path`, up to
    /// `MAX_DEVICE_PATH_TEXT` = 160 characters) that no amount of copy
    /// tightening can shrink, so it is the one value on any redesigned
    /// screen that can exceed the 96-column floor budget. This pins what
    /// happens when it does: the line clips at the framebuffer's right
    /// edge (`seed_gop_ui::font::draw_glyph_scaled`'s own clipping), and
    /// the overflow stays confined to that one row — it never wraps into
    /// the next line, never collides with either chrome band, and never
    /// panics.
    ///
    /// Reported as a finding rather than fixed here: making a pathological
    /// device path readable is a truncate/ellipsize/wrap decision for
    /// `screens::device`, not a spacing change.
    #[test]
    fn a_pathological_device_path_clips_at_the_right_edge_and_nowhere_else() {
        let mut fb = ChromeAuditFb::new();
        fb.reset();
        let long = "PciRoot(0x0)/".repeat(20);
        let info = graphics_info(&long);
        let st = screens::device::DeviceState::new();
        screens::device::render(&mut fb, &st, &info, BUILD);

        assert!(
            fb.band_collisions.is_empty(),
            "an over-long device path must never bleed into a chrome band: {:?}",
            fb.band_collisions
        );
        assert!(
            !fb.right_overruns.is_empty(),
            "the 160-character device path is expected to overrun the right margin today"
        );
        let device_path_row = content_top() + seed_gop_ui::layout::LINE_PITCH;
        let rows = device_path_row..device_path_row + seed_gop_ui::font::GLYPH_HEIGHT;
        assert!(
            fb.right_overruns.iter().all(|&(y, _, _)| rows.contains(&y)),
            "the overrun must be confined to the device-path row: {:?}",
            fb.right_overruns
        );
    }
}
