//! `crate::launcher` — the desktop rehearsal edition's landing screen /
//! tools menu (SPEC_MAIN_MENU.md §4, §6.1). Replaces the implicit
//! "launch straight into the ceremony" behavior of `crate::window::run`
//! with a rich, keyboard-first landing screen: five items — rehearse a
//! seed, cross-device verification, learn, self-check, about/audit
//! (§4.1) — reachable from one place, arrow **and** number-shortcut
//! navigation (§4.2), rendered inside the existing SPEC §4.3 watermark
//! bands `crate::window::present_frame` composites every frame (§4.4).
//!
//! # Module layout (SPEC_MAIN_MENU.md §6.1)
//!
//! - [`menu`] — the five-item model, host-testable arrow/number
//!   navigation logic, and the landing-screen row renderer.
//! - [`compat`] — item (2), cross-device verification over `seed-compat`
//!   (SPEC_COMPAT §5-§9; SPEC_MAIN_MENU.md §15 OQ1: **enabled** on this
//!   edition).
//! - [`learn`] — item (3), the SPEC §34 educational content plus the
//!   `edu-ui`/`dice-coin-art` read-only demos.
//! - [`about`] — item (5), version/build-id/edition/watermark/audit info.
//!
//! Item (1) (`crate::ceremony::run`) and item (4) (`crate::check::run`)
//! already exist; this module only calls them (§6.1) — item (4) is
//! rendered through the shared [`seed_flow::output::TextOutput`] seam via
//! [`render_check_report`] instead of `check::print_report`'s stdout path.
//!
//! # Composition seam (SPEC_MAIN_MENU.md §6.2) — WP-M1
//!
//! `crate::window::run` spawns [`run`] on the worker thread in place of
//! the old direct `ceremony::run(worker_fb, rx, W, H)` call. [`run`] owns
//! the landing loop: render the menu, read one key, dispatch, repeat
//! (§6.2's pseudocode), implemented via the private `run_loop`/
//! `LauncherOps` seam below so the sequencing logic (highlight movement,
//! number shortcuts, "which item routes to which handler", "a handler
//! returning re-renders the menu", "Esc quits") is host-testable against
//! fake render/key-read/activate behavior — see `tests::mock` — with no
//! real window, `SharedFramebuffer`, or `mpsc` channel involved.
//!
//! ## Item 1 / `ceremony::run_rehearsal` (formerly "the one honest
//! limitation")
//!
//! Every routed tool below (`compat::run`, `learn::run`, `about::run`,
//! the in-window `check::run` wrapper, and now `ceremony::run_rehearsal`)
//! takes `(&mut SharedFramebuffer, &mut ChannelKeys, ..)` and returns
//! normally, so the landing loop can re-render itself afterward (§4.5
//! "return to the menu"). Before the SPEC.md §21 amendment (2026-08-04,
//! "pre-secret Back navigation"), `crate::ceremony::run` had a different,
//! `-> !` signature (an **owned** `Receiver<KeyMsg>`, never returning)
//! that this module could only hand off to once per launch — see that
//! module's own doc comment for why it now returns
//! [`ceremony::RehearsalOutcome::BackToMenu`] once the user backs all the
//! way out before any secret exists, and still never returns on every
//! other path (SPEC §21/§26's "never return to a menu" discipline is
//! unchanged for those). [`RealOps`] now constructs its single
//! [`crate::channel_keys::ChannelKeys`] eagerly, exactly like every other
//! resource it owns, and every item — including item 1 — is freely
//! re-enterable for the rest of this worker thread's life.

use std::sync::mpsc::Receiver;

use seed_flow::chrome::{self, KeyHint};
use seed_flow::output::{FbTextOutput, TextOutput};
use seed_gop_ui::font::{draw_text, scrub_fill};
use seed_gop_ui::layout::{LINE_PITCH, MARGIN_X};
use seed_gop_ui::theme;

use crate::ceremony;
use crate::channel_keys::{ChannelKeys, KeyMsg};
use crate::check;
use crate::launcher::about::BUILD_ID;
use crate::shared_screen::{SharedFramebuffer, WindowTextOutput};
use crate::vectors;

/// The main-menu screen's footer key hints (design doc §3.3; `ACCENT`
/// selection replaces the plain-text `>` cursor `menu::render`'s
/// `TextOutput`-only version still uses for its own host tests).
const MENU_HINTS: [KeyHint; 4] = [
    KeyHint { key: "Up/Down", label: "Move", enabled: true, danger: false },
    KeyHint { key: "Enter", label: "Select", enabled: true, danger: false },
    KeyHint { key: "1-5", label: "Jump", enabled: true, danger: false },
    KeyHint { key: "Esc", label: "Quit", enabled: true, danger: false },
];

/// The Esc confirm-quit dialog's footer key hints.
const CONFIRM_QUIT_HINTS: [KeyHint; 2] = [
    KeyHint { key: "Up/Down/Y/N", label: "Choose", enabled: true, danger: false },
    KeyHint { key: "Enter", label: "Confirm", enabled: true, danger: false },
];

/// The read-only screens' (About) shared single-hint footer -- any key
/// (SPEC_MAIN_MENU.md §4.1 item 5's "any key returns" convention).
const RETURN_HINT: [KeyHint; 1] = [KeyHint { key: "any key", label: "Return to the menu", enabled: true, danger: false }];

/// Self-check's own footer: unlike About, only `Enter` returns
/// ([`RealOps::activate_check`]'s own read loop).
const ENTER_RETURN_HINT: [KeyHint; 1] = [KeyHint { key: "Enter", label: "Return to the menu", enabled: true, danger: false }];

pub mod about;
pub mod compat;
/// SPEC_DERIVATION_CUSTOM.md §9/§11.2: the SECONDARY desktop free-form
/// custom derivation-path tool, reached with `[P]` from the compat result
/// screen and operating on the compat-derived public/throwaway seed (§9.6).
pub mod custom_path;
pub mod learn;
pub mod menu;

/// Entry point (SPEC_MAIN_MENU.md §6.2), wired in by `crate::window::run`
/// in place of the old direct `ceremony::run(worker_fb, rx, W, H)` call.
/// Owns the landing loop for the rest of this worker thread's life: never
/// returns (mirrors every worker-thread entry point in this crate —
/// `crate::ceremony::run`'s own doc comment: "every path ends in an idle
/// loop"), because the only ways out of the loop are `NavAction::Quit`
/// (§4.6 — falls into [`render_quit_screen`] + [`idle_forever`], since
/// this worker thread does not own the winit event loop and so cannot
/// itself close the OS window; closing it remains a valid quit at any
/// time, as documented there) or item (1) handing off permanently to
/// `ceremony::run` (see module doc comment's "one honest limitation").
pub fn run(fb: SharedFramebuffer, keys_rx: Receiver<KeyMsg>, window_width: u32, window_height: u32) -> ! {
    let mut ops = RealOps {
        out: WindowTextOutput::new(fb.clone()),
        fb: fb.clone(),
        window_width,
        window_height,
        channel_keys: ChannelKeys::new(keys_rx),
    };

    run_loop(menu::items(), &mut ops);

    // `run_loop` returns only via `NavAction::Quit` (SPEC §4.2/§4.6).
    let mut fb = fb;
    render_quit_screen(&mut fb);
    idle_forever()
}

/// The landing loop's I/O seam (SPEC_MAIN_MENU.md §6.2 pseudocode: render
/// -> read key -> dispatch -> repeat), abstracted behind one trait so
/// [`run_loop`] itself never touches a real `SharedFramebuffer` or
/// `mpsc` channel and is exercised in `tests::mock` against a fake
/// implementation instead.
trait LauncherOps {
    /// Render the landing screen for the currently-highlighted row.
    fn render(&mut self, items: &[menu::MenuItem], highlighted: u8);
    /// Render the Esc confirm-quit dialog with `highlighted` selected
    /// (SPEC §4.6 quit, guarded by a deliberate confirm — see
    /// [`confirm_quit`]).
    fn render_confirm_quit(&mut self, highlighted: menu::ConfirmChoice);
    /// Block for the next raw keystroke.
    fn read_key(&mut self) -> KeyMsg;
    /// Activate (route to) the row with this id (SPEC_MAIN_MENU.md §4.1).
    /// Blocks for the duration of that tool; returning means "back to the
    /// menu" (§4.5).
    fn activate(&mut self, id: u8);
}

/// SPEC_MAIN_MENU.md §6.2's landing loop, decoupled from any concrete
/// I/O via [`LauncherOps`] so it is host-testable (task DoD: "drive the
/// menu state machine with a mock key source + a captured-text
/// `TextOutput` double"). Returns only once [`menu::handle_key`] reports
/// [`menu::NavAction::Quit`] (`Esc` at the top level, SPEC §4.2/§4.6).
fn run_loop<O: LauncherOps>(items: &[menu::MenuItem], ops: &mut O) {
    let mut highlighted = items.iter().find(|it| it.enabled).map_or(1, |it| it.id);
    loop {
        ops.render(items, highlighted);
        let key = ops.read_key();
        match menu::handle_key(items, highlighted, key) {
            menu::NavAction::Highlight(id) => highlighted = id,
            menu::NavAction::Activate(id) => ops.activate(id),
            // SPEC §4.6 quit is now guarded: a single stray `Esc` opens
            // the confirm-quit dialog instead of closing immediately. Only
            // a deliberate confirm (Yes + Enter) returns from `run_loop`;
            // anything else falls through and re-renders the menu.
            menu::NavAction::Quit => {
                if confirm_quit(ops) {
                    return;
                }
            }
            menu::NavAction::None => {}
        }
    }
}

/// The Esc confirm-quit sub-loop (SPEC §4.6, guarded): render the dialog,
/// read one key, dispatch via [`menu::confirm_quit_handle_key`], repeat.
/// Returns `true` only on a deliberate `Yes` + `Enter` (actually quit);
/// returns `false` on `No`/`[N]`/`Esc`/`Enter`-while-`No` (back to the
/// menu). The highlight DEFAULTS to `No`, so a reflexive `Esc`-then-`Enter`
/// keeps the app open. Reuses the same [`LauncherOps`] render/key seam as
/// the menu loop — no new thread or channel.
fn confirm_quit<O: LauncherOps>(ops: &mut O) -> bool {
    let mut choice = menu::ConfirmChoice::No;
    loop {
        ops.render_confirm_quit(choice);
        let key = ops.read_key();
        match menu::confirm_quit_handle_key(choice, key) {
            menu::ConfirmAction::Highlight(c) => choice = c,
            menu::ConfirmAction::Quit => return true,
            menu::ConfirmAction::Cancel => return false,
            menu::ConfirmAction::None => {}
        }
    }
}

/// The real [`LauncherOps`] implementation: renders into the shared
/// [`SharedFramebuffer`]/[`WindowTextOutput`] seam every pre-secret
/// `seed-flow` screen already renders through, and reads keys off the
/// same `mpsc` channel `crate::window::run` hands to every worker-thread
/// entry point (§6.2 "no new threads, no new channels").
///
/// SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation"):
/// `ceremony::run_rehearsal` (item 1) now returns instead of never
/// returning (see its own doc comment), so it needs exactly the same
/// `&mut ChannelKeys` seam every other item already uses — the previous
/// "one honest limitation" (item 1 usable only once per launch, before
/// any other item, because `ceremony::run` used to take an **owned**
/// `Receiver<KeyMsg>` it could hand off to permanently) is gone: this
/// struct now constructs its single [`ChannelKeys`] eagerly, like a
/// normal resource, and every item — including item 1 — is freely
/// re-enterable.
struct RealOps {
    out: WindowTextOutput,
    fb: SharedFramebuffer,
    window_width: u32,
    window_height: u32,
    channel_keys: ChannelKeys,
}

impl RealOps {
    /// Item (1) (SPEC_MAIN_MENU.md §4.1): runs the rehearsal ceremony.
    /// Returns to the landing loop (§4.5) either because the ceremony
    /// completed (it never returns on that path -- see `run_rehearsal`'s
    /// own doc comment) or because the user backed all the way out
    /// before any secret existed (SPEC.md §21 amendment:
    /// `RehearsalOutcome::BackToMenu`).
    fn activate_generate(&mut self) {
        let mut fbc = self.fb.clone();
        let ceremony::RehearsalOutcome::BackToMenu =
            ceremony::run_rehearsal(&mut fbc, &mut self.channel_keys, self.window_width, self.window_height);
    }

    /// Item (4) (SPEC_MAIN_MENU.md §4.1): runs the existing headless
    /// vector check and renders its [`check::CheckReport`] into the
    /// shared `TextOutput` seam instead of stdout (`crate::check::
    /// print_report`'s target); returns to the launcher on `Enter`
    /// (§4.1 item 4 "Return semantics").
    fn activate_check(&mut self) {
        let report = check::run(&vectors::frozen_dir());
        scrub_fill(&mut self.fb, 0);
        chrome::draw_header_plain(&mut self.fb, "ALEA -- Self-check / verify build", BUILD_ID);
        {
            let mut out = FbTextOutput::at(&mut self.fb, chrome::content_top());
            render_check_report(&mut out, &report);
        }
        chrome::draw_footer(&mut self.fb, &ENTER_RETURN_HINT);
        loop {
            if let KeyMsg::Enter = self.read_key() {
                return;
            }
        }
    }
}

impl LauncherOps for RealOps {
    fn render(&mut self, items: &[menu::MenuItem], highlighted: u8) {
        scrub_fill(&mut self.fb, 0);
        chrome::draw_header_plain(&mut self.fb, "ALEA -- main menu", BUILD_ID);
        let mut y = chrome::content_top();
        for it in items {
            let selected = it.id == highlighted;
            let color = if !it.enabled {
                theme::CAPTION
            } else if selected {
                theme::ACCENT
            } else {
                theme::TEXT
            };
            let cursor = if selected { ">" } else { " " };
            let title_line = if it.enabled {
                format!("{cursor} [{}] {}", it.key, it.title)
            } else {
                format!("{cursor} [{}] {} (disabled)", it.key, it.title)
            };
            draw_text(&mut self.fb, MARGIN_X, y, &title_line, theme::on_bg(color));
            y += LINE_PITCH;
            draw_text(&mut self.fb, MARGIN_X, y, &format!("      {}", it.desc), theme::on_bg(theme::CAPTION));
            y += LINE_PITCH;
        }
        chrome::draw_footer(&mut self.fb, &MENU_HINTS);
    }

    fn render_confirm_quit(&mut self, highlighted: menu::ConfirmChoice) {
        scrub_fill(&mut self.fb, 0);
        chrome::draw_header_plain(&mut self.fb, "ALEA -- main menu", BUILD_ID);
        let mut y = chrome::content_top();
        {
            let mut out = FbTextOutput::at(&mut self.fb, y);
            out.write_line("Close Alea Test?");
            out.write_line("");
            out.write_line("Unsaved practice progress is discarded (nothing real is at stake).");
            out.write_line("");
        }
        y += LINE_PITCH * 4;
        let no_color = if highlighted == menu::ConfirmChoice::No { theme::ACCENT } else { theme::TEXT };
        let yes_color = if highlighted == menu::ConfirmChoice::Yes { theme::ACCENT } else { theme::TEXT };
        let no_cursor = if highlighted == menu::ConfirmChoice::No { ">" } else { " " };
        let yes_cursor = if highlighted == menu::ConfirmChoice::Yes { ">" } else { " " };
        draw_text(&mut self.fb, MARGIN_X, y, &format!("{no_cursor} [N] No, keep working"), theme::on_bg(no_color));
        y += LINE_PITCH;
        draw_text(&mut self.fb, MARGIN_X, y, &format!("{yes_cursor} [Y] Yes, close"), theme::on_bg(yes_color));
        chrome::draw_footer(&mut self.fb, &CONFIRM_QUIT_HINTS);
    }

    fn read_key(&mut self) -> KeyMsg {
        self.channel_keys.recv()
    }

    fn activate(&mut self, id: u8) {
        match id {
            1 => self.activate_generate(),
            2 => {
                let mut fbc = self.fb.clone();
                compat::run(&mut fbc, &mut self.channel_keys);
            }
            3 => {
                let mut fbc = self.fb.clone();
                learn::run(&mut fbc, &mut self.channel_keys);
            }
            4 => self.activate_check(),
            5 => {
                let mut fbc = self.fb.clone();
                about::run(&mut fbc, &mut self.channel_keys);
            }
            _ => {}
        }
    }
}

/// SPEC_MAIN_MENU.md §4.1 item (4): renders a [`check::CheckReport`]
/// (total / failed / one line per case) into `out`, the in-window
/// analogue of `check::print_report`'s stdout output.
fn render_check_report(out: &mut dyn TextOutput, report: &check::CheckReport) {
    out.write_line(&format!("Self-check / verify build -- {} case(s)", report.total_cases));
    out.write_line("");
    for line in &report.lines {
        out.write_line(line);
    }
    out.write_line("");
    out.write_line(&format!(
        "{} vector(s) passed, {} failed",
        report.total_cases - report.failed_cases,
        report.failed_cases
    ));
    // GAP 3 (desktop rehearsal feature parity): the SPEC §11.6 aggregate
    // crypto known-answer self-test, per-item PASS/FAIL, alongside the
    // frozen-vector reproduction above.
    out.write_line("");
    out.write_line("SPEC 11.6 aggregate crypto self-test:");
    for line in check::kat_lines(&report.kat) {
        out.write_line(&line);
    }
}

/// SPEC §4.6 quit screen: this worker thread cannot itself close the OS
/// window (only `crate::window::run`'s event-loop thread owns that), so —
/// exactly like every other non-secret exit path in `crate::ceremony` —
/// this renders a goodbye message and idles; closing the window remains a
/// valid quit at any time (§4.6).
fn render_quit_screen(fb: &mut SharedFramebuffer) {
    let mut out = WindowTextOutput::new(fb.clone());
    out.clear();
    out.write_line("Quit Alea Test");
    out.write_line("");
    out.write_line("You may now close this window.");
}

fn idle_forever() -> ! {
    loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time/shape check (SPEC_MAIN_MENU.md §6.2): every routed
    /// submodule's `run` takes exactly `(&mut SharedFramebuffer, &mut
    /// ChannelKeys)` — the same backend + key source the ceremony uses,
    /// no new thread, no new channel.
    #[test]
    fn routed_submodule_signatures_match_the_shared_seam() {
        fn assert_fn_shape(_f: fn(&mut SharedFramebuffer, &mut ChannelKeys)) {}
        assert_fn_shape(compat::run);
        assert_fn_shape(learn::run);
        assert_fn_shape(about::run);
    }

    /// Host-testable double for [`LauncherOps`] (task DoD: "drive the
    /// menu state machine with a mock key source + a captured-text
    /// `TextOutput` double"). Scripts a fixed sequence of keys and records
    /// every render/activate call for assertion, entirely without a real
    /// window, `SharedFramebuffer`, or `mpsc` channel.
    struct MockOps {
        keys: std::vec::Vec<KeyMsg>,
        /// Every `highlighted` value `render` was called with, in order.
        rendered_highlights: std::vec::Vec<u8>,
        /// Every `highlighted` choice `render_confirm_quit` was called
        /// with, in order (empty unless the confirm-quit dialog opened).
        confirm_renders: std::vec::Vec<menu::ConfirmChoice>,
        /// Every id `activate` was called with, in order.
        activated: std::vec::Vec<u8>,
    }

    /// The keys that deliberately confirm a quit from the menu: `Esc`
    /// opens the guarded dialog, `[Y]` highlights "Yes, close", `Enter`
    /// confirms it. Appended to a script whenever a test needs `run_loop`
    /// to actually return (the old bare-`Esc` quit is now guarded).
    const QUIT_TAIL: [KeyMsg; 3] = [KeyMsg::Escape, KeyMsg::Char('Y'), KeyMsg::Enter];

    impl MockOps {
        fn new(keys: &[KeyMsg]) -> Self {
            let mut keys: std::vec::Vec<KeyMsg> = keys.to_vec();
            keys.reverse(); // pop() from the front in script order
            Self {
                keys,
                rendered_highlights: std::vec::Vec::new(),
                confirm_renders: std::vec::Vec::new(),
                activated: std::vec::Vec::new(),
            }
        }

        /// Build a script that performs `keys` then a deliberate quit
        /// (so `run_loop` returns instead of hanging — the bare-`Esc`
        /// quit is now routed through the confirm dialog).
        fn with_quit(keys: &[KeyMsg]) -> Self {
            let mut all = keys.to_vec();
            all.extend_from_slice(&QUIT_TAIL);
            Self::new(&all)
        }
    }

    impl LauncherOps for MockOps {
        fn render(&mut self, _items: &[menu::MenuItem], highlighted: u8) {
            self.rendered_highlights.push(highlighted);
        }

        fn render_confirm_quit(&mut self, highlighted: menu::ConfirmChoice) {
            self.confirm_renders.push(highlighted);
        }

        fn read_key(&mut self) -> KeyMsg {
            // A script that runs dry means the loop never reached a
            // confirmed quit — a test bug, not real launcher behavior
            // (real `RealOps::read_key` blocks on a live channel). Panic
            // loudly rather than hang: since bare `Esc` now opens the
            // guarded dialog instead of quitting, an un-terminated script
            // would otherwise spin forever.
            self.keys.pop().expect("MockOps script exhausted without a confirmed quit (use with_quit / QUIT_TAIL)")
        }

        fn activate(&mut self, id: u8) {
            self.activated.push(id);
        }
    }

    #[test]
    fn down_then_down_moves_the_highlight_and_skips_nothing_when_all_enabled() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Down, KeyMsg::Down]);
        run_loop(menu::items(), &mut ops);
        // Renders happen *before* each key read: [1] (initial), then [2],
        // [3], then the quit tail (which renders only the confirm dialog).
        assert_eq!(ops.rendered_highlights, vec![1, 2, 3]);
        assert!(ops.activated.is_empty());
    }

    #[test]
    fn up_from_the_first_row_wraps_to_the_last() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Up]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.rendered_highlights, vec![1, 5]);
    }

    #[test]
    fn navigation_skips_a_disabled_row() {
        struct DisabledRow;
        // menu::items() ships with every row enabled (SPEC_MAIN_MENU.md
        // §15 OQ1: compat ships enabled); build a local 3-row fixture with
        // row 2 disabled to exercise the "skip disabled rows" rule the
        // same way `launcher::menu`'s own tests do, but through the full
        // `run_loop` seam this module owns.
        let _ = DisabledRow;
        let items = [
            menu::MenuItem { id: 1, key: '1', title: "a", desc: "", enabled: true },
            menu::MenuItem { id: 2, key: '2', title: "b", desc: "", enabled: false },
            menu::MenuItem { id: 3, key: '3', title: "c", desc: "", enabled: true },
        ];
        let mut ops = MockOps::with_quit(&[KeyMsg::Down]);
        run_loop(&items, &mut ops);
        assert_eq!(ops.rendered_highlights, vec![1, 3]);
    }

    #[test]
    fn number_shortcut_activates_immediately_without_a_prior_highlight_move() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Char('4')]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.activated, vec![4]);
    }

    #[test]
    fn each_item_number_routes_to_its_own_id() {
        let mut ops = MockOps::with_quit(&[
            KeyMsg::Char('1'),
            KeyMsg::Char('2'),
            KeyMsg::Char('3'),
            KeyMsg::Char('4'),
            KeyMsg::Char('5'),
        ]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.activated, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn activating_an_item_returns_to_the_menu_and_re_renders() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Char('3'), KeyMsg::Down]);
        run_loop(menu::items(), &mut ops);
        // Render sequence: [1] (initial, before activating 3), [1] again
        // (back at the menu after the tool returns, highlight unchanged),
        // then [2] after Down. Activation itself does not move the
        // highlight. The trailing quit tail renders only the confirm
        // dialog, not the menu, so it adds nothing here.
        assert_eq!(ops.rendered_highlights, vec![1, 1, 2]);
        assert_eq!(ops.activated, vec![3]);
    }

    #[test]
    fn enter_activates_the_current_highlight() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Down, KeyMsg::Down, KeyMsg::Enter]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.activated, vec![3]);
    }

    /// SPEC §4.6 quit is guarded: a bare `Esc` at the top level opens the
    /// confirm-quit dialog and does NOT return from `run_loop`. The dialog
    /// renders (default highlight `No`), and `run_loop` only returns once
    /// the user deliberately confirms (`Yes` + `Enter`) — the quit tail.
    #[test]
    fn escape_at_the_top_level_opens_the_confirm_dialog_and_does_not_quit_immediately() {
        let mut ops = MockOps::with_quit(&[]);
        run_loop(menu::items(), &mut ops);
        // Only the initial menu render before the guarded quit.
        assert_eq!(ops.rendered_highlights, vec![1]);
        // The dialog opened (default No) then moved to Yes for the confirm.
        assert_eq!(ops.confirm_renders, vec![menu::ConfirmChoice::No, menu::ConfirmChoice::Yes]);
        assert!(ops.activated.is_empty());
    }

    /// Esc opens the dialog; the default highlight is `No`, so a reflexive
    /// `Esc`-then-`Enter` cancels back to the menu (app stays open, the
    /// menu re-renders) rather than quitting.
    #[test]
    fn escape_then_enter_on_default_no_returns_to_the_menu() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Escape, KeyMsg::Enter]);
        run_loop(menu::items(), &mut ops);
        // Menu rendered initially, then AGAIN after the dialog cancelled —
        // proof the app did not quit on the stray Esc+Enter.
        assert_eq!(ops.rendered_highlights, vec![1, 1]);
        // First dialog defaulted to No; the confirm tail's dialog followed.
        assert_eq!(
            ops.confirm_renders,
            vec![menu::ConfirmChoice::No, menu::ConfirmChoice::No, menu::ConfirmChoice::Yes]
        );
        assert!(ops.activated.is_empty());
    }

    /// `[N]` on the dialog cancels straight back to the menu; a second
    /// `Esc` on the dialog does the same. Either way the app stays open.
    #[test]
    fn n_or_second_escape_on_the_dialog_returns_to_the_menu() {
        // Esc -> dialog, [N] -> menu; Esc -> dialog, Esc -> menu; then quit.
        let mut ops = MockOps::with_quit(&[KeyMsg::Escape, KeyMsg::Char('N'), KeyMsg::Escape, KeyMsg::Escape]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.rendered_highlights, vec![1, 1, 1]);
        assert!(ops.activated.is_empty());
    }

    /// Choosing Yes (via `Down`) + `Enter` quits: `run_loop` returns.
    #[test]
    fn yes_highlighted_plus_enter_quits() {
        let mut ops = MockOps::new(&[KeyMsg::Escape, KeyMsg::Down, KeyMsg::Enter]);
        run_loop(menu::items(), &mut ops); // returns (no panic) => quit
        assert_eq!(ops.rendered_highlights, vec![1]);
        assert_eq!(ops.confirm_renders, vec![menu::ConfirmChoice::No, menu::ConfirmChoice::Yes]);
        assert!(ops.activated.is_empty());
    }

    /// A single stray `Esc` (opens the dialog) followed by an innocuous
    /// key must NOT quit: the innocuous key is a no-op that leaves the
    /// dialog open on `No`; the app is proven alive by later cancelling
    /// back to the menu (menu re-renders) before an explicit confirm.
    #[test]
    fn stray_escape_then_innocuous_key_does_not_quit() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Escape, KeyMsg::Char('q'), KeyMsg::Char('n')]);
        run_loop(menu::items(), &mut ops);
        // Menu re-rendered after the [n] cancel => the app stayed open.
        assert_eq!(ops.rendered_highlights, vec![1, 1]);
        // The stray 'q' left the dialog on No (re-rendered, not quit).
        assert_eq!(ops.confirm_renders[0], menu::ConfirmChoice::No);
        assert_eq!(ops.confirm_renders[1], menu::ConfirmChoice::No);
        assert!(ops.activated.is_empty());
    }

    #[test]
    fn digit_for_a_disabled_row_is_a_no_op_and_the_loop_keeps_going() {
        let items = [
            menu::MenuItem { id: 1, key: '1', title: "a", desc: "", enabled: false },
            menu::MenuItem { id: 2, key: '2', title: "b", desc: "", enabled: true },
        ];
        let mut ops = MockOps::with_quit(&[KeyMsg::Char('1'), KeyMsg::Char('2')]);
        run_loop(&items, &mut ops);
        assert_eq!(ops.activated, vec![2]);
    }

    #[test]
    fn backspace_is_ignored_and_the_loop_keeps_going() {
        let mut ops = MockOps::with_quit(&[KeyMsg::Backspace, KeyMsg::Char('5')]);
        run_loop(menu::items(), &mut ops);
        assert_eq!(ops.activated, vec![5]);
    }

    /// [`render_check_report`] is the in-window analogue of
    /// `check::print_report`'s stdout output (SPEC_MAIN_MENU.md §4.1
    /// item 4): total/failed counts and every per-case line must appear.
    #[test]
    fn render_check_report_shows_totals_and_every_case_line() {
        struct RecordingOutput {
            lines: std::vec::Vec<std::string::String>,
        }
        impl TextOutput for RecordingOutput {
            fn write_line(&mut self, line: &str) {
                self.lines.push(line.to_string());
            }
            fn clear(&mut self) {
                self.lines.clear();
            }
        }

        let report = check::CheckReport {
            total_cases: 2,
            failed_cases: 1,
            lines: vec!["file.json :: case-a :: OK".to_string(), "file.json :: case-b :: MISMATCH(word_count)".to_string()],
            kat: seed_selftest::run_aggregate_self_test(None),
        };
        let mut out = RecordingOutput { lines: std::vec::Vec::new() };
        render_check_report(&mut out, &report);
        let joined = out.lines.join("\n");
        assert!(joined.contains("case-a :: OK"));
        assert!(joined.contains("case-b :: MISMATCH"));
        assert!(joined.contains("1 vector(s) passed, 1 failed"));
    }

    /// GAP 3 (desktop rehearsal feature parity): the `[4]` self-check
    /// screen must now render the SPEC §11.6 aggregate crypto self-test's
    /// per-item PASS/FAIL report, with every item passing, alongside the
    /// frozen-vector reproduction.
    #[test]
    fn render_check_report_shows_the_aggregate_kat_all_passing() {
        struct RecordingOutput {
            lines: std::vec::Vec<std::string::String>,
        }
        impl TextOutput for RecordingOutput {
            fn write_line(&mut self, line: &str) {
                self.lines.push(line.to_string());
            }
            fn clear(&mut self) {
                self.lines.clear();
            }
        }

        let kat = seed_selftest::run_aggregate_self_test(None);
        assert!(kat.all_clean(), "aggregate self-test must be clean on the host");
        let report = check::CheckReport {
            total_cases: 1,
            failed_cases: 0,
            lines: vec!["file.json :: case-a :: OK".to_string()],
            kat,
        };
        let mut out = RecordingOutput { lines: std::vec::Vec::new() };
        render_check_report(&mut out, &report);
        let joined = out.lines.join("\n");
        assert!(joined.contains("SPEC 11.6 aggregate crypto self-test:"));
        assert!(joined.contains("SHA-256 KAT :: PASS"));
        assert!(joined.contains("secp256k1 KAT :: PASS"));
        assert!(joined.contains("BIP32 KAT :: PASS"));
        assert!(joined.contains("state-machine invariant KAT :: PASS"));
        assert!(joined.contains("aggregate crypto self-test :: ALL PASS"));
        assert!(!joined.contains(":: FAIL"));
    }
}
