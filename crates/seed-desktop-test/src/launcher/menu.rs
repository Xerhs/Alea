//! The landing screen's static menu model + host-testable navigation
//! logic (SPEC_MAIN_MENU.md §4.1 "five items", §4.2 "keyboard navigation
//! model", §6.1 `model.rs`/`nav.rs`/`render.rs` — folded into this one
//! file per the WP-M0 scaffold task brief's module list).
//!
//! Deliberately free of any `winit`/`softbuffer`/I/O dependency: every
//! function here takes plain values ([`KeyMsg`], `&[MenuItem]`) and
//! returns plain values, so it is exercised by ordinary `#[cfg(test)]`
//! unit tests on a host with no display server at all — the same
//! discipline `seed_flow::text`/`seed_flow::keys` already follow over
//! their own `MockTerminal`/`InputEvent` seams (SPEC_MAIN_MENU.md §6.3).

use seed_flow::output::TextOutput;

use crate::channel_keys::KeyMsg;

/// SPEC_MAIN_MENU.md §4.1: the five landing-screen items, in order.
/// `key` is the SPEC §4.2 number-shortcut digit; `enabled` mirrors the
/// SPEC §22.5-style "unavailable modes are disabled with a specific
/// reason" convention (used today for the compat row, until/unless its
/// own gating logic is wired up here — see `SPEC_MAIN_MENU.md` §15 OQ1
/// resolution: compat ships **enabled** by default on this edition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuItem {
    /// 1-based row id, also the SPEC §4.2 number-shortcut digit.
    pub id: u8,
    pub key: char,
    pub title: &'static str,
    pub desc: &'static str,
    pub enabled: bool,
}

/// SPEC_MAIN_MENU.md §4.1's exactly-five landing rows, in the mock's
/// order (§4.3). `desc` strings are the mock's one-line descriptions.
pub const ITEMS: [MenuItem; 5] = [
    MenuItem {
        id: 1,
        key: '1',
        title: "Create your own seed",
        desc: "Practice the full ceremony on public test entropy. No real keys.",
        enabled: true,
    },
    MenuItem {
        id: 2,
        key: '2',
        title: "Verify a seed from another device",
        desc: "Reproduce a SeedSigner/Coldcard dice-coin seed to check a wallet.",
        // SPEC_MAIN_MENU.md §15 (OQ1 resolved): ENABLED on the desktop
        // rehearsal edition per the SPEC_COMPAT.md v0.6.3 amendment.
        enabled: true,
    },
    MenuItem {
        id: 3,
        key: '3',
        title: "Learn",
        desc: "Entropy, BIP39, hardware wallets & signers, and what Alea does.",
        enabled: true,
    },
    MenuItem {
        id: 4,
        key: '4',
        title: "Self-check / verify build",
        desc: "Reproduce every published test vector bit-for-bit.",
        enabled: true,
    },
    MenuItem {
        id: 5,
        key: '5',
        title: "About / audit-status",
        desc: "Version, build id, watermark meaning, where the audit docs live.",
        enabled: true,
    },
];

/// `ITEMS` as a slice (convenience for callers that want an iterator/
/// slice rather than the fixed-size array).
#[must_use]
pub fn items() -> &'static [MenuItem] {
    &ITEMS
}

/// The result of one keystroke against the landing screen (SPEC
/// §4.2: arrows move a cursor, `Enter` activates, a digit both
/// highlights *and* activates, `Esc` quits/no-ops at the top level).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavAction {
    /// Move the highlighted cursor to this row id, no activation.
    Highlight(u8),
    /// Activate (route to) this row id.
    Activate(u8),
    /// `Esc` at the top level (SPEC §4.2/§4.6).
    Quit,
    /// Key with no effect on the landing screen (e.g. `Backspace`).
    None,
}

/// SPEC_MAIN_MENU.md §4.2: fold one raw keystroke into a [`NavAction`]
/// given the currently-highlighted row id. `Up`/`Down` skip disabled
/// rows (§4.2 "skipping disabled rows"); a digit key both highlights and
/// immediately activates its row *only if* that row is enabled (a
/// disabled row's digit is a no-op, matching the "unavailable modes are
/// disabled" convention it mirrors).
///
/// Host-testable (SPEC_MAIN_MENU.md §6.3): pure function over [`KeyMsg`]
/// and `items`, no I/O.
#[must_use]
pub fn handle_key(items: &[MenuItem], current: u8, key: KeyMsg) -> NavAction {
    match key {
        KeyMsg::Up => next_enabled(items, current, Direction::Up).map_or(NavAction::None, NavAction::Highlight),
        KeyMsg::Down => next_enabled(items, current, Direction::Down).map_or(NavAction::None, NavAction::Highlight),
        KeyMsg::Enter => {
            if items.iter().any(|it| it.id == current && it.enabled) {
                NavAction::Activate(current)
            } else {
                NavAction::None
            }
        }
        KeyMsg::Char(c) => match items.iter().find(|it| it.key == c) {
            Some(it) if it.enabled => NavAction::Activate(it.id),
            _ => NavAction::None,
        },
        KeyMsg::Escape => NavAction::Quit,
        KeyMsg::Backspace | KeyMsg::Other => NavAction::None,
    }
}

/// The two choices on the Esc confirm-quit dialog (mod.rs `confirm_quit`
/// intercept). `No` is the safe default highlight so a reflexive
/// `Esc`-then-`Enter` keeps the app open rather than closing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmChoice {
    /// "No, keep working" — the default highlight (safe: `Enter` here
    /// returns to the menu, never quits).
    No,
    /// "Yes, close" — quitting requires this to be highlighted *and* a
    /// deliberate `Enter` (or the explicit `[Y]` then `Enter`).
    Yes,
}

/// One keystroke's effect on the confirm-quit dialog (mod.rs
/// `confirm_quit`). Pure/host-testable, mirroring [`handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    /// Move the highlight to this choice, without confirming.
    Highlight(ConfirmChoice),
    /// A deliberate confirm of `Yes` — actually quit the app.
    Quit,
    /// Return to the menu without quitting (`No`/`[N]`/`Esc`, or `Enter`
    /// while `No` is highlighted).
    Cancel,
    /// Key with no effect on the dialog (stay put) — so a single stray
    /// `Esc` followed by an innocuous key cannot quit.
    None,
}

/// Fold one raw keystroke on the confirm-quit dialog into a
/// [`ConfirmAction`], given the currently-highlighted choice. Closing the
/// app REQUIRES `Yes` highlighted + `Enter` (or `[Y]` then `Enter`);
/// every other key either moves the highlight, cancels back to the menu,
/// or is a no-op — so an accidental single `Esc` (which opens this
/// dialog) plus one reflexive keypress never quits.
///
/// - `Up`/`Down` toggle between the two choices.
/// - `[Y]` highlights `Yes` (does NOT quit on its own — still needs
///   `Enter`); `[N]` cancels straight back to the menu.
/// - `Enter` confirms the highlighted choice: `Yes` -> [`ConfirmAction::
///   Quit`], `No` -> [`ConfirmAction::Cancel`].
/// - `Esc` cancels back to the menu (a second `Esc` = "no, keep working").
/// - Anything else is a no-op (the dialog stays open, unchanged).
///
/// Host-testable (SPEC_MAIN_MENU.md §6.3): pure function over [`KeyMsg`].
#[must_use]
pub fn confirm_quit_handle_key(current: ConfirmChoice, key: KeyMsg) -> ConfirmAction {
    match key {
        KeyMsg::Up | KeyMsg::Down => ConfirmAction::Highlight(match current {
            ConfirmChoice::No => ConfirmChoice::Yes,
            ConfirmChoice::Yes => ConfirmChoice::No,
        }),
        KeyMsg::Enter => match current {
            ConfirmChoice::Yes => ConfirmAction::Quit,
            ConfirmChoice::No => ConfirmAction::Cancel,
        },
        KeyMsg::Char('y' | 'Y') => ConfirmAction::Highlight(ConfirmChoice::Yes),
        KeyMsg::Char('n' | 'N') => ConfirmAction::Cancel,
        KeyMsg::Escape => ConfirmAction::Cancel,
        KeyMsg::Char(_) | KeyMsg::Backspace | KeyMsg::Other => ConfirmAction::None,
    }
}

/// Render the Esc confirm-quit dialog (mod.rs `confirm_quit`) onto the
/// shared [`TextOutput`] seam, marking the highlighted choice with `>`.
/// `No` is listed first and is the safe default. Copy is plain and calm
/// per the task brief (safe rehearsal edition); both option lines stay
/// well within the canvas width, so no word-wrap is needed here.
/// Host-testable against any `TextOutput` double, exactly like [`render`].
pub fn render_confirm_quit(out: &mut dyn TextOutput, highlighted: ConfirmChoice) {
    out.clear();
    out.write_line("Close Alea Test?");
    out.write_line("");
    out.write_line("Unsaved practice progress is discarded (nothing real is at stake).");
    out.write_line("");
    let no_cursor = if highlighted == ConfirmChoice::No { ">" } else { " " };
    let yes_cursor = if highlighted == ConfirmChoice::Yes { ">" } else { " " };
    out.write_line(&format!("{no_cursor} [N] No, keep working"));
    out.write_line(&format!("{yes_cursor} [Y] Yes, close"));
    out.write_line("");
    out.write_line("Up/Down move   Enter confirm   Esc keeps working");
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Up,
    Down,
}

/// Find the next *enabled* row id in `direction` from `current`,
/// wrapping around, skipping disabled rows (SPEC §4.2). Returns `None`
/// only if no row in `items` is enabled at all.
fn next_enabled(items: &[MenuItem], current: u8, direction: Direction) -> Option<u8> {
    if items.is_empty() || items.iter().all(|it| !it.enabled) {
        return None;
    }
    let ids: Vec<u8> = items.iter().map(|it| it.id).collect();
    let start = ids.iter().position(|&id| id == current).unwrap_or(0);
    let len = ids.len();
    let mut idx = start;
    for _ in 0..len {
        idx = match direction {
            Direction::Up => (idx + len - 1) % len,
            Direction::Down => (idx + 1) % len,
        };
        let candidate = ids[idx];
        if items.iter().any(|it| it.id == candidate && it.enabled) {
            return Some(candidate);
        }
    }
    None
}

/// SPEC_MAIN_MENU.md §4.3 mock: render the landing screen's rows (title +
/// one-line description per item, `>` marking the highlighted row, a
/// disabled row's title annotated inline) onto the shared [`TextOutput`]
/// seam every pre-secret `seed-flow` screen already renders through
/// (§6.3). Host-testable against any `TextOutput` double.
pub fn render(out: &mut dyn TextOutput, items: &[MenuItem], highlighted: u8) {
    out.clear();
    out.write_line("ALEA - main menu");
    out.write_line("");
    for it in items {
        let cursor = if it.id == highlighted { ">" } else { " " };
        if it.enabled {
            out.write_line(&format!("{cursor} [{}] {}", it.key, it.title));
        } else {
            out.write_line(&format!("{cursor} [{}] {} (disabled)", it.key, it.title));
        }
        out.write_line(&format!("      {}", it.desc));
    }
    out.write_line("");
    out.write_line("Up/Down move   Enter select   1-5 jump   Esc quit");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingOutput {
        lines: Vec<String>,
    }
    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
    }
    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {
            self.lines.clear();
        }
    }

    #[test]
    fn exactly_five_items_in_spec_order() {
        assert_eq!(items().len(), 5);
        let titles: Vec<&str> = items().iter().map(|it| it.title).collect();
        assert_eq!(
            titles,
            vec![
                "Create your own seed",
                "Verify a seed from another device",
                "Learn",
                "Self-check / verify build",
                "About / audit-status",
            ]
        );
    }

    #[test]
    fn digit_key_activates_matching_enabled_row() {
        assert_eq!(handle_key(items(), 1, KeyMsg::Char('3')), NavAction::Activate(3));
    }

    #[test]
    fn digit_key_for_disabled_row_is_a_no_op() {
        let disabled = [MenuItem { enabled: false, ..ITEMS[1] }, ITEMS[0]];
        assert_eq!(handle_key(&disabled, 1, KeyMsg::Char('2')), NavAction::None);
    }

    #[test]
    fn enter_activates_the_current_highlight_if_enabled() {
        assert_eq!(handle_key(items(), 4, KeyMsg::Enter), NavAction::Activate(4));
    }

    #[test]
    fn down_then_up_returns_to_start() {
        let down = handle_key(items(), 1, KeyMsg::Down);
        assert_eq!(down, NavAction::Highlight(2));
        let NavAction::Highlight(next) = down else { unreachable!() };
        assert_eq!(handle_key(items(), next, KeyMsg::Up), NavAction::Highlight(1));
    }

    #[test]
    fn down_wraps_around_from_the_last_row() {
        assert_eq!(handle_key(items(), 5, KeyMsg::Down), NavAction::Highlight(1));
    }

    #[test]
    fn up_wraps_around_from_the_first_row() {
        assert_eq!(handle_key(items(), 1, KeyMsg::Up), NavAction::Highlight(5));
    }

    #[test]
    fn navigation_skips_disabled_rows() {
        let items = [ITEMS[0], MenuItem { enabled: false, ..ITEMS[1] }, ITEMS[2]];
        assert_eq!(handle_key(&items, 1, KeyMsg::Down), NavAction::Highlight(3));
    }

    #[test]
    fn escape_at_top_level_quits() {
        assert_eq!(handle_key(items(), 1, KeyMsg::Escape), NavAction::Quit);
    }

    #[test]
    fn backspace_is_a_no_op() {
        assert_eq!(handle_key(items(), 1, KeyMsg::Backspace), NavAction::None);
    }

    #[test]
    fn confirm_quit_default_no_plus_enter_cancels_not_quits() {
        // A reflexive Esc-then-Enter must keep the app open.
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Enter), ConfirmAction::Cancel);
    }

    #[test]
    fn confirm_quit_yes_plus_enter_quits() {
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Enter), ConfirmAction::Quit);
    }

    #[test]
    fn confirm_quit_up_down_toggle_the_highlight() {
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Down), ConfirmAction::Highlight(ConfirmChoice::Yes));
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Up), ConfirmAction::Highlight(ConfirmChoice::Yes));
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Down), ConfirmAction::Highlight(ConfirmChoice::No));
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Up), ConfirmAction::Highlight(ConfirmChoice::No));
    }

    #[test]
    fn confirm_quit_y_highlights_yes_but_does_not_quit_on_its_own() {
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Char('y')), ConfirmAction::Highlight(ConfirmChoice::Yes));
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Char('Y')), ConfirmAction::Highlight(ConfirmChoice::Yes));
    }

    #[test]
    fn confirm_quit_n_or_escape_cancel_back_to_menu() {
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Char('n')), ConfirmAction::Cancel);
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Char('N')), ConfirmAction::Cancel);
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Escape), ConfirmAction::Cancel);
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::Yes, KeyMsg::Escape), ConfirmAction::Cancel);
    }

    #[test]
    fn confirm_quit_innocuous_keys_are_no_ops() {
        // A stray Esc opens the dialog; a reflexive innocuous key must not quit.
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Char('q')), ConfirmAction::None);
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Backspace), ConfirmAction::None);
        assert_eq!(confirm_quit_handle_key(ConfirmChoice::No, KeyMsg::Other), ConfirmAction::None);
    }

    #[test]
    fn render_confirm_quit_marks_the_default_no_and_shows_both_options() {
        let mut out = RecordingOutput::new();
        render_confirm_quit(&mut out, ConfirmChoice::No);
        let joined = out.lines.join("\n");
        assert!(joined.contains("Close Alea Test?"));
        assert!(joined.contains("> [N] No, keep working"));
        assert!(joined.contains("  [Y] Yes, close"));
    }

    #[test]
    fn render_confirm_quit_can_mark_yes_when_highlighted() {
        let mut out = RecordingOutput::new();
        render_confirm_quit(&mut out, ConfirmChoice::Yes);
        let joined = out.lines.join("\n");
        assert!(joined.contains("> [Y] Yes, close"));
        assert!(joined.contains("  [N] No, keep working"));
    }

    #[test]
    fn render_shows_every_title_and_the_cursor_on_the_highlighted_row() {
        let mut out = RecordingOutput::new();
        render(&mut out, items(), 3);
        let joined = out.lines.join("\n");
        for it in items() {
            assert!(joined.contains(it.title), "missing title {}", it.title);
        }
        assert!(joined.contains("> [3] Learn"));
    }
}
