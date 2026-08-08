//! Menu-level keystroke abstraction for the pre-secret flow (SPEC §22.1:
//! "[Esc] Exit before generation").
//!
//! # STEP D: collapsed onto `seed_platform_x86::input`
//!
//! This module used to define its own parallel `MenuKey` enum and
//! `MenuKeySource` trait, existing solely because
//! `seed_platform_x86::input::InputEvent` folded Escape into the same
//! `Other` bucket as every other special key — this crate's menu screens
//! (SPEC §22.1's opening warning, the §22.2 acknowledgement screens, and
//! every `PreSecretError` recovery screen) genuinely need a
//! distinguishable Escape, which `InputEvent::Other` could not provide.
//! Now that `seed_platform_x86::input::InputEvent` has its own dedicated
//! [`InputEvent::Escape`](seed_platform_x86::input::InputEvent::Escape)
//! variant (the Phase 1 fix this dedup depends on) and its production
//! `uefi_backend::FirmwareKeySource` adapter reports it correctly, the two
//! shapes are identical and there is nothing left to keep separate:
//!
//! - [`MenuKey`] is now a plain type alias for
//!   [`seed_platform_x86::input::InputEvent`] — not a second enum with
//!   its own copy of the same five variants.
//! - [`MenuKeySource`] stays its own trait (so a single physical keyboard
//!   can still be represented by two independent `&mut dyn Trait` role
//!   borrows where a caller needs that — see `firmware_wiring::
//!   AliasedInput`'s own doc comment), but the blanket `impl<T:
//!   seed_platform_x86::input::KeySource> MenuKeySource for T` below means
//!   any real [`seed_platform_x86::input::KeySource`] implementer (in
//!   particular `uefi_backend::FirmwareKeySource`, the one real-firmware
//!   keystroke reader this project defines) is a [`MenuKeySource`] for
//!   free, with no second hand-copied UEFI scan-code mapping anywhere.
//!   Test doubles that have no real `KeySource` backing (e.g.
//!   `test_support::ScriptedMenuKeys` below, `seed-desktop-test`'s
//!   `ChannelKeys`) still implement [`MenuKeySource`] directly, which the
//!   blanket impl does not conflict with (it only applies to types that
//!   are themselves a real `KeySource`).
//! - The SPEC §11.5 keyboard self-test itself is no longer re-implemented
//!   here: [`run_keyboard_self_test`] is now a thin adapter that hands a
//!   `&mut dyn MenuKeySource` to `seed_platform_x86::input::run_self_test`
//!   through a one-line local `KeySource` shim, so the actual sequence/
//!   comparison/fail-closed logic (`self_test_sequence`, the match-arm
//!   comparison, the first-mismatch-stops rule) lives in exactly one
//!   place in the whole workspace.

use seed_platform_x86::input::SelfTestExpectation;

/// One normalized menu keystroke (SPEC §22.1, §22.3-§22.5 menu screens).
/// Exactly [`seed_platform_x86::input::InputEvent`] — see the module doc
/// comment for why this is a type alias, not a second enum.
pub type MenuKey = seed_platform_x86::input::InputEvent;

/// Blocking menu-key-read abstraction. See the module doc comment for why
/// this stays a distinct trait from `seed_platform_x86::input::KeySource`
/// (the dual-role-borrow need), and for the blanket impl immediately
/// below that makes any real `KeySource` implementer satisfy this trait
/// automatically.
pub trait MenuKeySource {
    /// Block until a key is available, then return its normalized form.
    fn read_menu_key(&mut self) -> MenuKey;
}

/// Any real [`seed_platform_x86::input::KeySource`] is automatically a
/// [`MenuKeySource`] too (STEP D): the two traits' single method differs
/// only in name, and every variant `InputEvent`/`MenuKey` reports is now
/// identical, so there is no information to lose or logic to duplicate
/// in this forwarding call.
impl<T: seed_platform_x86::input::KeySource> MenuKeySource for T {
    fn read_menu_key(&mut self) -> MenuKey {
        self.read_key_blocking()
    }
}

/// Result of [`read_continue_or_escape`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinueOrEscape {
    /// Enter was pressed.
    Continue,
    /// Escape was pressed.
    Escape,
}

/// Block until the user presses Enter or Escape; every other key is
/// silently ignored and the read repeats (SPEC §22.1/§22.2 screens offer
/// exactly these two actions; nothing else is echoed, logged, or acted
/// on).
pub fn read_continue_or_escape(k: &mut dyn MenuKeySource) -> ContinueOrEscape {
    loop {
        match k.read_menu_key() {
            MenuKey::Enter => return ContinueOrEscape::Continue,
            MenuKey::Escape => return ContinueOrEscape::Escape,
            _ => {}
        }
    }
}

/// Block until the user presses Enter (SPEC §22.3 combined diagnostics
/// recap: a pure information screen, no Escape offered there — the state
/// machine has no legal Escape edge from any of the four mandatory-gate
/// states). Every other key, including Escape, is ignored.
pub fn read_enter(k: &mut dyn MenuKeySource) {
    loop {
        if let MenuKey::Enter = k.read_menu_key() {
            return;
        }
    }
}

/// Result of [`read_menu_choice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuChoice {
    /// One of the `allowed` characters was pressed.
    Picked(char),
    /// Escape was pressed (only returned when `escape_allowed` is set).
    Escape,
}

/// Block until the user presses one of `allowed` (case-insensitive) or,
/// if `escape_allowed`, Escape. Every other key — including a
/// syntactically valid digit/letter that is not in `allowed` (SPEC
/// §22.5: "Unavailable modes are disabled" — the caller never lists a
/// disabled option's key in `allowed`) — is silently ignored and the read
/// repeats, never advancing on an invalid choice.
pub fn read_menu_choice(
    k: &mut dyn MenuKeySource,
    allowed: &[char],
    escape_allowed: bool,
) -> MenuChoice {
    loop {
        match k.read_menu_key() {
            MenuKey::Char(c) => {
                if let Some(&matched) = allowed
                    .iter()
                    .find(|&&a| a.eq_ignore_ascii_case(&c))
                {
                    return MenuChoice::Picked(matched);
                }
            }
            MenuKey::Escape if escape_allowed => return MenuChoice::Escape,
            _ => {}
        }
    }
}

/// Block until the user presses Enter (confirm) or `decline_key`
/// (decline), case-insensitively; every other key — including Escape — is
/// ignored. Used by SPEC §11.4's local-display confirmation, which is a
/// plain yes/no, not a `PreSecretDisposition`-bearing menu choice like
/// [`read_menu_choice`].
pub fn read_confirm_or_decline(k: &mut dyn MenuKeySource, decline_key: char) -> bool {
    loop {
        match k.read_menu_key() {
            MenuKey::Enter => return true,
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&decline_key) => return false,
            _ => {}
        }
    }
}

/// SPEC.md §11.5 amendment (2026-08-04, "Keyboard-layout self-test made
/// OPTIONAL/skippable"; see also SPEC_MAIN_MENU.md §15): how far
/// [`crate::driver::run_pre_secret_flow`]'s keyboard self-test offer may
/// be skipped. Threaded per edition through
/// [`crate::driver::Gates::keyboard_self_test_skip`] — one plain, named
/// field each edition's own `Gates`-construction call site sets
/// explicitly — rather than a hidden runtime switch, per the amendment's
/// own instruction that desktop and production differ only in how
/// forgiving the skip path is, never in whether an *attempted* self-test
/// can fail closed (that part of SPEC §11.5 is unchanged; see
/// `crate::driver`'s gate-handling doc comments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardSelfTestSkipPolicy {
    /// Desktop rehearsal edition (SPEC.md §11.5 amendment: "simply
    /// optional"): the self-test is offered, and Skip is accepted
    /// immediately with no extra ceremony — this is a practice run on
    /// public, watermarked, fixed entropy, so the friction of an
    /// acknowledgement screen is not warranted.
    DesktopOptional,
    /// Any edition that is not the desktop rehearsal build (production
    /// UEFI, and the UEFI *test* edition, which shares production's real
    /// hidden-re-entry keyboard mechanics even though it is not itself
    /// SPEC §4.1 production): offered by default and recommended: Skip
    /// requires the user to read and accept
    /// [`crate::text::KEYBOARD_SELF_TEST_SKIP_WARNING_11_5`] first (SPEC.md
    /// §11.5 amendment: "skippable via an explicit acknowledgement of the
    /// consequence").
    RecommendedSkippableWithAcknowledgement,
}

/// The user's choice at the SPEC.md §11.5-amendment keyboard self-test
/// offer screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestOfferChoice {
    /// Run the self-test now.
    Start,
    /// Skip it (subject to [`KeyboardSelfTestSkipPolicy`]).
    Skip,
}

/// Block until the user presses Enter (start the self-test now) or `S`/`s`
/// (skip it, subject to whatever [`KeyboardSelfTestSkipPolicy`] the caller
/// is enforcing); every other key, including Escape, is ignored and the
/// read repeats — mirrors [`read_confirm_or_decline`]'s discipline of
/// never advancing on an unrecognized key.
pub fn read_self_test_offer_choice(k: &mut dyn MenuKeySource) -> SelfTestOfferChoice {
    loop {
        match k.read_menu_key() {
            MenuKey::Enter => return SelfTestOfferChoice::Start,
            MenuKey::Char(c) if c.eq_ignore_ascii_case(&'s') => return SelfTestOfferChoice::Skip,
            _ => {}
        }
    }
}

/// Run the SPEC §11.5 keyboard-layout self-test against a
/// [`MenuKeySource`] (see module doc comment: STEP D reduced this to a
/// thin adapter over the single real implementation,
/// `seed_platform_x86::input::run_self_test`).
///
/// `on_step(index, total, expected)` fires before each keystroke is
/// awaited, mirroring `run_self_test`'s callback exactly (it is passed
/// straight through, unmodified).
pub fn run_keyboard_self_test<F>(
    k: &mut dyn MenuKeySource,
    on_step: F,
) -> Result<(), seed_platform_x86::input::SelfTestFailure>
where
    F: FnMut(usize, usize, SelfTestExpectation),
{
    /// Adapts a `&mut dyn MenuKeySource` back into a `KeySource`, so the
    /// one keystroke this ceremony reads at a time can be handed to
    /// `seed_platform_x86::input::run_self_test` without that function
    /// needing to know about this crate's `MenuKeySource` seam at all.
    struct Adapter<'a>(&'a mut dyn MenuKeySource);

    impl seed_platform_x86::input::KeySource for Adapter<'_> {
        fn read_key_blocking(&mut self) -> seed_platform_x86::input::InputEvent {
            self.0.read_menu_key()
        }
    }

    seed_platform_x86::input::run_self_test(&mut Adapter(k), on_step)
}

/// Host-test support: a scripted [`MenuKeySource`] double, mirroring the
/// pattern `seed_platform_x86::input`'s own tests use for `KeySource`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{MenuKey, MenuKeySource};

    pub(crate) struct ScriptedMenuKeys {
        events: std::vec::Vec<MenuKey>,
        pos: usize,
    }

    impl ScriptedMenuKeys {
        pub(crate) fn new(events: std::vec::Vec<MenuKey>) -> Self {
            Self { events, pos: 0 }
        }
    }

    impl MenuKeySource for ScriptedMenuKeys {
        fn read_menu_key(&mut self) -> MenuKey {
            let ev = self
                .events
                .get(self.pos)
                .copied()
                .expect("ScriptedMenuKeys read past scripted keystream");
            self.pos += 1;
            ev
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::ScriptedMenuKeys;
    use super::*;

    #[test]
    fn read_continue_or_escape_ignores_other_keys_first() {
        let mut k = ScriptedMenuKeys::new(std::vec![
            MenuKey::Other,
            MenuKey::Char('x'),
            MenuKey::Enter,
        ]);
        assert_eq!(read_continue_or_escape(&mut k), ContinueOrEscape::Continue);
    }

    #[test]
    fn read_continue_or_escape_returns_escape() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Escape]);
        assert_eq!(read_continue_or_escape(&mut k), ContinueOrEscape::Escape);
    }

    #[test]
    fn read_enter_ignores_escape_too() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Escape, MenuKey::Enter]);
        read_enter(&mut k); // must not hang/panic, must consume both
    }

    #[test]
    fn read_menu_choice_picks_allowed_char_case_insensitively() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('B')]);
        let choice = read_menu_choice(&mut k, &['a', 'b', 'c'], false);
        assert_eq!(choice, MenuChoice::Picked('b'));
    }

    #[test]
    fn read_menu_choice_ignores_disallowed_char_then_accepts_allowed() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('z'), MenuKey::Char('a')]);
        let choice = read_menu_choice(&mut k, &['a'], false);
        assert_eq!(choice, MenuChoice::Picked('a'));
    }

    #[test]
    fn read_menu_choice_returns_escape_only_when_allowed() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Escape, MenuKey::Char('a')]);
        let choice = read_menu_choice(&mut k, &['a'], true);
        assert_eq!(choice, MenuChoice::Escape);
    }

    #[test]
    fn read_confirm_or_decline_returns_true_on_enter() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Other, MenuKey::Enter]);
        assert!(read_confirm_or_decline(&mut k, 'n'));
    }

    #[test]
    fn read_confirm_or_decline_returns_false_on_decline_key_case_insensitive() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('N')]);
        assert!(!read_confirm_or_decline(&mut k, 'n'));
    }

    #[test]
    fn read_confirm_or_decline_ignores_escape() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Escape, MenuKey::Enter]);
        assert!(read_confirm_or_decline(&mut k, 'n'));
    }

    #[test]
    fn read_menu_choice_ignores_escape_when_not_allowed() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Escape, MenuKey::Char('a')]);
        let choice = read_menu_choice(&mut k, &['a'], false);
        assert_eq!(choice, MenuChoice::Picked('a'));
    }

    fn valid_self_test_keystream() -> std::vec::Vec<MenuKey> {
        let mut v = std::vec::Vec::new();
        for c in b'A'..=b'Z' {
            v.push(MenuKey::Char(c as char));
        }
        for d in b'1'..=b'6' {
            v.push(MenuKey::Char(d as char));
        }
        v.push(MenuKey::Backspace);
        v.push(MenuKey::Enter);
        v
    }

    #[test]
    fn keyboard_self_test_passes_on_exact_matching_keystream() {
        let mut k = ScriptedMenuKeys::new(valid_self_test_keystream());
        let mut steps = 0usize;
        let result = run_keyboard_self_test(&mut k, |_, _, _| steps += 1);
        assert!(result.is_ok());
        assert_eq!(steps, seed_platform_x86::input::SELF_TEST_LEN);
    }

    #[test]
    fn keyboard_self_test_fails_closed_on_escape_instead_of_letter() {
        let mut events = valid_self_test_keystream();
        events[0] = MenuKey::Escape;
        let mut k = ScriptedMenuKeys::new(events);
        let err = run_keyboard_self_test(&mut k, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 0);
    }

    #[test]
    fn keyboard_self_test_fails_closed_on_wrong_letter() {
        let mut events = valid_self_test_keystream();
        events[3] = MenuKey::Char('X'); // was 'D'
        let mut k = ScriptedMenuKeys::new(events);
        let err = run_keyboard_self_test(&mut k, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 3);
    }

    #[test]
    fn keyboard_self_test_accepts_lowercase() {
        let mut events = valid_self_test_keystream();
        events[0] = MenuKey::Char('a');
        let mut k = ScriptedMenuKeys::new(events);
        assert!(run_keyboard_self_test(&mut k, |_, _, _| {}).is_ok());
    }

    #[test]
    fn keyboard_self_test_stops_at_first_mismatch_does_not_overread() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('Q')]); // expected 'A'
        let err = run_keyboard_self_test(&mut k, |_, _, _| {}).unwrap_err();
        assert_eq!(err.index, 0);
    }

    // ---- SPEC.md §11.5 amendment: self-test offer choice ----

    #[test]
    fn self_test_offer_choice_enter_means_start() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Enter]);
        assert_eq!(read_self_test_offer_choice(&mut k), SelfTestOfferChoice::Start);
    }

    #[test]
    fn self_test_offer_choice_s_means_skip_case_insensitively() {
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('S')]);
        assert_eq!(read_self_test_offer_choice(&mut k), SelfTestOfferChoice::Skip);
        let mut k = ScriptedMenuKeys::new(std::vec![MenuKey::Char('s')]);
        assert_eq!(read_self_test_offer_choice(&mut k), SelfTestOfferChoice::Skip);
    }

    #[test]
    fn self_test_offer_choice_ignores_other_keys_including_escape() {
        let mut k = ScriptedMenuKeys::new(std::vec![
            MenuKey::Escape,
            MenuKey::Char('x'),
            MenuKey::Other,
            MenuKey::Char('s'),
        ]);
        assert_eq!(read_self_test_offer_choice(&mut k), SelfTestOfferChoice::Skip);
    }
}
