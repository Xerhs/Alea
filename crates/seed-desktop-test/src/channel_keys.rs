//! Keyboard input bridge (SPEC §12.3, §17.4, §22.1): the OS window (owned
//! by the main thread, `crate::window`) translates real `winit` keyboard
//! events into [`KeyMsg`] and sends them down an `mpsc` channel; the
//! ceremony worker thread (`crate::ceremony`) blocks on the receiving end
//! through [`ChannelKeys`] (mirrors `seed_flow::flow_secret::driver`'s
//! own single-live-keyboard-borrow design, threaded across a channel
//! instead of a single-process call stack).
//!
//! # Smooth key mapping (1-6, H/T, A-Z, Enter, Backspace, Esc)
//!
//! [`crate::window`] maps every printable character key and Enter/
//! Backspace/Escape into exactly one [`KeyMsg`] variant; every other key
//! (arrows, function keys, modifiers alone, ...) becomes [`KeyMsg::Other`],
//! which every `seed-flow` menu/hidden-entry primitive already ignores.
//!
//! # One `KeySource` impl serves both seams (STEP D dedup)
//!
//! [`ChannelKeys`] implements only [`seed_platform_x86::input::KeySource`]
//! directly; [`seed_flow::keys::MenuKeySource`] (the pre-secret,
//! Escape-aware seam) comes for free via that trait's blanket impl over
//! any real `KeySource` (see its own doc comment). Before Phase 1 added
//! `InputEvent::Escape`, this file had to hand-write both impls
//! separately and deliberately mapped `KeyMsg::Escape` differently
//! between them (`MenuKey::Escape` pre-secret, folded into
//! `InputEvent::Other` post-secret, because `InputEvent` had no Escape
//! variant to report). Now that `InputEvent::Escape` exists and the real
//! firmware backends (`seed_platform_x86::input::uefi_backend::
//! FirmwareKeySource`) already report it post-secret too, that divergence
//! is no longer needed *or* consistent with the canonical mapping: the
//! single impl below reports `InputEvent::Escape` for both roles, exactly
//! like the real firmware backends. This is not a post-secret behavior
//! change — `seed_platform_x86::input::read_hidden` already treats
//! `InputEvent::Escape` and `InputEvent::Other` identically (SPEC §12.3:
//! neither is echoed or stored), so every existing post-secret call site
//! that used to see `Other` for Escape and ignored it still ignores it,
//! now under its own, correctly-reported name.

use seed_platform_x86::input::{InputEvent, KeySource};
use std::sync::mpsc::Receiver;

/// One normalized keystroke crossing the window-thread -> worker-thread
/// boundary. A strict subset of what a physical keyboard can produce —
/// exactly the keys every screen in this ceremony ever acts on.
///
/// # `Up`/`Down` (SPEC_MAIN_MENU.md §4.2, §6.3, OQ2 — resolved §15)
///
/// Added for the desktop-local launcher arrow-cursor navigation only.
/// This is a **desktop-crate-local** extension: `seed_platform_x86::
/// input::InputEvent` (the shared/production keystroke enum) is
/// deliberately left untouched, so [`KeySource::read_key_blocking`] below
/// still folds `Up`/`Down` into `InputEvent::Other` for every existing
/// `seed-flow` consumer (ceremony pre-secret/secret-phase screens, which
/// have no notion of arrow navigation and must keep behaving exactly as
/// before). Code that *does* care about arrows (`crate::launcher`) reads
/// [`ChannelKeys::recv`] directly instead of going through the
/// `KeySource`/`MenuKeySource` seam, which is the only place `Up`/`Down`
/// survive as distinct values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMsg {
    Char(char),
    Enter,
    Escape,
    Backspace,
    /// Desktop-local launcher arrow-cursor nav (SPEC_MAIN_MENU.md §4.2, OQ2).
    Up,
    /// Desktop-local launcher arrow-cursor nav (SPEC_MAIN_MENU.md §4.2, OQ2).
    Down,
    Other,
}

/// Blocking keystream over an `mpsc::Receiver<KeyMsg>`. Implements
/// [`seed_platform_x86::input::KeySource`] directly; that also makes it a
/// [`seed_flow::keys::MenuKeySource`] (pre-secret screens) via that
/// trait's blanket impl — see module doc comment for why one impl safely
/// serves both seams.
pub struct ChannelKeys {
    rx: Receiver<KeyMsg>,
}

impl ChannelKeys {
    #[must_use]
    pub fn new(rx: Receiver<KeyMsg>) -> Self {
        Self { rx }
    }

    /// Blocks for the next key, reporting the raw [`KeyMsg`] (including
    /// `Up`/`Down`) unfiltered. If the sending half has been dropped (the
    /// OS window was closed), this reports `Escape` so any in-progress
    /// pre-secret screen unwinds toward `AppState::ExitToFirmware`
    /// instead of hanging forever — post-secret screens that ignore
    /// Escape-shaped input simply keep receiving it (harmless: every
    /// post-secret hidden-entry/menu read loops on unrecognized input
    /// exactly as it would on real repeated bad keystrokes) until the
    /// process itself exits (the window closing already ends `main`).
    ///
    /// `pub` (SPEC_MAIN_MENU.md §4.2/§6.3, OQ2): this is the seam
    /// `crate::launcher` reads directly to get the desktop-local `Up`/
    /// `Down` arrow-nav keys that [`KeySource::read_key_blocking`] below
    /// deliberately folds into `InputEvent::Other` for every other,
    /// arrow-unaware `seed-flow` consumer.
    pub fn recv(&mut self) -> KeyMsg {
        self.rx.recv().unwrap_or(KeyMsg::Escape)
    }
}

impl KeySource for ChannelKeys {
    fn read_key_blocking(&mut self) -> InputEvent {
        match self.recv() {
            KeyMsg::Char(c) => InputEvent::Char(c),
            KeyMsg::Enter => InputEvent::Enter,
            KeyMsg::Backspace => InputEvent::Backspace,
            // Reported distinctly (STEP D dedup), matching the real
            // firmware backends (`seed_platform_x86::input::uefi_backend::
            // FirmwareKeySource`) now that `InputEvent::Escape` exists —
            // see module doc comment. `read_hidden` and every other
            // post-secret consumer already treat `Escape`/`Other`
            // identically, so this is not a behavior change downstream.
            KeyMsg::Escape => InputEvent::Escape,
            // Desktop-local launcher arrows (SPEC_MAIN_MENU.md §4.2, OQ2)
            // have no `InputEvent` counterpart by design — the shared/
            // production keystroke enum stays frozen — so every ordinary
            // `seed-flow` menu/hidden-entry read loop sees these exactly
            // as it always saw an unrecognized key. `crate::launcher`
            // reads [`ChannelKeys::recv`] directly to see `Up`/`Down`
            // distinctly instead of going through this trait.
            KeyMsg::Up | KeyMsg::Down => InputEvent::Other,
            KeyMsg::Other => InputEvent::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seed_flow::keys::{MenuKey, MenuKeySource};
    use std::sync::mpsc::channel;

    #[test]
    fn menu_key_source_maps_every_variant() {
        let (tx, rx) = channel();
        let mut keys = ChannelKeys::new(rx);
        tx.send(KeyMsg::Char('a')).unwrap();
        assert_eq!(keys.read_menu_key(), MenuKey::Char('a'));
        tx.send(KeyMsg::Enter).unwrap();
        assert_eq!(keys.read_menu_key(), MenuKey::Enter);
        tx.send(KeyMsg::Escape).unwrap();
        assert_eq!(keys.read_menu_key(), MenuKey::Escape);
        tx.send(KeyMsg::Backspace).unwrap();
        assert_eq!(keys.read_menu_key(), MenuKey::Backspace);
        tx.send(KeyMsg::Other).unwrap();
        assert_eq!(keys.read_menu_key(), MenuKey::Other);
    }

    #[test]
    fn key_source_maps_every_variant_escape_reported_distinctly() {
        let (tx, rx) = channel();
        let mut keys = ChannelKeys::new(rx);
        tx.send(KeyMsg::Char('z')).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Char('z'));
        tx.send(KeyMsg::Enter).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Enter);
        tx.send(KeyMsg::Backspace).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Backspace);
        // STEP D dedup: matches the real firmware backends now that
        // `InputEvent::Escape` exists — see module doc comment.
        tx.send(KeyMsg::Escape).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Escape);
        tx.send(KeyMsg::Other).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Other);
    }

    #[test]
    fn dropped_sender_reports_escape_instead_of_hanging() {
        let (tx, rx) = channel();
        drop(tx);
        let mut keys = ChannelKeys::new(rx);
        assert_eq!(keys.read_menu_key(), MenuKey::Escape);
    }

    /// SPEC_MAIN_MENU.md §4.2/OQ2: `Up`/`Down` are folded into
    /// `InputEvent::Other` on the shared `KeySource` seam so every
    /// existing (arrow-unaware) `seed-flow` consumer is unaffected.
    #[test]
    fn key_source_folds_up_down_into_other() {
        let (tx, rx) = channel();
        let mut keys = ChannelKeys::new(rx);
        tx.send(KeyMsg::Up).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Other);
        tx.send(KeyMsg::Down).unwrap();
        assert_eq!(keys.read_key_blocking(), InputEvent::Other);
    }

    /// SPEC_MAIN_MENU.md §4.2/OQ2: `ChannelKeys::recv` is the raw seam
    /// `crate::launcher` reads directly, so `Up`/`Down` survive distinctly
    /// there even though the `KeySource` trait above folds them away.
    #[test]
    fn recv_reports_up_down_distinctly() {
        let (tx, rx) = channel();
        let mut keys = ChannelKeys::new(rx);
        tx.send(KeyMsg::Up).unwrap();
        assert_eq!(keys.recv(), KeyMsg::Up);
        tx.send(KeyMsg::Down).unwrap();
        assert_eq!(keys.recv(), KeyMsg::Down);
    }
}
