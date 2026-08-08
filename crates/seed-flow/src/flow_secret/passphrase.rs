//! Optional BIP39 passphrase — offer / masked entry / confirm screens
//! (SPEC_PASSPHRASE §4, §6, §9), plus the SPEC_PASSPHRASE §8 extended
//! printable-ASCII keyboard gating.
//!
//! These are **post-secret** screens (SPEC_PASSPHRASE §6.2): GOP-only
//! rendering, no `[Back]`/menu edge, fatal routing on any unexpected event
//! is handled by the state machine. The passphrase itself is NEVER rendered
//! as characters — masked entry shows one neutral placeholder glyph per
//! accepted byte (a deliberate length-leak-only tradeoff, SPEC_PASSPHRASE
//! §4.3) — never logged, never in the transcript (SPEC_PASSPHRASE §5.3).
//!
//! The secret buffers are the arena-resident [`PassphraseAscii`] fields
//! (`passphrase` = committed / entry-1, `passphrase_confirm` = entry-2), so
//! the SPEC §26 whole-arena shutdown scrub and the SPEC §20.4 panic-handler
//! whole-arena scrub both reach them (SPEC_PASSPHRASE §5.1/§5.2, M3).

use seed_core::contracts::Framebuffer;
use seed_core::passphrase::{PassphraseAscii, PassphraseInputError};
use seed_platform_x86::input::{InputEvent, KeySource};

use crate::flow_secret::gop_screen::draw_lines;
use crate::output::LineBuf;
use core::fmt::Write as _;

// ============================================================================
// SPEC_PASSPHRASE §9 — mandatory plain-language warnings (footgun discipline)
// ============================================================================

/// The SPEC_PASSPHRASE §9 "at entry" warnings, shown on the offer screen.
/// Every point of the §9 list is conveyed: separate wallet / forget = lost
/// forever / needs its own separate backup / every passphrase = a different
/// wallet / no recovery.
pub const OFFER_WARN: &[&str] = &[
    "A passphrase creates a SEPARATE wallet (BIP39 \"25th word\").",
    "- Your words PLUS this passphrase is a DIFFERENT wallet from your words alone.",
    "- If you FORGET the passphrase, your money is LOST FOREVER, even with all your words.",
    "- The passphrase needs its OWN backup, stored APART from your words.",
    "- Every different passphrase is a different wallet. A typo just makes another wallet;",
    "  there is no \"wrong passphrase\" error, no recovery, and no reset.",
    "Leave it empty if you are not sure - you can always practice first.",
];

/// FIX (live desktop rehearsal, 2026-08-05): a plain, unmissable statement
/// that this is a genuine *optional* step, so a user running the full
/// ceremony notices the choice instead of skating past the warning block.
/// Truthful and neutral — it changes no semantics (the explicit [Y]/[N]
/// choice below still requires a key and still ignores Enter) and only
/// restates, in one plain sentence, what SPEC_PASSPHRASE §9's warnings
/// already imply.
pub const OFFER_OPTIONAL_STEP: &str =
    "This is an OPTIONAL step - the passphrase is the BIP39 \"25th word\".";
/// FIX (same): the plain-language call to action, kept on its own line
/// directly above the prominent [Y]/[N] prompt so the decision is not
/// buried in the warning paragraph.
pub const OFFER_SKIP_HINT: &str =
    "Add one now with [Y], or skip it with [N]. Most people skip this.";

/// The offer prompt (printable-ASCII keyboard verified / available).
pub const OFFER_PROMPT: &str = "[Y] Add a passphrase      [N] No passphrase (empty)";

/// The offer prompt when passphrase entry is DISABLED because the extended
/// printable-ASCII keyboard self-test was not confirmed (SPEC_PASSPHRASE
/// §8.2 fail-closed, surfaced BEFORE any entry).
pub const OFFER_DISABLED_1: &str =
    "A passphrase requires a verified keyboard, which was not confirmed on this device.";
/// Second disabled line: only the empty path remains.
pub const OFFER_DISABLED_2: &str = "Generation continues with the EMPTY passphrase.";
/// Disabled-offer prompt (only the empty path is offered).
pub const OFFER_DISABLED_PROMPT: &str = "[N] Continue with no passphrase (empty)";

const OFFER_TITLE: &str = "OPTIONAL PASSPHRASE";

/// The user's choice at the passphrase offer (SPEC_PASSPHRASE §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferChoice {
    /// `[Y]` — add a passphrase (only offered when entry is available).
    Yes,
    /// `[N]` — no passphrase; use the empty (byte-identical) path.
    No,
}

/// Render the SPEC_PASSPHRASE §6.1/§9 offer screen. When `entry_available`
/// is `false` (extended keyboard self-test not confirmed, SPEC_PASSPHRASE
/// §8.2) the screen states so and offers only the empty path.
pub fn render_offer(fb: &mut dyn Framebuffer, entry_available: bool) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let mut lines: [&str; 24] = [""; 24];
    let mut n = 0usize;
    let mut push = |s: &'static str| {
        lines[n] = s;
        n += 1;
    };
    push(OFFER_TITLE);
    push("");
    for &w in OFFER_WARN {
        push(w);
    }
    push("");
    if entry_available {
        push(OFFER_OPTIONAL_STEP);
        push(OFFER_SKIP_HINT);
        push("");
        push(OFFER_PROMPT);
    } else {
        push(OFFER_DISABLED_1);
        push(OFFER_DISABLED_2);
        push(OFFER_DISABLED_PROMPT);
    }
    draw_lines(fb, &lines[..n]);
}

/// Block until the user chooses. When `entry_available` is `false`, only
/// `[N]` (empty) is accepted; `[Y]` is ignored (there is nothing to enter).
pub fn read_offer_choice<K: KeySource + ?Sized>(keys: &mut K, entry_available: bool) -> OfferChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Char(c) if entry_available && c.eq_ignore_ascii_case(&'y') => {
                return OfferChoice::Yes;
            }
            InputEvent::Char(c) if c.eq_ignore_ascii_case(&'n') => return OfferChoice::No,
            _ => {}
        }
    }
}

// ============================================================================
// SPEC_PASSPHRASE §4.1/§4.3 — masked entry
// ============================================================================

const ENTRY_TITLE_1: &str = "ENTER PASSPHRASE (masked)";
const ENTRY_TITLE_2: &str = "RE-ENTER PASSPHRASE (masked; must match)";
const ENTRY_HELP: &str = "Type your passphrase. Printable ASCII only (letters, digits, space, punctuation).";
const ENTRY_KEYS: &str = "[Enter] Commit   [Backspace] Delete   [Esc] Cancel (use empty passphrase)";
const ENTRY_MASK_GLYPH: char = '*';
/// SPEC_PASSPHRASE §3.2: shown when a non-printable-ASCII / non-ASCII key
/// is refused (never silently accepted).
pub const ENTRY_ERR_NON_ASCII: &str = "That key is not printable ASCII and was rejected (not added).";
/// SPEC_PASSPHRASE §3.3: shown when the buffer is full.
pub const ENTRY_ERR_FULL: &str = "Passphrase is full (maximum length reached).";
/// SPEC_PASSPHRASE §4.1: shown on the confirm screen after a mismatch.
pub const CONFIRM_MISMATCH_MSG: &str = "The two entries did not match. Both were discarded; enter it again.";

/// Which of the two SPEC_PASSPHRASE §4.1 entries is being typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPhase {
    /// Entry 1 (into `arena.passphrase`).
    First,
    /// Entry 2 (into `arena.passphrase_confirm`).
    Confirm,
}

/// How one masked entry ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryOutcome {
    /// `[Enter]` was pressed — the buffer holds the committed bytes (which
    /// may be empty).
    Committed,
    /// `[Esc]` — cancel; the buffer has already been scrubbed by this
    /// function. The caller uses the empty passphrase (forward-only,
    /// SPEC_PASSPHRASE §6.2).
    Cancelled,
}

/// Render one frame of a masked entry screen: one [`ENTRY_MASK_GLYPH`] per
/// entered byte (content NEVER rendered), plus an optional transient error
/// line. The passphrase bytes are never passed to any text API.
fn render_entry(fb: &mut dyn Framebuffer, phase: EntryPhase, len: usize, banner: Option<&str>) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let mut mask = LineBuf::new();
    let _ = mask.write_str("  ");
    for _ in 0..len {
        let _ = mask.write_char(ENTRY_MASK_GLYPH);
    }

    let mut count = LineBuf::new();
    let _ = write!(count, "Length: {len}");

    let title = match phase {
        EntryPhase::First => ENTRY_TITLE_1,
        EntryPhase::Confirm => ENTRY_TITLE_2,
    };
    let banner_line = banner.unwrap_or("");
    draw_lines(
        fb,
        &[
            title,
            "",
            ENTRY_HELP,
            "",
            mask.as_str(),
            count.as_str(),
            "",
            banner_line,
            "",
            ENTRY_KEYS,
        ],
    );
}

/// Drive one masked passphrase entry into `buf` (an arena-resident
/// [`PassphraseAscii`]). Accepts printable-ASCII chars (rejecting anything
/// else with an on-screen note, SPEC_PASSPHRASE §3.2), Backspace (scrubbing
/// the removed cell), Enter (commit), and Escape (cancel-to-empty,
/// scrubbing the buffer first — forward-only, SPEC_PASSPHRASE §6.2).
///
/// `buf` is assumed empty on entry; on `Cancelled` it is scrubbed before
/// returning. `initial_banner` lets the caller show the mismatch message on
/// the first frame after a failed confirm.
pub fn run_entry<K: KeySource + ?Sized>(
    fb: &mut dyn Framebuffer,
    keys: &mut K,
    buf: &mut PassphraseAscii,
    phase: EntryPhase,
    initial_banner: Option<&str>,
) -> EntryOutcome {
    let mut banner: Option<&str> = initial_banner;
    loop {
        render_entry(fb, phase, buf.len(), banner);
        match keys.read_key_blocking() {
            InputEvent::Enter => return EntryOutcome::Committed,
            InputEvent::Escape => {
                buf.scrub();
                return EntryOutcome::Cancelled;
            }
            InputEvent::Backspace => {
                buf.backspace();
                banner = None;
            }
            InputEvent::Char(c) => match buf.push_char(c) {
                Ok(()) => banner = None,
                Err(PassphraseInputError::NotPrintableAscii) => banner = Some(ENTRY_ERR_NON_ASCII),
                Err(PassphraseInputError::Full) => banner = Some(ENTRY_ERR_FULL),
            },
            _ => {}
        }
    }
}

// ============================================================================
// SPEC_PASSPHRASE §8 — extended printable-ASCII keyboard self-test policy
// ============================================================================

/// How the driver decides whether passphrase entry is available on this
/// edition (SPEC_PASSPHRASE §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKeyboardPolicy {
    /// Desktop rehearsal edition (SPEC_PASSPHRASE §8.3): the host OS
    /// delivers the full printable-ASCII charset, so entry is available
    /// without a firmware self-test.
    HostKeyboardTrusted,
    /// Bootable UEFI editions (SPEC_PASSPHRASE §8.2): the full
    /// printable-ASCII charset must be round-trip-verified by the extended
    /// self-test when the user opts into a passphrase; a failure/skip
    /// disables passphrase entry only (generation proceeds with empty).
    RequireExtendedSelfTest,
}

/// SPEC_PASSPHRASE §8.2 keyboard-unverified acknowledgement screen (shown
/// when the extended self-test fails after the user chose `[Y]`).
pub const KBD_UNVERIFIED_1: &str =
    "Keyboard check failed: this device did not deliver every required key.";
/// Second line.
pub const KBD_UNVERIFIED_2: &str =
    "Passphrase entry is disabled; generation continues with the EMPTY passphrase.";
/// Acknowledge prompt.
pub const KBD_UNVERIFIED_PROMPT: &str = "[Enter] Continue";

/// Render the SPEC_PASSPHRASE §8.2 keyboard-unverified screen.
pub fn render_keyboard_unverified(fb: &mut dyn Framebuffer) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    draw_lines(fb, &[KBD_UNVERIFIED_1, KBD_UNVERIFIED_2, "", KBD_UNVERIFIED_PROMPT]);
}

/// Run the SPEC_PASSPHRASE §8.2 extended printable-ASCII keyboard self-test
/// (delegates to the platform layer). Returns `true` iff every required
/// printable-ASCII code point round-tripped; `false` fails closed and
/// disables passphrase entry (SPEC_PASSPHRASE §8.2 extended-charset scope:
/// generation is NOT disabled). `on_step` mirrors the base self-test.
pub fn run_extended_self_test<K: KeySource + ?Sized>(keys: &mut K, fb: &mut dyn Framebuffer) -> bool {
    struct Adapter<'a, K: KeySource + ?Sized>(&'a mut K);
    impl<K: KeySource + ?Sized> KeySource for Adapter<'_, K> {
        fn read_key_blocking(&mut self) -> InputEvent {
            self.0.read_key_blocking()
        }
    }
    seed_platform_x86::input::run_extended_ascii_self_test(&mut Adapter(keys), |expected| {
        render_extended_step(fb, expected);
    })
    .is_ok()
}

const EXT_TITLE: &str = "KEYBOARD CHECK FOR PASSPHRASE (type each shown key)";

fn render_extended_step(fb: &mut dyn Framebuffer, expected: char) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let mut line = LineBuf::new();
    let _ = write!(line, "Press:  {expected}");
    draw_lines(fb, &[EXT_TITLE, "", line.as_str()]);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    struct VecFb {
        w: u32,
        h: u32,
        buf: std::vec::Vec<u32>,
    }
    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, buf: std::vec![0u32; (w as usize) * (h as usize)] }
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

    struct ScriptedKeys {
        events: std::vec::Vec<InputEvent>,
        pos: usize,
    }
    impl ScriptedKeys {
        fn new(events: std::vec::Vec<InputEvent>) -> Self {
            Self { events, pos: 0 }
        }
    }
    impl KeySource for ScriptedKeys {
        fn read_key_blocking(&mut self) -> InputEvent {
            let ev = self.events.get(self.pos).copied().expect("read past scripted keystream");
            self.pos += 1;
            ev
        }
    }

    #[test]
    fn offer_reads_yes_and_no_when_available() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('y')]);
        assert_eq!(read_offer_choice(&mut k, true), OfferChoice::Yes);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('N')]);
        assert_eq!(read_offer_choice(&mut k, true), OfferChoice::No);
    }

    #[test]
    fn offer_ignores_yes_when_entry_unavailable() {
        // 'Y' must be ignored (nothing to enter); only 'N' advances.
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('y'), InputEvent::Char('n')]);
        assert_eq!(read_offer_choice(&mut k, false), OfferChoice::No);
    }

    /// FIX 3: the offer still requires an explicit Y/N — Enter (and any
    /// other stray key) is ignored, so a user cannot skate past the
    /// optional passphrase step by mashing Enter as on other screens.
    #[test]
    fn offer_ignores_enter_and_requires_explicit_y_or_n() {
        let mut k = ScriptedKeys::new(std::vec![
            InputEvent::Enter,
            InputEvent::Backspace,
            InputEvent::Char('n'),
        ]);
        assert_eq!(read_offer_choice(&mut k, true), OfferChoice::No);
    }

    /// FIX 3: the clarifying "optional 25th word" line and the plain
    /// skip/add call-to-action are present, truthful, and neutral, and the
    /// screen renders them (non-blank framebuffer).
    #[test]
    fn offer_shows_the_clarifying_optional_step_line() {
        // The clarifying copy states optionality and the "25th word" framing.
        let step = OFFER_OPTIONAL_STEP.to_lowercase();
        assert!(step.contains("optional"), "must plainly say the step is optional");
        assert!(step.contains("25th word"), "must name the BIP39 25th word framing");
        // The call-to-action names both keys and does not force a choice.
        assert!(OFFER_SKIP_HINT.contains("[Y]") && OFFER_SKIP_HINT.contains("[N]"));
        assert!(OFFER_SKIP_HINT.to_lowercase().contains("skip"));
        // And it is actually drawn on the available-entry offer screen.
        let mut fb = VecFb::new(1024, 768);
        render_offer(&mut fb, true);
        assert!(fb.buf.iter().any(|&p| p != 0));
    }

    #[test]
    fn render_offer_shows_warnings_and_disabled_variant() {
        let mut fb = VecFb::new(1024, 768);
        render_offer(&mut fb, true);
        assert!(fb.buf.iter().any(|&p| p != 0));
        let mut fb2 = VecFb::new(1024, 768);
        render_offer(&mut fb2, false);
        assert!(fb2.buf.iter().any(|&p| p != 0));
        // The warnings convey every SPEC_PASSPHRASE §9 point.
        let all = OFFER_WARN.join(" ").to_lowercase();
        assert!(all.contains("separate wallet"));
        assert!(all.contains("lost forever"));
        assert!(all.contains("own backup"));
        assert!(all.contains("different wallet"));
        assert!(all.contains("no recovery") || all.contains("no reset"));
    }

    #[test]
    fn run_entry_commits_typed_printable_ascii() {
        let mut fb = VecFb::new(1024, 768);
        let mut buf = PassphraseAscii::new();
        let mut k = ScriptedKeys::new(std::vec![
            InputEvent::Char('A'),
            InputEvent::Char(' '),
            InputEvent::Char('4'),
            InputEvent::Char('2'),
            InputEvent::Char('!'),
            InputEvent::Enter,
        ]);
        assert_eq!(run_entry(&mut fb, &mut k, &mut buf, EntryPhase::First, None), EntryOutcome::Committed);
        assert_eq!(buf.as_bytes(), b"A 42!");
    }

    #[test]
    fn run_entry_rejects_non_ascii_and_supports_backspace() {
        let mut fb = VecFb::new(1024, 768);
        let mut buf = PassphraseAscii::new();
        let mut k = ScriptedKeys::new(std::vec![
            InputEvent::Char('a'),
            InputEvent::Char('é'),  // rejected, not added
            InputEvent::Char('b'),
            InputEvent::Backspace,  // removes 'b'
            InputEvent::Char('c'),
            InputEvent::Enter,
        ]);
        assert_eq!(run_entry(&mut fb, &mut k, &mut buf, EntryPhase::First, None), EntryOutcome::Committed);
        assert_eq!(buf.as_bytes(), b"ac");
    }

    #[test]
    fn run_entry_escape_scrubs_and_cancels() {
        let mut fb = VecFb::new(1024, 768);
        let mut buf = PassphraseAscii::new();
        let mut k = ScriptedKeys::new(std::vec![
            InputEvent::Char('s'),
            InputEvent::Char('e'),
            InputEvent::Char('c'),
            InputEvent::Escape,
        ]);
        assert_eq!(run_entry(&mut fb, &mut k, &mut buf, EntryPhase::First, None), EntryOutcome::Cancelled);
        assert!(buf.is_empty(), "Escape must scrub the buffer before cancelling");
    }

    #[test]
    fn empty_commit_is_allowed() {
        let mut fb = VecFb::new(1024, 768);
        let mut buf = PassphraseAscii::new();
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Enter]);
        assert_eq!(run_entry(&mut fb, &mut k, &mut buf, EntryPhase::First, None), EntryOutcome::Committed);
        assert!(buf.is_empty());
    }
}
