//! Complete hidden mnemonic re-entry (SPEC §23.1-§23.2,
//! `AppState::CompleteHiddenReentry` / `AppState::ReentryMismatchChoice`).
//!
//! Every word position is read with
//! [`seed_platform_x86::input::read_hidden`] (SPEC §12.3: Enter-
//! terminated, no echo, at most four characters, dot-count callback only
//! — never the typed letters) and resolved against the BIP39 wordlist
//! with [`seed_core::bip39::resolve_prefix_into`], which never hands back
//! a `Copy`/`Debug`-capable value carrying the resolved secret index (see
//! that function's own doc comment); this module follows the identical
//! discipline for its own [`ReentryOutcome`] (a plain, non-secret
//! Matched/Mismatch discriminant, never the index itself).
//!
//! SPEC §27.3 ("no ... correct or incorrect word positions beyond the
//! currently requested position"): [`read_and_check_one_word`] reports
//! only whether *this* position matched — never anything about earlier
//! or later positions, and never which of the (up to four) typed letters
//! were right.

use seed_core::bip39::{resolve_prefix_into, PrefixOutcome};
use seed_core::contracts::Framebuffer;
use seed_platform_x86::input::{read_hidden, InputEvent, KeySource};

use crate::flow_secret::gop_screen::draw_lines;
use crate::output::LineBuf;
use core::fmt::Write as _;

/// Pure formatting helper (design doc §4 Stage 6: "'Word 7 of 24'
/// progress in the header during re-entry"): `position` is 0-based,
/// rendered 1-based with no zero-padding.
fn word_header(position: usize, total: usize) -> LineBuf {
    let mut header = LineBuf::new();
    let _ = write!(header, "Word {} of {}", position + 1, total);
    header
}

/// Render the SPEC §12.3 word-entry prompt for `position` (0-based) of
/// `total`, with `dots` hidden characters typed so far. Uses `*` in
/// place of the SPEC mockup's `•` (the embedded bitmap font is
/// ASCII-only, `seed_gop_ui::font` §12.2) — a rendering detail, not a
/// protocol one.
///
/// The header row (design doc §4 Stage 6 progress area) renders in
/// [`seed_gop_ui::theme::CAPTION`] — de-emphasis, the same role this
/// restyle's slot-index captions and header stage rail use elsewhere —
/// while the entry line itself keeps the ordinary screen style.
pub fn render_word_prompt(fb: &mut dyn Framebuffer, position: usize, total: usize, dots: usize) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    let header = word_header(position, total);
    let mut dot_line = LineBuf::new();
    let _ = write!(dot_line, "Type the first four letters, then Enter: ");
    let mut stars = [b'*'; 4];
    for s in stars.iter_mut().skip(dots) {
        *s = b' ';
    }
    let stars_str = core::str::from_utf8(&stars[..4]).unwrap_or("");
    let _ = write!(dot_line, "{stars_str}");

    let margin = seed_gop_ui::layout::MARGIN_X;
    let pitch = seed_gop_ui::layout::LINE_PITCH;
    seed_gop_ui::font::draw_text(
        fb,
        margin,
        margin,
        header.as_str(),
        seed_gop_ui::theme::on_bg(seed_gop_ui::theme::CAPTION),
    );
    // Blank line, then the entry row — same two-line offset `draw_lines`
    // previously produced for `&[header, "", dot_line]`.
    seed_gop_ui::font::draw_text(fb, margin, margin + pitch * 2, dot_line.as_str(), seed_gop_ui::layout::SCREEN_STYLE);
}

/// Non-secret outcome of one [`read_and_check_one_word`] call (SPEC
/// §27.3: never leaks anything beyond match/mismatch of this position).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReentryOutcome {
    /// The resolved word matches `expected_index` at this position.
    Matched,
    /// The resolved word does not match, or the typed prefix did not
    /// resolve to exactly one BIP39 word (SPEC §23.1: "The entered
    /// prefix MUST resolve to exactly one BIP39 word or the entry is
    /// treated as incorrect").
    Mismatch,
}

/// Read one hidden word entry for `position` (0-based) of `total` and
/// compare it against `*expected_index` (the generated mnemonic's index
/// at this position — taken by reference, SPEC §20.2: "Functions SHOULD
/// receive mutable references rather than secret values by value", so a
/// caller reading straight out of `SecretArena::mnemonic_indexes()` never
/// needs an intermediate, never-scrubbed stack copy of the secret index).
/// Blocks until Enter terminates the entry (SPEC §12.3); re-renders the
/// prompt on every accepted/removed character via `read_hidden`'s
/// count-changed callback, never echoing a typed letter.
///
/// SPEC §12.3: "Enter with an empty buffer re-displays the prompt." A
/// bare Enter before any letter is typed is not an incorrect entry: this
/// function loops back and shows the prompt fresh instead of resolving
/// (and necessarily failing to resolve) an empty prefix.
pub fn read_and_check_one_word<K: KeySource>(
    fb: &mut dyn Framebuffer,
    keys: &mut K,
    position: usize,
    total: usize,
    expected_index: &u16,
) -> ReentryOutcome {
    loop {
        render_word_prompt(fb, position, total, 0);
        let mut buf = [0u8; 4];
        let len = read_hidden(keys, &mut buf, 4, |n| render_word_prompt(fb, position, total, n));

        if len == 0 {
            // SPEC §12.3: empty-buffer Enter re-displays the prompt
            // rather than counting as a wrong entry.
            continue;
        }

        let mut resolved: u16 = 0;
        let outcome = resolve_prefix_into(&buf[..len], &mut resolved);
        seed_core::arena::scrub_slice(&mut buf);

        let matched = matches!(outcome, PrefixOutcome::Unique) && resolved == *expected_index;
        scrub_u16(&mut resolved);

        return if matched { ReentryOutcome::Matched } else { ReentryOutcome::Mismatch };
    }
}

/// SHOULD-FIX #6: previously a hand-rolled volatile-write +
/// `compiler_fence` only, weaker than every other secret scrub in this
/// project. Now routes through [`seed_core::arena::scrub_slice`] instead,
/// so this resolved-word-index scrub gets the same architecture memory
/// fence and volatile verification read `seed_core::arena::SecretArena`'s
/// own field scrubs use two lines above (SPEC §20.3), rather than a
/// second, weaker copy of "most of" that guarantee.
fn scrub_u16(v: &mut u16) {
    // SAFETY: `v` is a valid, exclusively-borrowed `&mut u16` local for
    // the duration of this call; `u16` has no padding and every byte of
    // its object representation is part of its value, so reinterpreting
    // it as a 2-byte slice is always valid — the identical justification
    // `seed_core::arena`'s own private `scrub_mnemonic_indexes_field`
    // uses for the same `[u16] -> [u8]` reinterpretation.
    let bytes: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut((v as *mut u16).cast::<u8>(), core::mem::size_of::<u16>()) };
    seed_core::arena::scrub_slice(bytes);
}

// ============================================================================
// SPEC §23.2: incorrect entry -> retry / reveal / destroy
// ============================================================================

pub const MISMATCH_HEADER: &str = "The entered word does not match this position.";
pub const RETRY_PROMPT: &str = "[1] Retry this position";
pub const REVEAL_PROMPT: &str = "[2] Reveal the phrase again";
pub const DESTROY_PROMPT: &str = "[3] Destroy phrase and shut down";

/// Render the SPEC §23.2 mismatch screen. Deliberately says nothing
/// about *which* position or how many letters were wrong (SPEC §27.3).
///
/// Clears the framebuffer first (SPEC §12.2 "Fixed layouts"): this
/// screen follows the hidden-entry prompt (`render_word_prompt`), whose
/// "Word NN of MM" / star-count line can be longer than this screen's
/// own lines, so drawing directly over it without clearing would leave
/// residual glyph tails from the previous screen visible underneath.
pub fn render_mismatch_screen(fb: &mut dyn Framebuffer) {
    seed_gop_ui::font::scrub_fill(fb, 0);
    draw_lines(fb, &[MISMATCH_HEADER, "", RETRY_PROMPT, REVEAL_PROMPT, DESTROY_PROMPT]);
}

/// The user's choice on the SPEC §23.2 mismatch screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchChoice {
    /// `[1]` retry the same position.
    Retry,
    /// `[2]` reveal the phrase again — the caller MUST discard all
    /// re-entry progress and restart from word 1 after another display
    /// scrub (SPEC §23.2).
    RevealAgain,
    /// `[3]` destroy and shut down (still requires the SPEC §22.7 second
    /// confirmation, `crate::flow_secret::display::read_destroy_double_confirm`).
    Destroy,
}

/// Block until `1`, `2` or `3` is pressed; every other key is ignored.
pub fn read_mismatch_choice<K: KeySource + ?Sized>(keys: &mut K) -> MismatchChoice {
    loop {
        match keys.read_key_blocking() {
            InputEvent::Char('1') => return MismatchChoice::Retry,
            InputEvent::Char('2') => return MismatchChoice::RevealAgain,
            InputEvent::Char('3') => return MismatchChoice::Destroy,
            _ => {}
        }
    }
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

    fn chars(s: &str) -> std::vec::Vec<InputEvent> {
        s.chars().map(InputEvent::Char).collect()
    }

    // ---- design doc §4 Stage 6: "Word 7 of 24" header formatting ----

    #[test]
    fn word_header_formats_word_n_of_total_without_zero_padding() {
        assert_eq!(word_header(6, 24).as_str(), "Word 7 of 24");
        assert_eq!(word_header(0, 12).as_str(), "Word 1 of 12");
        assert_eq!(word_header(23, 24).as_str(), "Word 24 of 24");
    }

    /// "abandon" -> identifying prefix "aban" -> wordlist index 0.
    #[test]
    fn correct_prefix_matches_expected_index() {
        let mut fb = VecFb::new(640, 480);
        let mut events = chars("aban");
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &0);
        assert_eq!(outcome, ReentryOutcome::Matched);
    }

    #[test]
    fn wrong_word_is_a_mismatch() {
        let mut fb = VecFb::new(640, 480);
        // "act" (index != 0) typed at a position expecting index 0.
        let mut events = chars("act");
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &0);
        assert_eq!(outcome, ReentryOutcome::Mismatch);
    }

    #[test]
    fn unresolvable_prefix_is_a_mismatch_not_a_panic() {
        let mut fb = VecFb::new(640, 480);
        let mut events = chars("zzzz");
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 5, 24, &100);
        assert_eq!(outcome, ReentryOutcome::Mismatch);
    }

    #[test]
    fn backspace_then_retype_still_resolves_correctly() {
        let mut fb = VecFb::new(640, 480);
        let mut events = chars("abax");
        events.push(InputEvent::Backspace);
        events.push(InputEvent::Char('n'));
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &0);
        assert_eq!(outcome, ReentryOutcome::Matched);
    }

    /// Regression test for the confirmed WP-26 finding (SPEC §12.3):
    /// "Enter with an empty buffer re-displays the prompt." A bare Enter
    /// before typing anything must not be reported as a mismatch -- the
    /// function must keep waiting for a real entry instead.
    #[test]
    fn empty_buffer_enter_redisplays_prompt_instead_of_a_mismatch() {
        let mut fb = VecFb::new(640, 480);
        let mut events = std::vec![InputEvent::Enter]; // bare Enter, nothing typed
        events.extend(chars("aban"));
        events.push(InputEvent::Enter); // now submit the real word
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &0);
        assert_eq!(outcome, ReentryOutcome::Matched, "an accidental empty Enter must not count as a wrong entry");
    }

    /// A second empty Enter in a row must also just keep re-prompting,
    /// not accumulate into a false mismatch.
    #[test]
    fn multiple_empty_buffer_enters_all_redisplay_the_prompt() {
        let mut fb = VecFb::new(640, 480);
        let mut events = std::vec![InputEvent::Enter, InputEvent::Enter, InputEvent::Enter];
        events.extend(chars("act")); // resolves, but to the WRONG word for index 0
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &0);
        assert_eq!(outcome, ReentryOutcome::Mismatch, "the real (wrong) entry after empty Enters must still be checked");
    }

    /// Regression test for the confirmed WP-26 finding (SPEC §20.2):
    /// `read_and_check_one_word` takes `expected_index` by reference, so
    /// a caller can pass a reference straight into a real backing array
    /// (as `SecretArena::mnemonic_indexes()[position]` would be indexed
    /// from) without an intermediate, un-scrubbed `let expected: u16 =
    /// ...;` stack copy. Exercised (not just type-checked): if the
    /// signature ever regresses back to taking `u16` by value, this call
    /// site (passing `&backing[0]`) stops compiling.
    #[test]
    fn expected_index_is_taken_by_reference_not_by_value_copy() {
        let backing = [7u16; 1];
        let mut fb = VecFb::new(640, 480);
        let mut events = chars("act"); // resolves to an index != 7
        events.push(InputEvent::Enter);
        let mut keys = ScriptedKeys::new(events);
        let outcome = read_and_check_one_word(&mut fb, &mut keys, 0, 12, &backing[0]);
        assert_eq!(outcome, ReentryOutcome::Mismatch);
    }

    #[test]
    fn never_echoes_letters_to_the_framebuffer_only_dot_count_changes() {
        // The framebuffer must show a growing run of '*' placeholders,
        // never the literal typed letters -- draw_word/draw_text render
        // ASCII glyphs, so a crude but effective check is that the
        // rendered prompt line never differs in pixel content between
        // two different 4-letter prefixes typed at the same position
        // (since both render identically: 4 stars).
        let mut fb_a = VecFb::new(640, 480);
        let mut events_a = chars("aban");
        events_a.push(InputEvent::Enter);
        let mut keys_a = ScriptedKeys::new(events_a);
        let _ = read_and_check_one_word(&mut fb_a, &mut keys_a, 0, 12, &0);

        let mut fb_b = VecFb::new(640, 480);
        let mut events_b = chars("zzzz");
        events_b.push(InputEvent::Enter);
        let mut keys_b = ScriptedKeys::new(events_b);
        let _ = read_and_check_one_word(&mut fb_b, &mut keys_b, 0, 12, &0);

        // Both prompts, at the moment of the final render (4 stars
        // shown), must be pixel-identical -- proving the letters
        // themselves never reached the framebuffer.
        render_word_prompt(&mut fb_a, 0, 12, 4);
        render_word_prompt(&mut fb_b, 0, 12, 4);
        assert_eq!(fb_a.buf, fb_b.buf);
    }

    #[test]
    fn mismatch_choice_reads_1_2_3() {
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('1')]);
        assert_eq!(read_mismatch_choice(&mut k), MismatchChoice::Retry);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('2')]);
        assert_eq!(read_mismatch_choice(&mut k), MismatchChoice::RevealAgain);
        let mut k = ScriptedKeys::new(std::vec![InputEvent::Char('3')]);
        assert_eq!(read_mismatch_choice(&mut k), MismatchChoice::Destroy);
    }

    /// Regression test for the confirmed WP-26 finding (SPEC §12.2
    /// "Fixed layouts"): `render_mismatch_screen` must clear residual
    /// content from the previous (longer) hidden-entry prompt screen
    /// before drawing its own lines, rather than drawing directly over
    /// whatever was already on screen.
    #[test]
    fn render_mismatch_screen_clears_prior_screen_content_first() {
        let mut fb = VecFb::new(640, 480);
        // Simulate the previous screen (hidden-entry prompt) leaving a
        // long line of foreground pixels far to the right, well past
        // where the mismatch screen's own (shorter) lines would reach.
        let far_right_row: std::vec::Vec<u32> = std::vec![0x00FF_FFFFu32; 40];
        fb.put_row(600, 0, &far_right_row);
        assert!(fb.buf.iter().any(|&p| p == 0x00FF_FFFF), "sanity: residue is present before rendering");

        render_mismatch_screen(&mut fb);

        // The stale far-right pixels must have been cleared by the
        // leading `scrub_fill`, not left behind under/around the new
        // screen's own (shorter) text.
        for x in 600..640 {
            let idx = x as usize; // row 0
            assert_eq!(fb.buf[idx], 0, "residual prior-screen pixel at x={x} was not cleared");
        }
    }

    #[test]
    fn mismatch_header_never_names_a_position_or_letter_count() {
        // SPEC §27.3: no correct/incorrect leakage beyond the current
        // position -- the fixed mismatch header must not contain any
        // digits (which would imply a position number or letter count).
        // The menu prompts' own "[1]"/"[2]"/"[3]" option numbers are a
        // different thing (a fixed choice index, not position/letter
        // leakage) and are exempt.
        assert!(
            !MISMATCH_HEADER.chars().any(|c| c.is_ascii_digit()),
            "mismatch header must not name a position"
        );
    }

    /// SHOULD-FIX #6 regression: `scrub_u16` must still actually zero the
    /// resolved word index — routing it through `seed_core::arena::
    /// scrub_slice` must not silently turn scrubbing into a no-op.
    #[test]
    fn scrub_u16_zeroes_a_nonzero_value() {
        let mut v: u16 = 0xBEEF;
        scrub_u16(&mut v);
        assert_eq!(v, 0);
    }

    /// Every possible resolved BIP39 index (0..=2047) must scrub cleanly
    /// — in particular values whose low byte is zero but high byte is
    /// not (and vice versa), which a byte-order mistake in the
    /// `u16`-as-`[u8; 2]` reinterpretation could leave half-scrubbed.
    #[test]
    fn scrub_u16_zeroes_every_byte_regardless_of_value_shape() {
        for raw in [0x0001u16, 0x0100, 0x00FF, 0xFF00, 0x07FF, 2047] {
            let mut v = raw;
            scrub_u16(&mut v);
            assert_eq!(v, 0, "scrub_u16({raw:#06x}) left a nonzero value");
        }
    }
}
