//! Fixed screen text (SPEC §22.1, §22.2, §22.4, §22.5, §6, §8.4, §16,
//! §17.2, §18.2, §18.3).
//!
//! [`REQUIRED_WARNING_8_4`], [`MACHINE_ONLY_WARNING_18_2`],
//! [`PHYSICAL_ONLY_WARNING_18_3`], [`DICE_COINS_FIRMWARE_WARNING_6`],
//! [`MACHINE_HEALTH_CHECK_DISCLAIMER_16`],
//! [`PHYSICAL_FAIRNESS_DISCLAIMER_17_2`] and [`ACK_LABEL`] are copied
//! byte-for-byte from `SPEC.md`'s blockquoted/quoted required wording —
//! each has a test below asserting the exact string, so a future SPEC.md
//! edit that changes the wording is caught by a failing test rather than
//! silently drifting. Everything else here is UI copy driven by the same
//! sections but not mandated verbatim by the spec.

use crate::entropy_avail::MachineOnlyDisclosure;
use crate::output::{write_screen, LineBuf, LINE_CAPACITY, TextOutput};
use core::fmt::Write as _;

// ============================================================================
// SPEC_DICE_COIN_VISUAL.md §7: word-boundary prose wrapping
// ============================================================================

/// Word-wrap `text` to `cols` glyph cells, yielding borrowed `&str`
/// subslices of the input (SPEC_DICE_COIN_VISUAL.md §7, minor m3).
///
/// `no_std`, allocation-free: every yielded line is a view into the
/// original buffer -- no `String`, no `Vec`. Alea's copy is ASCII, so byte
/// offsets equal cell offsets. Behaviour:
///
/// - Breaks only at ASCII spaces between words; **no word is split
///   mid-token** (§7 rule 2).
/// - A single token longer than `cols` is hard-split at `cols`-cell
///   offsets -- the only sub-token break (§7 rule 3).
/// - Runs of spaces collapse to one break opportunity; leading/trailing
///   spaces on a wrapped line are trimmed (§7 minor m3).
/// - `cols` is clamped to [`LINE_CAPACITY`] so a yielded slice can never
///   overflow the caller's [`LineBuf`] (§7 minor m3).
///
/// This helper is invoked **only** by prose emitters (disclaimers,
/// warnings, notices). Fixed-layout art/menus/labels/strip MUST bypass it
/// (§7 rule 5 / §7.5); running them through it would corrupt their
/// geometry.
#[must_use]
pub fn wrap_words(text: &str, cols: usize) -> WrapWords<'_> {
    WrapWords { rest: text, cols: cols.min(LINE_CAPACITY).max(1) }
}

/// Iterator returned by [`wrap_words`]. Yields one wrapped line per
/// `next()`, each a subslice of the original `&str`.
pub struct WrapWords<'a> {
    rest: &'a str,
    cols: usize,
}

impl<'a> Iterator for WrapWords<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let bytes = self.rest.as_bytes();
        // Trim leading spaces: the next line begins at the next non-space.
        let mut start = 0;
        while start < bytes.len() && bytes[start] == b' ' {
            start += 1;
        }
        if start >= bytes.len() {
            self.rest = "";
            return None;
        }
        let s = &self.rest[start..];
        let sb = s.as_bytes();

        if sb.len() <= self.cols {
            // The whole remaining tail fits on one line.
            self.rest = "";
            return Some(trim_ascii_end(s));
        }

        // The tail is longer than `cols`: find the last space at or before
        // the `cols`-th byte to break on a word boundary. `sb[start]` is
        // never a space (trimmed above), so a break index of 0 is
        // impossible -- any space found is a genuine inter-word break.
        let mut brk = None;
        let mut i = self.cols; // a space exactly at `cols` is a valid break
        loop {
            if sb[i] == b' ' {
                brk = Some(i);
                break;
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        match brk {
            Some(i) => {
                let line = trim_ascii_end(&s[..i]);
                self.rest = &s[i..];
                Some(line)
            }
            None => {
                // Over-long single token (§7 rule 3): hard-split at `cols`.
                let line = &s[..self.cols];
                self.rest = &s[self.cols..];
                Some(line)
            }
        }
    }
}

/// Column budget for word-wrapping prose paragraphs on the fixed pre-secret
/// text screens (SPEC_DICE_COIN_VISUAL.md §7). The pre-secret [`TextOutput`]
/// trait is line-oriented and does not expose the backend's actual column
/// count, so — exactly as the SPEC §17.2 disclaimer does in
/// [`crate::flow_secret::physical::render_physical_screen`] — prose here is
/// wrapped to a fixed safe budget that fits BOTH the 800x600 UEFI floor
/// (98 cols) and the 1024x768 desktop rehearsal (126 cols). 80 leaves
/// generous margin on every target while never splitting a word mid-token.
pub const PROSE_WRAP_COLS: usize = 80;

/// Emit `prose` word-wrapped to [`PROSE_WRAP_COLS`] via [`wrap_words`], one
/// wrapped line per `write_line` call. For the fixed pre-secret warning
/// screens whose single mandated paragraph would otherwise render as one
/// over-long line and clip mid-word on the 98/126-col targets. Only prose
/// paragraphs are routed through here — never fixed-layout art, labels or
/// prompts (SPEC_DICE_COIN_VISUAL.md §7.5).
fn write_wrapped_prose(out: &mut dyn TextOutput, prose: &str) {
    for line in wrap_words(prose, PROSE_WRAP_COLS) {
        out.write_line(line);
    }
}

/// Trim trailing ASCII spaces from a slice (no alloc).
fn trim_ascii_end(s: &str) -> &str {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 0 && b[end - 1] == b' ' {
        end -= 1;
    }
    &s[..end]
}

// ============================================================================
// SPEC.md §21 amendment (2026-08-04, "pre-secret Back navigation"): the
// one uniform affordance shown on every pre-secret screen. Esc always
// goes back exactly one step (SPEC.md §21 amendment); from the very first
// ceremony screen (the opening warning), "back" means returning control
// to the caller (SPEC §22.1's "Exit before generation" for a UEFI
// caller; the desktop launcher's main menu for that caller) — the same
// key, the same label, everywhere.
// ============================================================================

/// Shown on every pre-secret screen that offers Escape (SPEC.md §21
/// amendment). Replaces the previous per-screen, inconsistent
/// `"[Esc] Exit before generation"` / `"[Esc] Return"` wording — this is
/// additive UX, not a change to any mandated warning text.
pub const BACK_PROMPT: &str = "[Esc] Back";

// ============================================================================
// SPEC §22.1 opening warning
// ============================================================================

pub const OPENING_TITLE: &str = "ALEA";
/// Single source: `crate::screens::prepare::WARNING_BODY` (Task 10 moved
/// the string data there — the Stage 1 Prepare screen folds this same
/// SPEC §22.1 warning body in with the §22.2 commitments). Re-exported
/// under this name so this module's own `render_opening_warning` (still
/// used by the pre-redesign text-mode call sites) needs no changes.
pub use crate::screens::prepare::WARNING_BODY as OPENING_BODY;
pub const OPENING_CONTINUE_PROMPT: &str = "[Enter] Continue";
/// SPEC.md §21 amendment: Esc on the opening warning is the first
/// ceremony screen's Back — which, having no earlier screen to return to,
/// hands control back to the caller (SPEC §22.1's "Exit before
/// generation" for a UEFI caller; the desktop launcher's main menu for
/// that caller). Same uniform label as every other pre-secret screen.
pub const OPENING_ESCAPE_PROMPT: &str = BACK_PROMPT;

/// Render the SPEC §22.1 opening warning screen. Does not read input;
/// the caller reads the following key via [`crate::keys::read_continue_or_escape`].
pub fn render_opening_warning(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line(OPENING_TITLE);
    out.write_line("");
    write_screen(out, OPENING_BODY);
    out.write_line("");
    out.write_line(OPENING_CONTINUE_PROMPT);
    out.write_line(OPENING_ESCAPE_PROMPT);
}

// ============================================================================
// SPEC §22.2 environment acknowledgement (three grouped screens)
// ============================================================================

/// SPEC §22.2: "Each screen is labeled: 'These are your statements.
/// Alea cannot verify them.'" — verbatim, required on all three
/// screens.
pub const ACK_LABEL: &str = "These are your statements. Alea cannot verify them.";

pub const ACK_SCREEN_1_TITLE: &str = "Screen 1 -- Release integrity";
pub const ACK_SCREEN_1_ITEMS: &[&str] = &[
    "- The release signature was independently verified.",
    "- The USB media was read back after writing and matched.",
];

pub const ACK_SCREEN_2_TITLE: &str = "Screen 2 -- Machine and connectivity";
pub const ACK_SCREEN_2_ITEMS: &[&str] = &[
    "- This is a physical machine.",
    "- It is not a corporate or shared managed endpoint.",
    "- The network cable is disconnected.",
    "- Wireless is disabled where possible.",
    "- No remote management is known to be active.",
];

pub const ACK_SCREEN_3_TITLE: &str = "Screen 3 -- Physical environment and aftercare";
pub const ACK_SCREEN_3_ITEMS: &[&str] = &[
    "- This is a private room.",
    "- There are no cameras, capture devices or untrusted observers.",
    "- A paper or metal backup is ready.",
    "- Complete power-off is possible afterward.",
];

pub const ACK_CONFIRM_PROMPT: &str = "[Enter] I confirm all of the above";
/// SPEC.md §21 amendment: same uniform Back label as every other
/// pre-secret screen — Esc here goes back one screen (to the previous ack
/// screen, or to the opening warning from the first one).
pub const ACK_ESCAPE_PROMPT: &str = BACK_PROMPT;

/// The three SPEC §22.2 acknowledgement screens, in order, as
/// `(title, items)` pairs — iterated by the driver so each requires its
/// own distinct confirmation (SPEC §22.2: "Acknowledgements are grouped
/// into three screens, each requiring a distinct confirmation").
pub const ACK_SCREENS: [(&str, &[&str]); 3] = [
    (ACK_SCREEN_1_TITLE, ACK_SCREEN_1_ITEMS),
    (ACK_SCREEN_2_TITLE, ACK_SCREEN_2_ITEMS),
    (ACK_SCREEN_3_TITLE, ACK_SCREEN_3_ITEMS),
];

/// Render one SPEC §22.2 acknowledgement screen.
pub fn render_ack_screen(out: &mut dyn TextOutput, title: &str, items: &[&str]) {
    out.clear();
    out.write_line(title);
    out.write_line("");
    out.write_line(ACK_LABEL);
    out.write_line("");
    write_screen(out, items);
    out.write_line("");
    out.write_line(ACK_CONFIRM_PROMPT);
    out.write_line(ACK_ESCAPE_PROMPT);
}

// ============================================================================
// SPEC §8.4 required warning
// ============================================================================

/// SPEC §8.4, verbatim: "Before production generation, the application
/// MUST display" this text.
pub const REQUIRED_WARNING_8_4: &str = "Alea removes the normal operating system from the seed-generation \
process. It cannot prove that your firmware, processor, memory, input \
devices, display path or physical environment are trustworthy.";

/// Render the SPEC §8.4 required warning as its own screen, requiring
/// acknowledgement (SPEC: "Before production generation, the application
/// MUST display" — shown here as the last pre-secret screen, immediately
/// before the driver commits to the chosen entropy mode).
pub fn render_required_warning(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("REQUIRED WARNING");
    out.write_line("");
    write_wrapped_prose(out, REQUIRED_WARNING_8_4);
    out.write_line("");
    out.write_line("[Enter] I understand");
}

// ============================================================================
// SPEC §11.5 keyboard-layout self-test offer (amendment 2026-08-04:
// OPTIONAL/skippable, per-edition — see `crate::keys::
// KeyboardSelfTestSkipPolicy` and SPEC_MAIN_MENU.md §15)
// ============================================================================

pub const KEYBOARD_SELF_TEST_OFFER_TITLE: &str = "KEYBOARD SELF-TEST";
pub const KEYBOARD_SELF_TEST_OFFER_BODY: &[&str] = &[
    "This confirms your keyboard layout behaves as expected before any",
    "secret exists, so complete hidden re-entry later needs no",
    "multiple-choice fallback.",
];
pub const KEYBOARD_SELF_TEST_START_PROMPT: &str = "[Enter] Start test";
pub const KEYBOARD_SELF_TEST_START_RECOMMENDED_PROMPT: &str = "[Enter] Start test (recommended)";
pub const KEYBOARD_SELF_TEST_SKIP_PROMPT: &str = "[S] Skip";

/// Render the SPEC.md §11.5-amendment offer screen: run the self-test now,
/// or skip it. `recommended` selects the production-style prompt wording
/// (SPEC.md §11.5 amendment: "offered by default and strongly
/// recommended") versus the plain desktop wording; it does not by itself
/// gate whether Skip requires an acknowledgement — that is
/// [`render_keyboard_self_test_skip_acknowledgement`]'s job, driven by
/// `crate::keys::KeyboardSelfTestSkipPolicy` in the caller.
pub fn render_keyboard_self_test_offer_screen(out: &mut dyn TextOutput, recommended: bool) {
    out.clear();
    out.write_line(KEYBOARD_SELF_TEST_OFFER_TITLE);
    out.write_line("");
    write_screen(out, KEYBOARD_SELF_TEST_OFFER_BODY);
    out.write_line("");
    if recommended {
        out.write_line(KEYBOARD_SELF_TEST_START_RECOMMENDED_PROMPT);
    } else {
        out.write_line(KEYBOARD_SELF_TEST_START_PROMPT);
    }
    out.write_line(KEYBOARD_SELF_TEST_SKIP_PROMPT);
}

/// SPEC.md §11.5 amendment, in substance (not a SPEC.md blockquote, so
/// not byte-for-byte the way [`REQUIRED_WARNING_8_4`] etc. are — see the
/// module doc comment): "Skipping means an unsuitable keyboard layout
/// will only be discovered during hidden re-entry, where the words are
/// not shown — you may be unable to complete verification." Shown only on
/// [`crate::keys::KeyboardSelfTestSkipPolicy::RecommendedSkippableWithAcknowledgement`]
/// editions when the user chooses Skip.
pub const KEYBOARD_SELF_TEST_SKIP_WARNING_11_5: &str = "Skipping means an unsuitable keyboard layout will only be discovered \
during hidden re-entry, where the words are not shown -- you may be \
unable to complete verification.";

pub const KEYBOARD_SELF_TEST_SKIP_ACK_PROMPT: &str = "[Enter] Skip anyway";
pub const KEYBOARD_SELF_TEST_SKIP_BACK_PROMPT: &str = "[B] Back, run the test instead";

/// Render the production-edition explicit skip acknowledgement (SPEC.md
/// §11.5 amendment). The caller reads the following key via
/// [`crate::keys::read_confirm_or_decline`] with `decline_key = 'b'`:
/// `true` confirms the skip, `false` returns to the offer screen so the
/// self-test can still be run.
pub fn render_keyboard_self_test_skip_acknowledgement(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("SKIP KEYBOARD SELF-TEST?");
    out.write_line("");
    out.write_line(KEYBOARD_SELF_TEST_SKIP_WARNING_11_5);
    out.write_line("");
    out.write_line(KEYBOARD_SELF_TEST_SKIP_ACK_PROMPT);
    out.write_line(KEYBOARD_SELF_TEST_SKIP_BACK_PROMPT);
}

// ============================================================================
// SPEC §18.2 / §18.3 mode warnings
// ============================================================================

/// SPEC §18.2, verbatim.
pub const MACHINE_ONLY_WARNING_18_2: &str = "You are trusting this machine's random-number hardware completely. You \
cannot witness or verify the quality of this entropy. If this hardware \
is faulty or malicious, the resulting wallet is unsafe, and nothing on \
this screen would look different.";

/// SPEC §18.3, verbatim.
pub const PHYSICAL_ONLY_WARNING_18_3: &str = "Security now depends entirely on the fairness and independence of your \
rolls and flips and on the integrity of this computer's firmware and \
execution.";

/// Render the SPEC §18.2 machine-only warning as its own screen,
/// requiring acknowledgement before mode 3 may be chosen.
///
/// `disclosure`, when `Some` (real firmware wiring always supplies one
/// here — see [`crate::entropy_avail::MachineAvailabilityGate::
/// machine_only_disclosure`]'s doc comment), additionally renders SPEC
/// §18.2's four required disclosure items — source class, algorithm
/// identifier, CPU/microcode policy result and policy version — before
/// the fixed warning text.
pub fn render_machine_only_warning(out: &mut dyn TextOutput, disclosure: Option<&MachineOnlyDisclosure>) {
    out.clear();
    out.write_line("MACHINE-ONLY ENTROPY");
    out.write_line("");
    if let Some(d) = disclosure {
        let mut line = LineBuf::new();
        let _ = write!(line, "Source class: {}", d.source_class);
        out.write_line(line.as_str());

        let mut line = LineBuf::new();
        let _ = write!(line, "Algorithm identifier: {}", d.algorithm_identifier.as_str());
        out.write_line(line.as_str());

        let mut line = LineBuf::new();
        match d.cpu_microcode_result {
            Some(true) => {
                let _ = write!(line, "CPU and microcode policy result: allowed");
            }
            Some(false) => {
                let _ = write!(line, "CPU and microcode policy result: not allowed");
            }
            None => {
                let _ = write!(line, "CPU and microcode policy result: not applicable to this source class");
            }
        }
        out.write_line(line.as_str());

        let mut line = LineBuf::new();
        let _ = write!(line, "Entropy policy version: {}", d.policy_version);
        out.write_line(line.as_str());
        out.write_line("");
    }
    write_wrapped_prose(out, MACHINE_ONLY_WARNING_18_2);
    out.write_line("");
    out.write_line("[Enter] I understand");
}

/// Render the SPEC §18.3 physical-only warning as its own screen,
/// requiring acknowledgement before mode 2 may be chosen.
pub fn render_physical_only_warning(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("PHYSICAL-ONLY ENTROPY");
    out.write_line("");
    write_wrapped_prose(out, PHYSICAL_ONLY_WARNING_18_3);
    out.write_line("");
    out.write_line("[Enter] I understand");
}

// ============================================================================
// SPEC §16 machine-source health-check disclaimer
// ============================================================================

/// SPEC §16, verbatim: "The UI MUST state" this text whenever machine
/// source health-check results are shown (`crate::flow_secret::machine::
/// render_acquiring`, SPEC §21 `AppState::MachineEntropyAcquisition` —
/// the only screen in this crate that runs while
/// `seed_platform_x86::rng::health`'s checks execute, for both `Combined`
/// and `MachineOnly` modes).
///
/// [`seed_platform_x86::rng::health`]'s own doc comment explicitly defers
/// this exact wording to "the presentation layer (WP-25/26)" — this
/// constant plus [`crate::flow_secret::machine::render_acquiring`] is
/// that presentation layer.
pub const MACHINE_HEALTH_CHECK_DISCLAIMER_16: &str = "These checks can detect some catastrophic failures. They do not prove \
that the source is unpredictable, correctly implemented or independent \
from another source.";

// ============================================================================
// SPEC §17.2 physical-entropy fairness/independence disclaimer
// ============================================================================

/// SPEC §17.2, verbatim: "The UI MUST state" this text on the SPEC §17.4
/// physical-entry screen ([`crate::flow_secret::physical::
/// render_physical_screen`]) while dice/coin events are being collected.
pub const PHYSICAL_FAIRNESS_DISCLAIMER_17_2: &str = "The number of rolls or flips does not prove that your dice or coins are \
fair or that the events are independent.";

// ============================================================================
// SPEC §6 dice/coins-do-not-protect-against-malicious-firmware warning
// ============================================================================

/// SPEC §6, verbatim: "The application MUST warn" this text whenever the
/// chosen entropy mode uses physical dice/coins (`Combined` or
/// `DiceOnly` — SPEC §18.1's modes 1 and 2). Distinct from
/// [`PHYSICAL_ONLY_WARNING_18_3`]: that warning is about the fairness and
/// independence of the rolls/flips themselves; this one is about
/// malicious firmware defeating the physical-randomness assumption
/// entirely by recording keystrokes or altering execution.
pub const DICE_COINS_FIRMWARE_WARNING_6: &str = "Physical dice and coins do not protect against malicious firmware that \
records your keystrokes or changes the program's execution. Use a \
machine whose firmware and physical environment you have reason to \
trust.";

/// Render the SPEC §6 dice/coins firmware warning as its own screen,
/// requiring acknowledgement before a dice/coins-using entropy mode
/// (`Combined` or `DiceOnly`) may be committed to.
pub fn render_dice_coins_firmware_warning(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line("DICE AND COINS DO NOT PROTECT AGAINST MALICIOUS FIRMWARE");
    out.write_line("");
    write_wrapped_prose(out, DICE_COINS_FIRMWARE_WARNING_6);
    out.write_line("");
    out.write_line("[Enter] I understand");
}

// ============================================================================
// SPEC §22.4 word-count selection
// ============================================================================

pub const WORD_COUNT_TITLE: &str = "Choose recovery-word length";
/// SPEC §22.4: "The interface MUST avoid presenting 12 words as
/// categorically unsafe" — neutral, purely descriptive wording, no
/// "less secure"/"not recommended" language attached to the 12-word
/// option.
pub const WORD_COUNT_OPTION_12: &str = "[1] 12 words -- 128 bits of generated entropy";
pub const WORD_COUNT_OPTION_24: &str = "[2] 24 words -- 256 bits of generated entropy";

/// Render the SPEC §22.4 word-count selection screen.
pub fn render_word_count_screen(out: &mut dyn TextOutput) {
    out.clear();
    out.write_line(WORD_COUNT_TITLE);
    out.write_line("");
    out.write_line(WORD_COUNT_OPTION_12);
    out.write_line(WORD_COUNT_OPTION_24);
    out.write_line("");
    out.write_line(BACK_PROMPT);
}

pub const ENTROPY_MODE_TITLE: &str = "Choose entropy method";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::MockTerminal;

    // ---- SPEC_DICE_COIN_VISUAL.md §7: wrap_words ----

    #[test]
    fn wrap_words_breaks_only_at_word_boundaries() {
        let out: std::vec::Vec<&str> = wrap_words("the quick brown fox", 10).collect();
        assert_eq!(out, std::vec!["the quick", "brown fox"]);
        // No line ever exceeds cols, and no word is split.
        for line in &out {
            assert!(line.len() <= 10);
        }
        assert_eq!(out.join(" "), "the quick brown fox");
    }

    #[test]
    fn wrap_words_hard_splits_an_over_long_single_token() {
        // A token longer than `cols` is the sole case that breaks inside a
        // token, at `cols`-cell offsets (§7 rule 3).
        let out: std::vec::Vec<&str> = wrap_words("abcdefghijklmno", 5).collect();
        assert_eq!(out, std::vec!["abcde", "fghij", "klmno"]);
    }

    #[test]
    fn wrap_words_collapses_space_runs_and_trims_edges() {
        let out: std::vec::Vec<&str> = wrap_words("  alpha   beta  ", 7).collect();
        assert_eq!(out, std::vec!["alpha", "beta"]);
    }

    #[test]
    fn wrap_words_short_text_is_returned_whole() {
        let out: std::vec::Vec<&str> = wrap_words("hello", 80).collect();
        assert_eq!(out, std::vec!["hello"]);
    }

    #[test]
    fn wrap_words_yields_borrowed_subslices_of_the_input() {
        // Presentation-only: the wrapper never allocates; each yielded
        // slice must point inside the original buffer (§7 minor m3).
        let text = "the quick brown fox";
        let base = text.as_ptr() as usize;
        for line in wrap_words(text, 10) {
            let p = line.as_ptr() as usize;
            assert!(p >= base && p < base + text.len(), "slice must be a view into the input");
        }
    }

    /// The SPEC §17.2 disclaimer wraps to EXACTLY the two fragments the
    /// physical-entry screen renders (SPEC_DICE_COIN_VISUAL.md §7/§8): line
    /// 1 is 79 cols ending "...dice or coins are fair or", line 2 is 32
    /// cols. Re-joining with a single space reproduces the verbatim const.
    #[test]
    fn wrap_words_splits_the_17_2_disclaimer_into_the_two_spec_fragments() {
        let out: std::vec::Vec<&str> = wrap_words(PHYSICAL_FAIRNESS_DISCLAIMER_17_2, 80).collect();
        assert_eq!(
            out,
            std::vec![
                "The number of rolls or flips does not prove that your dice or coins are fair or",
                "that the events are independent.",
            ]
        );
        assert_eq!(out[0].len(), 79);
        assert_eq!(out[1].len(), 32);
        assert_eq!(out.join(" "), PHYSICAL_FAIRNESS_DISCLAIMER_17_2);
    }

    // ---- verbatim-text regression tests (SPEC §8.4, §18.2, §18.3, §22.2) ----

    #[test]
    fn required_warning_8_4_is_verbatim() {
        assert_eq!(
            REQUIRED_WARNING_8_4,
            "Alea removes the normal operating system from the seed-generation \
process. It cannot prove that your firmware, processor, memory, input \
devices, display path or physical environment are trustworthy."
        );
    }

    #[test]
    fn machine_only_warning_18_2_is_verbatim() {
        assert_eq!(
            MACHINE_ONLY_WARNING_18_2,
            "You are trusting this machine's random-number hardware completely. You \
cannot witness or verify the quality of this entropy. If this hardware \
is faulty or malicious, the resulting wallet is unsafe, and nothing on \
this screen would look different."
        );
    }

    #[test]
    fn physical_only_warning_18_3_is_verbatim() {
        assert_eq!(
            PHYSICAL_ONLY_WARNING_18_3,
            "Security now depends entirely on the fairness and independence of your \
rolls and flips and on the integrity of this computer's firmware and \
execution."
        );
    }

    #[test]
    fn machine_health_check_disclaimer_16_is_verbatim() {
        assert_eq!(
            MACHINE_HEALTH_CHECK_DISCLAIMER_16,
            "These checks can detect some catastrophic failures. They do not prove \
that the source is unpredictable, correctly implemented or independent \
from another source."
        );
    }

    #[test]
    fn physical_fairness_disclaimer_17_2_is_verbatim() {
        assert_eq!(
            PHYSICAL_FAIRNESS_DISCLAIMER_17_2,
            "The number of rolls or flips does not prove that your dice or coins are \
fair or that the events are independent."
        );
    }

    #[test]
    fn dice_coins_firmware_warning_6_is_verbatim() {
        assert_eq!(
            DICE_COINS_FIRMWARE_WARNING_6,
            "Physical dice and coins do not protect against malicious firmware that \
records your keystrokes or changes the program's execution. Use a \
machine whose firmware and physical environment you have reason to \
trust."
        );
    }

    #[test]
    fn dice_coins_firmware_warning_mentions_keystrokes_and_execution() {
        // SPEC §6 distinguishes this warning from §18.3's by its specific
        // content: malicious firmware recording keystrokes or changing
        // execution, not merely the fairness of the physical randomness.
        assert!(DICE_COINS_FIRMWARE_WARNING_6.contains("records your keystrokes"));
        assert!(DICE_COINS_FIRMWARE_WARNING_6.contains("changes the program's execution"));
        assert!(!PHYSICAL_ONLY_WARNING_18_3.contains("keystrokes"));
    }

    #[test]
    fn ack_label_is_verbatim() {
        assert_eq!(
            ACK_LABEL,
            "These are your statements. Alea cannot verify them."
        );
    }

    #[test]
    fn all_three_ack_screens_carry_the_exact_label() {
        let mut term = MockTerminal::new();
        for (title, items) in ACK_SCREENS {
            render_ack_screen(&mut term, title, items);
        }
        let occurrences = term.lines.iter().filter(|l| l.as_str() == ACK_LABEL).count();
        assert_eq!(occurrences, 3, "every one of the three ack screens must show the exact label");
    }

    #[test]
    fn word_count_screen_never_calls_12_words_unsafe() {
        let mut term = MockTerminal::new();
        render_word_count_screen(&mut term);
        for line in &term.lines {
            let lower = line.to_lowercase();
            assert!(
                !lower.contains("unsafe") && !lower.contains("not recommended") && !lower.contains("weak"),
                "12-word option must not be presented as categorically unsafe: {line:?}"
            );
        }
    }

    #[test]
    fn opening_warning_offers_continue_and_escape() {
        let mut term = MockTerminal::new();
        render_opening_warning(&mut term);
        assert!(term.contains(OPENING_CONTINUE_PROMPT));
        assert!(term.contains(OPENING_ESCAPE_PROMPT));
    }

    #[test]
    fn required_warning_screen_renders_the_verbatim_text() {
        let mut term = MockTerminal::new();
        render_required_warning(&mut term);
        // The mandated paragraph is now word-wrapped for display, so it no
        // longer appears as one contiguous line — but its reflowed
        // fragments appear in order and re-join to the verbatim const.
        assert!(term.contains_wrapped(REQUIRED_WARNING_8_4, PROSE_WRAP_COLS));
    }

    // ---- FIX 1: pre-secret warning prose word-wraps to the column budget ----

    /// Assert the wrapped prose emitted by `render` fits the column budget,
    /// never splits a word mid-token, and reflows back to `prose` verbatim.
    fn assert_prose_screen_wraps(render: impl FnOnce(&mut dyn TextOutput), prose: &str) {
        let mut term = MockTerminal::new();
        render(&mut term);
        let frags: std::vec::Vec<&str> = wrap_words(prose, PROSE_WRAP_COLS).collect();
        // The wrapped fragments appear as consecutive rendered lines.
        assert!(
            term.contains_wrapped(prose, PROSE_WRAP_COLS),
            "wrapped prose fragments not found in order: {frags:?}"
        );
        // Every rendered line is within the column budget (no clip): the
        // warning screens carry no fixed-layout line wider than the budget.
        for line in &term.lines {
            assert!(
                line.chars().count() <= PROSE_WRAP_COLS,
                "line overflows the {PROSE_WRAP_COLS}-col budget ({} cols): {line:?}",
                line.chars().count()
            );
        }
        // No fragment splits a word: reflowing with single spaces
        // reproduces the original paragraph exactly (so every original word
        // survives whole across the wrapped lines).
        assert_eq!(frags.join(" "), prose, "wrapped fragments must reflow to the verbatim prose");
        for word in prose.split_whitespace() {
            assert!(
                frags.iter().any(|f| f.split_whitespace().any(|w| w == word)),
                "word {word:?} was split across wrapped lines"
            );
        }
    }

    #[test]
    fn required_warning_screen_prose_wraps_within_budget_without_midword_split() {
        assert_prose_screen_wraps(render_required_warning, REQUIRED_WARNING_8_4);
    }

    #[test]
    fn physical_only_warning_screen_prose_wraps_within_budget_without_midword_split() {
        assert_prose_screen_wraps(render_physical_only_warning, PHYSICAL_ONLY_WARNING_18_3);
    }

    #[test]
    fn dice_coins_firmware_warning_screen_prose_wraps_within_budget_without_midword_split() {
        assert_prose_screen_wraps(render_dice_coins_firmware_warning, DICE_COINS_FIRMWARE_WARNING_6);
    }

    /// A specific originally-long sentence from each warning reappears as
    /// whole words spread across the wrapped lines (the concrete symptom
    /// live rehearsal hit: mid-word clipping at the right edge).
    #[test]
    fn physical_only_warning_long_sentence_survives_as_whole_words() {
        let frags: std::vec::Vec<&str> = wrap_words(PHYSICAL_ONLY_WARNING_18_3, PROSE_WRAP_COLS).collect();
        // Was one 130-col line; now more than one line, none over budget.
        assert!(frags.len() >= 2, "long prose must wrap onto multiple lines");
        // The clipped-mid-word phrase from the screenshot survives whole.
        assert!(frags.iter().any(|f| f.contains("integrity")));
        assert_eq!(frags.join(" "), PHYSICAL_ONLY_WARNING_18_3);
    }

    // ---- SPEC.md §11.5 amendment: keyboard self-test offer/skip ----

    #[test]
    fn keyboard_self_test_offer_screen_shows_start_and_skip() {
        let mut term = MockTerminal::new();
        render_keyboard_self_test_offer_screen(&mut term, false);
        assert!(term.contains(KEYBOARD_SELF_TEST_START_PROMPT));
        assert!(term.contains(KEYBOARD_SELF_TEST_SKIP_PROMPT));
        assert!(!term.contains(KEYBOARD_SELF_TEST_START_RECOMMENDED_PROMPT));
    }

    #[test]
    fn keyboard_self_test_offer_screen_recommended_wording_when_asked() {
        let mut term = MockTerminal::new();
        render_keyboard_self_test_offer_screen(&mut term, true);
        assert!(term.contains(KEYBOARD_SELF_TEST_START_RECOMMENDED_PROMPT));
        assert!(term.contains(KEYBOARD_SELF_TEST_SKIP_PROMPT));
    }

    /// The mandated substance (SPEC.md §11.5 amendment): skipping means an
    /// unsuitable layout only surfaces during hidden re-entry, where
    /// words are not shown.
    #[test]
    fn keyboard_self_test_skip_warning_conveys_hidden_reentry_consequence() {
        assert!(KEYBOARD_SELF_TEST_SKIP_WARNING_11_5.contains("hidden re-entry"));
        assert!(KEYBOARD_SELF_TEST_SKIP_WARNING_11_5.contains("not shown"));
        assert!(KEYBOARD_SELF_TEST_SKIP_WARNING_11_5.to_lowercase().contains("skip"));
    }

    #[test]
    fn keyboard_self_test_skip_acknowledgement_screen_renders_the_warning_and_both_prompts() {
        let mut term = MockTerminal::new();
        render_keyboard_self_test_skip_acknowledgement(&mut term);
        assert!(term.contains(KEYBOARD_SELF_TEST_SKIP_WARNING_11_5));
        assert!(term.contains(KEYBOARD_SELF_TEST_SKIP_ACK_PROMPT));
        assert!(term.contains(KEYBOARD_SELF_TEST_SKIP_BACK_PROMPT));
    }

    #[test]
    fn machine_only_screen_renders_the_verbatim_text() {
        let mut term = MockTerminal::new();
        render_machine_only_warning(&mut term, None);
        // Word-wrapped for display like the other three warning screens; the
        // reflowed fragments appear in order and re-join to the verbatim const.
        assert!(term.contains_wrapped(MACHINE_ONLY_WARNING_18_2, PROSE_WRAP_COLS));
    }

    #[test]
    fn machine_only_warning_screen_prose_wraps_within_budget_without_midword_split() {
        assert_prose_screen_wraps(
            |o| render_machine_only_warning(o, None),
            MACHINE_ONLY_WARNING_18_2,
        );
    }

    /// SPEC §18.2: "The user must see: source class; algorithm
    /// identifier; CPU and microcode policy result where relevant;
    /// policy version" — all four items must be present (in addition to
    /// the fixed warning text) when a real disclosure is supplied.
    #[test]
    fn machine_only_screen_renders_the_spec_18_2_disclosure_when_present() {
        let mut term = MockTerminal::new();
        let disclosure = MachineOnlyDisclosure {
            source_class: "RDSEED64",
            algorithm_identifier: seed_protocol::policy::AlgoId::from_str("RDSEED (CPU instruction)").unwrap(),
            cpu_microcode_result: Some(true),
            policy_version: 7,
        };
        render_machine_only_warning(&mut term, Some(&disclosure));
        assert!(term.contains("RDSEED64"));
        assert!(term.contains("RDSEED (CPU instruction)"));
        assert!(term.contains("allowed"));
        assert!(term.contains("7"));
        assert!(term.contains_wrapped(MACHINE_ONLY_WARNING_18_2, PROSE_WRAP_COLS));
    }

    #[test]
    fn physical_only_screen_renders_the_verbatim_text() {
        let mut term = MockTerminal::new();
        render_physical_only_warning(&mut term);
        assert!(term.contains_wrapped(PHYSICAL_ONLY_WARNING_18_3, PROSE_WRAP_COLS));
    }

    #[test]
    fn dice_coins_firmware_warning_screen_renders_the_verbatim_text() {
        let mut term = MockTerminal::new();
        render_dice_coins_firmware_warning(&mut term);
        assert!(term.contains_wrapped(DICE_COINS_FIRMWARE_WARNING_6, PROSE_WRAP_COLS));
    }

}

