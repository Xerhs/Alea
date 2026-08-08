//! Cross-device VERIFICATION flow (SPEC_COMPAT.md "Method A" +
//! SPEC_COMPAT_ENTROPY.md "Method C"), ported from
//! `seed-desktop-test/src/launcher/compat.rs` to this no_std + alloc,
//! GOP-rendered UEFI edition.
//!
//! # What is reused vs. what changed
//!
//! Every digest / word-count / refusal decision is `seed_compat`'s job and
//! is NEVER reimplemented here: Method A goes through
//! [`seed_compat::compat_derive`], Method C through
//! [`seed_compat::entropy_encoding::entropy_encoding_derive`]. The SPEC
//! §24.2 verification values (master fingerprint + BIP44/49/84/86
//! first-receive addresses) are computed via `seed_core`/`seed_derive`
//! from the reproduced mnemonic, exactly mirroring the desktop launcher's
//! own `finish`/`finish_entropy` split.
//!
//! The desktop version's differences, adapted here:
//! - Rendering goes through [`seed_flow::output::TextOutput`] (an
//!   `FbTextOutput` over the session GOP), not the desktop
//!   `WindowTextOutput`.
//! - The key type is [`seed_platform_x86::input::InputEvent`] (via the
//!   firmware `FirmwareKeySource`), and input is **number-key + Esc only**
//!   (SPEC_MAIN_MENU.md §17.2) — the desktop launcher's Up/Down arrow
//!   navigation is deliberately dropped; menu selection is by digit.
//! - `String`/`Vec`/`format!` come from `alloc` (this crate has a global
//!   allocator), not `std`.
//!
//! Every screen carries the SPEC_COMPAT §7/§8 permanent banners verbatim so
//! the "this is NOT an Alea seed / public-throwaway only" framing is
//! unmissable.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use seed_compat::entropy_encoding::{
    entropy_encoding_derive, Encoding, EntropyEncodingError, EntropyEncodingOutput, METHOD_ID,
};
use seed_compat::{
    compat_derive, CompatError, CompatOutput, CompatProfile, EventAlphabet,
    WordCount as CompatWordCount, WordCountRule,
};
use seed_core::contracts::{AddressBuf, PathStandard, WordCount as CoreWordCount};
use seed_flow::output::TextOutput;
use seed_platform_x86::input::InputEvent as Key;
use zeroize::Zeroize;

use crate::custom_path;

// ============================================================================
// SPEC_COMPAT §7/§8 fixed banner text (verbatim — do not reword)
// ============================================================================

/// SPEC_COMPAT §8, line 1 of the permanent, non-removable mode banner.
pub(crate) const MODE_BANNER_LINE_1: &str =
    "COMPATIBILITY / VERIFICATION MODE -- reproduces another vendor's method --";
/// SPEC_COMPAT §8, line 2.
pub(crate) const MODE_BANNER_LINE_2: &str =
    "NOT Alea generation -- public/throwaway seeds only";
/// SPEC_COMPAT §7's result-screen watermark line, verbatim.
pub(crate) const RESULT_WATERMARK: &str =
    "[COMPATIBILITY / VERIFICATION -- NOT AN ALEA SEED -- PUBLIC/THROWAWAY]";
/// SPEC_COMPAT §8: the mnemonic-prefix warning (SPEC §4.2 wording reused).
const PUBLIC_TEST_PHRASE_PREFIX: &str = "PUBLIC TEST PHRASE -- NEVER USE WITH FUNDS";
/// Method C result-screen foreign-material watermark (SPEC_COMPAT_ENTROPY
/// §2/§9).
const FOREIGN_WATERMARK: &str =
    "REPRODUCTION OF FOREIGN MATERIAL -- NEVER AN ALEA SEED -- NEVER USE WITH FUNDS";

/// SPEC_COMPAT_ENTROPY §2 item 4 / §9 honesty caveat, shown at entry AND on
/// the result screen.
const ENTROPY_HONESTY_CAVEAT: [&str; 4] = [
    "Typed entropy is only as strong as the randomness of whatever produced it --",
    "this tool cannot witness that randomness. Use it to CONFIRM a seed another",
    "tool made from the same symbols, never to CREATE one you will fund.",
    "For real seeds, use Alea's witnessed dice/coin/machine generation.",
];

fn render_common_banner(out: &mut dyn TextOutput) {
    out.write_line(MODE_BANNER_LINE_1);
    out.write_line(MODE_BANNER_LINE_2);
    out.write_line(RESULT_WATERMARK);
    out.write_line("");
}

// ============================================================================
// The three user-facing profiles (SPEC_COMPAT §5.1.4/§7: `iancoleman-hex`
// is an internal digest oracle only and is never offered here)
// ============================================================================

const PROFILE_IDS: [&str; 3] = ["coldcard-dice", "seedsigner-dice", "seedsigner-coin"];

fn user_profiles() -> [&'static CompatProfile; 3] {
    PROFILE_IDS.map(|id| seed_compat::profile(id).expect("missing user-facing compat profile"))
}

fn profile_menu_label(id: &str) -> &'static str {
    match id {
        "coldcard-dice" => "COLDCARD -- dice (SHA256 of rolls; you pick 12 or 24 words)",
        "seedsigner-dice" => "SeedSigner -- dice (SHA256 of rolls; 50 rolls = 12 words, 99 = 24 words)",
        "seedsigner-coin" => "SeedSigner -- coin flips (SHA256 of flips; 128 = 12 words, 256 = 24 words)",
        _ => "unknown profile",
    }
}

fn event_noun(profile: &CompatProfile) -> &'static str {
    match profile.alphabet {
        EventAlphabet::Dice1to6 => "rolls",
        EventAlphabet::Coin01 => "flips",
    }
}

fn singular(noun: &str) -> &'static str {
    match noun {
        "rolls" => "roll",
        "flips" => "flip",
        _ => "event",
    }
}

/// Live-typing UX filter only; the authoritative alphabet check happens
/// inside `seed_compat::compat_derive` on submit.
fn alphabet_allows(alphabet: EventAlphabet, c: char) -> bool {
    match alphabet {
        EventAlphabet::Dice1to6 => ('1'..='6').contains(&c),
        EventAlphabet::Coin01 => c == '0' || c == '1',
    }
}

fn alphabet_hint(alphabet: EventAlphabet) -> &'static str {
    match alphabet {
        EventAlphabet::Dice1to6 => {
            "Digits 1-6 only, one key per roll (6 is hashed as-is, never remapped to 0)."
        }
        EventAlphabet::Coin01 => "Digits 0/1 only, one key per flip.",
    }
}

fn compat_word_count_n(w: CompatWordCount) -> u16 {
    match w {
        CompatWordCount::W12 => 12,
        CompatWordCount::W24 => 24,
    }
}

/// The profile menu's total row count: three dice/coin (Method A) profiles
/// plus the one synthetic entropy-encoding (Method C) row.
fn profile_menu_len(profiles: &[&'static CompatProfile; 3]) -> usize {
    profiles.len() + 1
}

/// Index of the synthetic entropy-encoding (Method C) row.
fn entropy_menu_index(profiles: &[&'static CompatProfile; 3]) -> usize {
    profiles.len()
}

// ============================================================================
// Hex helper (alloc)
// ============================================================================

fn bytes_to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Pre-sized capacity for the event-entry buffer (exceeds the largest
/// canonical event count, 256 coin flips) so a valid run never reallocates,
/// keeping [`scrub_string`]'s single-allocation wipe complete.
const EVENT_BUFFER_CAP: usize = 512;

/// Best-effort in-place scrub of a growable `String` holding the typed
/// dice/coin event pre-image. Volatile zero writes behind a compiler fence,
/// then clear. Defense-in-depth on this public/throwaway surface.
fn scrub_string(s: &mut String) {
    // SAFETY: NUL is valid UTF-8, so the buffer stays well-formed for the
    // `clear()` below; we drop all of it immediately regardless.
    let bytes = unsafe { s.as_mut_vec() };
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    s.clear();
}

// ============================================================================
// Profile menu (number-key + Esc, SPEC_MAIN_MENU.md §17.2 — no arrows)
// ============================================================================

fn render_profile_menu(out: &mut dyn TextOutput, profiles: &[&'static CompatProfile; 3]) {
    out.clear();
    render_common_banner(out);
    out.write_line("COMPATIBILITY VERIFICATION -- audit another wallet's dice/coin math");
    out.write_line("This does NOT generate an Alea seed. Test/throwaway seeds only.");
    out.write_line("");
    out.write_line("Choose the device and method to reproduce:");
    for (i, p) in profiles.iter().enumerate() {
        out.write_line(&format!("  [{}] {}", i + 1, profile_menu_label(p.id)));
    }
    let entropy_idx = entropy_menu_index(profiles);
    out.write_line(&format!(
        "  [{}] Entropy encodings (iancoleman-style raw entropy)",
        entropy_idx + 1
    ));
    out.write_line("");
    out.write_line("[1-4] select   [Esc] back to main menu");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileNav {
    Activate(usize),
    Quit,
    None,
}

/// Number-key + Esc only (SPEC_MAIN_MENU.md §17.2). No arrow navigation.
fn handle_profile_key(len: usize, key: Key) -> ProfileNav {
    match key {
        Key::Char(c) => match c.to_digit(10) {
            Some(d) if d >= 1 && (d as usize) <= len => ProfileNav::Activate(d as usize - 1),
            _ => ProfileNav::None,
        },
        Key::Escape => ProfileNav::Quit,
        _ => ProfileNav::None,
    }
}

// ============================================================================
// Event-string entry screen (SPEC_COMPAT §7: the algorithm description
// (one compact line) and the source citation — formerly a separate
// "method" interstitial screen — are now rendered as a persistent header
// block at the top of THIS screen, above the input line, so they stay
// visible the whole time the user is typing, per the ceremony UX redesign
// §5 "merge interstitial method screens into their entry screens".
//
// # Review fix (Task 19): the header does NOT also carry the full
// word-count-rule breakdown and caveats list
//
// An earlier version of this merge put the FULL method screen (up to 12
// lines: the multi-line word-count-rule match block, the source line, a
// "Caveats:" heading, and every one of a profile's caveat lines) directly
// above the input line. For `coldcard-dice` (4 caveats, `FreeChoice` rule)
// that pushed the input echo line ("  {buffer}_") to row 24 and the count
// feedback to row 26 -- both already past `MAX_LINES_AT_FLOOR` (23) at the
// SPEC §11.4 800x600 floor, so the user could not see what they had typed
// while entering a security-relevant verification input. `FbTextOutput`/
// `draw_text` clip silently rather than scroll or panic, so this was a
// silent usability bug, not a crash.
//
// The fix follows SPEC.md's 2026-08-06 §22.5a amendment (pagination for
// content that does not fit the floor as one screen): the persistent
// header here is compressed to the three essentials the original
// requirement actually named -- "algorithm+citation visible while
// typing" -- via [`compact_method_line`] (one line) and the `Source:`
// line, with a `[?]` key that opens [`render_method_detail`] (the FULL
// former method-screen content: complete word-count-rule breakdown +
// every caveat, verbatim, nothing dropped) as an on-demand detail page.
// [`tests::event_entry_worst_case_fits_the_800x600_floor_with_room_for_echo_and_count`]
// pins the fixed shape (banner + compact header + entry UI, independent
// of profile/caveat count) at a small, fixed line budget so the echo and
// count rows are ALWAYS visible regardless of how many caveats a future
// profile carries; [`render_method_detail`]'s own line count is checked
// separately per profile ([`tests::method_detail_worst_case_profile_fits_the_800x600_floor`]).
// ============================================================================

/// One-line algorithm summary for the persistent entry-screen header
/// (SPEC_COMPAT §7's "the DOCUMENTED math" framing, compressed to a
/// single row) -- the full multi-line breakdown lives in
/// [`render_method_detail`], reachable via `[?]`.
fn compact_method_line(profile: &CompatProfile) -> String {
    let noun = event_noun(profile);
    match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => format!(
            "Method: SHA256(ASCII of your {}) -> BIP39; {len12} {noun}=12w, {len24} {noun}=24w",
            singular(noun)
        ),
        WordCountRule::FreeChoice { .. } => format!(
            "Method: SHA256(ASCII of your {}) -> BIP39; you choose 12w/24w",
            singular(noun)
        ),
    }
}

/// The compact, ALWAYS-visible entry-screen header: banner + emulating +
/// one-line method summary + source citation ("algorithm+citation visible
/// while typing", the original requirement) -- fixed at 4 lines
/// regardless of profile, so [`render_event_entry`]'s total line count
/// never depends on a profile's caveat count. Shared with
/// [`render_word_count_choice`]/[`render_refusal`]'s own callers is NOT
/// this function's job (they render their own, unrelated screens); this
/// is entry-screen-only.
fn render_event_entry_header(out: &mut dyn TextOutput, profile: &CompatProfile) {
    render_common_banner(out);
    out.write_line(&format!("Emulating: {}", profile.display_name));
    out.write_line(&compact_method_line(profile));
    out.write_line(&format!("Source:    {}", profile.source_url));
}

fn render_event_entry(out: &mut dyn TextOutput, profile: &CompatProfile, buffer: &str) {
    out.clear();
    render_event_entry_header(out, profile);
    out.write_line("");
    let noun = event_noun(profile);
    out.write_line(&format!("Enter your {noun} for {}", profile.display_name));
    out.write_line(alphabet_hint(profile.alphabet));
    out.write_line("");
    out.write_line(&format!("  {buffer}_"));
    out.write_line("");
    out.write_line(&format!("{} {noun} entered so far.", buffer.chars().count()));
    out.write_line("");
    out.write_line("Backspace undo   Enter continue   [?] Full method & caveats   Esc back to profile list");
}

/// The full method detail: complete word-count-rule breakdown + every
/// caveat, verbatim -- the content [`render_event_entry`]'s header used
/// to carry directly, now an on-demand `[?]` screen (SPEC.md §22.5a
/// pagination) instead of always-drawn, so the entry screen's input echo
/// and count feedback are never pushed off the 800x600 floor by however
/// many caveats a profile happens to have.
fn render_method_detail(out: &mut dyn TextOutput, profile: &CompatProfile) {
    out.clear();
    render_event_entry_header(out, profile);
    out.write_line("");
    let noun = event_noun(profile);
    match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => {
            out.write_line(&format!(
                "Method:    entropy = SHA256( ASCII of your {} digits )",
                singular(noun)
            ));
            out.write_line(&format!(
                "           WORD COUNT IS SET BY THE NUMBER OF {}:",
                noun.to_uppercase()
            ));
            out.write_line(&format!(
                "             exactly {len12} {noun} -> 12 words (first 16 bytes of the digest)"
            ));
            out.write_line(&format!(
                "             exactly {len24} {noun} -> 24 words (full digest)"
            ));
            out.write_line(&format!(
                "             any other count  -> your {} REFUSES it, and so does this",
                profile.vendor
            ));
            out.write_line("           then standard BIP39 (SPEC §14)");
        }
        WordCountRule::FreeChoice {
            advisory_min_12,
            advisory_min_24,
        } => {
            out.write_line(&format!(
                "Method:    entropy = SHA256( ASCII of your {} digits )",
                singular(noun)
            ));
            out.write_line(&format!(
                "           YOU CHOOSE THE WORD COUNT ({} runs a separate script for each):",
                profile.vendor
            ));
            out.write_line("             12 words -> first 16 bytes of the digest");
            out.write_line("             24 words -> full digest");
            out.write_line(&format!(
                "             {advisory_min_12}/{advisory_min_24} {noun} are advisory minimums only, not enforced"
            ));
            out.write_line("           then standard BIP39 (SPEC §14)");
        }
    }
    out.write_line("Caveats:");
    for c in profile.caveats {
        out.write_line(&format!("  - {c}"));
    }
    out.write_line("");
    out.write_line("This proves the DOCUMENTED math, not that your device's firmware is honest.");
    out.write_line("");
    out.write_line("Press any key to return.");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    Submit,
    Cancel,
    /// `[?]` was pressed: show the full method detail
    /// ([`render_method_detail`]/[`render_encoding_method_detail`]), then
    /// return to this same entry screen with `buffer` untouched.
    ShowDetail,
    None,
}

fn handle_entry_key(profile: &CompatProfile, buffer: &mut String, key: Key) -> EntryAction {
    match key {
        // '?' is never a valid dice ('1'-'6') or coin ('0'/'1') digit, so
        // this never shadows a real event keystroke.
        Key::Char('?') => EntryAction::ShowDetail,
        Key::Char(c) if alphabet_allows(profile.alphabet, c) => {
            buffer.push(c);
            EntryAction::None
        }
        Key::Backspace => {
            buffer.pop();
            EntryAction::None
        }
        Key::Enter if !buffer.is_empty() => EntryAction::Submit,
        Key::Escape => EntryAction::Cancel,
        _ => EntryAction::None,
    }
}

// ============================================================================
// Word-count choice screen (FreeChoice profiles only, e.g. coldcard-dice)
// ============================================================================

fn render_word_count_choice(out: &mut dyn TextOutput, profile: &CompatProfile, events: &str) {
    out.clear();
    render_common_banner(out);
    out.write_line(&format!(
        "{} lets you choose the word count -- it is NOT derived",
        profile.vendor
    ));
    out.write_line(&format!(
        "from the {} count ({} entered).",
        event_noun(profile),
        events.chars().count()
    ));
    out.write_line("");
    out.write_line("[1] 12 words -- first 16 bytes of the digest");
    out.write_line("[2] 24 words -- full digest");
    out.write_line("");
    out.write_line("Esc back to event entry");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordCountAction {
    Chosen(CompatWordCount),
    Cancel,
    None,
}

fn handle_word_count_key(key: Key) -> WordCountAction {
    match key {
        Key::Char('1') => WordCountAction::Chosen(CompatWordCount::W12),
        Key::Char('2') => WordCountAction::Chosen(CompatWordCount::W24),
        Key::Escape => WordCountAction::Cancel,
        _ => WordCountAction::None,
    }
}

// ============================================================================
// Refusal screen (SPEC_COMPAT §7, review F1/F5) — never paired with a phrase
// ============================================================================

fn render_refusal(
    out: &mut dyn TextOutput,
    profile: &CompatProfile,
    entered: u16,
    requested_words: Option<u16>,
) {
    out.clear();
    render_common_banner(out);
    let noun = event_noun(profile);
    let (len12, len24) = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => (len12, len24),
        WordCountRule::FreeChoice { .. } => {
            out.write_line(&format!(
                "REFUSED: {} requires you to choose 12 or 24 words explicitly.",
                profile.display_name
            ));
            out.write_line(
                "This profile's word count is a free choice, not derived from the event count.",
            );
            out.write_line(
                "(This tool refuses the same ambiguity the device's own scripts require you to resolve.)",
            );
            out.write_line("");
            out.write_line("Press any key to return to the profile list.");
            return;
        }
    };
    match requested_words {
        Some(w) => out.write_line(&format!(
            "REFUSED: {entered} {noun} cannot produce {w} words on {}.",
            profile.vendor
        )),
        None => out.write_line(&format!(
            "REFUSED: {entered} {noun} is not a canonical {} count for {}.",
            singular(noun),
            profile.vendor
        )),
    }
    out.write_line(&format!(
        "{} sets word count from the {} count: {len12} -> 12 words, {len24} -> 24 words,",
        profile.vendor,
        singular(noun)
    ));
    out.write_line(&format!(
        "and it refuses any other number of {noun}. Enter exactly {len12} or {len24} {noun}."
    ));
    out.write_line("(This tool refuses the same inputs the device refuses, on purpose.)");
    out.write_line("");
    out.write_line("Press any key to return to the profile list.");
}

/// Defensive fallback for structurally-unreachable
/// `BadAlphabet`/`Empty` (every keystroke is alphabet-filtered before it
/// reaches the buffer, and submission requires a non-empty buffer).
fn render_unexpected_refusal(out: &mut dyn TextOutput) {
    out.clear();
    render_common_banner(out);
    out.write_line("REFUSED: this event string could not be processed.");
    out.write_line("");
    out.write_line("Press any key to return to the profile list.");
}

// ============================================================================
// Result (success) screen (SPEC_COMPAT §7/§8)
// ============================================================================

struct RenderedAddress {
    label: &'static str,
    address: String,
}

struct Success {
    word_count: CompatWordCount,
    words: Vec<&'static str>,
    used_len: u16,
    entropy: [u8; 32],
    entropy_len: usize,
    master_fingerprint: [u8; 4],
    addresses: [RenderedAddress; 4],
}

impl Success {
    fn word_count_n(&self) -> usize {
        match self.word_count {
            CompatWordCount::W12 => 12,
            CompatWordCount::W24 => 24,
        }
    }

    fn entropy_hex(&self) -> String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    fn master_fingerprint_hex(&self) -> String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

impl Drop for Success {
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

/// Walks the SPEC §24.2 derivation chain over the mnemonic
/// `compat_derive` produced (mirrors
/// `tools/compat-verify/src/derive.rs::finish`). Recomputes the digest
/// independently only to recover the raw entropy bytes for the optional
/// `[E]` toggle — `seed_compat` deliberately does not expose them.
fn finish(events: &str, out: CompatOutput) -> Success {
    let digest = seed_core::hash::sha256(events.as_bytes());
    let entropy_len = match out.word_count {
        CompatWordCount::W12 => 16,
        CompatWordCount::W24 => 32,
    };
    let mut entropy = [0u8; 32];
    entropy[..entropy_len].copy_from_slice(&digest[..entropy_len]);

    let core_count = match out.word_count {
        CompatWordCount::W12 => CoreWordCount::Twelve,
        CompatWordCount::W24 => CoreWordCount::TwentyFour,
    };
    let n = match out.word_count {
        CompatWordCount::W12 => 12,
        CompatWordCount::W24 => 24,
    };
    let mut words = Vec::with_capacity(n);
    for idx in &out.mnemonic_indexes[..n] {
        words.push(seed_core::bip39::word(*idx));
    }

    let mut seed = [0u8; 64];
    seed_core::bip39::mnemonic_to_seed(&out.mnemonic_indexes, core_count, &mut seed);

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    seed_derive::bip32::master_from_seed(&seed, &mut key, &mut cc);
    let master_fingerprint = seed_derive::bip32::master_fingerprint(&key);
    key.zeroize();
    cc.zeroize();

    let standards: [(&'static str, PathStandard); 4] = [
        ("BIP44", PathStandard::Bip44),
        ("BIP49", PathStandard::Bip49),
        ("BIP84", PathStandard::Bip84),
        ("BIP86", PathStandard::Bip86),
    ];
    let addresses = standards.map(|(label, standard)| {
        let mut buf = AddressBuf::empty();
        seed_derive::address::first_address(&seed, standard, &mut buf)
            .expect("SPEC §24.2 fixed paths do not fail on a valid BIP39 seed");
        RenderedAddress {
            label,
            address: buf.as_str().unwrap_or("").to_string(),
        }
    });

    seed.zeroize();

    Success {
        word_count: out.word_count,
        words,
        used_len: out.used_len,
        entropy,
        entropy_len,
        master_fingerprint,
        addresses,
    }
}

fn render_result_success(
    out: &mut dyn TextOutput,
    profile: &CompatProfile,
    success: &Success,
    events: &str,
    show_entropy: bool,
) {
    out.clear();
    render_common_banner(out);
    let n = success.word_count_n();
    let noun = event_noun(profile);

    out.write_line(&format!(
        "Device/method:  {} (SHA256 of {})",
        profile.display_name, noun
    ));
    out.write_line(&format!(
        "Events entered: {events}   ({} {noun})",
        success.used_len
    ));
    let word_count_line = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { .. } => {
            format!("Word count:     {n} (derived from {} {noun})", success.used_len)
        }
        WordCountRule::FreeChoice { .. } => format!("Word count:     {n} (your choice)"),
    };
    out.write_line(&word_count_line);
    out.write_line("");

    out.write_line(PUBLIC_TEST_PHRASE_PREFIX);
    out.write_line(&format!("Mnemonic ({n} words):"));
    let mut line = String::new();
    for (i, w) in success.words.iter().enumerate() {
        line.push_str(&format!("{:02} {:<12}", i + 1, w));
        if i % 6 == 5 || i + 1 == success.words.len() {
            out.write_line(line.trim_end());
            line.clear();
        }
    }
    out.write_line("");

    out.write_line("Verification values (empty passphrase; SPEC §24):");
    out.write_line(&format!(
        "  Master fingerprint  {}",
        success.master_fingerprint_hex()
    ));
    let mut addr_line = String::new();
    for a in &success.addresses {
        addr_line.push_str(&format!("{} {}   ", a.label, a.address));
    }
    out.write_line(&format!("  {}", addr_line.trim_end()));
    out.write_line("");

    if show_entropy {
        out.write_line(&format!(
            "Entropy hex ({} bytes): {}",
            success.entropy_len,
            success.entropy_hex()
        ));
        out.write_line(
            "(Preimage is SHA256 over the ASCII string above. This is a PUBLIC test value.)",
        );
    } else {
        out.write_line("(Preimage is SHA256 over the ASCII string above. Entropy hex is a PUBLIC test");
        out.write_line(" value, shown only on explicit request: press [E].)");
    }
    out.write_line("");

    out.write_line(&format!(
        "This equals what {}'s PUBLISHED algorithm produces for these events.",
        profile.vendor
    ));
    out.write_line(&format!(
        "If your {} shows the same words, its math matched for THIS input.",
        profile.vendor
    ));
    out.write_line("It does NOT prove the device's firmware, secure element, or RNG are honest.");
    out.write_line("");
    out.write_line(
        "[E] Show/hide entropy hex   [P] Custom derivation path (free-form)   Any other key returns",
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultAction {
    ToggleEntropy,
    CustomPath,
    Back,
}

fn handle_result_key(key: Key) -> ResultAction {
    match key {
        Key::Char(c) if c.eq_ignore_ascii_case(&'e') => ResultAction::ToggleEntropy,
        Key::Char(c) if c.eq_ignore_ascii_case(&'p') => ResultAction::CustomPath,
        _ => ResultAction::Back,
    }
}

// ============================================================================
// Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md)
// ============================================================================

fn render_encoding_menu(out: &mut dyn TextOutput) {
    out.clear();
    render_common_banner(out);
    out.write_line("ENTROPY ENCODINGS -- reproduce iancoleman/bip39 RAW-entropy words");
    out.write_line("This does NOT generate an Alea seed. Test/throwaway seeds only.");
    out.write_line("");
    for line in ENTROPY_HONESTY_CAVEAT {
        out.write_line(line);
    }
    out.write_line("");
    out.write_line("Choose the entropy encoding your other tool used (explicit -- no autodetect):");
    for (i, e) in Encoding::ALL.iter().enumerate() {
        out.write_line(&format!("  [{}] {}", i + 1, e.display_name()));
    }
    out.write_line("");
    out.write_line("Only 128-bit (12-word) or 256-bit (24-word) retained entropy is verified.");
    out.write_line("[1-6] select   [Esc] back to profile list");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingNav {
    Activate(usize),
    Quit,
    None,
}

fn handle_encoding_key(len: usize, key: Key) -> EncodingNav {
    match key {
        Key::Char(c) => match c.to_digit(10) {
            Some(d) if d >= 1 && (d as usize) <= len => EncodingNav::Activate(d as usize - 1),
            _ => EncodingNav::None,
        },
        Key::Escape => EncodingNav::Quit,
        _ => EncodingNav::None,
    }
}

fn encoding_rule(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Binary => "each 0/1 -> 1 bit",
        Encoding::Base6 => "0->00 1->01 2->10 3->11 4->0 5->1 (bias-corrected, variable width)",
        Encoding::Dice => "face 6 -> 0, then 1->01 2->10 3->11 4->0 5->1 6->00 (variable width)",
        Encoding::Base10 => "0..7 -> 3-bit 000..111, 8->0, 9->1 (variable width)",
        Encoding::Hex => "each 0-9A-F -> its 4-bit nibble",
        Encoding::Cards => {
            "per-card table, suits C,D,H,S; first 32 cards 5-bit, next 16 4-bit, last 4 2-bit"
        }
    }
}

/// The compact, ALWAYS-visible encoding entry-screen header: banner +
/// reproducing line + one-line rule + source citation
/// ("algorithm+citation visible while typing") -- fixed at 4 lines
/// regardless of encoding (the `Cards`-only two-line addendum that used to
/// live here moved into [`render_encoding_method_detail`]), review fix
/// mirroring [`render_event_entry_header`]'s own rationale (see that
/// function's module-section doc comment above [`render_event_entry`]):
/// the FULL method breakdown pushed the input echo line to row 26 for the
/// `Cards` encoding (30 total lines) — well past `MAX_LINES_AT_FLOOR`
/// (23) — so it is now a `[?]` on-demand detail page instead of always
/// drawn.
fn render_encoding_entry_header(out: &mut dyn TextOutput, encoding: Encoding) {
    render_common_banner(out);
    out.write_line(&format!(
        "Reproducing: iancoleman/bip39 RAW entropy -- {}",
        encoding.display_name()
    ));
    out.write_line(&format!("Method ({METHOD_ID}): {}", encoding_rule(encoding)));
    out.write_line("Source:    github.com/iancoleman/bip39 src/js/entropy.js (eventBits) + index.js");
}

fn render_encoding_entry(out: &mut dyn TextOutput, encoding: Encoding, buffer: &str) {
    out.clear();
    render_encoding_entry_header(out, encoding);
    out.write_line("");
    out.write_line(&format!(
        "Enter the {} symbols your other tool used",
        encoding.display_name()
    ));
    out.write_line(&format!("Rule: {}", encoding_rule(encoding)));
    out.write_line("Full keyboard. Characters outside this encoding are ignored (as iancoleman does).");
    out.write_line("");
    out.write_line(&format!("  {buffer}_"));
    out.write_line("");
    out.write_line(&format!("{} character(s) entered so far.", buffer.chars().count()));
    out.write_line("");
    out.write_line("Backspace undo   Enter continue   [?] Full method & honesty note   Esc back to encoding list");
}

/// The full Method-C detail: the complete symbols-to-bits breakdown
/// (including the `Cards` with/without-replacement addendum), source
/// citation, and the SPEC_COMPAT_ENTROPY honesty caveat, verbatim — the
/// content [`render_encoding_entry`]'s header used to carry directly, now
/// an on-demand `[?]` screen (SPEC.md §22.5a pagination) instead of
/// always-drawn.
fn render_encoding_method_detail(out: &mut dyn TextOutput, encoding: Encoding) {
    out.clear();
    render_encoding_entry_header(out, encoding);
    out.write_line("");
    out.write_line("           concatenate all symbol bits (per-symbol table lookup, NOT base conversion)");
    out.write_line("           retain the LAST floor(bits/32)*32 bits (leading excess discarded)");
    out.write_line("           NO SHA-256 on the bits (the hashed / non-'raw' branch is Method A)");
    out.write_line("           128 retained bits -> 12 words, 256 -> 24 words; anything else is REFUSED");
    out.write_line("           then standard BIP39 (SPEC §14), PBKDF2-2048, empty passphrase");
    if encoding == Encoding::Cards {
        out.write_line("Cards:     with/without replacement does not change the bits; duplicate");
        out.write_line("           cards contribute their bits again.");
    }
    out.write_line("");
    for line in ENTROPY_HONESTY_CAVEAT {
        out.write_line(line);
    }
    out.write_line("");
    out.write_line("Press any key to return.");
}

/// Accepts every typed character (full keyboard); the encoding match is the
/// derive call's job (SPEC_COMPAT_ENTROPY §5.1/§9). `'?'` is intercepted
/// for [`EntryAction::ShowDetail`] rather than pushed to the buffer: no
/// encoding's alphabet uses `?` as a meaningful symbol, so a typed `?`
/// would already have been silently ignored by
/// `entropy_encoding_derive` (counted in `ignored_chars`) — reserving it
/// costs no real input.
fn handle_encoding_entry_key(buffer: &mut String, key: Key) -> EntryAction {
    match key {
        Key::Char('?') => EntryAction::ShowDetail,
        Key::Char(c) => {
            buffer.push(c);
            EntryAction::None
        }
        Key::Backspace => {
            buffer.pop();
            EntryAction::None
        }
        Key::Enter if !buffer.is_empty() => EntryAction::Submit,
        Key::Escape => EntryAction::Cancel,
        _ => EntryAction::None,
    }
}

fn render_encoding_refusal(out: &mut dyn TextOutput, encoding: Encoding, error: EntropyEncodingError) {
    out.clear();
    render_common_banner(out);
    match error {
        EntropyEncodingError::NoSymbols { ignored_chars } => {
            out.write_line(&format!(
                "REFUSED: no {} symbols were found in your input.",
                encoding.display_name()
            ));
            out.write_line(&format!(
                "All {ignored_chars} characters were outside the selected encoding and ignored"
            ));
            out.write_line("(iancoleman drops them too). Check the encoding, then re-enter symbols.");
        }
        EntropyEncodingError::TooLong => {
            out.write_line("REFUSED: that is far more entropy than verification needs (over 2048 bits).");
            out.write_line("Verification only reproduces a 128-bit (12-word) or 256-bit (24-word) phrase --");
            out.write_line("trim the input.");
        }
        EntropyEncodingError::UnsupportedLength {
            retained_bits,
            total_bits,
            iancoleman_words,
            accepted_symbols,
            ignored_chars,
        } => {
            if iancoleman_words >= 12 && retained_bits != 128 && retained_bits != 256 {
                out.write_line(&format!("REFUSED: {retained_bits} retained bits."));
                out.write_line(&format!(
                    "iancoleman would make a {iancoleman_words}-word NON-STANDARD phrase from this length;"
                ));
                out.write_line("Alea verifies only 12- and 24-word BIP39 mnemonics. Adjust to exactly 128 or");
                out.write_line("256 retained bits.");
            } else {
                out.write_line(&format!(
                    "REFUSED: {retained_bits} retained bits (below the 128 bits needed for 12 words)."
                ));
                out.write_line("Alea verifies only 12- (128-bit) and 24-word (256-bit) BIP39 mnemonics; add more");
                out.write_line("symbols to reach exactly 128 or 256 retained bits.");
            }
            out.write_line(&format!(
                "Accepted symbols: {accepted_symbols}   Ignored (outside encoding): {ignored_chars}   Total bits: {total_bits}"
            ));
        }
    }
    out.write_line("");
    out.write_line("Press any key to return to the encoding list.");
}

struct EntropySuccess {
    encoding: Encoding,
    word_count: CompatWordCount,
    words: Vec<&'static str>,
    accepted_symbols: u16,
    ignored_chars: u16,
    retained_bits: u16,
    total_bits: u16,
    entropy: [u8; 32],
    entropy_len: usize,
    master_fingerprint: [u8; 4],
    addresses: [RenderedAddress; 4],
}

impl EntropySuccess {
    fn word_count_n(&self) -> usize {
        match self.word_count {
            CompatWordCount::W12 => 12,
            CompatWordCount::W24 => 24,
        }
    }

    fn entropy_hex(&self) -> String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    fn master_fingerprint_hex(&self) -> String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

impl Drop for EntropySuccess {
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

fn finish_entropy(out: EntropyEncodingOutput) -> EntropySuccess {
    let core_count = match out.word_count {
        CompatWordCount::W12 => CoreWordCount::Twelve,
        CompatWordCount::W24 => CoreWordCount::TwentyFour,
    };
    let n = match out.word_count {
        CompatWordCount::W12 => 12,
        CompatWordCount::W24 => 24,
    };
    let mut words = Vec::with_capacity(n);
    for idx in &out.mnemonic_indexes[..n] {
        words.push(seed_core::bip39::word(*idx));
    }

    let mut seed = [0u8; 64];
    seed_core::bip39::mnemonic_to_seed(&out.mnemonic_indexes, core_count, &mut seed);

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    seed_derive::bip32::master_from_seed(&seed, &mut key, &mut cc);
    let master_fingerprint = seed_derive::bip32::master_fingerprint(&key);
    key.zeroize();
    cc.zeroize();

    let standards: [(&'static str, PathStandard); 4] = [
        ("BIP44", PathStandard::Bip44),
        ("BIP49", PathStandard::Bip49),
        ("BIP84", PathStandard::Bip84),
        ("BIP86", PathStandard::Bip86),
    ];
    let addresses = standards.map(|(label, standard)| {
        let mut buf = AddressBuf::empty();
        seed_derive::address::first_address(&seed, standard, &mut buf)
            .expect("SPEC §24.2 fixed paths do not fail on a valid BIP39 seed");
        RenderedAddress {
            label,
            address: buf.as_str().unwrap_or("").to_string(),
        }
    });

    seed.zeroize();

    let mut entropy = [0u8; 32];
    entropy[..out.entropy_len].copy_from_slice(&out.entropy[..out.entropy_len]);

    EntropySuccess {
        encoding: out.encoding,
        word_count: out.word_count,
        words,
        accepted_symbols: out.accepted_symbols,
        ignored_chars: out.ignored_chars,
        retained_bits: out.retained_bits,
        total_bits: out.total_bits,
        entropy,
        entropy_len: out.entropy_len,
        master_fingerprint,
        addresses,
    }
}

fn render_encoding_result(out: &mut dyn TextOutput, success: &EntropySuccess, input: &str) {
    out.clear();
    render_common_banner(out);
    out.write_line(FOREIGN_WATERMARK);
    out.write_line("");
    let n = success.word_count_n();

    out.write_line(&format!(
        "Method:         iancoleman/bip39 RAW entropy -- {} ({METHOD_ID})",
        success.encoding.display_name()
    ));
    out.write_line(&format!("Input:          {input}"));
    out.write_line(&format!("Encoding:       {}", success.encoding.display_name()));
    out.write_line(&format!(
        "Retained bits:  {} (of {} typed)  ->  {} words",
        success.retained_bits, success.total_bits, n
    ));
    out.write_line(&format!("Symbols used:   {}", success.accepted_symbols));
    out.write_line(&format!("Chars ignored:  {}", success.ignored_chars));
    out.write_line(&format!("Entropy (hex):  {}", success.entropy_hex()));
    out.write_line("");

    out.write_line(PUBLIC_TEST_PHRASE_PREFIX);
    out.write_line(&format!("Mnemonic ({n} words):"));
    let mut line = String::new();
    for (i, w) in success.words.iter().enumerate() {
        line.push_str(&format!("{:02} {:<12}", i + 1, w));
        if i % 6 == 5 || i + 1 == success.words.len() {
            out.write_line(line.trim_end());
            line.clear();
        }
    }
    out.write_line("");

    out.write_line("Verification values (empty passphrase; SPEC §24):");
    out.write_line(&format!(
        "  Master fingerprint  {}",
        success.master_fingerprint_hex()
    ));
    let mut addr_line = String::new();
    for a in &success.addresses {
        addr_line.push_str(&format!("{} {}   ", a.label, a.address));
    }
    out.write_line(&format!("  {}", addr_line.trim_end()));
    out.write_line("");

    out.write_line("This reproduces another tool's (iancoleman/bip39) raw-entropy result so you can");
    out.write_line("cross-check it. It is foreign/throwaway material, not an Alea-generated seed.");
    out.write_line("");
    out.write_line("[P] Custom derivation path (free-form)   Any other key returns");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingResultAction {
    CustomPath,
    Back,
}

fn handle_encoding_result_key(key: Key) -> EncodingResultAction {
    match key {
        Key::Char(c) if c.eq_ignore_ascii_case(&'p') => EncodingResultAction::CustomPath,
        _ => EncodingResultAction::Back,
    }
}

// ============================================================================
// The screen/dispatch loop
// ============================================================================

enum Stage {
    ProfileMenu,
    EventEntry {
        profile: &'static CompatProfile,
        buffer: String,
    },
    WordCount {
        profile: &'static CompatProfile,
        events: String,
    },
    Result {
        profile: &'static CompatProfile,
        events: String,
        requested: Option<CompatWordCount>,
        show_entropy: bool,
    },
    EncodingMenu,
    EncodingEntry {
        encoding: Encoding,
        buffer: String,
    },
    EncodingResult {
        encoding: Encoding,
        input: String,
    },
    Done,
}

/// The full verification screen/dispatch loop over an injected
/// [`TextOutput`] and a blocking key-read closure. `main` is the only
/// caller. Returns when the user backs out of the profile menu (Esc).
pub fn run_over(out: &mut dyn TextOutput, mut next_key: impl FnMut() -> Key) {
    let profiles = user_profiles();
    let mut stage = Stage::ProfileMenu;
    loop {
        stage = match stage {
            Stage::ProfileMenu => {
                render_profile_menu(out, &profiles);
                match handle_profile_key(profile_menu_len(&profiles), next_key()) {
                    ProfileNav::Activate(idx) if idx == entropy_menu_index(&profiles) => {
                        Stage::EncodingMenu
                    }
                    ProfileNav::Activate(idx) => Stage::EventEntry {
                        profile: profiles[idx],
                        buffer: String::with_capacity(EVENT_BUFFER_CAP),
                    },
                    ProfileNav::Quit => Stage::Done,
                    ProfileNav::None => Stage::ProfileMenu,
                }
            }
            Stage::EventEntry {
                profile,
                mut buffer,
            } => {
                render_event_entry(out, profile, &buffer);
                match handle_entry_key(profile, &mut buffer, next_key()) {
                    EntryAction::Submit => {
                        if matches!(profile.word_count_rule, WordCountRule::FreeChoice { .. }) {
                            Stage::WordCount {
                                profile,
                                events: buffer,
                            }
                        } else {
                            Stage::Result {
                                profile,
                                events: buffer,
                                requested: None,
                                show_entropy: false,
                            }
                        }
                    }
                    EntryAction::Cancel => {
                        scrub_string(&mut buffer);
                        Stage::ProfileMenu
                    }
                    EntryAction::ShowDetail => {
                        render_method_detail(out, profile);
                        let _ = next_key();
                        Stage::EventEntry { profile, buffer }
                    }
                    EntryAction::None => Stage::EventEntry { profile, buffer },
                }
            }
            Stage::WordCount { profile, events } => {
                render_word_count_choice(out, profile, &events);
                match handle_word_count_key(next_key()) {
                    WordCountAction::Chosen(wc) => Stage::Result {
                        profile,
                        events,
                        requested: Some(wc),
                        show_entropy: false,
                    },
                    WordCountAction::Cancel => Stage::EventEntry {
                        profile,
                        buffer: events,
                    },
                    WordCountAction::None => Stage::WordCount { profile, events },
                }
            }
            Stage::Result {
                profile,
                mut events,
                requested,
                show_entropy,
            } => match compat_derive(profile, &events, requested) {
                Ok(output) => {
                    let success = finish(&events, output);
                    render_result_success(out, profile, &success, &events, show_entropy);
                    match handle_result_key(next_key()) {
                        ResultAction::ToggleEntropy => Stage::Result {
                            profile,
                            events,
                            requested,
                            show_entropy: !show_entropy,
                        },
                        ResultAction::CustomPath => {
                            // Re-derive the THROWAWAY seed (deterministic),
                            // run the free-form custom-path tool over it,
                            // zeroize on return; come back to this screen.
                            if let Ok(o) = compat_derive(profile, &events, requested) {
                                let core_count = match o.word_count {
                                    CompatWordCount::W12 => CoreWordCount::Twelve,
                                    CompatWordCount::W24 => CoreWordCount::TwentyFour,
                                };
                                let mut seed = [0u8; 64];
                                seed_core::bip39::mnemonic_to_seed(
                                    &o.mnemonic_indexes,
                                    core_count,
                                    &mut seed,
                                );
                                custom_path::run_over(out, &mut next_key, &seed);
                                seed.zeroize();
                            }
                            Stage::Result {
                                profile,
                                events,
                                requested,
                                show_entropy,
                            }
                        }
                        ResultAction::Back => {
                            scrub_string(&mut events);
                            Stage::ProfileMenu
                        }
                    }
                }
                Err(CompatError::Refused { entered, .. }) => {
                    render_refusal(out, profile, entered, requested.map(compat_word_count_n));
                    let _ = next_key();
                    scrub_string(&mut events);
                    Stage::ProfileMenu
                }
                Err(_other) => {
                    render_unexpected_refusal(out);
                    let _ = next_key();
                    scrub_string(&mut events);
                    Stage::ProfileMenu
                }
            },
            Stage::EncodingMenu => {
                render_encoding_menu(out);
                match handle_encoding_key(Encoding::ALL.len(), next_key()) {
                    EncodingNav::Activate(idx) => Stage::EncodingEntry {
                        encoding: Encoding::ALL[idx],
                        buffer: String::with_capacity(EVENT_BUFFER_CAP),
                    },
                    EncodingNav::Quit => Stage::ProfileMenu,
                    EncodingNav::None => Stage::EncodingMenu,
                }
            }
            Stage::EncodingEntry {
                encoding,
                mut buffer,
            } => {
                render_encoding_entry(out, encoding, &buffer);
                match handle_encoding_entry_key(&mut buffer, next_key()) {
                    EntryAction::Submit => Stage::EncodingResult {
                        encoding,
                        input: buffer,
                    },
                    EntryAction::Cancel => {
                        scrub_string(&mut buffer);
                        Stage::EncodingMenu
                    }
                    EntryAction::ShowDetail => {
                        render_encoding_method_detail(out, encoding);
                        let _ = next_key();
                        Stage::EncodingEntry { encoding, buffer }
                    }
                    EntryAction::None => Stage::EncodingEntry { encoding, buffer },
                }
            }
            Stage::EncodingResult {
                encoding,
                mut input,
            } => match entropy_encoding_derive(encoding, &input) {
                Ok(output) => {
                    let success = finish_entropy(output);
                    render_encoding_result(out, &success, &input);
                    match handle_encoding_result_key(next_key()) {
                        EncodingResultAction::CustomPath => {
                            if let Ok(o) = entropy_encoding_derive(encoding, &input) {
                                let core_count = match o.word_count {
                                    CompatWordCount::W12 => CoreWordCount::Twelve,
                                    CompatWordCount::W24 => CoreWordCount::TwentyFour,
                                };
                                let mut seed = [0u8; 64];
                                seed_core::bip39::mnemonic_to_seed(
                                    &o.mnemonic_indexes,
                                    core_count,
                                    &mut seed,
                                );
                                custom_path::run_over(out, &mut next_key, &seed);
                                seed.zeroize();
                            }
                            Stage::EncodingResult { encoding, input }
                        }
                        EncodingResultAction::Back => {
                            scrub_string(&mut input);
                            Stage::EncodingMenu
                        }
                    }
                }
                Err(error) => {
                    render_encoding_refusal(out, encoding, error);
                    let _ = next_key();
                    scrub_string(&mut input);
                    Stage::EncodingMenu
                }
            },
            Stage::Done => return,
        };
    }
}

// ============================================================================
// Tests (Task 19 review fix: this crate's library target, `src/lib.rs`,
// makes these host-testable -- see that file's doc comment for why the
// `#![no_std] #![no_main]` binary itself cannot be).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The SPEC §11.4 800x600 floor's line budget -- the fixed source of
    /// truth every screen in this file must fit as ONE screen (no in-page
    /// scrolling: `FbTextOutput`/`draw_text` clip silently past the
    /// bottom edge rather than scrolling or panicking).
    const MAX_LINES: usize = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;

    /// A recording [`TextOutput`] double: `clear()` resets `lines`, so a
    /// screen's full rendered line count for THIS render call is simply
    /// `lines.len()` after the render function returns (every render
    /// function here calls `clear()` exactly once, first).
    struct Recorder {
        lines: Vec<String>,
    }
    impl Recorder {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
        fn joined(&self) -> String {
            self.lines.join("\n")
        }
    }
    impl TextOutput for Recorder {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {
            self.lines.clear();
        }
    }

    fn dice_profile() -> &'static CompatProfile {
        seed_compat::profile("seedsigner-dice").expect("seedsigner-dice profile")
    }

    fn coin_profile() -> &'static CompatProfile {
        seed_compat::profile("seedsigner-coin").expect("seedsigner-coin profile")
    }

    fn free_choice_profile() -> &'static CompatProfile {
        seed_compat::profile("coldcard-dice").expect("coldcard-dice profile")
    }

    // -- Review fix: the entry screens' TOTAL line count (header + entry
    // UI, including the input echo and count-feedback rows) must fit the
    // floor for every user-facing profile/encoding, independent of how
    // many caveats a profile carries or how long its rule description is
    // -- that independence is the whole point of the fix (the compact
    // header is fixed-size; caveats/full rule moved to the `[?]` detail
    // screen). ---------------------------------------------------------

    #[test]
    fn event_entry_fits_the_800x600_floor_with_the_echo_and_count_rows_visible_for_every_profile() {
        for profile in [dice_profile(), coin_profile(), free_choice_profile()] {
            let mut out = Recorder::new();
            render_event_entry(&mut out, profile, "123456789");
            assert!(
                out.lines.len() <= MAX_LINES,
                "{}: entry screen renders {} lines, exceeds the {MAX_LINES}-line floor budget",
                profile.id,
                out.lines.len()
            );
            let joined = out.joined();
            assert!(joined.contains("123456789_"), "{}: input echo row missing/off-screen", profile.id);
            assert!(joined.contains("entered so far"), "{}: count-feedback row missing/off-screen", profile.id);
            // The original requirement ("algorithm+citation visible while
            // typing") must still hold on the compact header.
            assert!(joined.contains("Method:"), "{}: algorithm summary missing from header", profile.id);
            assert!(joined.contains(profile.source_url), "{}: citation missing from header", profile.id);
        }
    }

    #[test]
    fn encoding_entry_fits_the_800x600_floor_with_the_echo_and_count_rows_visible_for_every_encoding() {
        for encoding in Encoding::ALL {
            let mut out = Recorder::new();
            render_encoding_entry(&mut out, encoding, "abc123");
            assert!(
                out.lines.len() <= MAX_LINES,
                "{}: encoding entry screen renders {} lines, exceeds the {MAX_LINES}-line floor budget",
                encoding.display_name(),
                out.lines.len()
            );
            let joined = out.joined();
            assert!(joined.contains("abc123_"), "{}: input echo row missing/off-screen", encoding.display_name());
            assert!(joined.contains("entered so far"), "{}: count-feedback row missing/off-screen", encoding.display_name());
            assert!(joined.contains("Method ("), "{}: algorithm summary missing from header", encoding.display_name());
            assert!(joined.contains("github.com/iancoleman/bip39"), "{}: citation missing from header", encoding.display_name());
        }
    }

    // -- The `[?]` detail screens carry the FULL content the entry
    // header no longer does (nothing dropped) -- each must itself fit
    // the floor as its own single screen. --------------------------------

    #[test]
    fn method_detail_fits_the_800x600_floor_for_every_profile_including_the_worst_case() {
        // coldcard-dice (FreeChoice, 4 caveats -- one of them a single
        // very long sentence) is the worst case by caveat COUNT (line
        // count, not string width, is what MAX_LINES gates).
        for profile in [dice_profile(), coin_profile(), free_choice_profile()] {
            let mut out = Recorder::new();
            render_method_detail(&mut out, profile);
            assert!(
                out.lines.len() <= MAX_LINES,
                "{}: method detail renders {} lines, exceeds the {MAX_LINES}-line floor budget",
                profile.id,
                out.lines.len()
            );
            let joined = out.joined();
            for caveat in profile.caveats {
                assert!(joined.contains(caveat), "{}: caveat dropped from detail screen: {caveat:?}", profile.id);
            }
        }
    }

    #[test]
    fn encoding_method_detail_fits_the_800x600_floor_for_every_encoding_including_cards() {
        for encoding in Encoding::ALL {
            let mut out = Recorder::new();
            render_encoding_method_detail(&mut out, encoding);
            assert!(
                out.lines.len() <= MAX_LINES,
                "{}: encoding method detail renders {} lines, exceeds the {MAX_LINES}-line floor budget",
                encoding.display_name(),
                out.lines.len()
            );
            let joined = out.joined();
            for line in ENTROPY_HONESTY_CAVEAT {
                assert!(joined.contains(line), "{}: honesty caveat line dropped from detail screen", encoding.display_name());
            }
        }
    }

    // -- `[?]` key handling ------------------------------------------------

    #[test]
    fn question_mark_opens_detail_on_the_profile_entry_screen_without_touching_the_buffer() {
        let profile = free_choice_profile();
        let mut buffer = String::from("123");
        let action = handle_entry_key(profile, &mut buffer, Key::Char('?'));
        assert_eq!(action, EntryAction::ShowDetail);
        assert_eq!(buffer, "123", "buffer must be untouched by the [?] key");
    }

    #[test]
    fn question_mark_opens_detail_on_the_encoding_entry_screen_without_touching_the_buffer() {
        let mut buffer = String::from("ab");
        let action = handle_encoding_entry_key(&mut buffer, Key::Char('?'));
        assert_eq!(action, EntryAction::ShowDetail);
        assert_eq!(buffer, "ab", "buffer must be untouched by the [?] key");
    }

    #[test]
    fn dice_and_coin_digits_are_unaffected_by_the_question_mark_reservation() {
        // '?' is never a valid dice/coin digit, so reserving it for
        // ShowDetail must not shadow any real event keystroke.
        let profile = dice_profile();
        let mut buffer = String::new();
        assert_eq!(handle_entry_key(profile, &mut buffer, Key::Char('3')), EntryAction::None);
        assert_eq!(buffer, "3");
    }
}
