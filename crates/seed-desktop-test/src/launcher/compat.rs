//! Launcher item (2) — cross-device verification (SPEC_MAIN_MENU.md §4.1
//! item 2, §6.1/§6.2 routing, §15 OQ1 resolution: **ENABLED** on this
//! edition, authorized by the SPEC_COMPAT.md v0.6.3 amendment §9). The
//! desktop-GUI analogue of `tools/compat-verify` (SPEC_COMPAT §9): profile
//! pick -> event-string entry (method/algorithm info shown as a persistent
//! header above the input line, ceremony UX redesign §5) -> (word-count
//! choice for a `FreeChoice` profile) -> mnemonic / fingerprint /
//! addresses, or a refusal for non-canonical `DerivedFromLength` lengths
//! (SPEC_COMPAT §5, §6, review F1).
//!
//! Reuses `seed_compat::compat_derive` for every digest/word-count/refusal
//! decision (never reimplemented here — SPEC_COMPAT §5–§6 is the sole
//! source of truth for that logic) and `seed_derive`/`seed_core` for the
//! SPEC §24.2 verification values (master fingerprint + BIP44/49/84/86
//! first-receive addresses), exactly mirroring `tools/compat-verify/src/
//! derive.rs`'s own "digest step is seed-compat's job; verification values
//! are the CLI's job" split — this screen is the GUI half of that same
//! split, not a second implementation of the digest/refusal logic.
//!
//! # SPEC_COMPAT §7/§8 discipline, carried verbatim
//!
//! Every screen in this module renders, via [`render_common_banner`]:
//! - the SPEC_COMPAT §8 permanent mode banner ("COMPATIBILITY /
//!   VERIFICATION MODE ... NOT Alea generation ... public/throwaway seeds
//!   only"), and
//! - the SPEC_COMPAT §7 result-screen watermark line verbatim,
//!   `[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]`
//!   ([`RESULT_WATERMARK`]),
//!
//! on every screen this tool ever shows, not only the result screen — so
//! the "this is not an Alea seed" framing is unmissable no matter where in
//! the flow the user is, *in addition to* the SPEC §4.3 desktop watermark
//! bands `crate::window::present_frame` already composites every frame
//! (this module never touches that mechanism at all, see that module's own
//! doc comment).
//!
//! A successful result additionally prefixes the mnemonic with
//! [`PUBLIC_TEST_PHRASE_PREFIX`] (SPEC §4.2 wording reused, SPEC_COMPAT
//! §8), and entropy hex is **never** shown alongside the mnemonic by
//! default (SPEC_COMPAT §7, review F7: no entropy/mnemonic concatenation
//! habit, even for these declared-public/throwaway values) — only on the
//! result screen's own explicit `[E]` toggle ([`ResultAction::ToggleEntropy`]).
//!
//! # Host-testable without a display (SPEC_MAIN_MENU.md §6.3)
//!
//! [`run`] is a thin two-line wrapper: everything else in this module is a
//! pure function or takes a plain `&mut dyn TextOutput` plus an injected
//! key source closure, exactly like `crate::ceremony`'s own `RecordingOutput`
//! pattern. [`run_over`] is the whole screen/dispatch loop, fully exercised
//! in `#[cfg(test)]` below against a scripted `Vec<KeyMsg>` — no
//! `SharedFramebuffer`/`ChannelKeys`/window needed at all.

use seed_compat::entropy_encoding::{entropy_encoding_derive, Encoding, EntropyEncodingError, EntropyEncodingOutput, METHOD_ID};
use seed_compat::{compat_derive, CompatError, CompatOutput, CompatProfile, EventAlphabet, WordCount as CompatWordCount, WordCountRule};
use seed_core::contracts::{AddressBuf, PathStandard, WordCount as CoreWordCount};
use seed_flow::output::TextOutput;
use zeroize::Zeroize;

use crate::channel_keys::{ChannelKeys, KeyMsg};
use crate::launcher::custom_path;
use crate::shared_screen::{SharedFramebuffer, WindowTextOutput};

// ============================================================================
// SPEC_COMPAT §7/§8 fixed banner text (verbatim — do not reword)
// ============================================================================

/// SPEC_COMPAT §8, line 1 of the permanent, non-removable mode banner.
pub const MODE_BANNER_LINE_1: &str = "COMPATIBILITY / VERIFICATION MODE — reproduces another vendor's method —";
/// SPEC_COMPAT §8, line 2.
pub const MODE_BANNER_LINE_2: &str = "NOT Alea generation — public/throwaway seeds only";
/// SPEC_COMPAT §7's result-screen watermark line, verbatim (also SPEC_MAIN_MENU.md
/// §15 OQ1: "the `NOT AN ALEA SEED` watermark" every desktop compat screen
/// must carry).
pub const RESULT_WATERMARK: &str = "[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]";
/// SPEC_COMPAT §8: the mnemonic-prefix warning (SPEC §4.2 wording reused).
pub const PUBLIC_TEST_PHRASE_PREFIX: &str = "PUBLIC TEST PHRASE — NEVER USE WITH FUNDS";

/// Method C (`EntropyEncodingRaw`) result-screen foreign-material watermark,
/// carried verbatim from the web "Entropy compat" tab (`web/src/app.js`) so
/// the desktop and web surfaces frame reproduced iancoleman/bip39 raw-entropy
/// material identically: this is another tool's output, reproduced only so it
/// can be cross-checked, and is NEVER an Alea seed (SPEC_COMPAT_ENTROPY §2/§9).
pub const FOREIGN_WATERMARK: &str = "REPRODUCTION OF FOREIGN MATERIAL — NEVER AN ALEA SEED — NEVER USE WITH FUNDS";

/// SPEC_COMPAT_ENTROPY §2 item 4 / §9: the honesty caveat that MUST appear at
/// the point of entry AND on the result screen (mirrors the CLI's
/// `ENTROPY_HONESTY_CAVEAT`, rendered here line-by-line through the
/// [`TextOutput`] seam). Typed entropy is not witnessed randomness — use this
/// to CONFIRM a seed another tool made, never to CREATE one you will fund.
const ENTROPY_HONESTY_CAVEAT: [&str; 4] = [
    "Typed entropy is only as strong as the randomness of whatever produced it —",
    "this tool cannot witness that randomness. Use it to CONFIRM a seed another",
    "tool made from the same symbols, never to CREATE one you will fund.",
    "For real seeds, use Alea's witnessed dice/coin/machine generation.",
];

/// Renders the SPEC_COMPAT §7/§8 banner block that opens **every** screen
/// this module shows (see module doc comment). Callers still call
/// `out.clear()` themselves first (mirrors every other `seed-flow`/
/// launcher screen's own `clear()`-then-render shape).
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

/// Fixed menu order (SPEC_COMPAT §7's literal profile menu example).
const PROFILE_IDS: [&str; 3] = ["coldcard-dice", "seedsigner-dice", "seedsigner-coin"];

/// Looks up the three user-facing profiles by id. Panics only if
/// `seed_compat::PROFILES` were ever edited to drop one of these three
/// reviewed ids — a build-breaking, review-caught change, not a runtime
/// condition this screen needs to handle gracefully.
fn user_profiles() -> [&'static CompatProfile; 3] {
    PROFILE_IDS.map(|id| seed_compat::profile(id).unwrap_or_else(|| panic!("missing user-facing compat profile {id:?}")))
}

/// SPEC_COMPAT §7's literal menu line for each profile, verbatim.
fn profile_menu_label(id: &str) -> &'static str {
    match id {
        "coldcard-dice" => "COLDCARD -- dice (SHA256 of rolls; you pick 12 or 24 words)",
        "seedsigner-dice" => "SeedSigner -- dice (SHA256 of rolls; 50 rolls = 12 words, 99 = 24 words)",
        "seedsigner-coin" => "SeedSigner -- coin flips (SHA256 of flips; 128 = 12 words, 256 = 24 words)",
        _ => "unknown profile",
    }
}

/// The noun used for this profile's events ("rolls" for dice, "flips" for
/// coins) — presentation-only, mirrors `tools/compat-verify/src/derive.rs`'s
/// own `event_noun` (not exported by `seed_compat`, so each caller derives
/// it from `profile.alphabet` the same trivial way).
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

/// Live-typing UX filter only (accept/reject a keystroke before it is even
/// added to the buffer) — the *authoritative* alphabet check still happens
/// inside `seed_compat::compat_derive` itself on submit; this just keeps
/// the on-screen buffer from ever containing a character that call would
/// reject anyway.
fn alphabet_allows(alphabet: EventAlphabet, c: char) -> bool {
    match alphabet {
        EventAlphabet::Dice1to6 => ('1'..='6').contains(&c),
        EventAlphabet::Coin01 => c == '0' || c == '1',
    }
}

fn alphabet_hint(alphabet: EventAlphabet) -> &'static str {
    match alphabet {
        EventAlphabet::Dice1to6 => "Digits 1-6 only, one key per roll (6 is hashed as-is, never remapped to 0).",
        EventAlphabet::Coin01 => "Digits 0/1 only, one key per flip.",
    }
}

fn compat_word_count_n(w: CompatWordCount) -> u16 {
    match w {
        CompatWordCount::W12 => 12,
        CompatWordCount::W24 => 24,
    }
}

// ============================================================================
// Profile-menu screen
// ============================================================================

fn render_profile_menu(out: &mut dyn TextOutput, profiles: &[&'static CompatProfile; 3], highlighted: usize) {
    out.clear();
    render_common_banner(out);
    out.write_line("COMPATIBILITY VERIFICATION -- audit another wallet's dice/coin math");
    out.write_line("This does NOT generate an Alea seed. Test/throwaway seeds only.");
    out.write_line("");
    out.write_line("Choose the device and method to reproduce:");
    for (i, p) in profiles.iter().enumerate() {
        let cursor = if i == highlighted { ">" } else { " " };
        out.write_line(&format!("{cursor} [{}] {}", i + 1, profile_menu_label(p.id)));
    }
    // The synthetic 4th row (SPEC_COMPAT_ENTROPY §7): Method C —
    // `EntropyEncodingRaw`, the iancoleman/bip39 raw-entropy front end. Not a
    // `PROFILES` (Method A) entry — it routes to the encoding submenu, not the
    // dice/coin method screen — so it lives at index `profiles.len()`, past the
    // three dice/coin profiles, exactly as `entropy_menu_index` reports.
    let entropy_idx = profiles.len();
    let cursor = if entropy_idx == highlighted { ">" } else { " " };
    out.write_line(&format!("{cursor} [{}] Entropy encodings (iancoleman-style raw entropy)", entropy_idx + 1));
    out.write_line("");
    out.write_line("Up/Down move   Enter select   1-4 jump   Esc back to main menu");
}

/// The profile menu's total row count: the three dice/coin (Method A)
/// profiles plus the one synthetic entropy-encoding (Method C) row.
fn profile_menu_len(profiles: &[&'static CompatProfile; 3]) -> usize {
    profiles.len() + 1
}

/// Index of the synthetic entropy-encoding (Method C) row in the profile menu
/// (always past the three dice/coin profiles).
fn entropy_menu_index(profiles: &[&'static CompatProfile; 3]) -> usize {
    profiles.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileNav {
    Highlight(usize),
    Activate(usize),
    Quit,
    None,
}

fn handle_profile_key(current: usize, len: usize, key: KeyMsg) -> ProfileNav {
    match key {
        KeyMsg::Up => ProfileNav::Highlight((current + len - 1) % len),
        KeyMsg::Down => ProfileNav::Highlight((current + 1) % len),
        KeyMsg::Enter => ProfileNav::Activate(current),
        KeyMsg::Char(c) => match c.to_digit(10) {
            Some(d) if d >= 1 && (d as usize) <= len => ProfileNav::Activate(d as usize - 1),
            _ => ProfileNav::None,
        },
        KeyMsg::Escape => ProfileNav::Quit,
        KeyMsg::Backspace | KeyMsg::Other => ProfileNav::None,
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
// Mirrors `alea-verify/src/verify.rs`'s own review-fix section comment
// above its `render_event_entry` (read that for the full rationale): an
// earlier version of this merge put the FULL method screen (up to 12
// lines for `coldcard-dice`'s `FreeChoice` rule + 4 caveats) directly
// above the input line, which pushed the input echo line and count
// feedback dangerously close to (and, on the tighter 800x600 floor this
// same layout also has to serve per the "one layout, both canvases" rule
// -- SPEC_WALLET_PREVIEW §3.3.1 -- past) `MAX_LINES_AT_FLOOR`. The header
// here is compressed to the three essentials the original requirement
// actually named -- "algorithm+citation visible while typing" -- via
// [`compact_method_line`] (one line) and the `Source:` line, with a
// `[?]` key that opens [`render_method_detail`] (the FULL former
// method-screen content: complete word-count-rule breakdown + every
// caveat, verbatim, nothing dropped) as an on-demand detail page.
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
/// never depends on a profile's caveat count.
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
/// to carry directly, now an on-demand `[?]` screen instead of
/// always-drawn, so the entry screen's input echo and count feedback are
/// never pushed off-screen by however many caveats a profile happens to
/// have.
fn render_method_detail(out: &mut dyn TextOutput, profile: &CompatProfile) {
    out.clear();
    render_event_entry_header(out, profile);
    out.write_line("");
    let noun = event_noun(profile);
    match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => {
            out.write_line(&format!("Method:    entropy = SHA256( ASCII of your {} digits )", singular(noun)));
            out.write_line(&format!("           WORD COUNT IS SET BY THE NUMBER OF {}:", noun.to_uppercase()));
            out.write_line(&format!("             exactly {len12} {noun} -> 12 words (first 16 bytes of the digest)"));
            out.write_line(&format!("             exactly {len24} {noun} -> 24 words (full digest)"));
            out.write_line(&format!("             any other count  -> your {} REFUSES it, and so does this", profile.vendor));
            out.write_line("           then standard BIP39 (SPEC §14)");
        }
        WordCountRule::FreeChoice { advisory_min_12, advisory_min_24 } => {
            out.write_line(&format!("Method:    entropy = SHA256( ASCII of your {} digits )", singular(noun)));
            out.write_line(&format!("           YOU CHOOSE THE WORD COUNT ({} runs a separate script for each):", profile.vendor));
            out.write_line("             12 words -> first 16 bytes of the digest");
            out.write_line("             24 words -> full digest");
            out.write_line(&format!("             {advisory_min_12}/{advisory_min_24} {noun} are advisory minimums only, not enforced"));
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

/// Mutates `buffer` in place for `Char`/`Backspace`; returns [`EntryAction::Submit`]
/// only on `Enter` with a non-empty buffer (an empty submit would only ever
/// reach `seed_compat::compat_derive`'s own [`CompatError::Empty`] path —
/// refused before that call is even worth making).
fn handle_entry_key(profile: &CompatProfile, buffer: &mut String, key: KeyMsg) -> EntryAction {
    match key {
        // '?' is never a valid dice ('1'-'6') or coin ('0'/'1') digit, so
        // this never shadows a real event keystroke.
        KeyMsg::Char('?') => EntryAction::ShowDetail,
        KeyMsg::Char(c) if alphabet_allows(profile.alphabet, c) => {
            buffer.push(c);
            EntryAction::None
        }
        KeyMsg::Backspace => {
            buffer.pop();
            EntryAction::None
        }
        KeyMsg::Enter if !buffer.is_empty() => EntryAction::Submit,
        KeyMsg::Escape => EntryAction::Cancel,
        _ => EntryAction::None,
    }
}

// ============================================================================
// Word-count choice screen (FreeChoice profiles only, i.e. coldcard-dice —
// SPEC_COMPAT §5.1.1, §6: word count is a free caller choice there, never
// derived from the roll count)
// ============================================================================

fn render_word_count_choice(out: &mut dyn TextOutput, profile: &CompatProfile, events: &str) {
    out.clear();
    render_common_banner(out);
    out.write_line(&format!("{} lets you choose the word count -- it is NOT derived", profile.vendor));
    out.write_line(&format!("from the {} count ({} entered).", event_noun(profile), events.chars().count()));
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

fn handle_word_count_key(key: KeyMsg) -> WordCountAction {
    match key {
        KeyMsg::Char('1') => WordCountAction::Chosen(CompatWordCount::W12),
        KeyMsg::Char('2') => WordCountAction::Chosen(CompatWordCount::W24),
        KeyMsg::Escape => WordCountAction::Cancel,
        _ => WordCountAction::None,
    }
}

// ============================================================================
// Refusal screen (SPEC_COMPAT §7, review F1/F5) — never paired with a
// rendered mnemonic
// ============================================================================

fn render_refusal(out: &mut dyn TextOutput, profile: &CompatProfile, entered: u16, requested_words: Option<u16>) {
    out.clear();
    render_common_banner(out);
    let noun = event_noun(profile);
    let (len12, len24) = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => (len12, len24),
        WordCountRule::FreeChoice { .. } => {
            out.write_line(&format!("REFUSED: {} requires you to choose 12 or 24 words explicitly.", profile.display_name));
            out.write_line("This profile's word count is a free choice, not derived from the event count.");
            out.write_line("(This tool refuses the same ambiguity the device's own scripts require you to resolve.)");
            out.write_line("");
            out.write_line("Press any key to return to the profile list.");
            return;
        }
    };
    match requested_words {
        Some(w) => out.write_line(&format!("REFUSED: {entered} {noun} cannot produce {w} words on {}.", profile.vendor)),
        None => out.write_line(&format!("REFUSED: {entered} {noun} is not a canonical {} count for {}.", singular(noun), profile.vendor)),
    }
    out.write_line(&format!(
        "{} sets word count from the {} count: {len12} -> 12 words, {len24} -> 24 words,",
        profile.vendor,
        singular(noun)
    ));
    out.write_line(&format!("and it refuses any other number of {noun}. Enter exactly {len12} or {len24} {noun}."));
    out.write_line("(This tool refuses the same inputs the device refuses, on purpose.)");
    out.write_line("");
    out.write_line("Press any key to return to the profile list.");
}

/// Defensive fallback for `CompatError::BadAlphabet`/`CompatError::Empty`,
/// structurally unreachable from this screen (see [`handle_entry_key`]'s
/// doc comment: every keystroke is alphabet-filtered before it reaches
/// `buffer`, and submission requires a non-empty buffer) but handled
/// without panicking rather than via `unreachable!()`, matching this
/// project's SPEC §13/§27.3 no-panic discipline.
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
    address: alloc_free::String,
}

/// A successful derivation, ready to render: the mnemonic words plus the
/// SPEC §24.2 verification values (master fingerprint + all four
/// first-receive addresses), computed via `seed_core`/`seed_derive` from
/// the mnemonic `seed_compat::compat_derive` produced — mirroring
/// `tools/compat-verify/src/derive.rs::finish` exactly (see module doc
/// comment for why this computation lives here, not in `seed-compat`
/// itself).
struct Success {
    word_count: CompatWordCount,
    words: alloc_free::Vec<&'static str>,
    used_len: u16,
    /// `digest[..16]` (12w) or `digest[..32]` (24w) — only rendered when
    /// the caller explicitly asks (SPEC_COMPAT §7, review F7).
    entropy: [u8; 32],
    entropy_len: usize,
    master_fingerprint: [u8; 4],
    addresses: [RenderedAddress; 4],
}

/// Host `std` module alias so this file's use of ordinary heap-allocated
/// `String`/`Vec` (this crate is `std`, unlike `no_std` `seed-compat`
/// itself — see this crate's own `Cargo.toml` doc comment) is never
/// mistaken for a `no_std`-compatibility shim by a reader skimming past
/// quickly.
mod alloc_free {
    pub type String = std::string::String;
    pub type Vec<T> = std::vec::Vec<T>;
}

fn bytes_to_hex(bytes: &[u8]) -> alloc_free::String {
    use std::fmt::Write;
    let mut s = alloc_free::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Pre-sized capacity for the event-entry buffer. Chosen to exceed the
/// largest canonical event count any user-facing profile accepts (256
/// SeedSigner coin flips for 24 words) so that typing a valid run never
/// triggers a heap reallocation — which in turn means [`scrub_string`]'s
/// single-allocation wipe covers the whole entered pre-image, with no
/// stale copy stranded in a discarded prior allocation.
const EVENT_BUFFER_CAP: usize = 512;

/// Best-effort in-place scrub of a growable `String` holding
/// reproduced-seed-adjacent data (the typed dice/coin event pre-image).
/// Overwrites the live allocation with volatile zero writes behind a
/// compiler fence (mirroring the `seed-protocol` physical-buffer scrub
/// discipline), then clears it. This is the throwaway / foreign-compat
/// surface (public test seeds only, SPEC_COMPAT §7), so it is
/// defense-in-depth: it cannot reach bytes left behind if the buffer had
/// reallocated while growing — hence the [`EVENT_BUFFER_CAP`] pre-size that
/// keeps the canonical entry paths reallocation-free.
fn scrub_string(s: &mut alloc_free::String) {
    // SAFETY: NUL (`0x00`) is valid UTF-8, so the buffer stays well-formed
    // for the `clear()` below; we drop all of it immediately regardless.
    let bytes = unsafe { s.as_mut_vec() };
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    s.clear();
}

impl Success {
    fn word_count_n(&self) -> usize {
        match self.word_count {
            CompatWordCount::W12 => 12,
            CompatWordCount::W24 => 24,
        }
    }

    fn entropy_hex(&self) -> alloc_free::String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    fn master_fingerprint_hex(&self) -> alloc_free::String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

impl Drop for Success {
    /// Scrubs the reproduced entropy bytes on drop. Every other field here
    /// is public (static mnemonic-word pointers, master fingerprint,
    /// rendered addresses); the raw `entropy` digest is the one
    /// seed-adjacent value, so it is zeroized even though this is the
    /// throwaway / foreign-compat surface (public test seeds only).
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

/// Walks the SPEC §24.2 derivation chain (`seed_core::bip39::mnemonic_to_seed`,
/// `seed_derive::bip32::{master_from_seed, master_fingerprint}`,
/// `seed_derive::address::first_address`) over the mnemonic
/// `seed_compat::compat_derive` already produced. Recomputes the digest
/// independently (`seed_core::hash::sha256`) purely to recover the raw
/// entropy bytes for the optional `[E]`-toggle display — `seed_compat`
/// deliberately does not expose them (SPEC_COMPAT §9: "this crate has no
/// obligation beyond `mnemonic_indexes`"), so this mirrors exactly the
/// digest step `compat_derive` itself already performed (SPEC_COMPAT §5.1).
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
    let mut words = alloc_free::Vec::with_capacity(n);
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

    let standards: [(&'static str, PathStandard); 4] =
        [("BIP44", PathStandard::Bip44), ("BIP49", PathStandard::Bip49), ("BIP84", PathStandard::Bip84), ("BIP86", PathStandard::Bip86)];
    let addresses = standards.map(|(label, standard)| {
        let mut buf = AddressBuf::empty();
        seed_derive::address::first_address(&seed, standard, &mut buf).expect("SPEC §24.2 fixed paths do not fail on a valid BIP39 seed");
        RenderedAddress { label, address: buf.as_str().unwrap_or("").to_string() }
    });

    seed.zeroize();

    Success { word_count: out.word_count, words, used_len: out.used_len, entropy, entropy_len, master_fingerprint, addresses }
}

fn render_result_success(out: &mut dyn TextOutput, profile: &CompatProfile, success: &Success, events: &str, show_entropy: bool) {
    out.clear();
    render_common_banner(out);
    let n = success.word_count_n();
    let noun = event_noun(profile);

    out.write_line(&format!("Device/method:  {} (SHA256 of {})", profile.display_name, noun));
    out.write_line(&format!("Events entered: {events}   ({} {noun})", success.used_len));
    let word_count_line = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { .. } => format!("Word count:     {n} (derived from {} {noun})", success.used_len),
        WordCountRule::FreeChoice { .. } => format!("Word count:     {n} (your choice)"),
    };
    out.write_line(&word_count_line);
    out.write_line("");

    out.write_line(PUBLIC_TEST_PHRASE_PREFIX);
    out.write_line(&format!("Mnemonic ({n} words):"));
    let mut line = alloc_free::String::new();
    for (i, w) in success.words.iter().enumerate() {
        line.push_str(&format!("{:02} {:<12}", i + 1, w));
        if i % 6 == 5 || i + 1 == success.words.len() {
            out.write_line(line.trim_end());
            line.clear();
        }
    }
    out.write_line("");

    out.write_line("Verification values (empty passphrase; SPEC §24):");
    out.write_line(&format!("  Master fingerprint  {}", success.master_fingerprint_hex()));
    let mut addr_line = alloc_free::String::new();
    for a in &success.addresses {
        addr_line.push_str(&format!("{} {}   ", a.label, a.address));
    }
    out.write_line(&format!("  {}", addr_line.trim_end()));
    out.write_line("");

    if show_entropy {
        out.write_line(&format!("Entropy hex ({} bytes): {}", success.entropy_len, success.entropy_hex()));
        out.write_line("(Preimage is SHA256 over the ASCII string above. This is a PUBLIC test value.)");
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
    out.write_line("[E] Show/hide entropy hex   [P] Custom derivation path (free-form)   Any other key returns");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultAction {
    ToggleEntropy,
    /// SPEC_DERIVATION_CUSTOM §9/§11.2: enter the free-form custom
    /// derivation-path tool over this just-derived public/throwaway seed.
    CustomPath,
    Back,
}

fn handle_result_key(key: KeyMsg) -> ResultAction {
    match key {
        KeyMsg::Char(c) if c.eq_ignore_ascii_case(&'e') => ResultAction::ToggleEntropy,
        KeyMsg::Char(c) if c.eq_ignore_ascii_case(&'p') => ResultAction::CustomPath,
        _ => ResultAction::Back,
    }
}

// ============================================================================
// Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md): the iancoleman/bip39
// raw-entropy front end (Binary/Base-6/Dice/Base-10/Hex/Cards -> mnemonic +
// addresses). The digest/refusal logic is `seed_compat::entropy_encoding`'s
// job (never reimplemented here); this screen is the desktop-GUI half of the
// same "front end is the tool's job, verification values are seed-derive's
// job" split the CLI's `tools/compat-verify` uses. Entropy hex is shown by
// default here (foreign/throwaway raw bits, exactly as the web tab does), so
// there is no `[E]` toggle on this path.
// ============================================================================

/// The six encodings, in the fixed `Encoding::ALL` order (SPEC_COMPAT_ENTROPY
/// §5.3), rendered as a numbered submenu reached from the profile menu's [4].
fn render_encoding_menu(out: &mut dyn TextOutput, highlighted: usize) {
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
        let cursor = if i == highlighted { ">" } else { " " };
        out.write_line(&format!("{cursor} [{}] {}", i + 1, e.display_name()));
    }
    out.write_line("");
    out.write_line("Only 128-bit (12-word) or 256-bit (24-word) retained entropy is verified.");
    out.write_line("Up/Down move   Enter select   1-6 jump   Esc back to profile list");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingNav {
    Highlight(usize),
    Activate(usize),
    Quit,
    None,
}

fn handle_encoding_key(current: usize, len: usize, key: KeyMsg) -> EncodingNav {
    match key {
        KeyMsg::Up => EncodingNav::Highlight((current + len - 1) % len),
        KeyMsg::Down => EncodingNav::Highlight((current + 1) % len),
        KeyMsg::Enter => EncodingNav::Activate(current),
        KeyMsg::Char(c) => match c.to_digit(10) {
            Some(d) if d >= 1 && (d as usize) <= len => EncodingNav::Activate(d as usize - 1),
            _ => EncodingNav::None,
        },
        KeyMsg::Escape => EncodingNav::Quit,
        KeyMsg::Backspace | KeyMsg::Other => EncodingNav::None,
    }
}

/// SPEC_COMPAT_ENTROPY §5.3: the short symbol->bits rule shown on the method
/// screen so the emulation is not opaque (mirrors the CLI's `encoding_rule`).
fn encoding_rule(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Binary => "each 0/1 -> 1 bit",
        Encoding::Base6 => "0->00 1->01 2->10 3->11 4->0 5->1 (bias-corrected, variable width)",
        Encoding::Dice => "face 6 -> 0, then 1->01 2->10 3->11 4->0 5->1 6->00 (variable width)",
        Encoding::Base10 => "0..7 -> 3-bit 000..111, 8->0, 9->1 (variable width)",
        Encoding::Hex => "each 0-9A-F -> its 4-bit nibble",
        Encoding::Cards => "per-card table, suits C,D,H,S; first 32 cards 5-bit, next 16 4-bit, last 4 2-bit",
    }
}

/// The compact, ALWAYS-visible encoding entry-screen header: banner +
/// reproducing line + one-line rule + source citation
/// ("algorithm+citation visible while typing") -- fixed at 4 lines
/// regardless of encoding (the `Cards`-only two-line addendum that used to
/// live here moved into [`render_encoding_method_detail`]), review fix
/// mirroring [`render_event_entry_header`]'s own rationale above.
fn render_encoding_entry_header(out: &mut dyn TextOutput, encoding: Encoding) {
    render_common_banner(out);
    out.write_line(&format!("Reproducing: iancoleman/bip39 RAW entropy -- {}", encoding.display_name()));
    out.write_line(&format!("Method ({METHOD_ID}): {}", encoding_rule(encoding)));
    out.write_line("Source:    github.com/iancoleman/bip39 src/js/entropy.js (eventBits) + index.js");
}

/// Free-form symbol entry (SPEC_COMPAT_ENTROPY §7). Full keyboard is available
/// on the desktop, so -- exactly like the free-form custom-path field
/// (`crate::launcher::custom_path`) -- this accepts any typed character; the
/// authoritative per-encoding alphabet match (and the silent dropping of
/// out-of-encoding characters, §9) happens inside
/// `seed_compat::entropy_encoding_derive` on submit, never here.
fn render_encoding_entry(out: &mut dyn TextOutput, encoding: Encoding, buffer: &str) {
    out.clear();
    render_encoding_entry_header(out, encoding);
    out.write_line("");
    out.write_line(&format!("Enter the {} symbols your other tool used", encoding.display_name()));
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
/// an on-demand `[?]` screen instead of always-drawn.
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

/// Mutates `buffer` in place for `Char`/`Backspace`; returns
/// [`EntryAction::Submit`] only on `Enter` with a non-empty buffer (an empty
/// submit would only ever reach `entropy_encoding_derive`'s own `NoSymbols`
/// path). Accepts every typed character (full keyboard); the encoding match is
/// the derive call's job (§5.1/§9). `'?'` is intercepted for
/// [`EntryAction::ShowDetail`] rather than pushed to the buffer: no
/// encoding's alphabet uses `?` as a meaningful symbol, so a typed `?`
/// would already have been silently ignored by `entropy_encoding_derive`
/// (counted in `ignored_chars`) — reserving it costs no real input.
fn handle_encoding_entry_key(buffer: &mut String, key: KeyMsg) -> EntryAction {
    match key {
        KeyMsg::Char('?') => EntryAction::ShowDetail,
        KeyMsg::Char(c) => {
            buffer.push(c);
            EntryAction::None
        }
        KeyMsg::Backspace => {
            buffer.pop();
            EntryAction::None
        }
        KeyMsg::Enter if !buffer.is_empty() => EntryAction::Submit,
        KeyMsg::Escape => EntryAction::Cancel,
        _ => EntryAction::None,
    }
}

/// SPEC_COMPAT_ENTROPY §5.5: the refusal screen for a non-{128,256} retained
/// length (or no accepted symbols / oversized input). Names iancoleman's
/// divergence and shows the retained-bit count, never fabricating a phrase
/// (mirrors the CLI's `entropy_refusal_screen`). Never carries a mnemonic.
fn render_encoding_refusal(out: &mut dyn TextOutput, encoding: Encoding, error: EntropyEncodingError) {
    out.clear();
    render_common_banner(out);
    match error {
        EntropyEncodingError::NoSymbols { ignored_chars } => {
            out.write_line(&format!("REFUSED: no {} symbols were found in your input.", encoding.display_name()));
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
        EntropyEncodingError::UnsupportedLength { retained_bits, total_bits, iancoleman_words, accepted_symbols, ignored_chars } => {
            if iancoleman_words >= 12 && retained_bits != 128 && retained_bits != 256 {
                out.write_line(&format!("REFUSED: {retained_bits} retained bits."));
                out.write_line(&format!(
                    "iancoleman would make a {iancoleman_words}-word NON-STANDARD phrase from this length;"
                ));
                out.write_line("Alea verifies only 12- and 24-word BIP39 mnemonics. Adjust to exactly 128 or");
                out.write_line("256 retained bits.");
            } else {
                out.write_line(&format!("REFUSED: {retained_bits} retained bits (below the 128 bits needed for 12 words)."));
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

/// A successful Method-C derivation, ready to render: the reproduced mnemonic
/// words + SPEC §24.2 verification values (master fingerprint + all four
/// first-receive addresses), computed via `seed_core`/`seed_derive` from the
/// mnemonic `entropy_encoding_derive` produced -- the same
/// "front-end-is-the-tool's-job, verification-values-are-seed-derive's-job"
/// split as [`Success`] and `tools/compat-verify/src/derive.rs::finish_entropy`.
struct EntropySuccess {
    encoding: Encoding,
    word_count: CompatWordCount,
    words: alloc_free::Vec<&'static str>,
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

    fn entropy_hex(&self) -> alloc_free::String {
        bytes_to_hex(&self.entropy[..self.entropy_len])
    }

    fn master_fingerprint_hex(&self) -> alloc_free::String {
        bytes_to_hex(&self.master_fingerprint)
    }
}

impl Drop for EntropySuccess {
    /// Scrubs the reproduced entropy bytes on drop (hygiene parity with
    /// [`Success`]; these are declared-public/throwaway verification values).
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

/// Walks the SPEC §24.2 derivation chain over the mnemonic
/// `entropy_encoding_derive` already produced (same chain as [`finish`]),
/// producing the master fingerprint + four first-receive addresses. The raw
/// retained entropy bytes come straight from the derive output (already the
/// MSB-first-packed retained tail, SPEC_COMPAT_ENTROPY §7 step 6).
fn finish_entropy(out: EntropyEncodingOutput) -> EntropySuccess {
    let core_count = match out.word_count {
        CompatWordCount::W12 => CoreWordCount::Twelve,
        CompatWordCount::W24 => CoreWordCount::TwentyFour,
    };
    let n = match out.word_count {
        CompatWordCount::W12 => 12,
        CompatWordCount::W24 => 24,
    };
    let mut words = alloc_free::Vec::with_capacity(n);
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

    let standards: [(&'static str, PathStandard); 4] =
        [("BIP44", PathStandard::Bip44), ("BIP49", PathStandard::Bip49), ("BIP84", PathStandard::Bip84), ("BIP86", PathStandard::Bip86)];
    let addresses = standards.map(|(label, standard)| {
        let mut buf = AddressBuf::empty();
        seed_derive::address::first_address(&seed, standard, &mut buf).expect("SPEC §24.2 fixed paths do not fail on a valid BIP39 seed");
        RenderedAddress { label, address: buf.as_str().unwrap_or("").to_string() }
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

/// SPEC_COMPAT_ENTROPY §7/§9: the Method-C result screen, carrying the
/// foreign-material watermark (verbatim from the web tab) plus the exact field
/// set the web renders -- retained bits, symbols used, chars ignored, entropy
/// hex, mnemonic, master fingerprint, and the four first-receive addresses.
/// The raw entropy hex is shown by default (foreign/throwaway raw bits, as the
/// web does); §24.3 is respected -- no seed/xprv/xpub/private-key is shown.
fn render_encoding_result(out: &mut dyn TextOutput, success: &EntropySuccess, input: &str) {
    out.clear();
    render_common_banner(out);
    out.write_line(FOREIGN_WATERMARK);
    out.write_line("");
    let n = success.word_count_n();

    out.write_line(&format!("Method:         iancoleman/bip39 RAW entropy -- {} ({METHOD_ID})", success.encoding.display_name()));
    out.write_line(&format!("Input:          {input}"));
    out.write_line(&format!("Encoding:       {}", success.encoding.display_name()));
    out.write_line(&format!("Retained bits:  {} (of {} typed)  ->  {} words", success.retained_bits, success.total_bits, n));
    out.write_line(&format!("Symbols used:   {}", success.accepted_symbols));
    out.write_line(&format!("Chars ignored:  {}", success.ignored_chars));
    out.write_line(&format!("Entropy (hex):  {}", success.entropy_hex()));
    out.write_line("");

    out.write_line(PUBLIC_TEST_PHRASE_PREFIX);
    out.write_line(&format!("Mnemonic ({n} words):"));
    let mut line = alloc_free::String::new();
    for (i, w) in success.words.iter().enumerate() {
        line.push_str(&format!("{:02} {:<12}", i + 1, w));
        if i % 6 == 5 || i + 1 == success.words.len() {
            out.write_line(line.trim_end());
            line.clear();
        }
    }
    out.write_line("");

    out.write_line("Verification values (empty passphrase; SPEC §24):");
    out.write_line(&format!("  Master fingerprint  {}", success.master_fingerprint_hex()));
    let mut addr_line = alloc_free::String::new();
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

fn handle_encoding_result_key(key: KeyMsg) -> EncodingResultAction {
    match key {
        KeyMsg::Char(c) if c.eq_ignore_ascii_case(&'p') => EncodingResultAction::CustomPath,
        _ => EncodingResultAction::Back,
    }
}

// ============================================================================
// The screen/dispatch loop (SPEC_MAIN_MENU.md §6.2-style state dispatch,
// mirroring `crate::ceremony::run`'s own `AppState` match loop)
// ============================================================================

enum Stage {
    ProfileMenu { cursor: usize },
    EventEntry { profile: &'static CompatProfile, buffer: alloc_free::String },
    WordCount { profile: &'static CompatProfile, events: alloc_free::String },
    Result { profile: &'static CompatProfile, events: alloc_free::String, requested: Option<CompatWordCount>, show_entropy: bool },
    // Method C — EntropyEncodingRaw (SPEC_COMPAT_ENTROPY.md) stages.
    EncodingMenu { cursor: usize },
    EncodingEntry { encoding: Encoding, buffer: alloc_free::String },
    EncodingResult { encoding: Encoding, input: alloc_free::String },
    Done,
}

/// The full screen/dispatch loop, over an injected `TextOutput` and an
/// injected blocking key-read closure — no `SharedFramebuffer`/
/// `ChannelKeys`/window dependency at all, so this is exercised directly
/// in `#[cfg(test)]` below (SPEC_MAIN_MENU.md §6.3). [`run`] is the only
/// caller outside tests.
fn run_over(out: &mut dyn TextOutput, mut next_key: impl FnMut() -> KeyMsg) {
    let profiles = user_profiles();
    let mut stage = Stage::ProfileMenu { cursor: 0 };
    loop {
        stage = match stage {
            Stage::ProfileMenu { cursor } => {
                render_profile_menu(out, &profiles, cursor);
                match handle_profile_key(cursor, profile_menu_len(&profiles), next_key()) {
                    ProfileNav::Highlight(c) => Stage::ProfileMenu { cursor: c },
                    ProfileNav::Activate(idx) if idx == entropy_menu_index(&profiles) => Stage::EncodingMenu { cursor: 0 },
                    ProfileNav::Activate(idx) => {
                        Stage::EventEntry { profile: profiles[idx], buffer: alloc_free::String::with_capacity(EVENT_BUFFER_CAP) }
                    }
                    ProfileNav::Quit => Stage::Done,
                    ProfileNav::None => Stage::ProfileMenu { cursor },
                }
            }
            Stage::EventEntry { profile, mut buffer } => {
                render_event_entry(out, profile, &buffer);
                match handle_entry_key(profile, &mut buffer, next_key()) {
                    EntryAction::Submit => {
                        if matches!(profile.word_count_rule, WordCountRule::FreeChoice { .. }) {
                            Stage::WordCount { profile, events: buffer }
                        } else {
                            Stage::Result { profile, events: buffer, requested: None, show_entropy: false }
                        }
                    }
                    EntryAction::Cancel => {
                        // The typed pre-image is discarded here; scrub it
                        // rather than dropping the growable buffer intact.
                        scrub_string(&mut buffer);
                        Stage::ProfileMenu { cursor: 0 }
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
                    WordCountAction::Chosen(wc) => Stage::Result { profile, events, requested: Some(wc), show_entropy: false },
                    WordCountAction::Cancel => Stage::EventEntry { profile, buffer: events },
                    WordCountAction::None => Stage::WordCount { profile, events },
                }
            }
            Stage::Result { profile, mut events, requested, show_entropy } => match compat_derive(profile, &events, requested) {
                Ok(output) => {
                    let success = finish(&events, output);
                    render_result_success(out, profile, &success, &events, show_entropy);
                    match handle_result_key(next_key()) {
                        ResultAction::ToggleEntropy => Stage::Result { profile, events, requested, show_entropy: !show_entropy },
                        ResultAction::CustomPath => {
                            // SPEC_DERIVATION_CUSTOM §9/§9.6: run the free-form
                            // custom-path tool over the THROWAWAY seed we just
                            // reproduced from the user's typed events. The seed is
                            // re-derived here (compat_derive is deterministic),
                            // borrowed for the entry/preview loop, and zeroized on
                            // return; on exit we come back to this same result screen.
                            if let Ok(o) = compat_derive(profile, &events, requested) {
                                let core_count = match o.word_count {
                                    CompatWordCount::W12 => CoreWordCount::Twelve,
                                    CompatWordCount::W24 => CoreWordCount::TwentyFour,
                                };
                                let mut seed = [0u8; 64];
                                seed_core::bip39::mnemonic_to_seed(&o.mnemonic_indexes, core_count, &mut seed);
                                custom_path::run_over(out, &mut next_key, &seed);
                                seed.zeroize();
                            }
                            Stage::Result { profile, events, requested, show_entropy }
                        }
                        ResultAction::Back => {
                            scrub_string(&mut events);
                            Stage::ProfileMenu { cursor: 0 }
                        }
                    }
                }
                Err(CompatError::Refused { entered, .. }) => {
                    render_refusal(out, profile, entered, requested.map(compat_word_count_n));
                    let _ = next_key();
                    scrub_string(&mut events);
                    Stage::ProfileMenu { cursor: 0 }
                }
                Err(_other) => {
                    render_unexpected_refusal(out);
                    let _ = next_key();
                    scrub_string(&mut events);
                    Stage::ProfileMenu { cursor: 0 }
                }
            },
            Stage::EncodingMenu { cursor } => {
                render_encoding_menu(out, cursor);
                match handle_encoding_key(cursor, Encoding::ALL.len(), next_key()) {
                    EncodingNav::Highlight(c) => Stage::EncodingMenu { cursor: c },
                    EncodingNav::Activate(idx) => {
                        Stage::EncodingEntry { encoding: Encoding::ALL[idx], buffer: alloc_free::String::with_capacity(EVENT_BUFFER_CAP) }
                    }
                    EncodingNav::Quit => Stage::ProfileMenu { cursor: entropy_menu_index(&profiles) },
                    EncodingNav::None => Stage::EncodingMenu { cursor },
                }
            }
            Stage::EncodingEntry { encoding, mut buffer } => {
                render_encoding_entry(out, encoding, &buffer);
                match handle_encoding_entry_key(&mut buffer, next_key()) {
                    EntryAction::Submit => Stage::EncodingResult { encoding, input: buffer },
                    EntryAction::Cancel => {
                        scrub_string(&mut buffer);
                        Stage::EncodingMenu { cursor: 0 }
                    }
                    EntryAction::ShowDetail => {
                        render_encoding_method_detail(out, encoding);
                        let _ = next_key();
                        Stage::EncodingEntry { encoding, buffer }
                    }
                    EntryAction::None => Stage::EncodingEntry { encoding, buffer },
                }
            }
            Stage::EncodingResult { encoding, mut input } => match entropy_encoding_derive(encoding, &input) {
                Ok(output) => {
                    let success = finish_entropy(output);
                    render_encoding_result(out, &success, &input);
                    match handle_encoding_result_key(next_key()) {
                        EncodingResultAction::CustomPath => {
                            // SPEC_DERIVATION_CUSTOM §9/§9.6: run the free-form
                            // custom-path tool over the THROWAWAY seed we just
                            // reproduced. Re-derived here (deterministic),
                            // borrowed for the entry/preview loop, zeroized on
                            // return; on exit we come back to this result screen.
                            if let Ok(o) = entropy_encoding_derive(encoding, &input) {
                                let core_count = match o.word_count {
                                    CompatWordCount::W12 => CoreWordCount::Twelve,
                                    CompatWordCount::W24 => CoreWordCount::TwentyFour,
                                };
                                let mut seed = [0u8; 64];
                                seed_core::bip39::mnemonic_to_seed(&o.mnemonic_indexes, core_count, &mut seed);
                                custom_path::run_over(out, &mut next_key, &seed);
                                seed.zeroize();
                            }
                            Stage::EncodingResult { encoding, input }
                        }
                        EncodingResultAction::Back => {
                            scrub_string(&mut input);
                            Stage::EncodingMenu { cursor: 0 }
                        }
                    }
                }
                Err(error) => {
                    render_encoding_refusal(out, encoding, error);
                    let _ = next_key();
                    scrub_string(&mut input);
                    Stage::EncodingMenu { cursor: 0 }
                }
            },
            Stage::Done => return,
        };
    }
}

/// Entry point for launcher item (2) (SPEC_MAIN_MENU.md §6.2 routing:
/// `launcher::compat::run(fb, keys)`). Takes the same
/// [`SharedFramebuffer`]/[`TextOutput`] backend and the same
/// [`ChannelKeys`] key source the ceremony and every other launcher tool
/// use — no new thread, no new channel (§4.5). Returns to the caller
/// (`crate::launcher`'s landing loop, once WP-M1 wires it in) once the
/// user backs all the way out of the profile menu (`Esc`).
pub fn run(fb: &mut SharedFramebuffer, keys: &mut ChannelKeys) {
    let mut out = WindowTextOutput::new(fb.clone());
    run_over(&mut out, || keys.recv());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unlike `crate::ceremony`'s own single-screen `RecordingOutput` (and
    /// unlike the real `WindowTextOutput`), [`clear`](TextOutput::clear)
    /// is a deliberate no-op here: this double keeps the **full
    /// transcript** of every screen `run_over` ever rendered, not just the
    /// current one, so a full-flow test (SPEC_MAIN_MENU.md §6.3: "reproduce
    /// a known seedsigner frozen compat case through the screen logic") can
    /// assert on content from an earlier screen in the flow (e.g. the
    /// result screen) even after later screens (e.g. the profile menu on
    /// the way back out) have cleared and re-rendered on top of it.
    struct RecordingOutput {
        lines: Vec<String>,
    }
    impl RecordingOutput {
        fn new() -> Self {
            Self { lines: Vec::new() }
        }
        fn joined(&self) -> String {
            self.lines.join("\n")
        }
    }
    impl TextOutput for RecordingOutput {
        fn write_line(&mut self, line: &str) {
            self.lines.push(line.to_string());
        }
        fn clear(&mut self) {}
    }

    /// Feeds a fixed script of [`KeyMsg`]s, then repeats [`KeyMsg::Escape`]
    /// forever once exhausted — mirrors [`ChannelKeys::recv`]'s own
    /// documented behavior when its sender is dropped, and guarantees
    /// [`run_over`] always terminates in a test even if the script is a
    /// little short, rather than hanging.
    struct ScriptedKeys {
        script: std::vec::IntoIter<KeyMsg>,
    }
    impl ScriptedKeys {
        fn new(keys: Vec<KeyMsg>) -> Self {
            Self { script: keys.into_iter() }
        }
        fn next(&mut self) -> KeyMsg {
            self.script.next().unwrap_or(KeyMsg::Escape)
        }
    }

    fn chars(s: &str) -> Vec<KeyMsg> {
        s.chars().map(KeyMsg::Char).collect()
    }

    // ---- pure nav/entry helper unit tests ----

    #[test]
    fn profile_key_digit_activates_matching_index() {
        assert_eq!(handle_profile_key(0, 3, KeyMsg::Char('2')), ProfileNav::Activate(1));
    }

    #[test]
    fn profile_key_out_of_range_digit_is_ignored() {
        assert_eq!(handle_profile_key(0, 3, KeyMsg::Char('9')), ProfileNav::None);
    }

    #[test]
    fn profile_key_down_wraps_around() {
        assert_eq!(handle_profile_key(2, 3, KeyMsg::Down), ProfileNav::Highlight(0));
    }

    #[test]
    fn profile_key_up_wraps_around() {
        assert_eq!(handle_profile_key(0, 3, KeyMsg::Up), ProfileNav::Highlight(2));
    }

    #[test]
    fn profile_key_escape_quits() {
        assert_eq!(handle_profile_key(0, 3, KeyMsg::Escape), ProfileNav::Quit);
    }

    #[test]
    fn entry_key_filters_out_of_alphabet_characters() {
        let profile = seed_compat::profile("seedsigner-dice").unwrap();
        let mut buffer = String::new();
        assert_eq!(handle_entry_key(profile, &mut buffer, KeyMsg::Char('7')), EntryAction::None);
        assert_eq!(buffer, "", "an out-of-alphabet character must never reach the buffer");
        assert_eq!(handle_entry_key(profile, &mut buffer, KeyMsg::Char('3')), EntryAction::None);
        assert_eq!(buffer, "3");
    }

    #[test]
    fn entry_key_backspace_undoes() {
        let profile = seed_compat::profile("seedsigner-dice").unwrap();
        let mut buffer = String::from("12");
        handle_entry_key(profile, &mut buffer, KeyMsg::Backspace);
        assert_eq!(buffer, "1");
    }

    #[test]
    fn entry_key_enter_on_empty_buffer_does_not_submit() {
        let profile = seed_compat::profile("seedsigner-dice").unwrap();
        let mut buffer = String::new();
        assert_eq!(handle_entry_key(profile, &mut buffer, KeyMsg::Enter), EntryAction::None);
    }

    #[test]
    fn entry_key_enter_on_nonempty_buffer_submits() {
        let profile = seed_compat::profile("seedsigner-dice").unwrap();
        let mut buffer = String::from("1");
        assert_eq!(handle_entry_key(profile, &mut buffer, KeyMsg::Enter), EntryAction::Submit);
    }

    #[test]
    fn coin_alphabet_rejects_dice_digits() {
        let profile = seed_compat::profile("seedsigner-coin").unwrap();
        let mut buffer = String::new();
        assert_eq!(handle_entry_key(profile, &mut buffer, KeyMsg::Char('2')), EntryAction::None);
        assert_eq!(buffer, "");
        handle_entry_key(profile, &mut buffer, KeyMsg::Char('0'));
        assert_eq!(buffer, "0");
    }

    // ---- banner presence on every screen (SPEC_COMPAT §7/§8, SPEC_MAIN_MENU.md §15 OQ1) ----

    #[test]
    fn banner_present_on_profile_menu() {
        let mut out = RecordingOutput::new();
        render_profile_menu(&mut out, &user_profiles(), 0);
        assert!(out.joined().contains(RESULT_WATERMARK));
        assert!(out.joined().contains(MODE_BANNER_LINE_1));
    }

    #[test]
    fn banner_present_on_event_entry_screen() {
        let mut out = RecordingOutput::new();
        render_event_entry(&mut out, seed_compat::profile("seedsigner-dice").unwrap(), "123");
        assert!(out.joined().contains(RESULT_WATERMARK));
    }

    /// The persistent-header-panel property this task delivers: the
    /// merged event-entry screen shows the method info (algorithm
    /// summary, source citation) AND the live typed buffer on the SAME
    /// render, not on two screens the user must page between. Would fail
    /// against the old two-screen structure, where the entry screen never
    /// rendered `Source:` content at all.
    ///
    /// Review fix (Task 19): caveats are NOT asserted here any more --
    /// they moved to the `[?]` detail screen (see
    /// `method_detail_screen_shows_every_caveat` below) so the entry
    /// screen's header stays a small, fixed size regardless of a
    /// profile's caveat count (the earlier all-in-one-header version of
    /// this screen pushed the input echo line off the SPEC §11.4
    /// 800x600-floor budget for `coldcard-dice`).
    #[test]
    fn event_entry_screen_shows_method_info_and_typed_buffer_together() {
        let profile = seed_compat::profile("coldcard-dice").unwrap();
        let mut out = RecordingOutput::new();
        render_event_entry(&mut out, profile, "123");
        let joined = out.joined();
        assert!(joined.contains(&format!("Emulating: {}", profile.display_name)), "missing method header in:\n{joined}");
        assert!(joined.contains("Method:"), "missing compact algorithm summary in:\n{joined}");
        assert!(joined.contains(&format!("Source:    {}", profile.source_url)), "missing source citation in:\n{joined}");
        assert!(joined.contains("  123_"), "missing the live typed buffer in:\n{joined}");
    }

    /// The `[?]` detail screen carries the FULL method content the entry
    /// header no longer does (nothing dropped): every caveat still
    /// renders, just on-demand instead of always-drawn.
    #[test]
    fn method_detail_screen_shows_every_caveat() {
        let profile = seed_compat::profile("coldcard-dice").unwrap();
        let mut out = RecordingOutput::new();
        render_method_detail(&mut out, profile);
        let joined = out.joined();
        for c in profile.caveats {
            assert!(joined.contains(c), "missing caveat {c:?} in:\n{joined}");
        }
    }

    #[test]
    fn question_mark_opens_detail_on_the_profile_entry_screen_without_touching_the_buffer() {
        let profile = seed_compat::profile("coldcard-dice").unwrap();
        let mut buffer = String::from("123");
        let action = handle_entry_key(profile, &mut buffer, KeyMsg::Char('?'));
        assert_eq!(action, EntryAction::ShowDetail);
        assert_eq!(buffer, "123", "buffer must be untouched by the [?] key");
    }

    #[test]
    fn question_mark_opens_detail_on_the_encoding_entry_screen_without_touching_the_buffer() {
        let mut buffer = String::from("ab");
        let action = handle_encoding_entry_key(&mut buffer, KeyMsg::Char('?'));
        assert_eq!(action, EntryAction::ShowDetail);
        assert_eq!(buffer, "ab", "buffer must be untouched by the [?] key");
    }

    // -- Review fix: the entry screens' TOTAL line count (header + entry
    // UI, including the input echo and count-feedback rows) must fit the
    // SPEC §11.4 800x600-floor budget for every user-facing profile/
    // encoding -- SPEC_WALLET_PREVIEW §3.3.1's "one layout, both
    // canvases" rule means this desktop edition's screens are held to the
    // same fixed-layout budget as the UEFI floor even though its own
    // 1024x768 canvas has more physical room, so this crate's compat.rs
    // and `alea-verify/src/verify.rs` stay the identical layout. ---------

    #[test]
    fn event_entry_fits_the_800x600_floor_with_the_echo_and_count_rows_visible_for_every_profile() {
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        for id in ["coldcard-dice", "seedsigner-dice", "seedsigner-coin"] {
            let profile = seed_compat::profile(id).unwrap();
            let mut out = RecordingOutput::new();
            render_event_entry(&mut out, profile, "123456789");
            assert!(
                out.lines.len() <= max_lines,
                "{id}: entry screen renders {} lines, exceeds the {max_lines}-line floor budget",
                out.lines.len()
            );
            let joined = out.joined();
            assert!(joined.contains("123456789_"), "{id}: input echo row missing/off-screen");
            assert!(joined.contains("entered so far"), "{id}: count-feedback row missing/off-screen");
        }
    }

    #[test]
    fn encoding_entry_fits_the_800x600_floor_with_the_echo_and_count_rows_visible_for_every_encoding() {
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        for encoding in Encoding::ALL {
            let mut out = RecordingOutput::new();
            render_encoding_entry(&mut out, encoding, "abc123");
            assert!(
                out.lines.len() <= max_lines,
                "{}: encoding entry screen renders {} lines, exceeds the {max_lines}-line floor budget",
                encoding.display_name(),
                out.lines.len()
            );
            let joined = out.joined();
            assert!(joined.contains("abc123_"), "{}: input echo row missing/off-screen", encoding.display_name());
            assert!(joined.contains("entered so far"), "{}: count-feedback row missing/off-screen", encoding.display_name());
        }
    }

    #[test]
    fn method_detail_fits_the_800x600_floor_for_every_profile_including_the_worst_case() {
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        for id in ["coldcard-dice", "seedsigner-dice", "seedsigner-coin"] {
            let profile = seed_compat::profile(id).unwrap();
            let mut out = RecordingOutput::new();
            render_method_detail(&mut out, profile);
            assert!(
                out.lines.len() <= max_lines,
                "{id}: method detail renders {} lines, exceeds the {max_lines}-line floor budget",
                out.lines.len()
            );
        }
    }

    #[test]
    fn encoding_method_detail_fits_the_800x600_floor_for_every_encoding_including_cards() {
        let max_lines = seed_gop_ui::layout::MAX_LINES_AT_FLOOR;
        for encoding in Encoding::ALL {
            let mut out = RecordingOutput::new();
            render_encoding_method_detail(&mut out, encoding);
            assert!(
                out.lines.len() <= max_lines,
                "{}: encoding method detail renders {} lines, exceeds the {max_lines}-line floor budget",
                encoding.display_name(),
                out.lines.len()
            );
        }
    }

    #[test]
    fn banner_present_on_word_count_screen() {
        let mut out = RecordingOutput::new();
        render_word_count_choice(&mut out, seed_compat::profile("coldcard-dice").unwrap(), "123456");
        assert!(out.joined().contains(RESULT_WATERMARK));
    }

    #[test]
    fn banner_present_on_refusal_screen() {
        let mut out = RecordingOutput::new();
        render_refusal(&mut out, seed_compat::profile("seedsigner-dice").unwrap(), 40, None);
        assert!(out.joined().contains(RESULT_WATERMARK));
    }

    #[test]
    fn banner_present_on_result_screen() {
        let p = seed_compat::profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        let out_derived = compat_derive(p, events, None).unwrap();
        let success = finish(events, out_derived);
        let mut out = RecordingOutput::new();
        render_result_success(&mut out, p, &success, events, false);
        assert!(out.joined().contains(RESULT_WATERMARK));
    }

    // ---- refusal rendering never carries a mnemonic word (review F1) ----

    #[test]
    fn refusal_screen_never_renders_a_mnemonic() {
        let mut out = RecordingOutput::new();
        render_refusal(&mut out, seed_compat::profile("seedsigner-dice").unwrap(), 40, None);
        let joined = out.joined();
        assert!(joined.contains("REFUSED"));
        assert!(!joined.contains("Mnemonic"));
    }

    // ---- no-concatenation discipline (SPEC_COMPAT §7, review F7) ----

    #[test]
    fn result_screen_omits_entropy_hex_by_default() {
        let p = seed_compat::profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        let out_derived = compat_derive(p, events, None).unwrap();
        let success = finish(events, out_derived);
        let mut out = RecordingOutput::new();
        render_result_success(&mut out, p, &success, events, false);
        assert!(!out.joined().contains("Entropy hex ("));
    }

    #[test]
    fn result_screen_shows_entropy_hex_only_when_toggled() {
        let p = seed_compat::profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        let out_derived = compat_derive(p, events, None).unwrap();
        let success = finish(events, out_derived);
        let mut out = RecordingOutput::new();
        render_result_success(&mut out, p, &success, events, true);
        assert!(out.joined().contains("Entropy hex ("));
        assert!(out.joined().contains(&success.entropy_hex()));
    }

    // ---- full-flow tests over the injected key/output seam (SPEC_MAIN_MENU.md §6.3) ----

    /// Host DoD test: "reproduce a known seedsigner frozen compat case
    /// through the screen logic (mock IO)". Uses SPEC_COMPAT §5.1.2's own
    /// published 99-roll vendor cross-check example (also pinned in
    /// `seed-compat`'s own `seedsigner_dice_99_rolls_vendor_example_24w`
    /// test) driven entirely through [`run_over`]'s scripted key seam.
    #[test]
    fn reproduces_known_seedsigner_frozen_case_through_screen_logic() {
        let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
        assert_eq!(events.len(), 99);

        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('2')); // profile menu: [2] SeedSigner -- dice -> straight to event entry
        keys.extend(chars(events)); // type every roll
        keys.push(KeyMsg::Enter); // submit (DerivedFromLength: straight to result)
        keys.push(KeyMsg::Escape); // result screen: back to profile menu
        keys.push(KeyMsg::Escape); // profile menu: quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        for word in ["eyebrow", "obvious", "such", "suggest", "radio"] {
            assert!(joined.contains(word), "missing expected mnemonic word {word:?} in:\n{joined}");
        }
        assert!(joined.contains(RESULT_WATERMARK));
        assert!(joined.contains(PUBLIC_TEST_PHRASE_PREFIX));
        // No-concatenation discipline held throughout the whole scripted run.
        assert!(!joined.contains("Entropy hex ("));
    }

    /// Host DoD test: "a non-canonical count shows the refusal".
    #[test]
    fn non_canonical_count_shows_the_refusal_through_screen_logic() {
        let events = "1".repeat(40); // seedsigner-dice canonical counts are 50/99

        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('2')); // [2] SeedSigner -- dice -> straight to event entry
        keys.extend(chars(&events));
        keys.push(KeyMsg::Enter); // submit -> refused
        keys.push(KeyMsg::Enter); // acknowledge refusal -> back to profile menu
        keys.push(KeyMsg::Escape); // quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        assert!(joined.contains("REFUSED"), "expected a refusal screen in:\n{joined}");
        assert!(joined.contains("40 rolls"));
        // The F1 property: a refusal must never carry a rendered mnemonic.
        assert!(!joined.contains("Mnemonic ("));
    }

    /// The F1 "phantom pairing" case (SPEC_COMPAT §7's own literal
    /// example): a canonical 99-roll length explicitly requested as 12
    /// words on a `FreeChoice`-adjacent... no, `DerivedFromLength` profile
    /// is refused, never silently coerced. This screen never exposes a
    /// `--words`-style toggle for `DerivedFromLength` profiles (word count
    /// is always derived automatically here), so this is exercised at the
    /// `compat_derive`/`finish` layer directly, matching the library-level
    /// regression `seed-compat` itself already carries.
    #[test]
    fn library_level_f1_phantom_pairing_stays_refused() {
        let p = seed_compat::profile("seedsigner-dice").unwrap();
        let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
        match compat_derive(p, events, Some(CompatWordCount::W12)) {
            Err(CompatError::Refused { entered, .. }) => assert_eq!(entered, 99),
            other => panic!("expected Refused, got a mnemonic-bearing outcome: {}", other.is_ok()),
        }
    }

    /// COLDCARD (`FreeChoice`) end-to-end: profile pick -> event entry
    /// (method info shown as its header) -> word-count choice -> result,
    /// entirely through the screen logic.
    #[test]
    fn coldcard_free_choice_flow_reaches_a_result() {
        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('1')); // [1] COLDCARD -- dice -> straight to event entry
        keys.extend(chars("123456"));
        keys.push(KeyMsg::Enter); // submit -> word-count choice (FreeChoice)
        keys.push(KeyMsg::Char('1')); // 12 words
        keys.push(KeyMsg::Escape); // result screen: back to profile menu
        keys.push(KeyMsg::Escape); // quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        assert!(joined.contains("mirror"), "expected the coldcard-dice 12w vendor-cross-check word in:\n{joined}");
        assert!(joined.contains("Word count:     12 (your choice)"));
    }

    /// Esc at the very top of the profile menu returns from [`run_over`]
    /// immediately (SPEC_MAIN_MENU.md §4.5/§6.2: "returns to the launcher"),
    /// without ever rendering a second screen.
    #[test]
    fn escape_at_profile_menu_returns_immediately() {
        let mut scripted = ScriptedKeys::new(std::vec![KeyMsg::Escape]);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());
        assert!(out.joined().contains("Choose the device and method to reproduce"));
        assert!(!out.joined().contains("Emulating:"), "must not have entered the event entry screen");
    }

    /// The three user-facing Method-A dice/coin profiles are offered, plus the
    /// synthetic Method-C entropy-encoding row. The internal `iancoleman-hex`
    /// digest oracle (SPEC_COMPAT §5.1.4/§7) is still never surfaced as a
    /// Method-A profile — the "iancoleman-style" wording that now legitimately
    /// appears belongs to the Method-C (raw-entropy) row, not to that oracle.
    #[test]
    fn the_three_profiles_plus_the_entropy_encoding_row_are_offered() {
        let mut out = RecordingOutput::new();
        render_profile_menu(&mut out, &user_profiles(), 0);
        let joined = out.joined();
        assert!(joined.contains("COLDCARD"));
        assert!(joined.contains("SeedSigner -- dice"));
        assert!(joined.contains("SeedSigner -- coin flips"));
        assert!(joined.contains("Entropy encodings (iancoleman-style raw entropy)"));
        assert!(!joined.contains("iancoleman-hex"));
    }

    // ---- Method C (EntropyEncodingRaw) — SPEC_COMPAT_ENTROPY.md ----

    /// The four-row profile menu routes [4] to the encoding submenu, which
    /// lists all six encodings in `Encoding::ALL` order.
    #[test]
    fn profile_menu_row_four_opens_the_six_encoding_submenu() {
        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('4')); // profile menu: [4] entropy encodings
        keys.push(KeyMsg::Escape); // encoding menu: back to profile list
        keys.push(KeyMsg::Escape); // profile menu: quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        for label in ["Binary [0-1]", "Base-6 [0-5]", "Dice [1-6]", "Base-10 [0-9]", "Hex [0-9A-F]", "Cards"] {
            assert!(joined.contains(label), "missing encoding label {label:?} in:\n{joined}");
        }
    }

    /// KNOWN VECTOR cross-check (task DoD): Hex `00`×16 (= 128 zero bits) ->
    /// `abandon abandon ... about` -> BIP84 first receive
    /// `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`, matching the web/CLI and
    /// `seed-compat`'s own `binary_zero_128_is_abandon_about` anchor. Driven
    /// entirely through the scripted key/output seam. Hex encoding is
    /// `Encoding::ALL[4]`, i.e. menu key `5`.
    #[test]
    fn reproduces_known_hex_zero_entropy_vector_through_screen_logic() {
        let input = "00000000000000000000000000000000"; // 32 hex chars = 128 bits
        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('4')); // profile menu: [4] entropy encodings
        keys.push(KeyMsg::Char('5')); // encoding menu: [5] Hex -> straight to encoding entry
        keys.extend(chars(input)); // type the 32 hex zeros
        keys.push(KeyMsg::Enter); // submit -> result
        keys.push(KeyMsg::Escape); // result: back to encoding menu
        keys.push(KeyMsg::Escape); // encoding menu: back to profile list
        keys.push(KeyMsg::Escape); // profile menu: quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        assert!(joined.contains("abandon"), "missing abandon in:\n{joined}");
        assert!(joined.contains("about"), "missing about in:\n{joined}");
        assert!(joined.contains("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), "missing BIP84 first receive in:\n{joined}");
        assert!(joined.contains(FOREIGN_WATERMARK), "foreign-material watermark must be on the result screen");
        assert!(joined.contains("Retained bits:  128"));
        assert!(joined.contains("Symbols used:   32"));
        assert!(joined.contains("Chars ignored:  0"));
        // Entropy hex is shown by default on this foreign/throwaway path.
        assert!(joined.contains("00000000000000000000000000000000"));
    }

    /// Refusal path (task DoD): a non-{128,256} retained length is refused,
    /// naming iancoleman's non-standard N-word divergence, and NEVER paired
    /// with a rendered mnemonic. 160 binary `1` bits -> retained 160 -> a
    /// 15-word iancoleman phrase (matching `seed-compat`'s own
    /// `refuses_non_standard_160_bit_length_naming_divergence`). Binary is
    /// `Encoding::ALL[0]`, i.e. menu key `1`.
    #[test]
    fn non_standard_length_shows_the_refusal_through_screen_logic() {
        let input = "1".repeat(160);
        let mut keys = Vec::new();
        keys.push(KeyMsg::Char('4')); // [4] entropy encodings
        keys.push(KeyMsg::Char('1')); // [1] Binary -> straight to encoding entry
        keys.extend(chars(&input));
        keys.push(KeyMsg::Enter); // submit -> refused
        keys.push(KeyMsg::Enter); // acknowledge refusal -> encoding menu
        keys.push(KeyMsg::Escape); // encoding menu: back to profiles
        keys.push(KeyMsg::Escape); // quit

        let mut scripted = ScriptedKeys::new(keys);
        let mut out = RecordingOutput::new();
        run_over(&mut out, || scripted.next());

        let joined = out.joined();
        assert!(joined.contains("REFUSED"), "expected a refusal in:\n{joined}");
        assert!(joined.contains("160 retained bits"));
        assert!(joined.contains("15-word NON-STANDARD phrase"));
        // The refusal must never carry a rendered mnemonic.
        assert!(!joined.contains("Mnemonic ("));
    }

    /// An empty submit never leaves the entry screen (mirrors Method A's
    /// non-empty-submit rule).
    #[test]
    fn encoding_entry_enter_on_empty_buffer_does_not_submit() {
        let mut buffer = String::new();
        assert_eq!(handle_encoding_entry_key(&mut buffer, KeyMsg::Enter), EntryAction::None);
    }

    /// The free-form entry accepts any typed character (full keyboard) — hex
    /// letters, card ranks/suits, separators — deferring the alphabet match to
    /// the derive call (SPEC_COMPAT_ENTROPY §5.1/§9).
    #[test]
    fn encoding_entry_accepts_arbitrary_keyboard_characters() {
        let mut buffer = String::new();
        for c in ['a', 'F', '9', ' ', 'K', 'S'] {
            assert_eq!(handle_encoding_entry_key(&mut buffer, KeyMsg::Char(c)), EntryAction::None);
        }
        assert_eq!(buffer, "aF9 KS");
    }

    /// §24.3 (task DoD): the Method-C result screen never names a secret
    /// artifact (no seed/xprv/xpub/private-key/chain-code), even though it does
    /// show the foreign/throwaway raw entropy hex.
    #[test]
    fn encoding_result_never_mentions_secret_artifacts() {
        let out_derived = entropy_encoding_derive(Encoding::Hex, "00000000000000000000000000000000").unwrap();
        let success = finish_entropy(out_derived);
        let mut out = RecordingOutput::new();
        render_encoding_result(&mut out, &success, "00000000000000000000000000000000");
        let joined = out.joined().to_lowercase();
        for bad in ["xprv", "xpub", "private key", "chain code", "seed phrase", "master key"] {
            assert!(!joined.contains(bad), "result must never mention {bad}");
        }
        // But the foreign watermark and the public-throwaway framing are present.
        assert!(out.joined().contains(FOREIGN_WATERMARK));
    }

    /// The foreign-material watermark and the honesty caveat are present on
    /// the Method-C menu, entry, `[?]` detail, and result screens
    /// (SPEC_COMPAT_ENTROPY §2/§9).
    ///
    /// Review fix (Task 19): the honesty caveat moved off the always-drawn
    /// entry-screen header onto the `[?]` detail screen (see
    /// `render_encoding_method_detail`) — `render_common_banner`'s
    /// `RESULT_WATERMARK` line is still on every screen including entry,
    /// but `ENTROPY_HONESTY_CAVEAT` is asserted against the menu and the
    /// detail screen now, not the entry screen.
    #[test]
    fn foreign_watermark_and_caveat_present_on_method_c_screens() {
        let mut menu = RecordingOutput::new();
        render_encoding_menu(&mut menu, 0);
        assert!(menu.joined().contains(RESULT_WATERMARK));
        assert!(menu.joined().contains(ENTROPY_HONESTY_CAVEAT[0]));

        let mut entry = RecordingOutput::new();
        render_encoding_entry(&mut entry, Encoding::Hex, "");
        assert!(entry.joined().contains(RESULT_WATERMARK));

        let mut detail = RecordingOutput::new();
        render_encoding_method_detail(&mut detail, Encoding::Hex);
        assert!(detail.joined().contains(ENTROPY_HONESTY_CAVEAT[0]));

        let out_derived = entropy_encoding_derive(Encoding::Hex, "00000000000000000000000000000000").unwrap();
        let success = finish_entropy(out_derived);
        let mut result = RecordingOutput::new();
        render_encoding_result(&mut result, &success, "00000000000000000000000000000000");
        assert!(result.joined().contains(FOREIGN_WATERMARK));
    }

    /// The encoding submenu Esc returns to the profile list with the entropy
    /// row highlighted (never escaping straight out of the tool).
    #[test]
    fn escape_on_encoding_menu_returns_to_profile_list() {
        assert_eq!(handle_encoding_key(0, 6, KeyMsg::Escape), EncodingNav::Quit);
        assert_eq!(handle_encoding_key(0, 6, KeyMsg::Char('5')), EncodingNav::Activate(4));
        assert_eq!(handle_encoding_key(0, 6, KeyMsg::Down), EncodingNav::Highlight(1));
        assert_eq!(handle_encoding_key(0, 6, KeyMsg::Up), EncodingNav::Highlight(5));
    }
}
