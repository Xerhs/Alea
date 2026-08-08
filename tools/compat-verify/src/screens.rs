//! Screen text builders (SPEC_COMPAT §7, §8; IMPLEMENTATION_MAP_COMPAT.md
//! §4 WP-C4).
//!
//! Every function here returns an owned `String` so `main.rs` can print it
//! and `tests/frozen_corpus.rs` can assert against it verbatim. Text
//! matches SPEC_COMPAT §7's templates exactly where the spec gives a
//! literal example (the profile menu, the `seedsigner-dice` method screen,
//! the "99 rolls asked as 12 words" refusal, and the 99-roll result
//! screen); the `coldcard-dice` / `seedsigner-coin` method and refusal
//! screens follow the same structure, built from each profile's own
//! `CompatProfile` record (SPEC_COMPAT §6) rather than being duplicated by
//! hand, so they can never drift from the reviewed profile table.

use seed_compat::entropy_encoding::{Encoding, EntropyEncodingError, METHOD_ID};
use seed_compat::{CompatProfile, WordCountRule, PROFILES};

use crate::derive::{event_noun, is_derived_from_length, EntropySuccess, Success};

/// SPEC_COMPAT §8: the permanent, non-removable banner every screen and
/// every CLI invocation carries. No setting, flag, or environment variable
/// removes it (SPEC_COMPAT §8 requirement list).
pub const MODE_BANNER: &str = "COMPATIBILITY / VERIFICATION MODE — reproduces another vendor's method —\nNOT Alea generation — public/throwaway seeds only";

/// SPEC_COMPAT §7/§8: the result-screen watermark line, verbatim.
pub const RESULT_WATERMARK: &str =
    "[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED — PUBLIC/THROWAWAY]";

/// SPEC_COMPAT §8: the mnemonic-prefix warning (SPEC §4.2 wording reused).
pub const PUBLIC_TEST_PHRASE_PREFIX: &str = "PUBLIC TEST PHRASE — NEVER USE WITH FUNDS";

/// SPEC_COMPAT §7: the profile menu, offering ONLY the three user-facing
/// profiles (`coldcard-dice`, `seedsigner-dice`, `seedsigner-coin`) --
/// `iancoleman-hex` is an internal digest oracle only and is never listed
/// here (SPEC_COMPAT §5.1.4, §7; `seed_compat::profile` already excludes
/// it, and this function additionally never reads `PROFILES` directly for
/// the menu, only the three fixed lines below, so an `iancoleman-hex`
/// table entry can never leak into the menu even if `profile()`'s
/// filtering were ever weakened).
pub fn profile_menu() -> String {
    [
        "COMPATIBILITY VERIFICATION  —  audit another wallet's dice/coin math",
        "This does NOT generate an Alea seed. Test/throwaway seeds only.",
        "",
        "Choose the device and method to reproduce:",
        "  [1] COLDCARD — dice (SHA256 of rolls; you pick 12 or 24 words)",
        "  [2] SeedSigner — dice (SHA256 of rolls; 50 rolls = 12 words, 99 = 24 words)",
        "  [3] SeedSigner — coin flips (SHA256 of flips; 128 = 12 words, 256 = 24 words)",
    ]
    .join("\n")
}

/// Source citation lines rendered verbatim on the method screen
/// (SPEC_COMPAT §5.1, §7 "Source:" field). Pinned per profile id, matching
/// the exact URLs SPEC_COMPAT §5.1.1/§5.1.2/§5.1.3 cite.
fn source_lines(profile: &CompatProfile) -> &'static [&'static str] {
    match profile.id {
        "coldcard-dice" => &[
            "coldcard.com/docs/verifying-dice-roll-math/",
            "coldcard.com/docs/rolls.py, coldcard.com/docs/rolls12.py",
        ],
        "seedsigner-dice" | "seedsigner-coin" => &[
            "github.com/SeedSigner/seedsigner .../mnemonic_generation.py",
            "github.com/SeedSigner/seedsigner .../tools/mnemonic.py",
        ],
        _ => &[],
    }
}

/// SPEC_COMPAT §7: the method screen, shown before any event entry --
/// exact algorithm, word-count rule, citation, and caveats, so the user is
/// never trusting an opaque emulation. For a `DerivedFromLength` profile it
/// states plainly that non-canonical counts are refused (review F1).
///
/// The `seedsigner-dice` case reproduces SPEC_COMPAT §7's literal example
/// verbatim (`tests/frozen_corpus.rs` pins this).
pub fn method_screen(profile: &CompatProfile) -> String {
    let noun = event_noun(profile);
    let mut out = String::new();
    out.push_str(&format!("Emulating: {}\n", profile.display_name));
    match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => {
            let lines = [
                format!("Method:    entropy = SHA256( ASCII of your {} digits )", singular(noun)),
                format!("           WORD COUNT IS SET BY THE NUMBER OF {}:", noun.to_uppercase()),
                format!("             exactly {len12} {noun} -> 12 words (first 16 bytes of the digest)"),
                format!("             exactly {len24} {noun} -> 24 words (full digest)"),
                format!("             any other count  -> your {} REFUSES it, and so does this", profile.vendor),
                "           then standard BIP39 (SPEC §14)".to_string(),
            ];
            out.push_str(&lines.join("\n"));
            out.push('\n');
        }
        WordCountRule::FreeChoice { advisory_min_12, advisory_min_24 } => {
            let lines = [
                format!("Method:    entropy = SHA256( ASCII of your {} digits )", singular(noun)),
                format!("           YOU CHOOSE THE WORD COUNT ({} runs a separate script for each):", profile.vendor),
                "             12 words -> first 16 bytes of the digest".to_string(),
                "             24 words -> full digest".to_string(),
                format!("             {advisory_min_12}/{advisory_min_24} {noun} are advisory minimums only, not enforced"),
                "           then standard BIP39 (SPEC §14)".to_string(),
            ];
            out.push_str(&lines.join("\n"));
            out.push('\n');
        }
    }
    let src = source_lines(profile);
    if let Some((first, rest)) = src.split_first() {
        out.push_str(&format!("Source:    {first}\n"));
        for line in rest {
            out.push_str(&format!("           {line}\n"));
        }
    }
    out.push_str("Caveats:   ");
    for (i, c) in profile.caveats.iter().enumerate() {
        if i > 0 {
            out.push_str("\n           ");
        }
        out.push_str(c);
    }
    out.push('\n');
    out.push_str("This proves the DOCUMENTED math, not that your device's firmware is honest.");
    out
}

fn singular(noun: &str) -> &'static str {
    match noun {
        "rolls" => "roll",
        "flips" => "flip",
        _ => noun_leak(noun),
    }
}

// Defensive fallback -- `event_noun` only ever returns "rolls"/"flips"
// today (SPEC_COMPAT §5.1: dice or coin alphabets only), so this is
// unreachable in practice; kept explicit rather than panicking (SPEC §13/
// §27.3 discipline extended to this host tool).
fn noun_leak(_noun: &str) -> &'static str {
    "event"
}

/// SPEC_COMPAT §7/§11.1 (review F1/F5): the refusal message for a
/// `DerivedFromLength` profile given a non-canonical event count, or a
/// canonical count paired with a disagreeing `--words` request. Never
/// paired with a rendered mnemonic (SPEC_COMPAT §3: `CompatError::Refused`
/// is a distinct outcome from success).
///
/// `requested_words` is `Some(12|24)` only for the "phantom pairing" case
/// (a canonical length asked for the *other* word count); SPEC_COMPAT §7's
/// literal example is exactly this case for `seedsigner-dice` at 99 rolls
/// asked as 12 words, reproduced verbatim below
/// (`tests/frozen_corpus.rs` pins this).
pub fn refusal_screen(profile: &CompatProfile, entered: u16, requested_words: Option<u16>) -> String {
    let noun = event_noun(profile);
    let (len12, len24) = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { len12, len24 } => (len12, len24),
        WordCountRule::FreeChoice { .. } => {
            return format!(
                "REFUSED: {vendor} requires you to choose 12 or 24 words explicitly.\n\
This profile's word count is a free choice, not derived from the {noun} count\n\
(pass --words 12 or --words 24).\n\
(This tool refuses the same ambiguity the device's own scripts require you to resolve.)",
                vendor = profile.display_name,
                noun = singular(noun),
            );
        }
    };

    let mut out = String::new();
    match requested_words {
        Some(w) => {
            out.push_str(&format!(
                "REFUSED: {entered} {noun} cannot produce {w} words on {vendor}.\n",
                vendor = profile.vendor,
            ));
        }
        None => {
            out.push_str(&format!(
                "REFUSED: {entered} {noun} is not a canonical {noun_singular} count for {vendor}.\n",
                vendor = profile.vendor,
                noun_singular = singular(noun),
            ));
        }
    }
    out.push_str(&format!(
        "{vendor} sets word count from the {noun_singular} count: {len12} -> 12 words, {len24} -> 24 words,\n\
and it refuses any other number of {noun}. Enter exactly {len12} or {len24} {noun}.\n\
(This tool refuses the same inputs the device refuses, on purpose.)",
        vendor = profile.vendor,
        noun_singular = singular(noun),
    ));
    out
}

/// SPEC_COMPAT §7's permitted claim (§4.3), profile-specific closing lines
/// for the result screen.
fn closing_claim(profile: &CompatProfile) -> String {
    format!(
        "This equals what {vendor}'s PUBLISHED algorithm produces for these events.\n\
If your {vendor} shows the same words, its {method} math matched for THIS input.\n\
It does NOT prove the device's firmware, secure element, or RNG are honest.",
        vendor = profile.vendor,
        method = if profile.coins_supported && profile.alphabet == seed_compat::EventAlphabet::Coin01 {
            "coin"
        } else {
            "dice"
        },
    )
}

/// Word-wrap `events` into fixed-width lines the way SPEC_COMPAT §7's
/// result-screen example does (two lines, second indented to align under
/// the first), so long strings do not overflow a terminal.
fn wrap_events(events: &str, width: usize) -> String {
    let bytes = events.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut first = true;
    while i < bytes.len() {
        let end = (i + width).min(bytes.len());
        if !first {
            out.push_str("\n                ");
        }
        out.push_str(&events[i..end]);
        i = end;
        first = false;
    }
    out
}

/// SPEC_COMPAT §7/§8: the result screen. Entropy hex is rendered ONLY when
/// `show_entropy` is `true` (review F7 -- no default concatenation of
/// entropy hex with the mnemonic, even for these declared-public/throwaway
/// values).
pub fn result_screen(success: &Success, events: &str, show_entropy: bool) -> String {
    let profile = success.profile;
    let n = success.word_count_n();
    let noun = event_noun(profile);

    let mut out = String::new();
    out.push_str(RESULT_WATERMARK);
    out.push_str("\n\n");

    out.push_str(&format!(
        "Device/method:  {} (SHA256 of {})\n",
        profile.display_name, noun
    ));
    out.push_str(&format!(
        "Events entered: {}   ({} {})\n",
        wrap_events(events, 56),
        success.used_len,
        noun
    ));
    let word_count_line = match profile.word_count_rule {
        WordCountRule::DerivedFromLength { .. } => {
            format!("Word count:     {n} (derived from {} {noun})", success.used_len)
        }
        WordCountRule::FreeChoice { .. } => format!("Word count:     {n} (your choice)"),
    };
    out.push_str(&word_count_line);
    out.push_str("\n\n");

    out.push_str(PUBLIC_TEST_PHRASE_PREFIX);
    out.push('\n');
    out.push_str(&format!("Mnemonic ({n} words):\n"));
    let words = success.words_slice();
    for (i, w) in words.iter().enumerate() {
        if i % 6 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str("  ");
        }
        out.push_str(&format!("{:02} {:<12}", i + 1, w));
    }
    out.push_str("\n\n");

    out.push_str("Verification values (empty passphrase; SPEC §24):\n");
    out.push_str(&format!(
        "  Master fingerprint  {}\n",
        success.master_fingerprint_hex()
    ));
    out.push_str("  ");
    for (i, addr) in success.addresses.iter().enumerate() {
        if i > 0 {
            out.push_str("   ");
        }
        out.push_str(&format!("{} {}", addr.label, addr.as_str()));
    }
    out.push_str("\n\n");

    if show_entropy {
        out.push_str(&format!("Entropy hex ({} bytes): {}\n", success.entropy_len, success.entropy_hex()));
        out.push_str("(Preimage is SHA256 over the ASCII string above. This is a PUBLIC test value.)\n\n");
    } else {
        out.push_str(
            "(Preimage is SHA256 over the ASCII string above. Entropy hex is a PUBLIC test\n\
 value, shown only on explicit request: `compat-verify run ... --show-entropy`.)\n\n",
        );
    }

    out.push_str(&closing_claim(profile));
    out
}

/// Confirms `id` names one of `seed_compat::PROFILES`' three user-facing
/// entries (used by `main.rs` for a friendlier "unknown profile" error that
/// lists valid ids, matching the exact menu SPEC_COMPAT §7 defines).
pub fn known_profile_ids() -> impl Iterator<Item = &'static str> {
    PROFILES
        .iter()
        .filter(|p| seed_compat::profile(p.id).is_some())
        .map(|p| p.id)
}

pub fn derived_from_length_note(profile: &CompatProfile) -> bool {
    is_derived_from_length(profile)
}

// ===========================================================================
// Method C — EntropyEncodingRaw screens (SPEC_COMPAT_ENTROPY.md §7, §9)
// ===========================================================================

/// SPEC_COMPAT_ENTROPY §2 item 4 / §9: the honesty caveat that MUST appear
/// at the point of entry AND on the result screen. Typed entropy is not
/// witnessed randomness — use this to *confirm* a seed another tool made,
/// never to *create* one you will fund.
pub const ENTROPY_HONESTY_CAVEAT: &str = "Typed entropy is only as strong as the true randomness of whatever produced it —\n\
this tool cannot witness or verify that randomness. Use it to CONFIRM a seed another\n\
tool made from the same symbols, never to CREATE one you will fund. For real seeds,\n\
use Alea's witnessed dice/coin/machine generation.";

/// SPEC_COMPAT_ENTROPY §9 (last bullet): the fixed mode/assumptions this
/// path uses, so a mismatch can be diagnosed. `EntropyEncodingRaw` is the
/// distinctive method identifier (never a generic encoding word).
pub const ENTROPY_MODE_ASSUMPTIONS: &str = "Mode (EntropyEncodingRaw): RAW entropy (NO SHA-256), explicit encoding (no autodetect),\n\
PBKDF2-HMAC-SHA512 2048 rounds, empty passphrase, last floor(bits/32)*32 bits retained\n\
(leading excess discarded). If your words don't match, check: wrong encoding? the other\n\
tool in hashed / non-'raw' mode (that is Method A)? non-2048 PBKDF2 rounds? a passphrase?\n\
characters outside the selected encoding were ignored (check the accepted-symbol count)?";

/// SPEC_COMPAT_ENTROPY §7: the encoding menu. Alea requires the user to pick
/// the encoding explicitly (no autodetect, §5.1) — this removes the single
/// biggest byte-exactness hazard.
pub fn entropy_encodings_menu() -> String {
    let mut out = String::new();
    out.push_str("COMPATIBILITY VERIFICATION  —  reproduce iancoleman/bip39 RAW-entropy words\n");
    out.push_str("This does NOT generate an Alea seed. Test/throwaway seeds only.\n\n");
    out.push_str(&format!("{ENTROPY_HONESTY_CAVEAT}\n\n"));
    out.push_str("Choose the entropy encoding your other tool used (explicit — no autodetect):\n");
    for (i, e) in Encoding::ALL.iter().enumerate() {
        out.push_str(&format!("  [{}] {}  (--encoding {})\n", i + 1, e.display_name(), e.id()));
    }
    out.push_str("\nOnly 128-bit (12-word) or 256-bit (24-word) retained entropy is verified.");
    out
}

/// SPEC_COMPAT_ENTROPY §5.3: a short, human description of the per-encoding
/// symbol→bits rule, rendered on the method screen so the emulation is not
/// opaque.
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

/// SPEC_COMPAT_ENTROPY §7: the Method-C method screen, shown before entry —
/// the exact algorithm, the raw-vs-hashed distinction, the honesty caveat,
/// and the mode assumptions. Never implies generation (§9).
pub fn entropy_method_screen(encoding: Encoding) -> String {
    let mut out = String::new();
    out.push_str(&format!("Reproducing: iancoleman/bip39 RAW entropy — {}\n", encoding.display_name()));
    out.push_str(&format!("Method ({METHOD_ID}):\n"));
    out.push_str(&format!("           symbols -> bits: {}\n", encoding_rule(encoding)));
    out.push_str("           concatenate all symbol bits (per-symbol table lookup, NOT base conversion)\n");
    out.push_str("           retain the LAST floor(bits/32)*32 bits (leading excess discarded)\n");
    out.push_str("           NO SHA-256 on the bits (the hashed / non-'raw' branch is Method A)\n");
    out.push_str("           128 retained bits -> 12 words, 256 -> 24 words; anything else is REFUSED\n");
    out.push_str("           then standard BIP39 (SPEC §14), PBKDF2-2048, empty passphrase\n");
    if encoding == Encoding::Cards {
        out.push_str("Cards:     with/without replacement does not change the bits; duplicate cards\n");
        out.push_str("           contribute their bits again. A physical shuffle draws WITHOUT replacement.\n");
    }
    out.push_str("Source:    github.com/iancoleman/bip39 src/js/entropy.js (eventBits) + index.js\n\n");
    out.push_str(&format!("{ENTROPY_HONESTY_CAVEAT}\n\n"));
    out.push_str(ENTROPY_MODE_ASSUMPTIONS);
    out
}

/// SPEC_COMPAT_ENTROPY §5.5: the refusal screen for a non-{128,256} retained
/// length (or no accepted symbols / oversized input). NAMES iancoleman's
/// divergence and shows the retained-bit count, never fabricating a phrase.
pub fn entropy_refusal_screen(encoding: Encoding, error: EntropyEncodingError) -> String {
    let mut out = String::new();
    match error {
        EntropyEncodingError::NoSymbols { ignored_chars } => {
            out.push_str(&format!(
                "REFUSED: no {} symbols were found in your input.\n",
                encoding.display_name()
            ));
            out.push_str(&format!(
                "All {ignored_chars} characters were outside the selected encoding and ignored\n\
(iancoleman drops them too). Check you picked the right encoding, then re-enter symbols.",
            ));
        }
        EntropyEncodingError::TooLong => {
            out.push_str(
                "REFUSED: that is far more entropy than verification needs (over 2048 bits).\n\
Verification only reproduces a 128-bit (12-word) or 256-bit (24-word) phrase — trim the input.",
            );
        }
        EntropyEncodingError::UnsupportedLength {
            retained_bits,
            total_bits,
            iancoleman_words,
            accepted_symbols,
            ignored_chars,
        } => {
            if iancoleman_words >= 12 && retained_bits != 128 && retained_bits != 256 {
                // 160/192/224/288/320… — iancoleman WOULD emit a
                // non-standard N-word phrase; name that divergence (§5.5).
                out.push_str(&format!(
                    "REFUSED: {retained_bits} retained bits.\n\
iancoleman would produce a {iancoleman_words}-word NON-STANDARD phrase from this length;\n\
Alea verifies only 12- and 24-word BIP39 mnemonics. Adjust to exactly 128 or 256\n\
retained bits.\n",
                ));
            } else {
                // Below 128 bits (0/32/64/96): not enough entropy yet.
                out.push_str(&format!(
                    "REFUSED: {retained_bits} retained bits (below the 128 bits needed for 12 words).\n\
Alea verifies only 12- (128-bit) and 24-word (256-bit) BIP39 mnemonics; add more symbols\n\
to reach exactly 128 or 256 retained bits. (Alea never silently stretches typed entropy.)\n",
                ));
            }
            out.push_str(&format!(
                "Accepted symbols: {accepted_symbols}   Ignored (outside encoding): {ignored_chars}   \
Total bits before truncation: {total_bits}",
            ));
        }
    }
    out
}

/// SPEC_COMPAT_ENTROPY §7/§9: the Method-C result screen — watermark, the
/// honesty caveat, the reproduced mnemonic, SPEC §24 verification values,
/// the silently-ignored-characters diagnosis + accepted-symbol count, and
/// the mode assumptions. Entropy hex is rendered ONLY when `show_entropy`
/// (review F7 — no default concatenation of entropy hex with the mnemonic).
pub fn entropy_result_screen(success: &EntropySuccess, input: &str, show_entropy: bool) -> String {
    let n = success.word_count_n();

    let mut out = String::new();
    out.push_str(RESULT_WATERMARK);
    out.push_str("\n\n");

    out.push_str(&format!(
        "Method:         iancoleman/bip39 RAW entropy — {} ({METHOD_ID})\n",
        success.encoding.display_name()
    ));
    out.push_str(&format!("Input:          {}\n", wrap_events(input, 56)));
    out.push_str(&format!(
        "Symbols:        {} accepted   ({} character(s) outside the encoding ignored)\n",
        success.accepted_symbols, success.ignored_chars
    ));
    out.push_str(&format!(
        "Entropy:        {} retained bits (of {} typed)  ->  {} words\n\n",
        success.retained_bits, success.total_bits, n
    ));

    out.push_str(PUBLIC_TEST_PHRASE_PREFIX);
    out.push('\n');
    out.push_str(&format!("Mnemonic ({n} words):\n"));
    let words = success.words_slice();
    for (i, w) in words.iter().enumerate() {
        if i % 6 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str("  ");
        }
        out.push_str(&format!("{:02} {:<12}", i + 1, w));
    }
    out.push_str("\n\n");

    out.push_str("Verification values (empty passphrase; SPEC §24):\n");
    out.push_str(&format!("  Master fingerprint  {}\n", success.master_fingerprint_hex()));
    out.push_str("  ");
    for (i, addr) in success.addresses.iter().enumerate() {
        if i > 0 {
            out.push_str("   ");
        }
        out.push_str(&format!("{} {}", addr.label, addr.as_str()));
    }
    out.push_str("\n\n");

    if show_entropy {
        out.push_str(&format!(
            "Entropy hex ({} bytes): {}\n",
            success.entropy_len,
            success.entropy_hex()
        ));
        out.push_str("(RAW retained bits, packed MSB-first. This is a PUBLIC test value.)\n\n");
    } else {
        out.push_str(
            "(Raw entropy hex is a PUBLIC test value, shown only on explicit request:\n\
 `compat-verify verify-entropy ... --show-entropy`.)\n\n",
        );
    }

    out.push_str(&format!("{ENTROPY_HONESTY_CAVEAT}\n\n"));
    out.push_str(ENTROPY_MODE_ASSUMPTIONS);
    out
}
