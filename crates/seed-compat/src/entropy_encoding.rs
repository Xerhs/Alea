//! Method C — `EntropyEncodingRaw` (SPEC_COMPAT_ENTROPY.md, "Method C").
//!
//! Owned by WP-C7 (extends the WP-C1…WP-C6 compat family). This module
//! reproduces `iancoleman/bip39`'s **raw-entropy** front end
//! (`src/js/entropy.js` `fromString`/`eventBits`, `src/js/index.js`
//! `setMnemonicFromEntropy` *`raw` branch only*) for the six typed
//! encodings — **Binary, Base-6, Dice, Base-10, Hex, Cards** — so a user
//! can VERIFY (reproduce + confirm) a seed another tool made from the same
//! symbols.
//!
//! It is **verification-only** (SPEC_COMPAT_ENTROPY §2): typed symbols are
//! unwitnessed/uncounted, so this MUST NEVER become a production
//! seed-generation source. It lives in `seed-compat` / the CLI / desktop
//! compat surface only, and `seed-uefi-production` MUST NOT depend on
//! `seed-compat` (the dependency-graph exclusion is the primary isolation
//! guarantee, SPEC_COMPAT §9; verified by `cargo tree`).
//!
//! ## The exact algorithm (SPEC_COMPAT_ENTROPY §5, byte-exact)
//!
//! 1. **Match** entropy characters with the encoding's alphabet (§5.1);
//!    ignore all non-matching characters (mirrors iancoleman's per-encoding
//!    matcher regex — silently-dropped chars, surfaced to the user, §9).
//! 2. If Dice: face **6 → base-6 digit 0** (`"00"`), faces 1–5 use the
//!    base-6 table (§5.2, the well-known "dice 6 becomes 0").
//! 3. **Map** each matched symbol via the verbatim `eventBits` table (§5.3)
//!    to a fixed **variable-length** bit-string and **concatenate** — this
//!    is a per-symbol bit-table lookup, *not* a BigInteger base-conversion
//!    and *not* a `log2(base) × count` estimate (the #1 byte-exactness
//!    hazard, §5.3 note).
//! 4. **Retain** the **last** `floor(len / 32) * 32` bits — the leading
//!    excess is discarded (§5.5's truncation quirk; iancoleman's
//!    `substring(len - bitsToUse)` keeps the tail despite its
//!    "discard trailing" comment; the B4 vector `1` then `0{128}` proving
//!    this yields all-zero entropy, not `80…00`).
//! 5. If the retained length is not exactly **128 or 256** bits →
//!    [`EntropyEncodingError::UnsupportedLength`], never a fabricated phrase
//!    (§5.5). The refusal names iancoleman's divergent non-standard N-word
//!    output so the user does not mistake it for an Alea bug.
//! 6. Pack the retained bits **MSB-first** into 16 or 32 entropy bytes.
//! 7. Feed the bytes to the EXISTING, unchanged
//!    `seed_core::bip39::entropy_to_indexes` pipeline (SHA-256 checksum,
//!    11-bit MSB-first words, SPEC §14) — the only reused half (§5.7).
//!
//! `#![no_std]`, no `alloc`: a bounded fixed bit buffer, never a panic on
//! bad input (typed error/refusal). Closed six-variant [`Encoding`] enum;
//! adding one is a reviewed code change, never data-driven (SPEC_COMPAT §6).

use seed_core::contracts::WordCount as CoreWordCount;

use crate::WordCount;

/// The six `iancoleman/bip39` entropy input encodings (SPEC_COMPAT_ENTROPY
/// §5.3). Closed set — adding a variant is a reviewed code + external-review
/// change, never a data-driven addition (SPEC_COMPAT §6, mirroring
/// [`crate::CompatMethod`]'s discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `[0-1]` — `0→"0"`, `1→"1"` (1 bit/symbol, fixed).
    Binary,
    /// `[0-5]` — `0→00 1→01 2→10 3→11 4→0 5→1` (variable: 2 bits for
    /// {0,1,2,3}, 1 bit for {4,5}; iancoleman's bias-corrected base-6).
    Base6,
    /// `[1-6]` — face **6 remapped to base-6 digit 0** (`"00"`), faces 1–5
    /// use the base-6 table (§5.2).
    Dice,
    /// `[0-9]` — `0..7 → 3-bit "000".."111"`, `8→0`, `9→1` (variable).
    Base10,
    /// `[0-9A-F]` — nibble, 4 bits (fixed), case-insensitive.
    Hex,
    /// `[A2-9TJQK][CDHS]` — per-card 52-entry table, suit order C,D,H,S;
    /// index 0–31 → 5 bits, 32–47 → 4 bits, 48–51 → 2 bits (variable).
    Cards,
}

impl Encoding {
    /// The closed set of all six encodings, in the SPEC_COMPAT_ENTROPY §5.3
    /// table order.
    pub const ALL: [Encoding; 6] = [
        Encoding::Binary,
        Encoding::Base6,
        Encoding::Dice,
        Encoding::Base10,
        Encoding::Hex,
        Encoding::Cards,
    ];

    /// Stable identifier used on the CLI (`--encoding <id>`) and in vector
    /// files. **NOT** a binary-policy-scanner denylist token: these are
    /// ordinary English words ("binary", "hex", "card", …) and MUST NOT be
    /// denylisted (SPEC_COMPAT_ENTROPY §2, item 3 — the scanner keys on the
    /// *distinctive* `EntropyEncodingRaw` identifier / watermark, never
    /// these generic words).
    pub fn id(self) -> &'static str {
        match self {
            Encoding::Binary => "binary",
            Encoding::Base6 => "base6",
            Encoding::Dice => "dice",
            Encoding::Base10 => "base10",
            Encoding::Hex => "hex",
            Encoding::Cards => "cards",
        }
    }

    /// Human-readable label for CLI display.
    pub fn display_name(self) -> &'static str {
        match self {
            Encoding::Binary => "Binary [0-1]",
            Encoding::Base6 => "Base-6 [0-5]",
            Encoding::Dice => "Dice [1-6]",
            Encoding::Base10 => "Base-10 [0-9]",
            Encoding::Hex => "Hex [0-9A-F]",
            Encoding::Cards => "Cards [A2-9TJQK][CDHS]",
        }
    }

    /// Look up an encoding by its [`Encoding::id`] (CLI selection). Closed
    /// lookup over [`Encoding::ALL`] — no autodetect (SPEC_COMPAT_ENTROPY
    /// §5.1: Alea requires explicit encoding selection).
    pub fn from_id(id: &str) -> Option<Encoding> {
        Encoding::ALL.iter().copied().find(|e| e.id() == id)
    }
}

/// The always-`raw`, always-explicit method identifier for Method C
/// (SPEC_COMPAT_ENTROPY §4). This is the **distinctive** string the
/// binary-policy scanner keys on (SPEC_COMPAT_ENTROPY §2 item 3), never the
/// generic per-encoding words.
pub const METHOD_ID: &str = "EntropyEncodingRaw";

/// Maximum concatenated `eventBits` length this front end will accumulate
/// (SPEC_COMPAT_ENTROPY §7: "bit derivation over a fixed maximum input
/// length"). 2048 bits comfortably covers every supported case (128/256)
/// plus every refusable non-standard length iancoleman can reach (160/192/
/// 224, a full-deck raw phrase, and generous leading-discard slack) while
/// keeping the fixed buffer small. Inputs whose accepted symbols would
/// exceed this yield [`EntropyEncodingError::TooLong`] rather than a panic.
pub const MAX_ENTROPY_BITS: usize = 2048;

/// A typed refusal/error from [`entropy_encoding_derive`] — never paired
/// with a fabricated mnemonic (SPEC_COMPAT_ENTROPY §5.5). Carries only
/// non-secret bit/symbol counts, so ordinary derives are sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyEncodingError {
    /// No character in the input matched the selected encoding's alphabet,
    /// so there is nothing to derive. `ignored_chars` is how many input
    /// characters were seen and dropped (SPEC_COMPAT_ENTROPY §9).
    NoSymbols {
        /// Count of input characters dropped because they were outside the
        /// selected encoding.
        ignored_chars: u16,
    },
    /// The concatenated `eventBits` exceeded [`MAX_ENTROPY_BITS`]; the input
    /// carries far more than the 128/256 bits verification needs.
    TooLong,
    /// After the last-32·k-bit truncation the retained entropy is not
    /// exactly 128 or 256 bits, so no standard BIP39 mnemonic exists (§5.5).
    /// The fields let the CLI name iancoleman's divergence and show the
    /// retained-bit count, never fabricating a phrase.
    UnsupportedLength {
        /// Retained bits after the last-32·k-bit truncation (a multiple of
        /// 32; the value shown to the user).
        retained_bits: u16,
        /// Total concatenated `eventBits` before truncation.
        total_bits: u16,
        /// The non-standard word count iancoleman WOULD emit from this
        /// retained length (`retained_bits / 32 * 3`; 0 when there is not
        /// even one full 32-bit block).
        iancoleman_words: u16,
        /// Number of symbols accepted from the input.
        accepted_symbols: u16,
        /// Number of input characters ignored (outside the encoding).
        ignored_chars: u16,
    },
}

/// A successful Method-C derivation (SPEC_COMPAT_ENTROPY §7). Mirrors
/// [`crate::CompatOutput`]'s secret-handling discipline (SPEC_COMPAT §9,
/// SPEC §20.2): it deliberately implements none of `Debug`/`Clone`/`Copy`/
/// `PartialEq`/`Eq`, and its `Drop` best-effort scrubs the reproduced
/// mnemonic indexes + entropy bytes. These are declared public/throwaway
/// verification values, so this is hygiene/consistency, not a live
/// secret-leak fix.
pub struct EntropyEncodingOutput {
    /// The encoding that was used (as selected — no autodetect).
    pub encoding: Encoding,
    /// Word count the retained entropy produced (12 for 128 bits, 24 for
    /// 256 bits).
    pub word_count: WordCount,
    /// BIP39 wordlist indexes; only the first `word_count` entries (12 or
    /// 24) are meaningful. Look up words with `seed_core::bip39::word`.
    pub mnemonic_indexes: [u16; 24],
    /// The retained raw entropy bytes; only `entropy_len` (16 or 32) are
    /// meaningful. Rendered by the CLI ONLY behind `--show-entropy`
    /// (SPEC_COMPAT_ENTROPY §7, review F7).
    pub entropy: [u8; 32],
    /// 16 (128-bit) or 32 (256-bit).
    pub entropy_len: usize,
    /// Number of symbols accepted from the input (SPEC_COMPAT_ENTROPY §9:
    /// shown so the user can spot a dropped character).
    pub accepted_symbols: u16,
    /// Number of input characters ignored because they were outside the
    /// selected encoding (SPEC_COMPAT_ENTROPY §9).
    pub ignored_chars: u16,
    /// Retained bits after the last-32·k-bit truncation (128 or 256).
    pub retained_bits: u16,
    /// Total concatenated `eventBits` before truncation (retained ≤ total;
    /// the difference is the leading excess discarded, §5.5).
    pub total_bits: u16,
}

impl EntropyEncodingOutput {
    /// Best-effort zero of the reproduced mnemonic indexes and entropy
    /// bytes, via `seed_core::arena::scrub_slice` — the same reviewed
    /// volatile-write + fence + verify primitive [`crate::CompatOutput`]
    /// and `SecretArena` use. Called automatically on `Drop`.
    pub fn scrub(&mut self) {
        // SAFETY: `mnemonic_indexes` is `[u16; 24]`; reinterpreting it as
        // its 48 constituent bytes through a `u8` pointer is always valid
        // (`u8` has no alignment/padding constraints) and stays within the
        // exclusively-borrowed field.
        let idx_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.mnemonic_indexes.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&self.mnemonic_indexes),
            )
        };
        seed_core::arena::scrub_slice(idx_bytes);
        seed_core::arena::scrub_slice(&mut self.entropy);
    }
}

impl Drop for EntropyEncodingOutput {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Fixed, bounded bit accumulator (SPEC_COMPAT_ENTROPY §7: no `alloc`, no
/// panic). Stores one bit per byte (`0`/`1`) so the variable-length
/// per-symbol strings and the leading-discard truncation are trivial and
/// exact; `overflow` latches if the input would exceed [`MAX_ENTROPY_BITS`].
struct BitBuf {
    bits: [u8; MAX_ENTROPY_BITS],
    len: usize,
    overflow: bool,
}

impl BitBuf {
    fn new() -> Self {
        BitBuf { bits: [0u8; MAX_ENTROPY_BITS], len: 0, overflow: false }
    }

    /// Append a single bit (`0`/`1`).
    fn push_bit(&mut self, b: u8) {
        if self.len < MAX_ENTROPY_BITS {
            self.bits[self.len] = b & 1;
            self.len += 1;
        } else {
            self.overflow = true;
        }
    }

    /// Append the bits of an `eventBits` string literal (each byte is the
    /// ASCII char `'0'` or `'1'`).
    fn push_str(&mut self, s: &str) {
        for c in s.bytes() {
            self.push_bit(c - b'0');
        }
    }
}

/// The verbatim `eventBits` bit-string for a single-character symbol in
/// `encoding` (SPEC_COMPAT_ENTROPY §5.3), or `None` if `ch` is outside the
/// encoding's alphabet (silently ignored, §5.1/§9). Cards are handled
/// separately (two-character tokens) by [`entropy_encoding_derive`].
fn single_char_bits(encoding: Encoding, ch: char) -> Option<&'static str> {
    match encoding {
        Encoding::Binary => match ch {
            '0' => Some("0"),
            '1' => Some("1"),
            _ => None,
        },
        // base 6: {"0":"00","1":"01","2":"10","3":"11","4":"0","5":"1"}
        Encoding::Base6 => match ch {
            '0' => Some("00"),
            '1' => Some("01"),
            '2' => Some("10"),
            '3' => Some("11"),
            '4' => Some("0"),
            '5' => Some("1"),
            _ => None,
        },
        // dice [1-6]: face 6 -> base-6 digit 0 ("00"); faces 1-5 -> base-6
        // table (§5.2). Digit '0' is NOT in the dice alphabet -> ignored.
        Encoding::Dice => match ch {
            '1' => Some("01"),
            '2' => Some("10"),
            '3' => Some("11"),
            '4' => Some("0"),
            '5' => Some("1"),
            '6' => Some("00"),
            _ => None,
        },
        // base 10: 0..7 -> 3-bit, 8->"0", 9->"1"
        Encoding::Base10 => match ch {
            '0' => Some("000"),
            '1' => Some("001"),
            '2' => Some("010"),
            '3' => Some("011"),
            '4' => Some("100"),
            '5' => Some("101"),
            '6' => Some("110"),
            '7' => Some("111"),
            '8' => Some("0"),
            '9' => Some("1"),
            _ => None,
        },
        // hexadecimal: nibble, 4 bits, case-insensitive.
        Encoding::Hex => ch.to_digit(16).map(|v| HEX_BITS[v as usize]),
        Encoding::Cards => None,
    }
}

/// Fixed 4-bit nibble strings for Hex (`0..=f`), verbatim from the
/// `"hexadecimal"` `eventBits` entry (SPEC_COMPAT_ENTROPY §5.3).
const HEX_BITS: [&str; 16] = [
    "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011",
    "1100", "1101", "1110", "1111",
];

/// Card rank order within a suit (`eventBits["card"]` §5.3): A,2,…,9,T,J,Q,K.
const CARD_RANKS: &[u8; 13] = b"A23456789TJQK";
/// Card suit order (§5.3, §5.3 note): Clubs, Diamonds, Hearts, Spades.
const CARD_SUITS: &[u8; 4] = b"CDHS";

/// Rank index 0–12 for an ASCII rank byte (case-insensitive), or `None`.
fn card_rank(b: u8) -> Option<u8> {
    let up = b.to_ascii_uppercase();
    CARD_RANKS.iter().position(|&r| r == up).map(|p| p as u8)
}

/// Suit index 0–3 for an ASCII suit byte (case-insensitive), or `None`.
fn card_suit(b: u8) -> Option<u8> {
    let up = b.to_ascii_uppercase();
    CARD_SUITS.iter().position(|&s| s == up).map(|p| p as u8)
}

/// Append the `eventBits["card"]` bits for a card at sequential index
/// `idx = suit*13 + rank` (SPEC_COMPAT_ENTROPY §5.3): index 0–31 → the
/// 5-bit binary of `idx`; 32–47 → 4-bit `idx-32`; 48–51 → 2-bit `idx-48`.
fn push_card_bits(buf: &mut BitBuf, idx: u8) {
    let (value, width): (u32, u32) = if idx < 32 {
        (idx as u32, 5)
    } else if idx < 48 {
        ((idx - 32) as u32, 4)
    } else {
        ((idx - 48) as u32, 2)
    };
    for k in (0..width).rev() {
        buf.push_bit(((value >> k) & 1) as u8);
    }
}

/// Reproduce iancoleman/bip39's **raw**-entropy derivation for `input` under
/// the explicitly selected `encoding` (SPEC_COMPAT_ENTROPY §7). See the
/// module docs for the seven byte-exact steps. Never panics on bad input;
/// returns a typed [`EntropyEncodingError`] refusal instead. On success the
/// reproduced mnemonic indexes come from the SAME
/// `seed_core::bip39::entropy_to_indexes` production uses (§5.7).
pub fn entropy_encoding_derive(
    encoding: Encoding,
    input: &str,
) -> Result<EntropyEncodingOutput, EntropyEncodingError> {
    let mut buf = BitBuf::new();
    let mut accepted: u32 = 0;
    // Input characters consumed by an accepted symbol (1 per single-char
    // symbol, 2 per card). Everything else is "ignored" (§9 diagnosis).
    let mut consumed_chars: u32 = 0;
    let total_chars = input.chars().count() as u32;

    match encoding {
        Encoding::Cards => {
            // Two-character tokens [A2-9TJQK][CDHS], scanned left-to-right
            // exactly like iancoleman's global `card` regex: at each byte,
            // a rank immediately followed by a suit is one match (consuming
            // both); otherwise advance one byte (that char is ignored). No
            // dedup / no with-vs-without-replacement logic in the bit path
            // (§6): duplicates contribute their bits again.
            let b = input.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if let Some(r) = card_rank(b[i]) {
                    if i + 1 < b.len() {
                        if let Some(s) = card_suit(b[i + 1]) {
                            push_card_bits(&mut buf, s * 13 + r);
                            accepted += 1;
                            consumed_chars += 2;
                            i += 2;
                            continue;
                        }
                    }
                }
                i += 1;
            }
        }
        _ => {
            for ch in input.chars() {
                if let Some(bits) = single_char_bits(encoding, ch) {
                    buf.push_str(bits);
                    accepted += 1;
                    consumed_chars += 1;
                }
            }
        }
    }

    let ignored_chars = clamp_u16(total_chars.saturating_sub(consumed_chars) as usize);

    if accepted == 0 {
        return Err(EntropyEncodingError::NoSymbols { ignored_chars });
    }
    if buf.overflow {
        return Err(EntropyEncodingError::TooLong);
    }

    let total_bits = buf.len;
    // §5.5: keep the LAST floor(len/32)*32 bits; discard the LEADING excess.
    let retained = (total_bits / 32) * 32;
    let retained_u16 = clamp_u16(retained);
    let total_u16 = clamp_u16(total_bits);
    let accepted_u16 = clamp_u16(accepted as usize);

    if retained != 128 && retained != 256 {
        return Err(EntropyEncodingError::UnsupportedLength {
            retained_bits: retained_u16,
            total_bits: total_u16,
            iancoleman_words: (retained / 32 * 3) as u16,
            accepted_symbols: accepted_u16,
            ignored_chars,
        });
    }

    // Pack the retained (tail) bits MSB-first into entropy bytes (§7 step 6).
    let start = total_bits - retained;
    let entropy_len = retained / 8;
    let mut entropy = [0u8; 32];
    for i in 0..retained {
        if buf.bits[start + i] != 0 {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    // §5.7: the ONLY reused half — the exact production BIP39 conversion.
    let mut mnemonic_indexes = [0u16; 24];
    let core_count = seed_core::bip39::entropy_to_indexes(&entropy[..entropy_len], &mut mnemonic_indexes)
        .expect("retained entropy is always exactly 16 or 32 bytes by construction");
    let word_count = match core_count {
        CoreWordCount::Twelve => WordCount::W12,
        CoreWordCount::TwentyFour => WordCount::W24,
    };

    Ok(EntropyEncodingOutput {
        encoding,
        word_count,
        mnemonic_indexes,
        entropy,
        entropy_len,
        accepted_symbols: accepted_u16,
        ignored_chars,
        retained_bits: retained_u16,
        total_bits: total_u16,
    })
}

/// Saturating cast for the non-secret, display-only bit/symbol counters.
fn clamp_u16(v: usize) -> u16 {
    if v > u16::MAX as usize {
        u16::MAX
    } else {
        v as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::vec::Vec;

    fn words_of(out: &EntropyEncodingOutput) -> Vec<&'static str> {
        let n = match out.word_count {
            WordCount::W12 => 12,
            WordCount::W24 => 24,
        };
        out.mnemonic_indexes[..n].iter().map(|&i| seed_core::bip39::word(i)).collect()
    }

    fn entropy_hex(out: &EntropyEncodingOutput) -> String {
        const HEXCHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::new();
        for b in &out.entropy[..out.entropy_len] {
            s.push(HEXCHARS[(b >> 4) as usize] as char);
            s.push(HEXCHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    fn expect_ok(encoding: Encoding, input: &str) -> EntropyEncodingOutput {
        match entropy_encoding_derive(encoding, input) {
            Ok(o) => o,
            Err(e) => panic!("expected Ok, got {e:?}"),
        }
    }

    fn expect_err(encoding: Encoding, input: &str) -> EntropyEncodingError {
        match entropy_encoding_derive(encoding, input) {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    fn repeat(s: &str, n: usize) -> String {
        let mut out = String::new();
        for _ in 0..n {
            out.push_str(s);
        }
        out
    }

    // ---- closed enum discipline (SPEC_COMPAT §6) ----

    #[test]
    fn encoding_enum_is_closed_six_variants() {
        assert_eq!(Encoding::ALL.len(), 6);
        // Every id round-trips and is unique.
        let mut ids: Vec<&str> = Encoding::ALL.iter().map(|e| e.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 6);
        for e in Encoding::ALL {
            assert_eq!(Encoding::from_id(e.id()), Some(e));
        }
        assert_eq!(Encoding::from_id("autodetect"), None);
    }

    // ---- per-encoding bit tables (SPEC_COMPAT_ENTROPY §5.3) ----

    #[test]
    fn binary_bit_table() {
        assert_eq!(single_char_bits(Encoding::Binary, '0'), Some("0"));
        assert_eq!(single_char_bits(Encoding::Binary, '1'), Some("1"));
        assert_eq!(single_char_bits(Encoding::Binary, '2'), None);
    }

    #[test]
    fn base6_bit_table_is_bias_corrected_variable_length() {
        let expect = [("0", "00"), ("1", "01"), ("2", "10"), ("3", "11"), ("4", "0"), ("5", "1")];
        for (c, bits) in expect {
            assert_eq!(single_char_bits(Encoding::Base6, c.chars().next().unwrap()), Some(bits));
        }
        assert_eq!(single_char_bits(Encoding::Base6, '6'), None);
    }

    #[test]
    fn dice_face_six_becomes_base6_zero() {
        // §5.2: face 6 -> base-6 digit 0 -> "00".
        assert_eq!(single_char_bits(Encoding::Dice, '6'), Some("00"));
        assert_eq!(single_char_bits(Encoding::Dice, '1'), Some("01"));
        assert_eq!(single_char_bits(Encoding::Dice, '5'), Some("1"));
        // '0' is outside the dice [1-6] alphabet -> ignored.
        assert_eq!(single_char_bits(Encoding::Dice, '0'), None);
    }

    #[test]
    fn base10_bit_table() {
        let expect = [
            ("0", "000"), ("1", "001"), ("2", "010"), ("3", "011"), ("4", "100"), ("5", "101"),
            ("6", "110"), ("7", "111"), ("8", "0"), ("9", "1"),
        ];
        for (c, bits) in expect {
            assert_eq!(single_char_bits(Encoding::Base10, c.chars().next().unwrap()), Some(bits));
        }
    }

    #[test]
    fn hex_bit_table_case_insensitive() {
        assert_eq!(single_char_bits(Encoding::Hex, '0'), Some("0000"));
        assert_eq!(single_char_bits(Encoding::Hex, '7'), Some("0111"));
        assert_eq!(single_char_bits(Encoding::Hex, '8'), Some("1000"));
        assert_eq!(single_char_bits(Encoding::Hex, 'f'), Some("1111"));
        assert_eq!(single_char_bits(Encoding::Hex, 'F'), Some("1111"));
        assert_eq!(single_char_bits(Encoding::Hex, 'a'), Some("1010"));
        assert_eq!(single_char_bits(Encoding::Hex, 'A'), Some("1010"));
        assert_eq!(single_char_bits(Encoding::Hex, 'g'), None);
    }

    #[test]
    fn card_table_widths_and_anchors() {
        // ac = index 0 -> "00000"; verify by deriving a single-block string.
        // idx 0 (ac) 5-bit, idx 51 (ks) 2-bit, idx 32 (7h) 4-bit.
        assert_eq!(card_rank(b'A').unwrap(), 0);
        assert_eq!(card_suit(b'C').unwrap(), 0);
        assert_eq!(card_suit(b'S').unwrap(), 3);
        assert_eq!(card_suit(b'S') .unwrap()* 13 + card_rank(b'K').unwrap(), 51); // ks
        assert_eq!(card_suit(b'H').unwrap() * 13 + card_rank(b'7').unwrap(), 32); // 7h
        // widths
        let mut b = BitBuf::new();
        push_card_bits(&mut b, 0);
        assert_eq!(b.len, 5);
        let mut b = BitBuf::new();
        push_card_bits(&mut b, 32);
        assert_eq!(b.len, 4);
        let mut b = BitBuf::new();
        push_card_bits(&mut b, 51);
        assert_eq!(b.len, 2);
    }

    // ---- truncation quirk (SPEC_COMPAT_ENTROPY §5.5) ----

    #[test]
    fn truncation_keeps_last_32k_bits_leading_discard() {
        // B4 discriminator: binary "1" then 128 "0" -> retained 128 all-zero
        // (leading 1 discarded), NOT 80..00.
        let input = {
            let mut s = String::from("1");
            s.push_str(&repeat("0", 128));
            s
        };
        let out = expect_ok(Encoding::Binary, &input);
        assert_eq!(out.total_bits, 129);
        assert_eq!(out.retained_bits, 128);
        assert_eq!(entropy_hex(&out), "00000000000000000000000000000000");
        assert_eq!(words_of(&out)[0], "abandon");
    }

    // ---- refusal path (SPEC_COMPAT_ENTROPY §5.5) ----

    #[test]
    fn refuses_non_standard_160_bit_length_naming_divergence() {
        // 160 binary "1" bits -> retained 160 -> iancoleman 15-word phrase.
        let out = expect_err(Encoding::Binary, &repeat("1", 160));
        match out {
            EntropyEncodingError::UnsupportedLength { retained_bits, iancoleman_words, .. } => {
                assert_eq!(retained_bits, 160);
                assert_eq!(iancoleman_words, 15);
            }
            other => panic!("expected UnsupportedLength, got {other:?}"),
        }
    }

    #[test]
    fn refuses_below_128_bits() {
        let out = expect_err(Encoding::Binary, &repeat("1", 96));
        match out {
            EntropyEncodingError::UnsupportedLength { retained_bits, iancoleman_words, .. } => {
                assert_eq!(retained_bits, 96);
                assert_eq!(iancoleman_words, 9);
            }
            other => panic!("expected UnsupportedLength, got {other:?}"),
        }
    }

    #[test]
    fn no_symbols_when_all_ignored() {
        // Hex mode fed only non-hex characters.
        match expect_err(Encoding::Hex, "xyz zzz!!") {
            EntropyEncodingError::NoSymbols { .. } => {}
            other => panic!("expected NoSymbols, got {other:?}"),
        }
    }

    #[test]
    fn too_long_input_is_refused_not_panicked() {
        // 3000 hex chars = 12000 bits > MAX_ENTROPY_BITS.
        let out = expect_err(Encoding::Hex, &repeat("f", 3000));
        assert_eq!(out, EntropyEncodingError::TooLong);
    }

    // ---- silently-ignored characters (SPEC_COMPAT_ENTROPY §9) ----

    #[test]
    fn ignored_chars_are_dropped_and_counted() {
        // Hex 80{16} with spaces/newlines interspersed -> same result as
        // clean input, ignored count reflects the whitespace.
        let out = expect_ok(Encoding::Hex, "80 80 80 80 80 80 80 80 80 80 80 80 80 80 80 80");
        assert_eq!(out.accepted_symbols, 32);
        assert_eq!(out.ignored_chars, 15); // 15 spaces
        assert_eq!(entropy_hex(&out), "80808080808080808080808080808080");
    }

    #[test]
    fn dice_zero_is_ignored_not_an_error() {
        // '0' is outside dice [1-6]; iancoleman drops it. 128 valid faces
        // '5' (-> "1") plus stray '0's still derives from the 128 faces.
        let mut s = repeat("5", 64); // 64 -> "1" each = 64 bits, not enough
        s.push('0'); // ignored
        // Need 128 bits: '5' -> 1 bit each; use 128 fives = 128 bits.
        s = repeat("5", 128);
        s.insert(0, '0');
        s.push('0');
        let out = expect_ok(Encoding::Dice, &s);
        assert_eq!(out.accepted_symbols, 128);
        assert_eq!(out.ignored_chars, 2);
        assert_eq!(entropy_hex(&out), "ffffffffffffffffffffffffffffffff");
    }

    // ---- end-to-end anchors (subset; full frozen corpus in the CLI) ----

    #[test]
    fn binary_zero_128_is_abandon_about() {
        let out = expect_ok(Encoding::Binary, &repeat("0", 128));
        assert_eq!(entropy_hex(&out), "00000000000000000000000000000000");
        assert_eq!(words_of(&out).last(), Some(&"about"));
        assert_eq!(words_of(&out)[0], "abandon");
    }

    #[test]
    fn hex_7f16_is_trezor_legal_winner_vector() {
        let out = expect_ok(Encoding::Hex, &repeat("7f", 16));
        assert_eq!(entropy_hex(&out), "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
        assert_eq!(
            words_of(&out),
            std::vec![
                "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
                "winner", "thank", "yellow"
            ]
        );
    }

    #[test]
    fn cards_c4_mixed_width_hand() {
        let out = expect_ok(
            Encoding::Cards,
            "AC 2C 3C 4C 5C 6C 7C 8C 9C TC JC QC KC AD 2D 3D 4D 5D 6D 7D 8D 9D TD JD TS JS QS KS",
        );
        assert_eq!(out.accepted_symbols, 28);
        assert_eq!(entropy_hex(&out), "00443214c74254b635cf84653a56d71b");
    }

    #[test]
    fn scrub_zeroes_output_buffers() {
        let mut out = expect_ok(Encoding::Binary, &repeat("1", 128));
        assert!(out.mnemonic_indexes.iter().any(|&w| w != 0));
        assert!(out.entropy[..out.entropy_len].iter().any(|&b| b != 0));
        out.scrub();
        assert!(out.mnemonic_indexes.iter().all(|&w| w == 0));
        assert!(out.entropy.iter().all(|&b| b == 0));
    }
}
