//! SPEC_DERIVATION_CUSTOM.md §9 — the SECONDARY desktop free-form BIP32
//! derivation-path PARSER (net-new; §12.2 item 2).
//!
//! The PRIMARY custom-path surface (the §11.5-safe structured builder in
//! [`crate::flow_secret::custom_path`], production UEFI) assembles a path
//! from validated keys and never needs to parse a string. This module is
//! its SECONDARY counterpart: on the DESKTOP rehearsal / compat tooling a
//! user has a full keyboard and may simply *type* a path
//! (`m/48'/0'/0'/2'/0/0`). That typed string must be turned into the
//! bounded `[u32; MAX_DEPTH]` form [`seed_derive::address::address_at`] /
//! [`seed_derive::bip32::derive_path`] already accept.
//!
//! # Safety properties (SPEC_DERIVATION_CUSTOM §9.1)
//!
//! - **`no_std`, no `alloc`.** The output is a caller-provided fixed
//!   `[u32; MAX_DEPTH]` plus a returned length — no heap.
//! - **No panic on any input.** Every rejection is a typed
//!   [`PathParseError`] (§9.5), never `unwrap`/`panic`/index-out-of-bounds
//!   (SPEC §13/§27.3). Any byte string — invalid UTF-8-shaped tokens,
//!   multibyte characters, absurdly long digit runs — returns an error,
//!   never a crash.
//! - **Public / variable-time is fine.** A derivation path is public
//!   protocol data; the parser sees no secret material.
//! - **Parsing consumes NO secret.** A parse failure is a benign
//!   "re-enter the path" on the desktop surface (§9.6), not a
//!   scrub-and-shutdown.
//!
//! # Grammar (SPEC_DERIVATION_CUSTOM §9.2) and rejection list (§9.3)
//!
//! ```ebnf
//! path     = "m" , element , { element } ;   (* >= 1 element; lone "m" rejected, R3 *)
//! element  = "/" , number , [ hardened ] ;
//! number   = digit , { digit } ;             (* semantic bound: value < 2^31, R12 *)
//! hardened = "'" | "h" | "H" ;
//! ```
//!
//! The enumerated R1..R14 rejection classes each map to a
//! [`PathParseError`] variant (see that type). Overflow (R11/R12) is
//! rejected, never wrapped: digits accumulate in a `u64`; a value past
//! `u32::MAX` is [`PathParseError::NumberOverflow`], and any numeric part
//! `>= 2^31` (the hardened index space) is
//! [`PathParseError::NumberTooLarge`] *before* the hardened bit is applied.

use seed_derive::bip32::{HARDENED_OFFSET, MAX_DEPTH};

/// A typed, no-panic, no-`alloc` parse rejection (SPEC_DERIVATION_CUSTOM
/// §9.5). Every §9.3 R# maps to exactly one variant; a failure touches no
/// secret and returns the user to the path field (§9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathParseError {
    /// R1 (empty string) / R3 (lone `m` with no element).
    Empty,
    /// R2 — whitespace anywhere in the string.
    Whitespace,
    /// R5 (leading slash / missing `m`) / R7 (uppercase `M`).
    MissingMasterPrefix,
    /// R4 (trailing slash) / R6 (double / empty segment).
    EmptySegment,
    /// R8 — a non-digit / stray character inside a number.
    BadDigit,
    /// R9 — a hardened marker with no number before it.
    MissingNumber,
    /// R10 (stray / misplaced / duplicated marker) / R13 (a marker other
    /// than `'` / `h` / `H`).
    BadMarker,
    /// R11 — numeric overflow past `u32::MAX` (rejected, never wrapped).
    /// Subsumed by [`NumberTooLarge`](Self::NumberTooLarge) for
    /// correctness (see SPEC_DERIVATION_CUSTOM §9.4); kept distinct only so
    /// a `>= 2^32` typo reports the friendlier "overflowed a 32-bit child
    /// number" cause.
    NumberOverflow,
    /// R12 — a numeric part `>= 2^31`, which would collide with the
    /// hardened bit.
    NumberTooLarge,
    /// R14 — more than [`MAX_DEPTH`] elements.
    TooDeep,
}

impl PathParseError {
    /// A short human-readable reason, for the desktop surface's "could not
    /// read that path: <reason>" line (SPEC_DERIVATION_CUSTOM §9.5/§9.6).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            PathParseError::Empty => "type a path such as m/84'/0'/0'/0/0",
            PathParseError::Whitespace => "no spaces are allowed in a path",
            PathParseError::MissingMasterPrefix => "a path must start with lowercase m/",
            PathParseError::EmptySegment => "an empty level (a // or a trailing /) is not allowed",
            PathParseError::BadDigit => "a level must be a decimal number",
            PathParseError::MissingNumber => "a hardened marker needs a number before it",
            PathParseError::BadMarker => "use one hardened marker (' or h or H) right after a number",
            PathParseError::NumberOverflow => "a level number overflowed a 32-bit child index",
            PathParseError::NumberTooLarge => "a level number must be below 2^31 (2147483648)",
            PathParseError::TooDeep => "a path may have at most 10 levels",
        }
    }
}

/// True for the three accepted hardened markers (`'`, `h`, `H`).
const fn is_marker(b: u8) -> bool {
    b == b'\'' || b == b'h' || b == b'H'
}

/// Parse one `/`-separated element token (the text between slashes, e.g.
/// `44'` or `0`) into a single child number (with [`HARDENED_OFFSET`]
/// already applied for a hardened marker). See the module doc comment for
/// the grammar; see [`PathParseError`] for the rejection mapping.
fn parse_element(token: &str) -> Result<u32, PathParseError> {
    let bytes = token.as_bytes();
    // R4 / R6: an empty token is a double slash or a trailing slash.
    if bytes.is_empty() {
        return Err(PathParseError::EmptySegment);
    }

    // Accumulate the leading decimal number in a u64 so an overflow past
    // u32::MAX is detected and REJECTED (R11), never silently wrapped.
    let mut value: u64 = 0;
    let mut digits = 0usize;
    while digits < bytes.len() && bytes[digits].is_ascii_digit() {
        value = value * 10 + u64::from(bytes[digits] - b'0');
        if value > u64::from(u32::MAX) {
            return Err(PathParseError::NumberOverflow); // R11
        }
        digits += 1;
    }

    if digits == 0 {
        // No leading digit. The first byte is either a marker with no
        // number before it (R9/R10) or a stray non-digit (R8).
        if is_marker(bytes[0]) {
            // `m/'` (just a marker) is R9; `m/'44` (marker before a
            // number) is R10.
            return Err(if bytes.len() == 1 { PathParseError::MissingNumber } else { PathParseError::BadMarker });
        }
        return Err(PathParseError::BadDigit); // R8
    }

    // Everything after the number must be at most ONE hardened marker.
    let rest = &bytes[digits..];
    let hardened = match rest.len() {
        0 => false,
        // Exactly one trailing char: a valid marker hardens the level;
        // anything else is a wrong marker in the marker position (R13).
        1 => {
            if is_marker(rest[0]) {
                true
            } else {
                return Err(PathParseError::BadMarker); // R13 (e.g. `44p`)
            }
        }
        // Two or more trailing chars. A leading marker means junk AFTER
        // the marker (duplicate/misplaced, R10, e.g. `44''`, `44'0`); a
        // leading non-marker means a stray char INSIDE the number (R8,
        // e.g. `4a4`, `0x2c`).
        _ => {
            return Err(if is_marker(rest[0]) { PathParseError::BadMarker } else { PathParseError::BadDigit });
        }
    };

    // R12: the numeric part must be < 2^31 BEFORE the hardened bit is
    // applied — 2^31 and above are the hardened index space, so a plain
    // number that large is ambiguous. (This subsumes R11; see §9.4.)
    if value >= u64::from(HARDENED_OFFSET) {
        return Err(PathParseError::NumberTooLarge);
    }

    // `value < 2^31` here, so this is a lossless narrowing.
    let base = value as u32;
    Ok(if hardened { base + HARDENED_OFFSET } else { base })
}

/// Parse a full typed derivation path (`m/44'/0'/0'/0/0`) into the bounded
/// `[u32; MAX_DEPTH]` form the derivation layer accepts, writing the child
/// numbers into `out` and returning the number written (the depth).
///
/// Implements the SPEC_DERIVATION_CUSTOM §9.2 grammar and §9.3 rejection
/// list exactly. No heap, no panic: every rejection is a typed
/// [`PathParseError`]; on `Err` the contents of `out` are unspecified but
/// no out-of-bounds access ever occurs.
///
/// # Errors
///
/// Returns a [`PathParseError`] for any string outside the grammar — see
/// that type and the module doc comment.
pub fn parse_path(input: &str, out: &mut [u32; MAX_DEPTH]) -> Result<usize, PathParseError> {
    // R1: the empty string.
    if input.is_empty() {
        return Err(PathParseError::Empty);
    }
    // R2: whitespace anywhere (leading, trailing, or internal).
    if input.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PathParseError::Whitespace);
    }
    // R5 / R7: the path must begin with a lowercase `m` (an uppercase `M`
    // has no distinct meaning here — SPEC_DERIVATION_CUSTOM §9.4 — and a
    // leading `/` or bare number has no master prefix at all).
    if input.as_bytes()[0] != b'm' {
        return Err(PathParseError::MissingMasterPrefix);
    }

    let mut segments = input.split('/');
    // The first segment must be exactly "m" (rejects e.g. `m4/0`, where a
    // stray char follows the master prefix instead of a slash).
    match segments.next() {
        Some("m") => {}
        _ => return Err(PathParseError::MissingMasterPrefix),
    }

    let mut depth = 0usize;
    for token in segments {
        // R14: reject a path deeper than MAX_DEPTH before writing past the
        // end of `out` (belt-and-suspenders ahead of `derive_path`'s own
        // depth check).
        if depth >= MAX_DEPTH {
            return Err(PathParseError::TooDeep);
        }
        out[depth] = parse_element(token)?;
        depth += 1;
    }

    // R3: a lone `m` (or `m` followed by nothing) has no element.
    if depth == 0 {
        return Err(PathParseError::Empty);
    }
    Ok(depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seed_derive::bip32::{PATH_BIP44, PATH_BIP49, PATH_BIP84, PATH_BIP86};

    fn parse(s: &str) -> Result<([u32; MAX_DEPTH], usize), PathParseError> {
        let mut out = [0u32; MAX_DEPTH];
        parse_path(s, &mut out).map(|len| (out, len))
    }

    // ------------------------------------------------------------------
    // Valid-path round-trips (SPEC_DERIVATION_CUSTOM §9.2).
    // ------------------------------------------------------------------

    /// Each of the four preset strings parses to exactly the frozen
    /// `PATH_BIP44` .. `PATH_BIP86` constant (§9.2 conformance assertion).
    #[test]
    fn presets_round_trip_to_the_frozen_constants() {
        let cases: [(&str, [u32; 5]); 4] = [
            ("m/44'/0'/0'/0/0", PATH_BIP44),
            ("m/49'/0'/0'/0/0", PATH_BIP49),
            ("m/84'/0'/0'/0/0", PATH_BIP84),
            ("m/86'/0'/0'/0/0", PATH_BIP86),
        ];
        for (s, expected) in cases {
            let (out, len) = parse(s).unwrap_or_else(|e| panic!("{s:?} should parse, got {e:?}"));
            assert_eq!(&out[..len], &expected, "{s:?} did not round-trip");
        }
    }

    #[test]
    fn accepts_h_and_upper_h_hardened_markers() {
        // m/84h/0h/0h/1/7 == BIP84 account 0, internal chain, index 7.
        let (out, len) = parse("m/84h/0H/0h/1/7").unwrap();
        assert_eq!(len, 5);
        assert_eq!(&out[..len], &[HARDENED_OFFSET + 84, HARDENED_OFFSET, HARDENED_OFFSET, 1, 7]);
    }

    #[test]
    fn accepts_single_element_and_max_values() {
        let (out, len) = parse("m/0").unwrap();
        assert_eq!((len, out[0]), (1, 0));
        // 2^31 - 1 is the largest plain number; hardened it becomes 2^32-1.
        let (out, _) = parse("m/2147483647'").unwrap();
        assert_eq!(out[0], u32::MAX);
        let (out, _) = parse("m/2147483647").unwrap();
        assert_eq!(out[0], HARDENED_OFFSET - 1);
    }

    #[test]
    fn accepts_full_max_depth_ten() {
        let (_, len) = parse("m/1/2/3/4/5/6/7/8/9/10").unwrap();
        assert_eq!(len, MAX_DEPTH);
    }

    /// Leading zeros are documented as parsing to their value, not an
    /// error (SPEC_DERIVATION_CUSTOM §9.4).
    #[test]
    fn leading_zeros_parse_to_their_value() {
        assert_eq!(parse("m/00'").unwrap().0[0], HARDENED_OFFSET); // 0'
        assert_eq!(parse("m/007").unwrap().0[0], 7);
    }

    // ------------------------------------------------------------------
    // The full enumerated rejection list R1..R14 (SPEC_DERIVATION_CUSTOM
    // §9.3). Each class maps to its typed error with no panic.
    // ------------------------------------------------------------------

    #[test]
    fn r1_empty_string() {
        assert_eq!(parse(""), Err(PathParseError::Empty));
    }

    #[test]
    fn r2_whitespace_anywhere() {
        for s in [" m/0", "m/0 ", "m/ 0", "m/0/ 1", "m/0\t1", "m/0\n"] {
            assert_eq!(parse(s), Err(PathParseError::Whitespace), "{s:?}");
        }
    }

    #[test]
    fn r3_lone_m_with_no_element() {
        assert_eq!(parse("m"), Err(PathParseError::Empty));
    }

    #[test]
    fn r4_trailing_slash() {
        assert_eq!(parse("m/44'/"), Err(PathParseError::EmptySegment));
    }

    #[test]
    fn r5_leading_slash_or_missing_m() {
        assert_eq!(parse("/44'/0'"), Err(PathParseError::MissingMasterPrefix));
        assert_eq!(parse("44'/0'"), Err(PathParseError::MissingMasterPrefix));
    }

    #[test]
    fn r6_double_or_empty_segment() {
        assert_eq!(parse("m//0'"), Err(PathParseError::EmptySegment));
        assert_eq!(parse("m/44'//0"), Err(PathParseError::EmptySegment));
    }

    #[test]
    fn r7_uppercase_m_prefix() {
        assert_eq!(parse("M/0"), Err(PathParseError::MissingMasterPrefix));
    }

    #[test]
    fn r8_non_digit_stray_character_in_a_number() {
        assert_eq!(parse("m/4a4/0"), Err(PathParseError::BadDigit));
        assert_eq!(parse("m/0x2c"), Err(PathParseError::BadDigit));
    }

    #[test]
    fn r9_missing_number_before_a_marker() {
        assert_eq!(parse("m/'"), Err(PathParseError::MissingNumber));
        assert_eq!(parse("m/44'/'"), Err(PathParseError::MissingNumber));
    }

    #[test]
    fn r10_stray_misplaced_or_duplicated_marker() {
        assert_eq!(parse("m/'44"), Err(PathParseError::BadMarker));
        assert_eq!(parse("m/44''"), Err(PathParseError::BadMarker));
        assert_eq!(parse("m/44'0"), Err(PathParseError::BadMarker));
        assert_eq!(parse("m/44/'0"), Err(PathParseError::BadMarker));
    }

    #[test]
    fn r11_numeric_overflow_rejects_not_wraps() {
        // 2^32 — one past u32::MAX; must reject, never wrap to 0.
        assert_eq!(parse("m/4294967296"), Err(PathParseError::NumberOverflow));
        // A very long digit run cannot panic or wrap either.
        assert_eq!(parse("m/999999999999999999999999"), Err(PathParseError::NumberOverflow));
    }

    #[test]
    fn r12_number_at_or_above_2_pow_31_collides_with_hardened_bit() {
        assert_eq!(parse("m/2147483648"), Err(PathParseError::NumberTooLarge)); // 2^31
        assert_eq!(parse("m/2147483648'"), Err(PathParseError::NumberTooLarge));
    }

    #[test]
    fn r13_marker_other_than_apostrophe_h_or_upper_h() {
        assert_eq!(parse("m/44p"), Err(PathParseError::BadMarker));
        assert_eq!(parse("m/44'H"), Err(PathParseError::BadMarker));
    }

    #[test]
    fn r14_depth_greater_than_max_depth() {
        assert_eq!(parse("m/0/0/0/0/0/0/0/0/0/0/0"), Err(PathParseError::TooDeep)); // 11 levels
    }

    /// No input — however malformed, multibyte, or long — ever panics; it
    /// always returns a typed error or a valid parse (SPEC §13/§27.3).
    #[test]
    fn never_panics_on_adversarial_input() {
        for s in ["m/\u{2074}", "m/44\u{2019}", "\u{00ff}", "m/", "m///", "mmmm", "m/-1", "m/+3", "m/1.5"] {
            let _ = parse(s); // must not panic
        }
    }

    #[test]
    fn every_error_has_a_nonempty_reason() {
        for e in [
            PathParseError::Empty,
            PathParseError::Whitespace,
            PathParseError::MissingMasterPrefix,
            PathParseError::EmptySegment,
            PathParseError::BadDigit,
            PathParseError::MissingNumber,
            PathParseError::BadMarker,
            PathParseError::NumberOverflow,
            PathParseError::NumberTooLarge,
            PathParseError::TooDeep,
        ] {
            assert!(!e.reason().is_empty());
        }
    }
}
