//! EFI GUID → canonical text rendering (WP-24, SPEC §15.1).
//!
//! `EFI_RNG_PROTOCOL.GetInfo()` reports supported algorithms as raw
//! 16-byte GUIDs. SPEC §15.1 requires "the selected algorithm is
//! explicitly reported" and policy comparison happens against text
//! identifiers (`entropy-policy.toml`'s `allowed_algorithms`, matching
//! `seed_protocol::policy::EfiRngPolicy::is_algorithm_allowed`'s `&str`
//! parameter). This module renders a raw GUID to text independent of the
//! `uefi` crate so it stays host-testable without linking it.
//!
//! Text form: 32 lowercase hex digits, **no hyphens** (the compact `N`
//! form, as opposed to the hyphenated `8-4-4-4-12` `D` form). This is a
//! deliberate departure from the more commonly seen hyphenated
//! rendering: `contracts.rs`'s `MAX_ALGO_ID` (32 bytes) and
//! `seed_protocol::policy::types::MAX_ALGO_ID_LEN` (32 bytes) are both
//! frozen/owned-elsewhere constants this crate cannot change, and the
//! hyphenated form is 36 bytes — it would not fit either buffer. The
//! compact form is exactly 32 bytes, filling both without truncation,
//! and is no less canonical (Microsoft's own `Guid.ToString("N")` format
//! and the format PowerShell/many EFI tools accept), so this module
//! standardizes on it: every algorithm identifier this driver ever
//! stages into a `SourceRecord` or compares against
//! `entropy-policy.toml`'s `allowed_algorithms` uses this exact form.
//!
//! Byte order: EFI/Microsoft-style GUIDs store the first three fields
//! little-endian and the last field (8 bytes) as a raw byte string (RFC
//! 4122 variant 2 / Appendix A of the UEFI spec). The real backend
//! ([`super::efi_rng::uefi_backend`]) gets these 16 raw bytes from
//! `uefi::Guid::to_bytes()` (a re-export of `uguid::Guid`, which defines
//! that exact wire layout), so this function's input is always that same
//! byte order.

/// Length of the compact (no-hyphen) 32-hex-digit GUID text form. Equal
/// to `seed_core::contracts::MAX_ALGO_ID` / `seed_protocol::policy::
/// types::MAX_ALGO_ID_LEN` by construction — see the module doc.
pub const GUID_TEXT_LEN: usize = 32;

fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn push_hex_byte(out: &mut [u8; GUID_TEXT_LEN], pos: &mut usize, b: u8) {
    out[*pos] = hex_nibble(b >> 4);
    out[*pos + 1] = hex_nibble(b & 0xF);
    *pos += 2;
}

/// Renders the 16 raw GUID bytes (`uefi::Guid::to_bytes()` wire order) as
/// 32 lowercase hex digits, no hyphens, e.g.
/// `"e43176d7b6e84827b7847ffdc4b68561"`.
///
/// The first three fields (bytes `0..4`, `4..6`, `6..8`) are
/// little-endian numeric fields, so their bytes are reversed before
/// hex-encoding; the last field (bytes `8..16`) is a raw byte string
/// encoded in storage order (SPEC §15.1, this module's header).
pub fn format_guid(raw: &[u8; 16]) -> [u8; GUID_TEXT_LEN] {
    let mut out = [0u8; GUID_TEXT_LEN];
    let mut pos = 0usize;

    for &b in raw[0..4].iter().rev() {
        push_hex_byte(&mut out, &mut pos, b);
    }
    for &b in raw[4..6].iter().rev() {
        push_hex_byte(&mut out, &mut pos, b);
    }
    for &b in raw[6..8].iter().rev() {
        push_hex_byte(&mut out, &mut pos, b);
    }
    for &b in raw[8..10].iter() {
        push_hex_byte(&mut out, &mut pos, b);
    }
    for &b in raw[10..16].iter() {
        push_hex_byte(&mut out, &mut pos, b);
    }

    debug_assert_eq!(pos, GUID_TEXT_LEN);
    out
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn as_str(buf: &[u8; GUID_TEXT_LEN]) -> String {
        core::str::from_utf8(buf).unwrap().into()
    }

    #[test]
    fn known_answer_uguid_doc_example() {
        // Known-answer vector taken directly from the `uguid` crate's own
        // doc example (`uguid-2.2.1/src/lib.rs`): the hyphenated GUID
        // text "01234567-89ab-cdef-0123-456789abcdef" round-trips through
        // `Guid::to_bytes()` to exactly this byte sequence; this module's
        // compact form is the same digits with the hyphens removed.
        let raw: [u8; 16] = [
            0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(as_str(&format_guid(&raw)), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn known_answer_efi_rng_algorithm_raw_guid() {
        // EFI_RNG_ALGORITHM_RAW's published hyphenated GUID text is
        // "e43176d7-b6e8-4827-b784-7ffdc4b68561" (`uefi-raw` crate's own
        // `RngAlgorithmType::ALGORITHM_RAW` constant). Same derivation as
        // the test above, independently re-checked byte-by-byte.
        let raw: [u8; 16] = [
            0xd7, 0x76, 0x31, 0xe4, 0xe8, 0xb6, 0x27, 0x48, 0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6,
            0x85, 0x61,
        ];
        assert_eq!(as_str(&format_guid(&raw)), "e43176d7b6e84827b7847ffdc4b68561");
    }

    #[test]
    fn output_is_correct_length_and_lowercase() {
        let raw = [0xABu8; 16];
        let out = format_guid(&raw);
        assert_eq!(out.len(), GUID_TEXT_LEN);
        assert!(out.iter().all(|&b| b.is_ascii_hexdigit()));
        assert!(!out.iter().any(|&b| b.is_ascii_uppercase()));
    }

    #[test]
    fn all_zero_guid_renders_as_nil_guid_text() {
        let raw = [0u8; 16];
        let expected: String = core::iter::repeat('0').take(32).collect();
        assert_eq!(as_str(&format_guid(&raw)), expected);
    }

    #[test]
    fn text_length_fits_max_algo_id_exactly() {
        // The whole reason for the hyphen-free form: it must fit
        // `seed_core::contracts::MAX_ALGO_ID` (32) exactly, since that is
        // a frozen contract this crate cannot change.
        assert_eq!(GUID_TEXT_LEN, seed_core::contracts::MAX_ALGO_ID);
    }
}
