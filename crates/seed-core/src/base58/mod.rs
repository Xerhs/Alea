//! Owned by WP-03 (SPEC §24). Fixed-buffer, no-alloc, encode-only
//! Base58Check encoder.
//!
//! Base58Check (as used by Bitcoin legacy/P2SH addresses, SPEC §24.2, and
//! by wallet-export extended-key serialization,
//! `docs/superpowers/specs/2026-08-07-wallet-export-design.md`) is:
//! `base58(payload || checksum)` where `checksum = SHA256(SHA256(payload))[..4]`
//! and leading `0x00` bytes in `payload` become leading `'1'` characters in
//! the output (SPEC §24.2/§24.3, Bitcoin's own convention).
//!
//! This module implements encode only — no code path here ever decodes a
//! Base58Check string back to bytes (IMPLEMENTATION_MAP.md §5, WP-03).
//!
//! No `std`, no `alloc`: every buffer here is a fixed-size stack array
//! sized against this module's own [`MAX_PAYLOAD`]. `out` is a plain
//! `&mut [u8]` — callers own their buffer's size (SPEC §24.2/§24.3 address
//! callers still size theirs against [`crate::contracts::MAX_B58`]; the
//! larger [`MAX_PAYLOAD`] here additionally covers wallet-export use,
//! e.g. a serialized BIP32 extended key, whose callers own bigger
//! buffers of their own).

use sha2::{Digest, Sha256};

/// The 58-character Base58 alphabet (Bitcoin's variant: no `0`, `O`, `I`,
/// `l` — SPEC §24.2 inherits Bitcoin's Base58Check exactly).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Maximum payload length this encoder accepts.
///
/// Two in-repo payload shapes both need to fit: the SPEC §24.2 address
/// payload (1 version byte + 20-byte `hash160` = 21 bytes) and a
/// wallet-export serialized BIP32 extended key (4-byte version + 1-byte
/// depth + 4-byte parent fingerprint + 4-byte child number + 32-byte
/// chain code + 33-byte key = 78 bytes, BIP32 "Serialization format").
/// 78 is the larger of the two, so it sets the bound.
pub const MAX_PAYLOAD: usize = 78;

/// `payload` + 4-byte checksum — the full pre-Base58 byte string.
const MAX_TOTAL: usize = MAX_PAYLOAD + 4;

/// Base58 expansion bound for [`MAX_TOTAL`] bytes, sizing the internal
/// digit-conversion working buffer: Base58 expands `n` bytes to at most
/// `n * 138 / 100 + 1` characters (the standard bound used by Bitcoin
/// Core's own `base58.cpp`, itself a safe rounding of
/// `log(256)/log(58) ≈ 1.3657`). For `MAX_TOTAL` = 82:
/// `82 * 138 / 100 + 1 = 113 + 1 = 114`.
const MAX_WORK: usize = MAX_TOTAL * 138 / 100 + 1;

/// Encodes `payload` as Base58Check into `out`, returning the number of
/// valid bytes written to `out[..n]` (SPEC §24.2, §24.3).
///
/// The checksum (first 4 bytes of `SHA256(SHA256(payload))`) is computed
/// internally and appended before Base58 conversion; callers pass the raw
/// version-byte-prefixed payload only (e.g. `0x00 || hash160(pubkey)` for
/// P2PKH, `0x05 || hash160(script)` for P2SH, or a serialized BIP32
/// extended key for wallet export).
///
/// # Panics
///
/// Panics if `payload.len() > MAX_PAYLOAD` (a programming-contract
/// violation, not a runtime data error — every in-repo caller passes a
/// fixed-size payload well within this bound) or if the encoded result
/// would not fit in `out` (the caller's responsibility to size; see each
/// call site's own buffer-size proof).
pub fn base58check_encode(payload: &[u8], out: &mut [u8]) -> usize {
    assert!(
        payload.len() <= MAX_PAYLOAD,
        "base58check_encode: payload exceeds MAX_PAYLOAD"
    );

    // ---- checksum = first 4 bytes of double SHA-256 ----
    let mut buf = [0u8; MAX_TOTAL];
    buf[..payload.len()].copy_from_slice(payload);
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    buf[payload.len()..payload.len() + 4].copy_from_slice(&second[..4]);
    let data = &buf[..payload.len() + 4];

    encode_raw(data, out)
}

/// Core Base58 big-integer conversion (no checksum applied), following the
/// classic Bitcoin Core `EncodeBase58` algorithm: repeated
/// base-256 → base-58 long division over a fixed digit-buffer, with
/// leading zero input bytes mapped 1:1 to leading `'1'` output
/// characters.
fn encode_raw(data: &[u8], out: &mut [u8]) -> usize {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let significant = &data[zeros..];

    // Digit buffer: each cell holds one base-58 digit (0..57). Sized to
    // MAX_WORK, which is always sufficient headroom for `data.len() <=
    // MAX_TOTAL` (see MAX_WORK's derivation).
    let mut b58 = [0u8; MAX_WORK];
    let size = b58.len();
    let mut length = 0usize;

    for &byte in significant {
        let mut carry = byte as u32;
        let mut i = 0usize;
        let mut j = size;
        while j > 0 && (carry != 0 || i < length) {
            j -= 1;
            carry += 256 * b58[j] as u32;
            b58[j] = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
        assert!(
            carry == 0,
            "base58check_encode: digit buffer overflow (payload too large)"
        );
        length = i;
    }

    // Skip any leading zero digits left in the working buffer.
    let mut start = size - length;
    while start < size && b58[start] == 0 {
        start += 1;
    }

    let total_len = zeros + (size - start);
    assert!(total_len <= out.len(), "base58check_encode: output too small");

    for i in 0..zeros {
        out[i] = b'1';
    }
    for (i, &digit) in b58[start..size].iter().enumerate() {
        out[zeros + i] = ALPHABET[digit as usize];
    }

    total_len
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::MAX_B58;
    use std::vec;
    use std::vec::Vec;

    fn encode_str(payload: &[u8]) -> alloc_free_string::FixedStr {
        let mut out = [0u8; MAX_B58];
        let n = base58check_encode(payload, &mut out);
        alloc_free_string::FixedStr { bytes: out, len: n }
    }

    /// Minimal `std`-free-ish helper for comparing output as `&str` in
    /// tests (tests run under `std`, this is purely test-side sugar).
    mod alloc_free_string {
        use super::MAX_B58;
        pub struct FixedStr {
            pub bytes: [u8; MAX_B58],
            pub len: usize,
        }
        impl FixedStr {
            pub fn as_str(&self) -> &str {
                core::str::from_utf8(&self.bytes[..self.len]).unwrap()
            }
        }
    }

    /// KAT: the well-known Bitcoin genesis-block coinbase P2PKH address,
    /// decomposed as version byte `0x00` + `hash160`
    /// (`62e907b15cbf27d5425399ebf6f0fb50ebb88f18`), independently
    /// recomputed with a reference Python implementation
    /// (`hashlib.sha256` double-hash + manual base58 big-integer division)
    /// to avoid transcription error in the expected string.
    #[test]
    fn kat_p2pkh_textbook_vector() {
        let mut payload = [0u8; 21];
        payload[0] = 0x00;
        let hash160: [u8; 20] = [
            0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0,
            0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
        ];
        payload[1..].copy_from_slice(&hash160);
        let s = encode_str(&payload);
        assert_eq!(s.as_str(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    /// KAT: all-zero 21-byte payload (version 0x00 + all-zero hash160)
    /// must produce all leading `'1'`s: 21 zero bytes -> 21 leading '1's,
    /// since the checksum of an all-zero payload is not itself all-zero
    /// (so only the payload's leading zeros collapse to '1', not more).
    #[test]
    fn leading_zero_bytes_become_leading_ones() {
        let payload = [0u8; 21];
        let s = encode_str(&payload);
        let leading_ones = s.as_str().bytes().take_while(|&b| b == b'1').count();
        // All 21 payload bytes are zero, so at least 21 leading '1's.
        assert!(leading_ones >= 21, "got {} leading ones in {}", leading_ones, s.as_str());
    }

    /// KAT: single zero byte payload -> single leading '1', rest encodes
    /// checksum of that one zero byte.
    #[test]
    fn single_zero_byte_payload() {
        let payload = [0u8];
        let s = encode_str(&payload);
        assert!(s.as_str().starts_with('1'));
        // Round-trip-able length sanity: payload(1) + checksum(4) = 5 bytes.
        assert!(s.as_str().len() >= 5);
    }

    /// KAT: empty payload — checksum of empty input is still 4 bytes, so
    /// output is never empty.
    #[test]
    fn empty_payload_still_encodes_checksum() {
        let payload: [u8; 0] = [];
        let s = encode_str(&payload);
        assert!(!s.as_str().is_empty());
    }

    /// P2SH example: version byte 0x05 + hash160 of an all-`0xFF` fill,
    /// verifying non-zero version bytes never leak a spurious leading '1'.
    #[test]
    fn p2sh_version_byte_no_spurious_leading_one() {
        let mut payload = [0u8; 21];
        payload[0] = 0x05;
        for b in &mut payload[1..] {
            *b = 0xFF;
        }
        let s = encode_str(&payload);
        assert!(!s.as_str().starts_with('1'));
    }

    /// Output length must always be within the documented MAX_WORK bound
    /// for every payload length up to MAX_PAYLOAD, across varied content
    /// (MAX_WORK is the Base58 expansion bound for MAX_PAYLOAD + 4 bytes
    /// of checksum — see its doc comment for the derivation).
    #[test]
    fn output_never_exceeds_max_work_across_payload_sizes() {
        for len in 0..=MAX_PAYLOAD {
            let mut payload = [0u8; MAX_PAYLOAD];
            for (i, b) in payload[..len].iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37).wrapping_add(11);
            }
            let mut out = [0u8; MAX_WORK];
            let n = base58check_encode(&payload[..len], &mut out);
            assert!(n <= MAX_WORK);
        }
    }

    /// KAT: the canonical Bitcoin wiki Base58Check worked example
    /// (https://en.bitcoin.it/wiki/Base58Check_encoding, "Encoding a
    /// Bitcoin address"). The wiki's published hex
    /// `00010966776006953D5567439E5E39F86A0D273BEED61967F6` is the full
    /// 25-byte *payload+checksum* blob (21-byte payload followed by its
    /// own 4-byte checksum, already appended) — NOT the input to this
    /// function. The input `payload` here is only the first 21 bytes
    /// (`00010966776006953D5567439E5E39F86A0D273BEE`); this function
    /// computes the checksum itself and must reproduce the wiki's
    /// trailing 4 bytes (`D61967F6`) internally, then encode all 25
    /// bytes to the wiki's expected string.
    #[test]
    fn kat_bitcoin_wiki_vector() {
        let payload: [u8; 21] = [
            0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E,
            0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE,
        ];
        let mut out = [0u8; MAX_B58];
        let n = base58check_encode(&payload, &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert_eq!(s, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
    }

    /// Length-sanity KAT: an xpub-sized (78-byte) payload — BIP32 extended
    /// key serialization is 4-byte version + 1-byte depth + 4-byte parent
    /// fingerprint + 4-byte child number + 32-byte chain code + 33-byte
    /// key = 78 bytes — must encode without panicking, and (per the
    /// standard `n*138/100+1` Base58 expansion bound applied to
    /// 78 + 4 = 82 total bytes) land in the 111-112 character range that
    /// real xpub/tpub strings occupy. Uses a non-zero varied byte pattern
    /// (a leading zero payload byte would collapse to a leading '1' and
    /// throw off the length, which real extended-key version bytes never
    /// have).
    #[test]
    fn xpub_sized_payload_length_sanity() {
        let mut payload = [0u8; 78];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        assert_ne!(payload[0], 0, "test payload must not start with a zero byte");
        let mut out = [0u8; 130];
        let n = base58check_encode(&payload, &mut out);
        assert!(
            (111..=112).contains(&n),
            "expected 111-112 chars for a 78-byte payload, got {n}"
        );
        // Must still be valid ASCII from the Base58 alphabet.
        core::str::from_utf8(&out[..n]).unwrap();
    }

    /// Checksum correctness: manually recompute double-SHA256 and verify
    /// the last 4 base58-decoded bytes (via independent decode) match.
    /// Since this module is encode-only, we verify via a minimal local
    /// base58 decoder used only in this test.
    #[test]
    fn checksum_matches_double_sha256() {
        let payload = [0x00u8; 1];
        let mut out = [0u8; MAX_B58];
        let n = base58check_encode(&payload, &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();

        // Local decode (test-only, not part of the module's public API).
        fn decode(s: &str) -> Vec<u8> {
            let mut num = vec![0u8; 1];
            let mut leading_zeros = 0usize;
            let mut counting_zeros = true;
            for c in s.chars() {
                if c == '1' && counting_zeros {
                    leading_zeros += 1;
                    continue;
                }
                counting_zeros = false;
                let digit = ALPHABET.iter().position(|&a| a as char == c).unwrap() as u32;
                let mut carry = digit;
                for byte in num.iter_mut().rev() {
                    carry += *byte as u32 * 58;
                    *byte = (carry & 0xFF) as u8;
                    carry >>= 8;
                }
                while carry > 0 {
                    num.insert(0, (carry & 0xFF) as u8);
                    carry >>= 8;
                }
            }
            let mut result = vec![0u8; leading_zeros];
            let first_nonzero = num.iter().position(|&b| b != 0).unwrap_or(num.len());
            result.extend_from_slice(&num[first_nonzero..]);
            result
        }

        let decoded = decode(s);
        assert_eq!(decoded.len(), 5); // 1 payload byte + 4 checksum bytes
        assert_eq!(&decoded[..1], &payload[..]);

        let first = Sha256::digest(payload);
        let second = Sha256::digest(first);
        assert_eq!(&decoded[1..5], &second[..4]);
    }
}
