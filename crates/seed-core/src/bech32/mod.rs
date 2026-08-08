//! Bech32 (BIP173) / Bech32m (BIP350) segwit address encoder.
//!
//! SPEC §24.2/§24.3: used to render the BIP84 (P2WPKH, witness v0) and
//! BIP86 (P2TR, witness v1) receive addresses. Encode-only, no allocation,
//! fixed output buffer (`contracts::AddressBuf`, capacity
//! `contracts::MAX_BECH32`).
//!
//! Witness version 0 MUST use the original Bech32 checksum constant
//! (BIP173); witness versions 1 and above MUST use the Bech32m checksum
//! constant (BIP350). The only difference between the two encodings is
//! this one constant XORed into the checksum polymod — see
//! [`CHECKSUM_CONST_BECH32`] / [`CHECKSUM_CONST_BECH32M`].

use crate::contracts::{AddressBuf, EncodeError};

/// Bech32 (BIP173) checksum XOR constant, used for witness version 0.
const CHECKSUM_CONST_BECH32: u32 = 1;

/// Bech32m (BIP350) checksum XOR constant, used for witness version >= 1.
const CHECKSUM_CONST_BECH32M: u32 = 0x2bc8_30a3;

/// Bech32/Bech32m character set (SPEC §24.2, BIP173 §"Specification").
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Maximum witness-program length in bytes accepted by this encoder
/// (BIP141: 2..=40 bytes; this project only produces 20-byte and 32-byte
/// programs per SPEC §24.2, but the general bound is enforced here).
const MAX_PROGRAM_BYTES: usize = 40;
const MIN_PROGRAM_BYTES: usize = 2;

/// Highest supported witness version (BIP141: 0..=16). SPEC §24.2 only
/// ever produces versions 0 and 1, but the encoder itself is general.
const MAX_WITNESS_VERSION: u8 = 16;

/// The Bech32/Bech32m generator polynomial (BIP173 reference code).
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// One step of the Bech32 polymod checksum computation (BIP173 reference
/// code, `bech32_polymod`).
fn polymod_step(chk: u32, v: u8) -> u32 {
    let top = chk >> 25;
    let mut chk = (chk & 0x01ff_ffff) << 5 ^ (v as u32);
    for i in 0..5 {
        if (top >> i) & 1 == 1 {
            chk ^= GENERATOR[i];
        }
    }
    chk
}

/// Expands the HRP into the checksum's high/zero/low bits per BIP173
/// `bech32_hrp_expand`.
fn polymod_hrp(mut chk: u32, hrp: &[u8]) -> u32 {
    for &b in hrp {
        chk = polymod_step(chk, b >> 5);
    }
    chk = polymod_step(chk, 0);
    for &b in hrp {
        chk = polymod_step(chk, b & 0x1f);
    }
    chk
}

/// Encodes a segwit witness program as a Bech32 (version 0) or Bech32m
/// (version >= 1) address string, per SPEC §24.2/§24.3 and BIP173/BIP350.
///
/// `hrp` is the human-readable part (e.g. `b"bc"` for mainnet), `version`
/// is the witness version (0..=16), and `program` is the raw witness
/// program bytes (2..=40 bytes; 20 for P2WPKH, 32 for P2TR).
///
/// On success, writes the lowercase address into `out` (retrievable via
/// `out.as_bytes()`/`out.as_str()`). Returns `EncodeError::InvalidVersion` if `version` is out of the
/// BIP141 range, `EncodeError::InvalidProgramLength` if `program`'s
/// length is out of the BIP141 range, and `EncodeError::BufferTooSmall`
/// if the encoded output would not fit `out`.
pub fn encode(
    hrp: &[u8],
    version: u8,
    program: &[u8],
    out: &mut AddressBuf,
) -> Result<(), EncodeError> {
    if version > MAX_WITNESS_VERSION {
        return Err(EncodeError::InvalidVersion);
    }
    if program.len() < MIN_PROGRAM_BYTES || program.len() > MAX_PROGRAM_BYTES {
        return Err(EncodeError::InvalidProgramLength);
    }

    // Convert the 8-bit program into 5-bit groups (BIP173 `convertbits`),
    // preceded by the version group. Worst case ceil(40*8/5)+1 = 65
    // groups; well within a local buffer.
    let mut data5: [u8; 65] = [0; 65];
    let mut data5_len = 0usize;
    data5[data5_len] = version;
    data5_len += 1;

    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in program {
        acc = (acc << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data5[data5_len] = ((acc >> bits) & 0x1f) as u8;
            data5_len += 1;
        }
    }
    if bits > 0 {
        data5[data5_len] = ((acc << (5 - bits)) & 0x1f) as u8;
        data5_len += 1;
    }

    let const_val = if version == 0 {
        CHECKSUM_CONST_BECH32
    } else {
        CHECKSUM_CONST_BECH32M
    };

    // Checksum over hrp + data5 + 6 zero placeholder groups, per BIP173
    // `bech32_create_checksum`.
    let mut chk = polymod_hrp(1, hrp);
    for &d in &data5[..data5_len] {
        chk = polymod_step(chk, d);
    }
    for _ in 0..6 {
        chk = polymod_step(chk, 0);
    }
    chk ^= const_val;

    let mut checksum5: [u8; 6] = [0; 6];
    for (i, slot) in checksum5.iter_mut().enumerate() {
        *slot = ((chk >> (5 * (5 - i))) & 0x1f) as u8;
    }

    let total_len = hrp.len() + 1 + data5_len + 6;
    if total_len > AddressBuf::CAPACITY {
        return Err(EncodeError::BufferTooSmall);
    }

    // Rendered into a local buffer first, then written into `out` through
    // its checked `set` accessor (SHOULD-FIX #4, `docs/PRE-RELEASE-AUDIT.md`:
    // `AddressBuf`'s `bytes`/`len` fields are private, so this can no
    // longer write directly into `out`'s backing array).
    let mut rendered = [0u8; AddressBuf::CAPACITY];
    let mut w = 0usize;
    rendered[w..w + hrp.len()].copy_from_slice(hrp);
    w += hrp.len();
    rendered[w] = b'1';
    w += 1;
    for &d in &data5[..data5_len] {
        rendered[w] = CHARSET[d as usize];
        w += 1;
    }
    for &d in &checksum5 {
        rendered[w] = CHARSET[d as usize];
        w += 1;
    }
    out.set(&rendered[..total_len]);

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn addr(s: &[u8]) -> &str {
        core::str::from_utf8(s).unwrap()
    }

    fn empty_buf() -> AddressBuf {
        AddressBuf::empty()
    }

    /// Decodes a bech32/bech32m string back into (hrp, version, program)
    /// for round-trip testing / vector verification. Test-only.
    fn decode(s: &str) -> (Vec<u8>, u8, Vec<u8>, bool) {
        let s = s.to_ascii_lowercase();
        let pos = s.rfind('1').unwrap();
        let hrp = s[..pos].as_bytes().to_vec();
        let data_part = &s[pos + 1..];
        let data5: Vec<u8> = data_part
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8)
            .collect();
        let (data_no_chk, checksum) = data5.split_at(data5.len() - 6);

        let mut chk = polymod_hrp(1, &hrp);
        for &d in data_no_chk {
            chk = polymod_step(chk, d);
        }
        for &d in checksum {
            chk = polymod_step(chk, d);
        }
        let is_bech32m = chk == CHECKSUM_CONST_BECH32M;
        let is_bech32 = chk == CHECKSUM_CONST_BECH32;
        assert!(is_bech32 || is_bech32m, "invalid checksum");

        let version = data_no_chk[0];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut program = Vec::new();
        for &d in &data_no_chk[1..] {
            acc = (acc << 5) | (d as u32);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                program.push(((acc >> bits) & 0xff) as u8);
            }
        }
        (hrp, version, program, is_bech32m)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn bip173_valid_vectors() {
        // BIP173 "Test vectors for valid segwit addresses" — canonical
        // witness-v0 addresses. The witness program bytes are extracted
        // from the known-good address via this module's own checksum-
        // verifying `decode` (which independently checks the polymod
        // against the BIP173 constant, so a wrong checksum constant
        // would fail the `is_bech32`/`is_bech32m` assertion inside
        // `decode` before ever reaching `encode`); re-encoding must then
        // reproduce the exact published address string byte-for-byte.
        let addresses: &[&str] = &[
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ];

        for &address in addresses {
            let (hrp, version, program, is_m) = decode(address);
            assert!(!is_m, "witness v0 addresses must checksum as bech32, not bech32m");
            assert_eq!(version, 0);

            let mut out = empty_buf();
            encode(&hrp, version, &program, &mut out).unwrap();
            let got = addr(out.as_bytes()).to_ascii_lowercase();
            assert_eq!(got, address.to_ascii_lowercase(), "encode mismatch for {address}");
        }
    }

    #[test]
    fn bip350_valid_vectors() {
        // BIP350 "Test vectors for valid segwit addresses" (bech32m set,
        // witness versions >= 1). Programs are extracted from the known-
        // good address via `decode` (see `bip173_valid_vectors` for why
        // this is still a meaningful known-answer check), then
        // re-encoded and compared byte-for-byte against the published
        // address string.
        let addresses: &[&str] = &[
            "BC1SW50QGDZ25J",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        ];

        for &address in addresses {
            let (hrp, version, program, is_m) = decode(address);
            assert!(is_m, "witness v1+ addresses must checksum as bech32m, not bech32");
            assert!(version >= 1);

            let mut out = empty_buf();
            encode(&hrp, version, &program, &mut out).unwrap();
            let got = addr(out.as_bytes()).to_ascii_lowercase();
            assert_eq!(got, address.to_ascii_lowercase(), "encode mismatch for {address}");
        }
    }

    #[test]
    fn version0_never_uses_bech32m_and_vice_versa() {
        // The classic pitfall: encoding v0 with the wrong (bech32m)
        // constant, or v1+ with the wrong (bech32) constant.
        let program20 = [0u8; 20];
        let program32 = [0u8; 32];

        let mut out = empty_buf();
        encode(b"bc", 0, &program20, &mut out).unwrap();
        let s = addr(out.as_bytes());
        let (_, ver, _, is_m) = decode(s);
        assert_eq!(ver, 0);
        assert!(!is_m, "witness v0 must use bech32, not bech32m");

        let mut out2 = empty_buf();
        encode(b"bc", 1, &program32, &mut out2).unwrap();
        let s2 = addr(out2.as_bytes());
        let (_, ver2, _, is_m2) = decode(s2);
        assert_eq!(ver2, 1);
        assert!(is_m2, "witness v1+ must use bech32m, not bech32");
    }

    #[test]
    fn round_trip_p2wpkh_and_p2tr() {
        let p2wpkh = hex("000102030405060708090a0b0c0d0e0f10111213");
        let mut out = empty_buf();
        encode(b"bc", 0, &p2wpkh, &mut out).unwrap();
        let s = addr(out.as_bytes());
        let (hrp, ver, prog, is_m) = decode(s);
        assert_eq!(hrp, b"bc");
        assert_eq!(ver, 0);
        assert_eq!(prog, p2wpkh);
        assert!(!is_m);

        let p2tr = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let mut out2 = empty_buf();
        encode(b"bc", 1, &p2tr, &mut out2).unwrap();
        let s2 = addr(out2.as_bytes());
        let (hrp2, ver2, prog2, is_m2) = decode(s2);
        assert_eq!(hrp2, b"bc");
        assert_eq!(ver2, 1);
        assert_eq!(prog2, p2tr);
        assert!(is_m2);
    }

    #[test]
    fn invalid_version_rejected() {
        let mut out = empty_buf();
        let err = encode(b"bc", 17, &[0u8; 20], &mut out).unwrap_err();
        assert_eq!(err, EncodeError::InvalidVersion);
    }

    #[test]
    fn invalid_program_length_rejected() {
        let mut out = empty_buf();
        assert_eq!(
            encode(b"bc", 0, &[0u8; 1], &mut out).unwrap_err(),
            EncodeError::InvalidProgramLength
        );
        assert_eq!(
            encode(b"bc", 0, &[0u8; 41], &mut out).unwrap_err(),
            EncodeError::InvalidProgramLength
        );
    }

    #[test]
    fn buffer_too_small_rejected() {
        let mut out = AddressBuf::empty();
        // Oversized HRP forces the total encoded length past the buffer
        // capacity, exercising the BufferTooSmall path directly.
        let big_hrp = [b'a'; 90];
        let err = encode(&big_hrp, 0, &[0u8; 20], &mut out).unwrap_err();
        assert_eq!(err, EncodeError::BufferTooSmall);
    }

    #[test]
    fn max_bech32_capacity_matches_worst_case() {
        // Worst case per contracts.rs derivation: 32-byte v1 program,
        // 2-byte HRP ("bc"/"tb"): 2 + 1 + 53 + 6 = 62 <= MAX_BECH32 (64).
        let mut out = empty_buf();
        assert!(AddressBuf::CAPACITY >= crate::contracts::MAX_BECH32);
        encode(b"bc", 1, &[0u8; 32], &mut out).unwrap();
        assert!(out.len() <= crate::contracts::MAX_BECH32);
    }
}
