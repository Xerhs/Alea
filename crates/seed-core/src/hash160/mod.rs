//! Owned by WP-02 (SPEC §24). `hash160 = RIPEMD160(SHA256(x))`.
//!
//! Wraps the pinned `sha2` and `ripemd` crates (SPEC §31, `IMPLEMENTATION_MAP.md`
//! §3). This is the primitive SPEC §24.2 uses to compute the master
//! fingerprint (first 4 bytes of `HASH160` of the master public key) and
//! any P2PKH/P2SH payload construction (§24.2/§24.3, consumed downstream
//! by WP-03's Base58Check encoder).
//!
//! `hash160` operates on public, non-secret data (public keys), so no
//! secret-handling rules (SPEC §13/§20) apply to this module; it is a pure
//! fixed-output function with no heap allocation (`no_std`, no `alloc`).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// `hash160(x) = RIPEMD160(SHA256(x))` (SPEC §24.2, `IMPLEMENTATION_MAP.md`
/// §4 frozen contract: `pub fn hash160(data: &[u8]) -> [u8; 20]`).
///
/// No allocation: both underlying hash implementations operate on fixed
/// internal state and the 32-byte SHA-256 intermediate digest is a stack
/// array.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::hash160;

    /// Decode a lowercase hex string into a fixed-size byte array. Test-only
    /// helper (`std` permitted under `#[cfg(test)]` per `AGENTS.md`).
    fn hex_to_vec(s: &str) -> std::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_20(s: &str) -> [u8; 20] {
        let v = hex_to_vec(s);
        let mut out = [0u8; 20];
        out.copy_from_slice(&v);
        out
    }

    /// SHA-256("") known answer (NIST FIPS 180-4 / RFC 6234 test vector):
    /// used to sanity-check the SHA-256 stage independently before
    /// checking the full hash160 composite.
    #[test]
    fn sha256_empty_kat() {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(b"");
        assert_eq!(
            d.as_slice(),
            &hex_to_vec("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[..]
        );
    }

    /// RIPEMD-160("") official known-answer test (RIPEMD reference test
    /// suite, ISO/IEC 10118-3): checked independently of the SHA-256 stage
    /// so a hash160 composite failure can be isolated to one primitive.
    #[test]
    fn ripemd160_empty_kat() {
        use ripemd::{Digest, Ripemd160};
        let d = Ripemd160::digest(b"");
        assert_eq!(
            d.as_slice(),
            &hex_to_vec("9c1185a5c5e9fc54612808977ee8f548b2258d31")[..]
        );
    }

    /// RIPEMD-160("abc") official known-answer test (RIPEMD reference test
    /// suite).
    #[test]
    fn ripemd160_abc_kat() {
        use ripemd::{Digest, Ripemd160};
        let d = Ripemd160::digest(b"abc");
        assert_eq!(
            d.as_slice(),
            &hex_to_vec("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")[..]
        );
    }

    /// hash160("") = RIPEMD160(SHA256("")). Composite known-answer test,
    /// cross-checked against an independent computation
    /// (`openssl dgst -sha256 -binary | openssl dgst -ripemd160`).
    #[test]
    fn hash160_empty() {
        let expected = hex_to_20("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
        assert_eq!(hash160(b""), expected);
    }

    /// hash160("abc") composite known-answer test, cross-checked against
    /// an independent computation
    /// (`printf 'abc' | openssl dgst -sha256 -binary | openssl dgst -ripemd160`).
    #[test]
    fn hash160_abc() {
        let expected = hex_to_20("bb1be98c142444d7a56aa3981c3942a978e4dc33");
        assert_eq!(hash160(b"abc"), expected);
    }

    /// hash160 of a 33-byte compressed-secp256k1-pubkey-shaped input (0x02
    /// prefix + 32 bytes of `0xff`), the realistic SPEC §24.2 input shape
    /// (`HASH160` of a public key). Cross-checked against an independent
    /// computation
    /// (`printf '\x02\xff...' | openssl dgst -sha256 -binary | openssl dgst -ripemd160`).
    #[test]
    fn hash160_33_byte_pubkey_shape() {
        let mut input = [0xffu8; 33];
        input[0] = 0x02;
        let expected = hex_to_20("2914980c04dec23ab03cfcd610adf39d62d7c5fb");
        assert_eq!(hash160(&input), expected);
    }

    /// hash160 output is always exactly 20 bytes for any input length,
    /// matching the frozen contract signature `-> [u8; 20]`.
    #[test]
    fn hash160_output_length_invariant() {
        assert_eq!(hash160(b"").len(), 20);
        assert_eq!(hash160(b"x").len(), 20);
        assert_eq!(hash160(&[0u8; 1000]).len(), 20);
    }
}
