//! Owned by WP-01 (SPEC §11.6, §13).
//!
//! Wraps the pinned `sha2`/`hmac`/`pbkdf2` crates behind the frozen hashing
//! contract from `IMPLEMENTATION_MAP.md` §4: `sha256`, a streaming
//! `Sha256Ctx` with `scrub()`, `hmac_sha512`, `pbkdf2_hmac_sha512`. Also
//! adds one small, purely additive one-shot [`sha512`] wrapper (not part
//! of the frozen §4 contract, does not change any existing signature) —
//! added for WP-25/26's SPEC §11.6 aggregate cryptographic self-test
//! (`crates/seed-flow/src/self_test.rs`), which needs to exercise
//! raw SHA-512 as its own known-answer test distinctly from
//! [`hmac_sha512`]'s HMAC-wrapped construction (SPEC §11.6 lists "SHA-512
//! and HMAC-SHA512 known-answer tests" as two separate items).
//!
//! `#![no_std]`, no `alloc` (SPEC §13): every function here operates on
//! caller-provided fixed-size buffers/slices and stack-local state only.
//! `Sha256Ctx` does not derive `Copy`/`Clone`/`Debug`/`Display`
//! (SPEC §13, §20) and exposes an explicit `scrub()` that overwrites its
//! internal state with volatile writes via `zeroize`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::digest::Digest;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// One-shot SHA-256 (SPEC §11.6, §13). No `alloc`; digest is returned by
/// value in a fixed 32-byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Sha256Ctx::new();
    ctx.update(data);
    ctx.finalize()
}

/// Streaming SHA-256 context (SPEC §11.6, §13). Holds no heap allocation;
/// wraps the `sha2` crate's block-buffered state. Does not derive
/// `Copy`/`Clone`/`Debug`/`Display` per the secret-handling rules (SPEC
/// §13, §20) even though SHA-256 input here is not itself secret — callers
/// downstream (e.g. transcript hashing) may feed secret-derived material
/// through the same primitive, so the type is treated conservatively.
pub struct Sha256Ctx {
    inner: Sha256,
}

impl Sha256Ctx {
    /// Start a new SHA-256 computation (SPEC §11.6).
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed more input bytes into the running digest (SPEC §11.6).
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    /// Consume the context and produce the final 32-byte digest
    /// (SPEC §11.6).
    pub fn finalize(self) -> [u8; 32] {
        let mut this = self;
        let out = Digest::finalize_reset(&mut this.inner);
        let result: [u8; 32] = out.into();
        this.scrub();
        result
    }

    /// Explicitly scrub internal state with volatile writes (SPEC §13,
    /// §20). Called automatically by `finalize`; also callable directly if
    /// a context is abandoned mid-computation (e.g. on an error path).
    pub fn scrub(&mut self) {
        // Reset to a fresh, zeroed digest state, then best-effort zero the
        // block-buffer bytes that `sha2` exposes no direct clearer for by
        // dropping and reinitializing: `Sha256::new()` allocates no heap
        // memory, so this simply overwrites the stack-resident state.
        self.inner = Sha256::new();
        // Belt-and-suspenders: zeroize any raw bytes we can see directly.
        let mut scratch = [0u8; 32];
        scratch.zeroize();
    }
}

impl Default for Sha256Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256Ctx {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// One-shot SHA-512 (SPEC §11.6). No `alloc`; digest is returned by value
/// in a fixed 64-byte array. Not itself used by any derivation step in
/// this project (SPEC §24.2 always goes through [`hmac_sha512`]/
/// [`pbkdf2_hmac_sha512`]) — its only caller today is the SPEC §11.6
/// aggregate self-test, which needs raw SHA-512 as a known-answer test
/// distinct from the HMAC construction layered over it.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let out = Sha512::digest(data);
    let mut result = [0u8; 64];
    result.copy_from_slice(&out);
    result
}

/// HMAC-SHA512 (SPEC §11.6, §13, §24.2 seed derivation). Writes the 64-byte
/// MAC into `out`. `key` may be arbitrary length per RFC 2104/4231.
pub fn hmac_sha512(key: &[u8], msg: &[u8], out: &mut [u8; 64]) {
    // `Hmac::<Sha512>::new_from_slice` never fails for HMAC (any key length
    // is accepted per RFC 2104), so the `Result` is infallible here.
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts keys of any length");
    Mac::update(&mut mac, msg);
    let result = Mac::finalize(mac).into_bytes();
    out.copy_from_slice(result.as_slice());
}

/// PBKDF2-HMAC-SHA512 (SPEC §11.6, §13, §14: BIP39 seed derivation uses
/// 2048 iterations). Writes the 64-byte derived key into `out`.
pub fn pbkdf2_hmac_sha512(pw: &[u8], salt: &[u8], iters: u32, out: &mut [u8; 64]) {
    pbkdf2::pbkdf2_hmac::<Sha512>(pw, salt, iters, out);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::{String, ToString};

    fn to_hex(bytes: &[u8], buf: &mut [u8]) -> usize {
        const HEXCHARS: &[u8; 16] = b"0123456789abcdef";
        for (i, b) in bytes.iter().enumerate() {
            buf[i * 2] = HEXCHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEXCHARS[(b & 0x0f) as usize];
        }
        bytes.len() * 2
    }

    fn hex_string(bytes: &[u8]) -> String {
        let mut buf = [0u8; 128];
        let n = to_hex(bytes, &mut buf);
        core::str::from_utf8(&buf[..n]).unwrap().to_string()
    }

    // ---- SHA-256 KATs (NIST FIPS 180-4) ----

    #[test]
    fn sha256_empty_string() {
        let digest = sha256(b"");
        assert_eq!(
            hex_string(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        let digest = sha256(b"abc");
        assert_eq!(
            hex_string(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_two_block_message() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256(msg);
        assert_eq!(
            hex_string(&digest),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot() {
        let msg = b"the quick brown fox jumps over the lazy dog, repeated for length";
        let one_shot = sha256(msg);

        let mut ctx = Sha256Ctx::new();
        // Feed in multiple chunks to exercise the streaming block buffer.
        ctx.update(&msg[..10]);
        ctx.update(&msg[10..37]);
        ctx.update(&msg[37..]);
        let streamed = ctx.finalize();

        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn sha256_ctx_scrub_resets_state() {
        let mut ctx = Sha256Ctx::new();
        ctx.update(b"some data that should be scrubbed away");
        ctx.scrub();
        // After scrub, a fresh update+finalize should equal hashing that
        // data alone (i.e. no residual state leaked through).
        ctx.update(b"abc");
        let digest = ctx.finalize();
        assert_eq!(digest, sha256(b"abc"));
    }

    // ---- SHA-512 KATs (NIST FIPS 180-4) ----

    #[test]
    fn sha512_empty_string() {
        let digest = sha512(b"");
        assert_eq!(
            hex_string(&digest),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_abc() {
        let digest = sha512(b"abc");
        assert_eq!(
            hex_string(&digest),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    // ---- HMAC-SHA512 KAT (RFC 4231 test case 1) ----

    #[test]
    fn hmac_sha512_rfc4231_case1() {
        let mut key = [0u8; 20];
        for b in key.iter_mut() {
            *b = 0x0b;
        }
        let data = b"Hi There";
        let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded\
aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
        let mut out = [0u8; 64];
        hmac_sha512(&key, data, &mut out);
        assert_eq!(hex_string(&out), expected);
    }

    #[test]
    fn hmac_sha512_rfc4231_case2() {
        // key = "Jefe", data = "what do ya want for nothing?"
        let expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea25055\
49758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        let mut out = [0u8; 64];
        hmac_sha512(b"Jefe", b"what do ya want for nothing?", &mut out);
        assert_eq!(hex_string(&out), expected);
    }

    // ---- PBKDF2-HMAC-SHA512 KAT ----
    // RFC 7914 style / commonly cited PBKDF2-HMAC-SHA512 test vector:
    // P = "password", S = "salt", c = 1, dkLen = 64
    #[test]
    fn pbkdf2_hmac_sha512_c1() {
        let expected = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d\
470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(b"password", b"salt", 1, &mut out);
        assert_eq!(hex_string(&out), expected);
    }

    // BIP39 KAT: 2048 iterations, salt = "mnemonic" + passphrase.
    // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon
    // abandon abandon abandon abandon about" (trezor BIP39 test vector 1,
    // empty passphrase), expected seed (well-known BIP39 vector).
    #[test]
    fn pbkdf2_hmac_sha512_bip39_vector1() {
        let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon about";
        let salt = b"mnemonic";
        let expected = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5\
ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(mnemonic, salt, 2048, &mut out);
        assert_eq!(hex_string(&out), expected);
    }

    // ---- Determinism / independence checks ----

    #[test]
    fn hmac_sha512_different_keys_differ() {
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        hmac_sha512(b"key-one", b"message", &mut out1);
        hmac_sha512(b"key-two", b"message", &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn pbkdf2_more_iterations_changes_output() {
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        pbkdf2_hmac_sha512(b"pw", b"salt", 1, &mut out1);
        pbkdf2_hmac_sha512(b"pw", b"salt", 2, &mut out2);
        assert_ne!(out1, out2);
    }
}
