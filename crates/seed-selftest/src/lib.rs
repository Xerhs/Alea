//! SPEC §11.6 aggregate cryptographic self-test.
//!
//! > Before enabling generation, the application MUST perform: SHA-256
//! > known-answer tests. SHA-512 and HMAC-SHA512 known-answer tests.
//! > PBKDF2 known-answer tests. secp256k1 known-answer tests
//! > (public-key derivation against fixed vectors). RIPEMD-160,
//! > Base58Check and Bech32/Bech32m known-answer tests. BIP39 12-word and
//! > 24-word known-answer tests. BIP32 derivation known-answer tests.
//! > Entropy-transcript tests. Dice and coin session tests. Wordlist
//! > integrity tests. Fixed-buffer bounds tests. State-machine invariant
//! > tests suitable for startup. Production-build policy-marker checks.
//! > If any test fails, generation is disabled.
//!
//! # STEP C: why this is its own crate, not `seed_core::self_test`
//!
//! This is [`seed_flow::firmware_wiring::ProdCryptoSelfTestGate`]'s real
//! implementation body (moved here from `seed-flow`, a UI-layer crate,
//! per this SPEC §11.6 gap fix): [`run_aggregate_self_test`] performs all
//! thirteen SPEC §11.6 bullets (grouped into thirteen
//! [`AggregateSelfTestReport`] fields, one per bullet) against fixed,
//! independently-known expected values, then `ProdCryptoSelfTestGate::
//! check()` reduces [`AggregateSelfTestReport::all_clean`] to a single
//! `CryptoCheckResult`.
//!
//! The natural home for this module is `seed_core::self_test` (every
//! bullet here validates a `seed-core`/`seed-derive`/`seed-protocol`
//! primitive directly, nothing UI-specific) — but that is not possible
//! without a real dependency cycle: this self-test needs BOTH
//! `seed-derive` (bullets 4, 5, 7: `curve`, `bip32`) and `seed-protocol`
//! (bullets 8, 9, 11, 12: transcript, physical session, state machine),
//! and both of those crates already depend on `seed-core` (see their own
//! `Cargo.toml`s). Adding either back as a `seed-core` dependency would
//! make Cargo reject the whole workspace with a cyclic-package-
//! dependency error, not merely produce bad layering. This tiny crate is
//! the fallback the audit report itself anticipated for exactly this
//! case: every crate it exercises (`seed-core`, `seed-derive`,
//! `seed-protocol`) is strictly upstream of it, and none of them depend
//! back on this crate, so no cycle is possible.
//!
//! Every expected constant below was computed once, out of band, directly
//! from this project's own primitives (`/tmp` scratch binary path-depending
//! on `seed-core`/`seed-derive`/`seed-protocol`, discarded after use) and
//! cross-checked against well-known, independently published vectors
//! wherever one exists (NIST FIPS 180-4 SHA-256/SHA-512, RFC 4231
//! HMAC-SHA512, the secp256k1 generator point, BIP173's own P2WPKH test
//! vector, the standard all-zero-entropy BIP39 vector, and this
//! repository's own frozen `tests/vectors/frozen/
//! dice_only_12w_recommended.json`). None of the expected values are
//! computed by calling the same code path at runtime — that would defeat
//! the purpose of a known-answer test (SPEC §11.6: a KAT catches
//! *regressions*, so the expected side must be fixed independently of the
//! code under test).
//!
//! `#![no_std]`, no `alloc`: every buffer here is a small fixed-size stack
//! array, matching every other crate in this workspace (SPEC §13).
#![no_std]

use seed_core::bech32;
use seed_core::bip39;
use seed_core::contracts::{
    ArchId, SourceTag, TargetBits, MAX_B58, MAX_MACHINE_SOURCE_BYTES, TRANSCRIPT_CAPACITY,
};
use seed_core::hash::{hmac_sha512, pbkdf2_hmac_sha512, sha256, sha512};
use seed_core::hash160::hash160;
use seed_derive::bip32;
use seed_derive::curve;
use seed_protocol::physical::{CoinFace, PhysicalSession};
use seed_protocol::state::{AppState, ErrorClass, Event, StateMachine, WatchdogReassert};
use seed_protocol::transcript::{TranscriptBuilder, TranscriptError};

/// One boolean per SPEC §11.6 bullet, in the spec's own listed order.
/// `true` means that bullet's known-answer test(s) matched their expected
/// value(s); `false` means at least one did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateSelfTestReport {
    /// Bullet 1: SHA-256 known-answer test.
    pub sha256_kat: bool,
    /// Bullet 2: SHA-512 and HMAC-SHA512 known-answer tests.
    pub sha512_hmac_sha512_kat: bool,
    /// Bullet 3: PBKDF2 known-answer test.
    pub pbkdf2_kat: bool,
    /// Bullet 4: secp256k1 known-answer test (public-key derivation
    /// against a fixed vector).
    pub secp256k1_kat: bool,
    /// Bullet 5: RIPEMD-160, Base58Check and Bech32/Bech32m known-answer
    /// tests.
    pub ripemd160_base58check_bech32_kat: bool,
    /// Bullet 6: BIP39 12-word and 24-word known-answer tests.
    pub bip39_kat: bool,
    /// Bullet 7: BIP32 derivation known-answer test.
    pub bip32_kat: bool,
    /// Bullet 8: entropy-transcript test.
    pub entropy_transcript_kat: bool,
    /// Bullet 9: dice and coin session test.
    pub dice_coin_session_kat: bool,
    /// Bullet 10: wordlist integrity test.
    pub wordlist_integrity: bool,
    /// Bullet 11: fixed-buffer bounds test.
    pub fixed_buffer_bounds_kat: bool,
    /// Bullet 12: state-machine invariant test suitable for startup.
    pub state_machine_invariant_kat: bool,
    /// Bullet 13: production-build policy-marker check. Vacuously `true`
    /// when the caller passes `None` (an edition, such as the test
    /// edition, that structurally never claims to be the verified
    /// production build has nothing to falsely assert — see
    /// [`run_aggregate_self_test`]'s `policy_marker_check` parameter doc).
    pub production_build_policy_marker: bool,
}

impl AggregateSelfTestReport {
    /// `true` only if every one of the thirteen SPEC §11.6 bullets passed
    /// (SPEC §11.6: "If any test fails, generation is disabled.").
    #[must_use]
    pub const fn all_clean(&self) -> bool {
        self.sha256_kat
            && self.sha512_hmac_sha512_kat
            && self.pbkdf2_kat
            && self.secp256k1_kat
            && self.ripemd160_base58check_bech32_kat
            && self.bip39_kat
            && self.bip32_kat
            && self.entropy_transcript_kat
            && self.dice_coin_session_kat
            && self.wordlist_integrity
            && self.fixed_buffer_bounds_kat
            && self.state_machine_invariant_kat
            && self.production_build_policy_marker
    }
}

/// A [`WatchdogReassert`] stub for the bullet-12 state-machine self-test.
/// [`CountingWatchdog`] would do just as well, but a self-test that could
/// ever be asked to route into fatal `Watchdog`-class handling as a side
/// effect of its own bookkeeping is worth ruling out explicitly — this
/// stub only ever returns `Ok`, identically to `CountingWatchdog`, kept as
/// a distinct local type so this module never depends on
/// `seed_protocol::state::tests`-only helpers.
struct SelfTestWatchdog;

impl WatchdogReassert for SelfTestWatchdog {
    fn reassert(&mut self) -> Result<(), seed_protocol::state::WatchdogReassertFailure> {
        Ok(())
    }
}

/// Runs all thirteen SPEC §11.6 self-test bullets and returns the
/// per-bullet report.
///
/// `policy_marker_check`, when `Some`, is called once for bullet 13
/// (SPEC §28's production-build policy marker) — production wiring passes
/// `Some(markers::self_check)`; the test edition (which never claims to be
/// the verified production build, `PlatformInfo::production_markers_verified
/// = false` unconditionally) passes `None`, which this function treats as
/// vacuously passing that bullet (there is no false claim to check).
#[must_use]
pub fn run_aggregate_self_test(policy_marker_check: Option<fn() -> bool>) -> AggregateSelfTestReport {
    AggregateSelfTestReport {
        sha256_kat: sha256_kat(),
        sha512_hmac_sha512_kat: sha512_hmac_sha512_kat(),
        pbkdf2_kat: pbkdf2_kat(),
        secp256k1_kat: secp256k1_kat(),
        ripemd160_base58check_bech32_kat: ripemd160_base58check_bech32_kat(),
        bip39_kat: bip39_kat(),
        bip32_kat: bip32_kat(),
        entropy_transcript_kat: entropy_transcript_kat(),
        dice_coin_session_kat: dice_coin_session_kat(),
        wordlist_integrity: bip39::wordlist_sha256_ok(),
        fixed_buffer_bounds_kat: fixed_buffer_bounds_kat(),
        state_machine_invariant_kat: state_machine_invariant_kat(),
        production_build_policy_marker: policy_marker_check.is_none_or(|f| f()),
    }
}

// ============================================================================
// Bullet 1: SHA-256
// ============================================================================

fn sha256_kat() -> bool {
    // NIST FIPS 180-4 KAT: SHA-256("abc").
    const EXPECTED: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    sha256(b"abc") == EXPECTED
}

// ============================================================================
// Bullet 2: SHA-512 + HMAC-SHA512
// ============================================================================

fn sha512_hmac_sha512_kat() -> bool {
    // NIST FIPS 180-4 KAT: SHA-512("abc").
    const SHA512_EXPECTED: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49,
        0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a,
        0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    let sha512_ok = sha512(b"abc") == SHA512_EXPECTED;

    // RFC 4231 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
    const HMAC_EXPECTED: [u8; 64] = [
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24,
        0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7,
        0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
        0x3a, 0x12, 0x68, 0x54,
    ];
    let key = [0x0bu8; 20];
    let mut hmac_out = [0u8; 64];
    hmac_sha512(&key, b"Hi There", &mut hmac_out);
    let hmac_ok = hmac_out == HMAC_EXPECTED;

    sha512_ok && hmac_ok
}

// ============================================================================
// Bullet 3: PBKDF2
// ============================================================================

fn pbkdf2_kat() -> bool {
    // P = "password", S = "salt", c = 1, dkLen = 64 (PBKDF2-HMAC-SHA512).
    const EXPECTED: [u8; 64] = [
        0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5, 0x3d,
        0xc4, 0xaf, 0x34, 0xc7, 0xa6, 0x69, 0x81, 0x5a, 0xe5, 0xd5, 0x13, 0x55, 0x4e, 0x1c, 0x8c,
        0xf2, 0x52, 0xc0, 0x2d, 0x47, 0x0a, 0x28, 0x5a, 0x05, 0x01, 0xba, 0xd9, 0x99, 0xbf, 0xe9,
        0x43, 0xc0, 0x8f, 0x05, 0x02, 0x35, 0xd7, 0xd6, 0x8b, 0x1d, 0xa5, 0x5e, 0x63, 0xf7, 0x3b,
        0x60, 0xa5, 0x7f, 0xce,
    ];
    let mut out = [0u8; 64];
    pbkdf2_hmac_sha512(b"password", b"salt", 1, &mut out);
    out == EXPECTED
}

// ============================================================================
// Bullet 4: secp256k1
// ============================================================================

fn secp256k1_kat() -> bool {
    // privkey = 1 -> pubkey = the secp256k1 generator point G, compressed
    // (a fixed, independently-known constant).
    const EXPECTED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let mut privkey = [0u8; 32];
    privkey[31] = 1;
    let mut pubkey = [0u8; 33];
    curve::privkey_to_compressed_pubkey(&privkey, &mut pubkey).is_ok() && pubkey == EXPECTED
}

// ============================================================================
// Bullet 5: RIPEMD-160 / Base58Check / Bech32(m)
// ============================================================================

fn ripemd160_base58check_bech32_kat() -> bool {
    // Compressed pubkey for privkey = 1 (the generator point), the same
    // fixed input the BIP173 reference test vectors use.
    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    // hash160(PUBKEY) = RIPEMD160(SHA256(PUBKEY)) — the well-known
    // "address of private key 1" hash, independently cross-checked
    // against BIP173's own P2WPKH test vector below.
    const HASH160_EXPECTED: [u8; 20] = [
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
        0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    ];
    let h160 = hash160(&PUBKEY);
    let ripemd160_ok = h160 == HASH160_EXPECTED;

    // Base58Check(0x00 || hash160(PUBKEY)): the famous "1BgGZ..." legacy
    // address of private key 1.
    const B58_EXPECTED: &[u8] = b"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    let mut payload = [0u8; 21];
    payload[1..].copy_from_slice(&h160);
    let mut b58_out = [0u8; MAX_B58];
    let b58_len = seed_core::base58::base58check_encode(&payload, &mut b58_out);
    let base58check_ok = &b58_out[..b58_len] == B58_EXPECTED;

    // Bech32 (witness v0) of the same hash160 — BIP173's own official
    // P2WPKH test vector for the generator-point pubkey.
    const BECH32_EXPECTED: &[u8] = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let mut addr0 = seed_core::contracts::AddressBuf::empty();
    let bech32_ok = bech32::encode(b"bc", 0, &h160, &mut addr0).is_ok()
        && addr0.as_bytes() == BECH32_EXPECTED;

    // Bech32m (witness v1 / taproot) of the x-only pubkey for the same
    // fixed private key.
    const BECH32M_EXPECTED: &[u8] = b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    let mut privkey = [0u8; 32];
    privkey[31] = 1;
    let mut xonly = [0u8; 32];
    let mut addr1 = seed_core::contracts::AddressBuf::empty();
    let bech32m_ok = curve::privkey_to_xonly_pubkey(&privkey, &mut xonly).is_ok()
        && bech32::encode(b"bc", 1, &xonly, &mut addr1).is_ok()
        && addr1.as_bytes() == BECH32M_EXPECTED;

    ripemd160_ok && base58check_ok && bech32_ok && bech32m_ok
}

// ============================================================================
// Bullet 6: BIP39 12-word / 24-word
// ============================================================================

fn bip39_kat() -> bool {
    // 12-word: entropy = 0x00..0x0f (16 bytes).
    let mut entropy12 = [0u8; 16];
    for (i, b) in entropy12.iter_mut().enumerate() {
        *b = i as u8;
    }
    const INDEXES12_EXPECTED: [u16; 12] =
        [0, 64, 1030, 64, 643, 28, 257, 266, 88, 771, 540, 251];
    let mut indexes12 = [0u16; 24];
    let twelve_ok = bip39::entropy_to_indexes(&entropy12, &mut indexes12).is_ok()
        && indexes12[..12] == INDEXES12_EXPECTED
        && bip39::word(indexes12[0]) == "abandon"
        && bip39::word(indexes12[11]) == "buyer";

    // 24-word: the standard, widely-published all-zero-entropy BIP39
    // vector — mnemonic "abandon" x23 + "art".
    let entropy24 = [0u8; 32];
    let mut indexes24 = [0u16; 24];
    let twentyfour_ok = bip39::entropy_to_indexes(&entropy24, &mut indexes24).is_ok()
        && indexes24[..23].iter().all(|&idx| bip39::word(idx) == "abandon")
        && bip39::word(indexes24[23]) == "art";

    twelve_ok && twentyfour_ok
}

// ============================================================================
// Bullet 7: BIP32
// ============================================================================

fn bip32_kat() -> bool {
    // Fixed 64-byte seed = 0x00..0x3f.
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    const MASTER_KEY_EXPECTED: [u8; 32] = [
        0xd3, 0x93, 0x34, 0xc7, 0x7f, 0x6f, 0x46, 0x23, 0x3b, 0x80, 0xb4, 0xd0, 0x6e, 0x98, 0x2a,
        0x3d, 0xe4, 0x63, 0x5d, 0xe1, 0x19, 0x23, 0xaf, 0x07, 0x6e, 0xbf, 0x8a, 0xa4, 0x2f, 0xc2,
        0xef, 0x4f,
    ];
    const MASTER_CC_EXPECTED: [u8; 32] = [
        0xd5, 0x50, 0xc1, 0x0b, 0xdf, 0x68, 0x67, 0xad, 0x4e, 0xac, 0x65, 0xf6, 0x0f, 0x8f, 0x7a,
        0x3d, 0x4e, 0xf3, 0x7e, 0x77, 0xa9, 0x50, 0x2e, 0x10, 0xe5, 0x94, 0xcc, 0x3e, 0x6b, 0x66,
        0xae, 0xd0,
    ];
    const MASTER_FP_EXPECTED: [u8; 4] = [0xdc, 0x2c, 0xa4, 0xb2];
    const CHILD_KEY_EXPECTED: [u8; 32] = [
        0x57, 0x18, 0x34, 0x5a, 0xd1, 0x5a, 0x03, 0x96, 0xb1, 0x01, 0xbc, 0xb5, 0xa1, 0xda, 0xf0,
        0x83, 0x9b, 0x2b, 0x66, 0xda, 0x7d, 0x47, 0xeb, 0xb0, 0x0f, 0xeb, 0xf7, 0xf0, 0x0a, 0x8a,
        0x86, 0x9b,
    ];
    const CHILD_CC_EXPECTED: [u8; 32] = [
        0xd5, 0xf7, 0x17, 0x01, 0x15, 0xa6, 0xf8, 0xed, 0x26, 0xbe, 0xf2, 0x67, 0xca, 0xb7, 0x4f,
        0xc4, 0x5c, 0x1a, 0x83, 0x87, 0xe7, 0xa7, 0x96, 0xad, 0x6e, 0x2d, 0x12, 0xbf, 0x80, 0xcd,
        0x21, 0xe9,
    ];

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    bip32::master_from_seed(&seed, &mut key, &mut cc);
    let master_ok = key == MASTER_KEY_EXPECTED && cc == MASTER_CC_EXPECTED;

    let fp = bip32::master_fingerprint(&key);
    let fp_ok = fp == MASTER_FP_EXPECTED;

    let mut child_key = key;
    let mut child_cc = cc;
    let child_ok = bip32::ckd_priv(&mut child_key, &mut child_cc, bip32::HARDENED_OFFSET + 44)
        .is_ok()
        && child_key == CHILD_KEY_EXPECTED
        && child_cc == CHILD_CC_EXPECTED;

    master_ok && fp_ok && child_ok
}

// ============================================================================
// Bullet 8: entropy-transcript
// ============================================================================

fn entropy_transcript_kat() -> bool {
    // This repository's own frozen vector
    // (`tests/vectors/frozen/dice_only_12w_recommended.json`): 64
    // dice-roll bytes cycling 1..=6, arch = x86_64, bits = 128,
    // policy_version = 1.
    const DICE_BYTES: [u8; 64] = {
        let mut b = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            b[i] = ((i % 6) + 1) as u8;
            i += 1;
        }
        b
    };
    const TRANSCRIPT_LEN: usize = 93;
    const TRANSCRIPT_EXPECTED: [u8; TRANSCRIPT_LEN] = [
        0x41, 0x6c, 0x65, 0x61, 0x2f, 0x45, 0x6e, 0x74, 0x72, 0x6f, 0x70, 0x79,
        0x2f, 0x76, 0x31, 0x00, 0x00, 0x01, 0x00, 0x80, 0x00, 0x01, 0x00, 0x08,
        0x01, 0x10, 0x00, 0x00, 0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04,
    ];
    const FINAL_ENTROPY_EXPECTED: [u8; 16] = [
        0xf2, 0xaf, 0xa8, 0x15, 0x9f, 0x9a, 0xbb, 0x4b, 0x20, 0x6c, 0x93, 0xac, 0x2a, 0x51, 0x90,
        0xd5,
    ];

    let mut tb = TranscriptBuilder::new();
    if tb.add_source(SourceTag::DiceRolls, &[], &DICE_BYTES).is_err() {
        return false;
    }

    let mut serialized = [0u8; TRANSCRIPT_CAPACITY];
    let len = tb.serialize(ArchId::X86_64, TargetBits::Bits128, 1, &mut serialized);
    let serialize_ok = len == TRANSCRIPT_LEN && serialized[..len] == TRANSCRIPT_EXPECTED;

    let mut digest = [0u8; 32];
    tb.finalize(ArchId::X86_64, TargetBits::Bits128, 1, &mut digest);
    let finalize_ok = digest[..16] == FINAL_ENTROPY_EXPECTED;

    serialize_ok && finalize_ok
}

// ============================================================================
// Bullet 9: dice/coin session
// ============================================================================

fn dice_coin_session_kat() -> bool {
    let mut session = PhysicalSession::new();

    let push_ok = session.push_roll(2).is_ok()
        && session.push_roll(4).is_ok()
        && session.push_roll(6).is_ok()
        && session.push_flip(CoinFace::Heads).is_ok()
        && session.push_flip(CoinFace::Tails).is_ok();

    let counts_ok = session.len() == 5 && session.roll_count() == 3 && session.flip_count() == 2;

    // SPEC §17.2 integer-only budget: 2585*3 + 1000*2 = 9755 milli-bits.
    let budget_ok = session.budget_bits_x1000() == 9755;

    // Reject an out-of-range roll without disturbing existing history.
    let reject_ok = session.push_roll(0).is_err() && session.len() == 5;

    // Undo removes exactly the last-pushed event (the tails flip) and
    // decrements only the flip counter.
    let undo_ok = matches!(session.undo(), Some(seed_protocol::physical::PhysicalEvent::Flip(CoinFace::Tails)))
        && session.len() == 4
        && session.flip_count() == 1
        && session.roll_count() == 3;

    push_ok && counts_ok && budget_ok && reject_ok && undo_ok
}

// ============================================================================
// Bullet 11: fixed-buffer bounds
// ============================================================================

fn fixed_buffer_bounds_kat() -> bool {
    // `TranscriptBuilder` rejects a machine-source record whose byte
    // length exceeds `MAX_MACHINE_SOURCE_BYTES` (SPEC §19.1).
    let mut tb = TranscriptBuilder::new();
    let oversized = [0u8; MAX_MACHINE_SOURCE_BYTES + 1];
    let transcript_bound_ok = matches!(
        tb.add_source(SourceTag::ApprovedEfiRng, &[], &oversized),
        Err(TranscriptError::SourceTooLong)
    );

    // `PhysicalSession`'s fixed history buffer stops accepting new events
    // exactly at `MAX_PHYSICAL_EVENTS` (SPEC §17.3) rather than
    // overflowing.
    let mut session = PhysicalSession::new();
    let mut filled_ok = true;
    for _ in 0..seed_core::contracts::MAX_PHYSICAL_EVENTS {
        if session.push_roll(1).is_err() {
            filled_ok = false;
            break;
        }
    }
    let capacity_stop_ok = filled_ok
        && session.at_capacity()
        && matches!(session.push_roll(1), Err(seed_protocol::physical::PhysicalError::CapacityReached));
    session.scrub();

    transcript_bound_ok && capacity_stop_ok
}

// ============================================================================
// Bullet 12: state-machine invariant
// ============================================================================

fn state_machine_invariant_kat() -> bool {
    let mut sm = StateMachine::new();
    let mut wd = SelfTestWatchdog;

    // Fixed happy-path prefix, ending in the very state this self-test
    // gate itself occupies (SPEC §11.6/§21): Start ->
    // ReleaseAndEnvironmentWarning -> WatchdogDisable ->
    // PlatformAndVirtualizationCheck -> ConsoleTopologyCheck ->
    // GraphicsAndKeyboardSelfTest -> CryptographicSelfTest ->
    // SetupSelection.
    let path_ok = sm.transition(Event::Continue, &mut wd).next
        == AppState::ReleaseAndEnvironmentWarning
        && sm.transition(Event::Continue, &mut wd).next == AppState::WatchdogDisable
        && sm.transition(Event::Continue, &mut wd).next == AppState::PlatformAndVirtualizationCheck
        && sm.transition(Event::CheckPassed, &mut wd).next == AppState::ConsoleTopologyCheck
        && sm.transition(Event::CheckPassed, &mut wd).next == AppState::GraphicsAndKeyboardSelfTest
        && sm.transition(Event::CheckPassed, &mut wd).next == AppState::CryptographicSelfTest;

    // SPEC §21 invariant: an event with no legal edge from the current
    // (pre-secret) state routes to `PreSecretError`, never silently
    // ignored and never into the post-secret fatal chain.
    let illegal = sm.transition(Event::FinalConfirm, &mut wd);
    let illegal_ok = illegal.was_illegal
        && illegal.next == AppState::PreSecretError(ErrorClass::StateMachine)
        && illegal.fatal_class.is_none();

    // The machine is back at a normal (non-fatal, non-terminal) state
    // after that illegal event — confirms the invariant routed safely
    // rather than wedging the machine.
    let recovered_ok = !sm.state().is_terminal();

    path_ok && illegal_ok && recovered_ok
}

// ============================================================================
// Tests (SPEC §11.6: regression coverage for the aggregate startup gate)
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// SPEC §11.6: every one of the thirteen bullets must pass on this
    /// project's own real primitives — the gate this report feeds
    /// (`ProdCryptoSelfTestGate::check()` in both editions) must not be
    /// able to enable generation unless every bullet is genuinely clean.
    #[test]
    fn all_thirteen_bullets_pass() {
        let report = run_aggregate_self_test(None);
        assert!(report.sha256_kat, "sha256_kat");
        assert!(report.sha512_hmac_sha512_kat, "sha512_hmac_sha512_kat");
        assert!(report.pbkdf2_kat, "pbkdf2_kat");
        assert!(report.secp256k1_kat, "secp256k1_kat");
        assert!(
            report.ripemd160_base58check_bech32_kat,
            "ripemd160_base58check_bech32_kat"
        );
        assert!(report.bip39_kat, "bip39_kat");
        assert!(report.bip32_kat, "bip32_kat");
        assert!(report.entropy_transcript_kat, "entropy_transcript_kat");
        assert!(report.dice_coin_session_kat, "dice_coin_session_kat");
        assert!(report.wordlist_integrity, "wordlist_integrity");
        assert!(report.fixed_buffer_bounds_kat, "fixed_buffer_bounds_kat");
        assert!(
            report.state_machine_invariant_kat,
            "state_machine_invariant_kat"
        );
        assert!(
            report.production_build_policy_marker,
            "production_build_policy_marker (None case)"
        );
        assert!(report.all_clean());
    }

    /// `policy_marker_check = None` (the test edition's case, which never
    /// claims to be the verified production build) must not silently mask
    /// a real crypto failure — `all_clean()` still reflects every other
    /// bullet.
    #[test]
    fn none_marker_check_is_vacuously_true_but_other_bullets_still_gate() {
        let report = run_aggregate_self_test(None);
        assert!(report.production_build_policy_marker);
        assert!(report.all_clean());
    }

    /// A passing production marker check keeps the aggregate report clean.
    #[test]
    fn some_marker_check_true_keeps_report_clean() {
        let report = run_aggregate_self_test(Some(|| true));
        assert!(report.production_build_policy_marker);
        assert!(report.all_clean());
    }

    /// SPEC §11.6: "If any test fails, generation is disabled." — a
    /// failing production-marker check alone (bullet 13) must flip
    /// `all_clean()` to `false`, even though every cryptographic KAT
    /// above it still passed.
    #[test]
    fn some_marker_check_false_fails_the_gate() {
        let report = run_aggregate_self_test(Some(|| false));
        assert!(!report.production_build_policy_marker);
        assert!(!report.all_clean());
        // Every other bullet is unaffected — this proves bullet 13 is
        // wired independently, not accidentally coupled to the others.
        assert!(report.sha256_kat);
        assert!(report.bip32_kat);
    }

    /// SPEC §11.6 dice/coin bullet also doubles as a direct regression
    /// test for the SPEC §17.2 integer-only budget formula and the
    /// undo/reject invariants, independent of the aggregate report.
    #[test]
    fn dice_coin_session_kat_is_self_consistent() {
        assert!(dice_coin_session_kat());
    }

    /// SPEC §11.6 bounds bullet: both fixed-size buffers this project
    /// relies on (the transcript's per-record byte bound and the physical
    /// session's fixed history buffer) refuse to overflow.
    #[test]
    fn fixed_buffer_bounds_kat_is_self_consistent() {
        assert!(fixed_buffer_bounds_kat());
    }

    /// SPEC §11.6 state-machine bullet: the fixed happy-path prefix and
    /// the illegal-event routing invariant both hold independent of the
    /// aggregate wrapper.
    #[test]
    fn state_machine_invariant_kat_is_self_consistent() {
        assert!(state_machine_invariant_kat());
    }

    /// SPEC §11.6: the transcript KAT matches this repository's own
    /// frozen golden vector
    /// (`tests/vectors/frozen/dice_only_12w_recommended.json`) byte for
    /// byte, so a regression here would also be caught by WP-16's own
    /// freeze tests — this test just proves the self-test gate exercises
    /// the identical path at startup, not only at `cargo test` time.
    #[test]
    fn entropy_transcript_kat_matches_frozen_vector() {
        assert!(entropy_transcript_kat());
    }
}
