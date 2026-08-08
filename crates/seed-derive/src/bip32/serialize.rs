//! BIP32 extended **public** key serialization (`xpub`/`ypub`/`zpub`), for
//! the opt-in wallet-export screen
//! (`docs/superpowers/specs/2026-08-07-wallet-export-design.md`, D1).
//!
//! # Public-only, by construction (spec D1)
//!
//! This module serializes **public** account data only. There is
//! deliberately no extended-*private*-key serializer anywhere in this crate,
//! and neither that key form's 4-byte version constant nor a serialized
//! instance of one appears in this file's or in [`super`]'s production
//! source — a property this module's own negative tests enforce
//! mechanically by scanning the production text of every `.rs` file in this
//! crate's `src/`, so a future edit that adds one anywhere fails the test
//! suite rather than silently shipping a private-key export path. (Both the constant and the prefix are deliberately spelled out
//! nowhere outside those tests, including in this comment, so the scanners
//! cannot trip over the very text that documents them.)
//!
//! The only input this module accepts is [`AccountPublic`], a plain
//! public-data record (depth, parent fingerprint, child number, chain code,
//! compressed public key). No function here takes a private key, a scalar,
//! or the secret arena; the private→public transition happens once, inside
//! [`super::account_public`], which scrubs every private intermediate before
//! returning (SPEC §13, §20.3).
//!
//! # Serialization format (BIP32 "Serialization format")
//!
//! 78 bytes, big-endian throughout:
//!
//! | offset | len | field |
//! |--------|-----|-------|
//! | 0      | 4   | version ([`XpubVersion`]) |
//! | 4      | 1   | depth |
//! | 5      | 4   | parent fingerprint |
//! | 9      | 4   | child number |
//! | 13     | 32  | chain code |
//! | 45     | 33  | compressed public key |
//!
//! Base58Check-encoded via `seed_core::base58::base58check_encode`, which
//! appends the 4-byte double-SHA256 checksum itself.
//!
//! # SLIP-132 version bytes
//!
//! [`XpubVersion`] selects only the 4 leading version bytes; the remaining
//! 74 bytes of the payload are identical across all three variants, which is
//! exactly what SLIP-132 specifies (the version prefix is a display hint for
//! the script type, not a different key). Pinned by
//! [`tests::slip132_variants_differ_only_in_the_version_bytes`].
//!
//! No `std`, no `alloc`, no panic paths: every buffer here is a fixed-size
//! stack array and the single call into `base58check_encode` is proved
//! in-bounds at its call site (see [`serialize_xpub`]).

use seed_core::base58::base58check_encode;

use super::AccountPublic;
use crate::curve::COMPRESSED_PUBKEY_LEN;

/// Length of the pre-Base58 BIP32 extended-key payload (BIP32
/// "Serialization format": 4 + 1 + 4 + 4 + 32 + 33). Exactly
/// `seed_core::base58::MAX_PAYLOAD`, which was sized for this shape.
pub const XPUB_PAYLOAD_LEN: usize = 78;

// Compile-time discharge of the first of `base58check_encode`'s two
// assertions (see `serialize_xpub`'s "# Panics" section): the payload this
// module hands it must fit the encoder's maximum. `<=` states the actual
// requirement — today the two are equal, but a future `MAX_PAYLOAD` *growth*
// is harmless and should not fail the build; only a shrink below 78 is a
// problem, and that this catches, at build time rather than as a runtime
// panic in firmware.
const _: () = assert!(XPUB_PAYLOAD_LEN <= seed_core::base58::MAX_PAYLOAD);

// The layout's last field must land exactly on the end of the payload. If
// `COMPRESSED_PUBKEY_LEN` ever changed, `xpub_payload`'s
// `payload[45..78].copy_from_slice(&acct.pubkey)` would become a
// length-mismatch panic at runtime; this makes it a build failure instead.
const _: () = assert!(45 + COMPRESSED_PUBKEY_LEN == XPUB_PAYLOAD_LEN);

/// Maximum length in bytes of the Base58Check-encoded extended public key
/// string.
///
/// Size proof: the encoder's input is `XPUB_PAYLOAD_LEN + 4 = 82` bytes,
/// whose value is `< 2^656`; Base58 needs at most
/// `ceil(656 * ln 2 / ln 58) = ceil(111.98) = 112` characters, and the
/// leading version byte is `0x04` for every variant here, so there are no
/// leading-zero bytes to expand into extra `'1'` characters. Real `xpub`
/// strings are 111 characters; 112 is the proven ceiling.
pub const XPUB_MAX_LEN: usize = 112;

/// The three mainnet extended-**public**-key version prefixes this project
/// can emit (BIP32 for `xpub`; SLIP-132 for `ypub`/`zpub`).
///
/// There is intentionally no private-key counterpart (spec D1): this enum's
/// entire value domain is public-key version bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpubVersion {
    /// `0x0488B21E` — BIP32 mainnet extended public key, `xpub...`.
    Xpub,
    /// `0x049D7CB2` — SLIP-132 P2WPKH-in-P2SH (BIP49), `ypub...`.
    Ypub,
    /// `0x04B24746` — SLIP-132 native P2WPKH (BIP84), `zpub...`.
    Zpub,
}

impl XpubVersion {
    /// The 4-byte big-endian version prefix for this variant.
    pub const fn version_bytes(self) -> [u8; 4] {
        match self {
            XpubVersion::Xpub => [0x04, 0x88, 0xB2, 0x1E],
            XpubVersion::Ypub => [0x04, 0x9D, 0x7C, 0xB2],
            XpubVersion::Zpub => [0x04, 0xB2, 0x47, 0x46],
        }
    }
}

/// Build the 78-byte pre-Base58 BIP32 extended-public-key payload for
/// `acct` under `version` (see the module-level layout table).
///
/// Every slice index below is a compile-time constant against a
/// compile-time-sized array, and the six ranges partition `0..78` exactly,
/// so no bounds check here can ever fail at runtime.
fn xpub_payload(acct: &AccountPublic, version: XpubVersion) -> [u8; XPUB_PAYLOAD_LEN] {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    payload[0..4].copy_from_slice(&version.version_bytes());
    payload[4] = acct.depth;
    payload[5..9].copy_from_slice(&acct.parent_fingerprint);
    payload[9..13].copy_from_slice(&acct.child_number.to_be_bytes());
    payload[13..45].copy_from_slice(&acct.chain_code);
    payload[45..78].copy_from_slice(&acct.pubkey);
    payload
}

/// Serialize `acct` as a Base58Check extended **public** key string into
/// `out`, returning the number of ASCII bytes written to `out[..n]`
/// (111 for every mainnet extended key; see [`XPUB_MAX_LEN`]).
///
/// `version` selects the 4-byte prefix — `xpub` (BIP32) or the SLIP-132
/// `ypub`/`zpub` display variants — and nothing else about the output.
///
/// # Panics
///
/// None reachable. `base58check_encode` asserts on two conditions, both
/// discharged statically here: its payload must be at most
/// `seed_core::base58::MAX_PAYLOAD` (78 — this payload is exactly 78 by
/// type), and the encoded result must fit `out` (at most 112 bytes by the
/// size proof on [`XPUB_MAX_LEN`], and `out` is `&mut [u8; 112]` by type).
/// This function itself contains no `unwrap`/`expect`/indexing that can
/// fail (SPEC §13, §27.3).
pub fn serialize_xpub(
    acct: &AccountPublic,
    version: XpubVersion,
    out: &mut [u8; XPUB_MAX_LEN],
) -> usize {
    let payload = xpub_payload(acct, version);
    base58check_encode(&payload, out)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::bip32::{account_public, ckd_priv, master_fingerprint, HARDENED_OFFSET, MAX_DEPTH};
    use crate::curve::{privkey_to_compressed_pubkey, COMPRESSED_PUBKEY_LEN};
    use seed_core::contracts::DeriveError;

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> std::string::String {
        const HEXCHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = std::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEXCHARS[(b >> 4) as usize] as char);
            s.push(HEXCHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    fn encode(acct: &AccountPublic, version: XpubVersion) -> std::string::String {
        let mut out = [0u8; XPUB_MAX_LEN];
        let n = serialize_xpub(acct, version, &mut out);
        std::str::from_utf8(&out[..n]).unwrap().into()
    }

    /// The 64-byte BIP39 seed of this repo's ceremony test mnemonic
    /// ("abandon abandon ... about", empty passphrase) — the exact same
    /// constant `crate::address`'s tests use, cross-checked there against
    /// `reference/python/seedref` and against BIP84's published vectors.
    const CEREMONY_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc\
19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn ceremony_seed() -> [u8; 64] {
        let v = hex_to_vec(CEREMONY_SEED_HEX);
        assert_eq!(v.len(), 64);
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&v);
        seed
    }

    /// `m/84'/0'/0'` — the account node the wallet-export screen exports.
    fn account_path() -> [u32; 3] {
        [HARDENED_OFFSET + 84, HARDENED_OFFSET, HARDENED_OFFSET]
    }

    // ------------------------------------------------------------------
    // Vector 1: BIP32's own published Test Vector 1 (bip-0032.mediawiki
    // "Test Vectors", seed 000102030405060708090a0b0c0d0e0f), chain m/0'.
    // The expected string is copied verbatim from that specification.
    //
    // That seed is 16 bytes, so this vector cannot go through
    // `account_public` (whose `[u8; 64]` signature matches this project's
    // only real source of seeds, BIP39's PBKDF2 output). It instead builds
    // the `AccountPublic` from the module's own primitives
    // (`master_from_seed_bytes` + `master_fingerprint` + `ckd_priv` +
    // `privkey_to_compressed_pubkey`), which is precisely what
    // `account_public` does internally — so this vector pins the 78-byte
    // layout and the Base58Check encoding against a published authority,
    // and the ceremony vectors below pin `account_public`'s own field
    // extraction.
    // ------------------------------------------------------------------

    const BIP32_TV1_SEED: &str = "000102030405060708090a0b0c0d0e0f";
    const BIP32_TV1_M_0H_XPUB: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    fn bip32_tv1_m_0h_account_public() -> AccountPublic {
        let seed = hex_to_vec(BIP32_TV1_SEED);
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        super::super::master_from_seed_bytes(&seed, &mut key, &mut cc);

        let parent_fingerprint = master_fingerprint(&key);
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET).unwrap();

        let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
        privkey_to_compressed_pubkey(&key, &mut pubkey).unwrap();

        AccountPublic {
            depth: 1,
            parent_fingerprint,
            child_number: HARDENED_OFFSET,
            chain_code: cc,
            pubkey,
        }
    }

    #[test]
    fn bip32_test_vector_1_m_0h_xpub_matches_published_string() {
        let acct = bip32_tv1_m_0h_account_public();
        assert_eq!(encode(&acct, XpubVersion::Xpub), BIP32_TV1_M_0H_XPUB);
    }

    // ------------------------------------------------------------------
    // Vector 2: this repo's ceremony seed, account node m/84'/0'/0'.
    //
    // Expected strings computed with `reference/python/seedref` (WP-11's
    // independent from-scratch reference stack: its own hmac/secp256k1/
    // ripemd160/base58 implementations, no shared code with this crate),
    // by running, from `reference/python/`:
    //
    //   python3 -c "
    //   from seedref.bip32 import master_from_seed, ckd_priv, h
    //   from seedref.secp256k1 import privkey_to_compressed_pubkey
    //   from seedref.ripemd160 import hash160
    //   from seedref.base58 import base58check_encode
    //   SEED = bytes.fromhex('5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
    //   PATH = [h(84), h(0), h(0)]
    //   node = master_from_seed(SEED)
    //   for i in PATH[:-1]:
    //       node = ckd_priv(node, i)
    //   fp = hash160(privkey_to_compressed_pubkey(node.key))[:4]
    //   node = ckd_priv(node, PATH[-1])
    //   for name, ver in (('xpub', 0x0488B21E), ('ypub', 0x049D7CB2), ('zpub', 0x04B24746)):
    //       payload = ver.to_bytes(4, 'big') + bytes([len(PATH)]) + fp + PATH[-1].to_bytes(4, 'big') + node.chain_code + privkey_to_compressed_pubkey(node.key)
    //       print(name, base58check_encode(payload))
    //   print('parent_fp', fp.hex(), 'cc', node.chain_code.hex(), 'pub', privkey_to_compressed_pubkey(node.key).hex())
    //   "
    //
    // The `zpub` line additionally matches BIP84's own published test
    // vector for this mnemonic (bip-0084.mediawiki "Test vectors",
    // "Account 0, extpub"), an authority entirely outside this repository —
    // so the Python-derived constants are corroborated by a second,
    // independent source, not merely self-consistent.
    // ------------------------------------------------------------------

    const CEREMONY_ACCOUNT_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    const CEREMONY_ACCOUNT_YPUB: &str = "ypub6XR9pJPUsVBFKweLeV85HtwdxjjmKEuUr6djm9mNdkh47X7ASsD6byaXFotRAKByFoWgSzCuoTjaYdrv2yoJroLAPtBuHFjVm5vNmhyNehE";
    /// BIP84 "Test vectors", Account 0 extended public key.
    const CEREMONY_ACCOUNT_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn ceremony_account_xpub_matches_python_reference() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        assert_eq!(encode(&acct, XpubVersion::Xpub), CEREMONY_ACCOUNT_XPUB);
    }

    #[test]
    fn ceremony_account_ypub_matches_python_reference() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        assert_eq!(encode(&acct, XpubVersion::Ypub), CEREMONY_ACCOUNT_YPUB);
    }

    #[test]
    fn ceremony_account_zpub_matches_bip84_published_vector() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        assert_eq!(encode(&acct, XpubVersion::Zpub), CEREMONY_ACCOUNT_ZPUB);
    }

    #[test]
    fn account_public_extracts_the_documented_public_fields() {
        // Same run of the Python reference command quoted above.
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        assert_eq!(acct.depth, 3);
        assert_eq!(to_hex(&acct.parent_fingerprint), "7ef32bdb");
        assert_eq!(acct.child_number, HARDENED_OFFSET);
        assert_eq!(
            to_hex(&acct.chain_code),
            "4a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc"
        );
        assert_eq!(
            to_hex(&acct.pubkey),
            "02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b"
        );
    }

    #[test]
    fn account_public_parent_fingerprint_is_hash160_of_the_parent_node_pubkey() {
        // Independently recompute the parent node (m/84'/0') here and take
        // HASH160 of its compressed pubkey, rather than trusting the
        // hardcoded hex above alone.
        let seed = ceremony_seed();
        let path = account_path();

        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        crate::bip32::derive_path(&seed, &path[..path.len() - 1], &mut key, &mut cc).unwrap();
        let expected = master_fingerprint(&key);

        let acct = account_public(&seed, &path).unwrap();
        assert_eq!(acct.parent_fingerprint, expected);
    }

    #[test]
    fn account_public_at_depth_zero_is_the_master_node() {
        let acct = account_public(&ceremony_seed(), &[]).unwrap();
        assert_eq!(acct.depth, 0);
        assert_eq!(acct.parent_fingerprint, [0u8; 4]);
        assert_eq!(acct.child_number, 0);

        // BIP32 master xpub for this seed, same reference command with
        // PATH = [] (depth 0, zero fingerprint, zero child number).
        assert_eq!(
            encode(&acct, XpubVersion::Xpub),
            "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
        );
    }

    #[test]
    fn account_public_rejects_paths_deeper_than_max_depth() {
        let seed = ceremony_seed();
        let too_deep = [0u32; MAX_DEPTH + 1];
        assert_eq!(
            account_public(&seed, &too_deep).err(),
            Some(DeriveError::InvalidIndex)
        );
    }

    // ------------------------------------------------------------------
    // SLIP-132: only the 4 version bytes change.
    // ------------------------------------------------------------------

    #[test]
    fn slip132_variants_differ_only_in_the_version_bytes() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();

        let x = xpub_payload(&acct, XpubVersion::Xpub);
        let y = xpub_payload(&acct, XpubVersion::Ypub);
        let z = xpub_payload(&acct, XpubVersion::Zpub);

        assert_eq!(&x[4..], &y[4..], "ypub payload body must be identical");
        assert_eq!(&x[4..], &z[4..], "zpub payload body must be identical");

        assert_eq!(&x[..4], &[0x04, 0x88, 0xB2, 0x1E]);
        assert_eq!(&y[..4], &[0x04, 0x9D, 0x7C, 0xB2]);
        assert_eq!(&z[..4], &[0x04, 0xB2, 0x47, 0x46]);
        assert_ne!(&x[..4], &y[..4]);
        assert_ne!(&x[..4], &z[..4]);
        assert_ne!(&y[..4], &z[..4]);
    }

    #[test]
    fn payload_layout_places_every_field_at_its_bip32_offset() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        let p = xpub_payload(&acct, XpubVersion::Xpub);
        assert_eq!(p.len(), 78);
        assert_eq!(p[..4], XpubVersion::Xpub.version_bytes());
        assert_eq!(p[4], acct.depth);
        assert_eq!(p[5..9], acct.parent_fingerprint);
        assert_eq!(p[9..13], acct.child_number.to_be_bytes());
        assert_eq!(p[13..45], acct.chain_code);
        assert_eq!(p[45..78], acct.pubkey);
    }

    #[test]
    fn encoded_length_stays_within_xpub_max_len() {
        let acct = account_public(&ceremony_seed(), &account_path()).unwrap();
        for version in [XpubVersion::Xpub, XpubVersion::Ypub, XpubVersion::Zpub] {
            let mut out = [0u8; XPUB_MAX_LEN];
            let n = serialize_xpub(&acct, version, &mut out);
            assert!(n <= XPUB_MAX_LEN, "encoded xpub must fit XPUB_MAX_LEN");
            assert_eq!(n, 111, "mainnet extended keys encode to 111 characters");
            assert!(out[..n].iter().all(|b| b.is_ascii_alphanumeric()));
        }
    }

    // ------------------------------------------------------------------
    // Negative test (wallet-export spec D1): no xprv serializer exists.
    //
    // Greps the production text of *every* `.rs` file under this crate's
    // `src/` (via `all_crate_src_files`) for the BIP32 extended-*private*-key
    // version constant and for a serialized instance of such a key, so the
    // module doc's "no xprv serializer anywhere in this crate" claim is
    // actually enforced rather than only spot-checked on two files. The scan
    // walks `CARGO_MANIFEST_DIR/src` with `std::fs` at test time (host-test
    // only) and runs on every `cargo test`. (The companion
    // `no_function_in_this_module_takes_private_key_material` test stays
    // deliberately module-scoped: sibling modules like `curve` legitimately
    // handle scalars and private-key bytes.)
    //
    // Two properties this scanner needs, both learned the hard way:
    //
    // 1. **It must not trip over itself.** Every needle is assembled from
    //    fragments at runtime, and only the *production* half of each file
    //    (everything before the first `#[cfg(test)]`) is scanned. Test code
    //    legitimately names the thing it is forbidding — including this test's
    //    own name — and test code does not ship.
    //
    // 2. **It must match the idioms this module actually uses**, not just one
    //    spelling. `version_bytes` writes version constants as a byte array
    //    (`[0x04, 0x88, 0xB2, 0x1E]`), so a naive search for the packed hex
    //    form `0x0488B21E` would sail straight past the most likely way
    //    someone would add a private-key version here. `hex_normalized`
    //    therefore lowercases, deletes every `0x` prefix, then keeps only hex
    //    digits — collapsing `0x0488_ADE4`, `0x0488ADE4` and
    //    `[0x04, 0x88, 0xAD, 0xE4]` to the same string. `decimal_normalized`
    //    additionally covers the decimal byte-array spelling
    //    (`[4, 136, 173, 228]`). Both spellings are proven to fire by the
    //    mutation probes recorded in this task's report.
    // ------------------------------------------------------------------

    const SERIALIZE_RS: &str = include_str!("serialize.rs");

    /// Read the production text of every `.rs` file under this crate's
    /// `src/`, so the D1 no-xprv scan backs its "anywhere in this crate"
    /// claim rather than only covering the two files this module happens to
    /// `include_str!`. Uses `CARGO_MANIFEST_DIR` (cargo sets it for every
    /// test build) + `std::fs`; host-test only. Each entry is
    /// `(display_path, full_text)` — callers apply [`production_half`].
    fn all_crate_src_files() -> std::vec::Vec<(std::string::String, std::string::String)> {
        fn walk(dir: &std::path::Path, out: &mut std::vec::Vec<(std::string::String, std::string::String)>) {
            let mut entries: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(dir)
                .expect("crate src/ is readable during tests")
                .map(|e| e.expect("readable dir entry").path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    let text = std::fs::read_to_string(&path).expect("source file is readable");
                    out.push((std::format!("{}", path.display()), text));
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = std::vec::Vec::new();
        walk(&src, &mut out);
        assert!(out.len() >= 2, "expected to find the crate's source files, saw {}", out.len());
        out
    }

    /// Fragments of the forbidden BIP32 extended-private-key version
    /// constant, kept apart so the needle never appears verbatim anywhere.
    const XPRV_VERSION_HI: &str = "0488";
    const XPRV_VERSION_LO: &str = "ade4";
    /// Same constant in decimal byte-array form.
    const XPRV_VERSION_DEC_HI: &str = "4,136,";
    const XPRV_VERSION_DEC_LO: &str = "173,228";
    /// Fragments of the Base58 prefix every serialized mainnet extended
    /// private key starts with. Deliberately stops before the
    /// checksum/length-dependent digit (real ones are `...9`, but that digit
    /// is not fixed by the version bytes, so requiring it would make this
    /// check vacuous).
    const XPRV_PREFIX_HEAD: &str = "xpr";
    const XPRV_PREFIX_TAIL: &str = "v";

    /// Tokens that must never appear in a function signature in this
    /// public-only module: private-key byte arrays, curve scalars, or any
    /// parameter named after secret material.
    const FORBIDDEN_SIGNATURE_TOKENS: &[&str] = &[
        "[u8; 32]",
        "[u8;32]",
        "privkey",
        "priv_key",
        "private_key",
        "secret",
        "Scalar",
        "SecretArena",
        "seed",
    ];

    /// Everything in `src` before the first `#[cfg(test)]` — the half that
    /// actually ships. Test code may name what it forbids; firmware may not.
    fn production_half(src: &str) -> &str {
        src.split("#[cfg(test)]")
            .next()
            .expect("split always yields at least one element")
    }

    /// Collapse every spelling of a hex constant to bare lowercase hex
    /// digits: lowercase, drop `0x` prefixes, then keep only `[0-9a-f]`.
    /// `0x0488_ADE4`, `0x0488ADE4` and `[0x04, 0x88, 0xAD, 0xE4]` all become
    /// `0488ade4`.
    fn hex_normalized(src: &str) -> std::string::String {
        src.to_ascii_lowercase()
            .replace("0x", "")
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect()
    }

    /// Whitespace removed, so a decimal byte array written across lines or
    /// with varying spacing still matches one needle.
    fn decimal_normalized(src: &str) -> std::string::String {
        src.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// The non-test half of this file, with comment lines removed and all
    /// whitespace runs collapsed to single spaces, so a multi-line function
    /// signature is still scannable as one contiguous string.
    fn production_code_one_line() -> std::string::String {
        let code_only: std::vec::Vec<&str> = production_half(SERIALIZE_RS)
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        code_only.join(" ").split_whitespace().collect::<std::vec::Vec<_>>().join(" ")
    }

    fn joined(fragments: &[&str]) -> std::string::String {
        let mut s = std::string::String::new();
        for f in fragments {
            s.push_str(f);
        }
        s
    }

    #[test]
    fn no_xprv_serializer_exists() {
        let hex_needle = joined(&[XPRV_VERSION_HI, XPRV_VERSION_LO]);
        let decimal_needle = joined(&[XPRV_VERSION_DEC_HI, XPRV_VERSION_DEC_LO]);
        let prefix_needle = joined(&[XPRV_PREFIX_HEAD, XPRV_PREFIX_TAIL]);

        for (name, src) in all_crate_src_files() {
            let production = production_half(&src);

            assert!(
                !hex_normalized(production).contains(&hex_needle),
                "{name} contains the BIP32 extended-private-key version constant (hex \
                 or byte-array form): no private-key serializer may exist \
                 (wallet-export spec D1)"
            );
            assert!(
                !decimal_normalized(production).contains(&decimal_needle),
                "{name} contains the BIP32 extended-private-key version constant \
                 (decimal byte-array form): no private-key serializer may exist \
                 (wallet-export spec D1)"
            );
            assert!(
                !production.to_ascii_lowercase().contains(&prefix_needle),
                "{name} contains a serialized extended-private-key string literal \
                 (wallet-export spec D1)"
            );
        }
    }

    #[test]
    fn no_function_in_this_module_takes_private_key_material() {
        // Scan only the non-test half of the file: the test module above
        // legitimately handles private keys while *building* expectations.
        let code = production_code_one_line();

        let mut scanned = 0usize;
        let mut rest = code.as_str();
        while let Some(pos) = rest.find("fn ") {
            let after = &rest[pos..];
            // The signature runs up to the body's opening brace (every
            // function in this module has a block body).
            let end = after.find('{').unwrap_or(after.len());
            let signature = &after[..end];
            for token in FORBIDDEN_SIGNATURE_TOKENS {
                assert!(
                    !signature.contains(token),
                    "function signature `{signature}` mentions `{token}`: this module \
                     is public-only (wallet-export spec D1)"
                );
            }
            scanned += 1;
            rest = &after[3..];
        }

        assert!(
            scanned >= 3,
            "expected to scan at least the module's three functions, saw {scanned} \
             -- the scanner itself is broken, not the module"
        );
    }
}
