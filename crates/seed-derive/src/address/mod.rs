//! Address construction for the four fixed wallet-verification standards
//! (SPEC §24.2 table, §24.3 display rules; `IMPLEMENTATION_MAP.md` WP-14).
//!
//! | Standard | Path              | Script type            | Address form |
//! | -------- | ----------------- | ----------------------- | ------------ |
//! | BIP44    | `m/44'/0'/0'/0/0` | P2PKH (legacy)          | `1...`       |
//! | BIP49    | `m/49'/0'/0'/0/0` | P2SH-P2WPKH (nested)    | `3...`       |
//! | BIP84    | `m/84'/0'/0'/0/0` | P2WPKH (native segwit)  | `bc1q...`    |
//! | BIP86    | `m/86'/0'/0'/0/0` | P2TR (taproot)          | `bc1p...`    |
//!
//! All four addresses are Bitcoin **mainnet** addresses for account 0,
//! external chain, index 0 (SPEC §24.2). This module builds each address
//! form from a compressed SEC1 public key (P2PKH/P2SH-P2WPKH/P2WPKH) or an
//! x-only public key (P2TR), and provides [`first_address`] — the single
//! frozen entry point (`IMPLEMENTATION_MAP.md` §4) that walks a BIP39 seed
//! all the way to one rendered address string for a given
//! [`PathStandard`].
//!
//! Two pitfalls called out explicitly by `IMPLEMENTATION_MAP.md` WP-14 and
//! handled here:
//! - P2SH-P2WPKH (BIP49) Base58Check-encodes `hash160` of the **witness
//!   program script** `0x00 0x14 <hash160(pubkey)>` (22 bytes) — not
//!   `hash160(pubkey)` directly. See [`p2sh_p2wpkh_address`].
//! - P2TR (BIP86) bech32m-encodes the **tweaked** taproot output key
//!   (BIP341 `Q = lift_x(P) + tagged_hash("TapTweak", P)·G`), not the raw
//!   internal x-only key. See [`p2tr_address`].
//!
//! Every function that touches private-key material (`first_address`)
//! zeroizes every local secret buffer (key, chain code, and — for hygiene,
//! matching this crate's `bip32`/`curve` modules — the derived public-key
//! bytes) on every return path, success or error (SPEC §13, §20.3). No
//! heap allocation (`#![no_std]`, no `alloc`, inherited from the crate
//! root).

use seed_core::bech32;
use seed_core::contracts::{AddressBuf, DeriveError, EncodeError, PathStandard};
use seed_core::hash160::hash160;
use zeroize::Zeroize;

use crate::bip32::{derive_account_path, derive_path};
use crate::curve::{
    privkey_to_compressed_pubkey, privkey_to_xonly_pubkey, taproot_tweak_xonly,
    COMPRESSED_PUBKEY_LEN, XONLY_PUBKEY_LEN,
};

/// SPEC_DERIVATION_OPTIONS §A.7.1 #2 / §A.7.3: the address-encoding script
/// type, **decoupled from [`PathStandard`]**. Today [`first_address`]
/// dispatches on `PathStandard`, which conflates the derivation purpose
/// with the address form; the bounded-grid extension needs the address
/// form as its own axis so [`address_at`] can render any pre-derived path
/// without re-encoding the purpose→form mapping at every call site.
///
/// For v1 the script type is always **implied by the chosen preset**
/// (there is no user-facing script-type picker — that is deferred with
/// custom paths, §A.3): [`ScriptType::for_standard`] is the only mapping
/// used, `BIP44 → P2PKH`, `BIP49 → P2SH-P2WPKH`, `BIP84 → P2WPKH`,
/// `BIP86 → P2TR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// P2PKH (legacy, `1...`) — BIP44.
    P2pkh,
    /// P2SH-P2WPKH (nested segwit, `3...`) — BIP49.
    P2shP2wpkh,
    /// P2WPKH (native segwit, `bc1q...`) — BIP84.
    P2wpkh,
    /// P2TR (taproot, `bc1p...`) — BIP86.
    P2tr,
}

impl ScriptType {
    /// The script type implied by a preset purpose (SPEC §24.2 table).
    /// The only purpose→form mapping v1 exposes (§A.2: "the purpose fixes
    /// the script type").
    #[must_use]
    pub const fn for_standard(standard: PathStandard) -> Self {
        match standard {
            PathStandard::Bip44 => ScriptType::P2pkh,
            PathStandard::Bip49 => ScriptType::P2shP2wpkh,
            PathStandard::Bip84 => ScriptType::P2wpkh,
            PathStandard::Bip86 => ScriptType::P2tr,
        }
    }
}

/// SPEC §24.2: Bitcoin mainnet Base58Check version byte for P2PKH
/// (`1...` addresses).
const MAINNET_P2PKH_VERSION: u8 = 0x00;

/// SPEC §24.2: Bitcoin mainnet Base58Check version byte for P2SH
/// (`3...` addresses, used here for the nested P2SH-P2WPKH form).
const MAINNET_P2SH_VERSION: u8 = 0x05;

/// SPEC §24.2: Bitcoin mainnet Bech32/Bech32m human-readable part, used
/// for both the P2WPKH (`bc1q...`) and P2TR (`bc1p...`) forms.
const MAINNET_HRP: &[u8] = b"bc";

/// SPEC §24.2: witness-program script prefix for a P2SH-nested native
/// segwit v0 program (`OP_0 OP_PUSHBYTES_20`, i.e. `0x00 0x14`), prepended
/// to `hash160(pubkey)` before hashing *again* for the P2SH address
/// (BIP49; see [`p2sh_p2wpkh_address`]'s doc comment for why this step
/// cannot be skipped).
const WITNESS_SCRIPT_PREFIX: [u8; 2] = [0x00, 0x14];

/// Writes `payload`'s Base58Check encoding into `out` as an
/// [`AddressBuf`] (SPEC §24.2/§24.3). Shared by [`p2pkh_address`] and
/// [`p2sh_p2wpkh_address`].
///
/// `payload` is always exactly 21 bytes in this module (1 version byte +
/// 20-byte `hash160`), well within
/// [`seed_core::base58::MAX_PAYLOAD`], and the Base58Check output (at
/// most [`seed_core::contracts::MAX_B58`] = 35 bytes) always fits
/// `AddressBuf`'s 92-byte buffer, so this cannot fail.
fn write_base58check(payload: &[u8], out: &mut AddressBuf) {
    let mut b58 = [0u8; seed_core::contracts::MAX_B58];
    let n = seed_core::base58::base58check_encode(payload, &mut b58);
    out.set(&b58[..n]);
    b58.zeroize();
}

/// Maps a [`bech32`] encoder failure onto [`DeriveError`] (`contracts.rs`
/// has no dedicated segwit-address-encoding error type, so the closest
/// existing variant is reused, matching the pattern this crate's `curve`
/// module already uses for the same reason — see
/// `curve::taproot_tweak_xonly`'s doc comment).
///
/// `EncodeError::BufferTooSmall` maps directly onto
/// `DeriveError::BufferTooSmall` (same meaning). `InvalidVersion` and
/// `InvalidProgramLength` are cryptographically unreachable on every call
/// site in this module (witness version and program length are always
/// one of the two fixed, correct combinations SPEC §24.2 defines — v0/20
/// bytes for P2WPKH, v1/32 bytes for P2TR); they map onto
/// `DeriveError::InvalidIndex` defensively rather than being `unwrap()`-ed
/// away, because SPEC §13/§27.3 forbid panicking on this path.
fn map_encode_err(e: EncodeError) -> DeriveError {
    match e {
        EncodeError::BufferTooSmall => DeriveError::BufferTooSmall,
        EncodeError::InvalidVersion | EncodeError::InvalidProgramLength => {
            DeriveError::InvalidIndex
        }
    }
}

/// SPEC §24.2 BIP44 row: the P2PKH (legacy, `1...`) mainnet address for a
/// compressed SEC1 public key — `base58check(0x00 || hash160(pubkey))`.
pub fn p2pkh_address(compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN], out: &mut AddressBuf) {
    let mut payload = [0u8; 21];
    payload[0] = MAINNET_P2PKH_VERSION;
    payload[1..].copy_from_slice(&hash160(compressed_pubkey));
    write_base58check(&payload, out);
    payload.zeroize();
}

/// SPEC §24.2 BIP49 row: the P2SH-P2WPKH (nested segwit, `3...`) mainnet
/// address for a compressed SEC1 public key.
///
/// **Pitfall** (`IMPLEMENTATION_MAP.md` WP-14): the P2SH address
/// Base58Check-encodes `hash160` of the *witness program script*
/// `0x00 0x14 || hash160(pubkey)` (22 bytes) — i.e. `hash160` is applied
/// **twice**, once to the pubkey to build the witness script and once
/// more to that script — not `hash160(pubkey)` directly. Encoding
/// `hash160(pubkey)` straight into the P2SH payload (skipping the
/// intermediate witness-script hash) is the classic bug this doc comment
/// exists to prevent; see the `p2sh_hashes_witness_script_not_pubkey_hash`
/// test below for a regression check.
pub fn p2sh_p2wpkh_address(compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN], out: &mut AddressBuf) {
    let pubkey_hash = hash160(compressed_pubkey);

    let mut witness_script = [0u8; 22];
    witness_script[..2].copy_from_slice(&WITNESS_SCRIPT_PREFIX);
    witness_script[2..].copy_from_slice(&pubkey_hash);

    let mut payload = [0u8; 21];
    payload[0] = MAINNET_P2SH_VERSION;
    payload[1..].copy_from_slice(&hash160(&witness_script));
    write_base58check(&payload, out);

    witness_script.zeroize();
    payload.zeroize();
}

/// SPEC §24.2 BIP84 row: the P2WPKH (native segwit, `bc1q...`) mainnet
/// address for a compressed SEC1 public key — Bech32 (witness version 0)
/// of `hash160(pubkey)`.
pub fn p2wpkh_address(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
    out: &mut AddressBuf,
) -> Result<(), DeriveError> {
    let program = hash160(compressed_pubkey);
    bech32::encode(MAINNET_HRP, 0, &program, out).map_err(map_encode_err)
}

/// SPEC §24.2 BIP86 row: the P2TR (taproot, `bc1p...`) mainnet address for
/// an x-only internal public key — Bech32m (witness version 1) of the
/// BIP341-**tweaked** output key.
///
/// **Pitfall** (`IMPLEMENTATION_MAP.md` WP-14): this encodes the *tweaked*
/// output key `Q = lift_x(P) + tagged_hash("TapTweak", P)·G`
/// ([`taproot_tweak_xonly`]), never the raw `internal_xonly_pubkey`
/// argument itself — encoding the untweaked internal key directly would
/// produce a well-formed but wrong address (a key-path-spendable output
/// only the raw private key, not the taproot-tweaked one, could sign for
/// under BIP341's actual output-key rule).
pub fn p2tr_address(
    internal_xonly_pubkey: &[u8; XONLY_PUBKEY_LEN],
    out: &mut AddressBuf,
) -> Result<(), DeriveError> {
    let mut tweaked = [0u8; XONLY_PUBKEY_LEN];
    let result = taproot_tweak_xonly(internal_xonly_pubkey, &mut tweaked);
    if let Err(e) = result {
        tweaked.zeroize();
        return Err(e);
    }
    let encoded = bech32::encode(MAINNET_HRP, 1, &tweaked, out).map_err(map_encode_err);
    tweaked.zeroize();
    encoded
}

/// SPEC §24.2/§24.3 frozen entry point (`IMPLEMENTATION_MAP.md` §4): the
/// first external receive address (account 0, external chain, index 0)
/// for one of the four fixed wallet-verification standards, derived
/// directly from the 64-byte BIP39 seed.
///
/// Walks [`derive_account_path`] (WP-13) to the standard's fixed 5-level
/// path, derives the appropriate public key form (compressed SEC1 for
/// BIP44/49/84, x-only for BIP86), and renders the matching address form
/// into `out`. Every intermediate secret (the derived private key/chain
/// code) and, for hygiene, every derived public-key buffer is zeroized on
/// every return path, success or error (SPEC §13, §20.3;
/// `IMPLEMENTATION_MAP.md` WP-14/WP-13: "scrub on every path incl.
/// errors").
///
/// # Errors
///
/// Returns `Err(DeriveError::InvalidChildKey)` if any step of the BIP32
/// derivation path is cryptographically invalid (see
/// [`derive_account_path`]'s doc comment — negligible probability for any
/// real seed), or propagates a [`p2wpkh_address`]/[`p2tr_address`]
/// encoding failure (also cryptographically unreachable for the fixed
/// program lengths/versions this function always passes them).
pub fn first_address(
    seed: &[u8; 64],
    standard: PathStandard,
    out: &mut AddressBuf,
) -> Result<(), DeriveError> {
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];

    let derived = derive_account_path(seed, standard, &mut key, &mut cc);
    if let Err(e) = derived {
        key.zeroize();
        cc.zeroize();
        return Err(e);
    }
    // The chain code is not used past this point (address construction
    // only needs the child private key to derive its public key); scrub
    // it immediately rather than holding it until the function returns.
    cc.zeroize();

    let result = match standard {
        PathStandard::Bip44 => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey).map(|()| {
                p2pkh_address(&pubkey, out);
            });
            pubkey.zeroize();
            inner
        }
        PathStandard::Bip49 => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey).map(|()| {
                p2sh_p2wpkh_address(&pubkey, out);
            });
            pubkey.zeroize();
            inner
        }
        PathStandard::Bip84 => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey)
                .and_then(|()| p2wpkh_address(&pubkey, out));
            pubkey.zeroize();
            inner
        }
        PathStandard::Bip86 => {
            let mut xonly = [0u8; XONLY_PUBKEY_LEN];
            let inner = privkey_to_xonly_pubkey(&key, &mut xonly)
                .and_then(|()| p2tr_address(&xonly, out));
            xonly.zeroize();
            inner
        }
    };

    key.zeroize();
    result
}

/// SPEC_DERIVATION_OPTIONS §A.7.1 #3 / §A.7.3: the **general** address
/// builder — derive the private key at an arbitrary bounded `path` (via
/// [`derive_path`]) and render it into `out` as the requested
/// [`ScriptType`], reusing the exact same four vector-checked address
/// builders [`first_address`] uses ([`p2pkh_address`],
/// [`p2sh_p2wpkh_address`], [`p2wpkh_address`], [`p2tr_address`] — pubkey
/// in / address out, unchanged).
///
/// This generalizes [`first_address`] along two axes at once: the path is
/// no longer the fixed `.../0'/0/0` leaf (any bounded account / change /
/// index — the v1 grid uses [`crate::bip32::preset_path`]), and the
/// address form is chosen explicitly rather than inferred from
/// `PathStandard`. `address_at(seed, ScriptType::for_standard(s),
/// &preset_path(s, 0, 0, 0), out)` is byte-identical to
/// `first_address(seed, s, out)` (checked by
/// `address_at_index_zero_matches_first_address` below).
///
/// Every intermediate secret (derived private key / chain code) and every
/// derived public-key buffer is zeroized on every return path, success or
/// error (SPEC §13, §20.3), exactly as [`first_address`] does.
///
/// # Errors
///
/// Propagates any [`derive_path`] BIP32 rejection (invalid child key, or a
/// path deeper than [`crate::bip32::MAX_DEPTH`]) and any
/// [`p2wpkh_address`]/[`p2tr_address`] encoding failure — all
/// cryptographically unreachable for a real seed and the fixed-length
/// programs this function passes.
pub fn address_at(
    seed: &[u8; 64],
    script_type: ScriptType,
    path: &[u32],
    out: &mut AddressBuf,
) -> Result<(), DeriveError> {
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];

    if let Err(e) = derive_path(seed, path, &mut key, &mut cc) {
        key.zeroize();
        cc.zeroize();
        return Err(e);
    }
    // The chain code is not used past derivation (address construction only
    // needs the child private key); scrub it immediately, matching
    // `first_address`.
    cc.zeroize();

    let result = match script_type {
        ScriptType::P2pkh => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey).map(|()| {
                p2pkh_address(&pubkey, out);
            });
            pubkey.zeroize();
            inner
        }
        ScriptType::P2shP2wpkh => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey).map(|()| {
                p2sh_p2wpkh_address(&pubkey, out);
            });
            pubkey.zeroize();
            inner
        }
        ScriptType::P2wpkh => {
            let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
            let inner = privkey_to_compressed_pubkey(&key, &mut pubkey)
                .and_then(|()| p2wpkh_address(&pubkey, out));
            pubkey.zeroize();
            inner
        }
        ScriptType::P2tr => {
            let mut xonly = [0u8; XONLY_PUBKEY_LEN];
            let inner = privkey_to_xonly_pubkey(&key, &mut xonly)
                .and_then(|()| p2tr_address(&xonly, out));
            xonly.zeroize();
            inner
        }
    };

    key.zeroize();
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::bip32::derive_account_path;

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn empty_buf() -> AddressBuf {
        AddressBuf::empty()
    }

    fn buf_str(buf: &AddressBuf) -> &str {
        buf.as_str().unwrap()
    }

    // ------------------------------------------------------------------
    // The standard "abandon...about" test mnemonic's BIP39 seed (SPEC
    // §24.2: empty passphrase). This is the widely published test seed
    // for the 12-word mnemonic
    // "abandon abandon abandon abandon abandon abandon abandon abandon
    // abandon abandon abandon about" with an empty BIP39 passphrase
    // (distinct from the python-mnemonic test suite's "TREZOR"-passphrase
    // seed for the same words, which is a different, non-empty-passphrase
    // value and NOT what SPEC §24.2 uses).
    //
    // This hex value and every expected address below were independently
    // cross-checked two ways before being hardcoded here:
    //   1. Against `reference/python/seedref` (WP-11), which computes the
    //      same seed from the mnemonic word indexes via its own
    //      `mnemonic_to_seed` and derives all four addresses through its
    //      own from-scratch `secp256k1`/`bip32`/`base58`/`bech32` stack
    //      (see `reference/python/tests/test_addresses.py`).
    //   2. Against a second, fully independent from-scratch computation
    //      (plain Python `hashlib`/`hmac`, schoolbook big-integer secp256k1
    //      point arithmetic, no shared code with either `seedref` or this
    //      crate) performed while implementing this module, reproducing
    //      the master fingerprint and all four addresses byte-for-byte.
    // The BIP84 address and master fingerprint additionally match BIP84's
    // own published specification test vector for this mnemonic
    // (bip-0084.mediawiki "Test vectors").
    // ------------------------------------------------------------------
    const TEST_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc\
19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    const EXPECTED_BIP44: &str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";
    const EXPECTED_BIP49: &str = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf";
    const EXPECTED_BIP84: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const EXPECTED_BIP86: &str =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    fn test_seed() -> [u8; 64] {
        let v = hex_to_vec(TEST_SEED_HEX);
        assert_eq!(v.len(), 64);
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    // ------------------------------------------------------------------
    // DoD: published BIP49/84/86 vectors (plus BIP44) pass, via the
    // frozen `first_address` entry point.
    // ------------------------------------------------------------------

    #[test]
    fn first_address_bip44_matches_published_vector() {
        let seed = test_seed();
        let mut out = empty_buf();
        first_address(&seed, PathStandard::Bip44, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP44);
    }

    #[test]
    fn first_address_bip49_matches_published_vector() {
        let seed = test_seed();
        let mut out = empty_buf();
        first_address(&seed, PathStandard::Bip49, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP49);
    }

    #[test]
    fn first_address_bip84_matches_published_vector() {
        let seed = test_seed();
        let mut out = empty_buf();
        first_address(&seed, PathStandard::Bip84, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP84);
    }

    #[test]
    fn first_address_bip86_matches_published_vector() {
        let seed = test_seed();
        let mut out = empty_buf();
        first_address(&seed, PathStandard::Bip86, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP86);
    }

    #[test]
    fn first_address_all_four_are_distinct() {
        let seed = test_seed();
        let mut seen = std::vec::Vec::new();
        for standard in [
            PathStandard::Bip44,
            PathStandard::Bip49,
            PathStandard::Bip84,
            PathStandard::Bip86,
        ] {
            let mut out = empty_buf();
            first_address(&seed, standard, &mut out).unwrap();
            let s = std::string::String::from(buf_str(&out));
            assert!(!seen.contains(&s), "duplicate address: {s}");
            seen.push(s);
        }
    }

    // ------------------------------------------------------------------
    // Master fingerprint cross-check (SPEC §24.2/§24.3): BIP84's own
    // published spec test vector for this exact mnemonic gives master
    // fingerprint 73c5da0a; `crate::bip32::master_fingerprint` is WP-13's
    // surface (not this module's), but re-checking it here anchors this
    // module's test seed to the same publicly documented vector the
    // addresses above are checked against.
    // ------------------------------------------------------------------

    #[test]
    fn test_seed_master_fingerprint_matches_published_vector() {
        use crate::bip32::master_from_seed;
        let seed = test_seed();
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed(&seed, &mut key, &mut cc);
        let fp = crate::bip32::master_fingerprint(&key);
        assert_eq!(fp, [0x73, 0xc5, 0xda, 0x0a]);
        key.zeroize();
        cc.zeroize();
    }

    // ------------------------------------------------------------------
    // Per-script-type unit tests, driven from the same test seed's
    // per-standard derived key, exercising each low-level function
    // ([`p2pkh_address`], [`p2sh_p2wpkh_address`], [`p2wpkh_address`],
    // [`p2tr_address`]) directly rather than only through
    // [`first_address`].
    // ------------------------------------------------------------------

    fn derive_pubkey(standard: PathStandard) -> [u8; COMPRESSED_PUBKEY_LEN] {
        let seed = test_seed();
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        derive_account_path(&seed, standard, &mut key, &mut cc).unwrap();
        let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
        privkey_to_compressed_pubkey(&key, &mut pubkey).unwrap();
        key.zeroize();
        cc.zeroize();
        pubkey
    }

    fn derive_xonly() -> [u8; XONLY_PUBKEY_LEN] {
        let seed = test_seed();
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        derive_account_path(&seed, PathStandard::Bip86, &mut key, &mut cc).unwrap();
        let mut xonly = [0u8; XONLY_PUBKEY_LEN];
        privkey_to_xonly_pubkey(&key, &mut xonly).unwrap();
        key.zeroize();
        cc.zeroize();
        xonly
    }

    #[test]
    fn p2pkh_address_matches_published_vector_directly() {
        let pubkey = derive_pubkey(PathStandard::Bip44);
        let mut out = empty_buf();
        p2pkh_address(&pubkey, &mut out);
        assert_eq!(buf_str(&out), EXPECTED_BIP44);
    }

    #[test]
    fn p2sh_p2wpkh_address_matches_published_vector_directly() {
        let pubkey = derive_pubkey(PathStandard::Bip49);
        let mut out = empty_buf();
        p2sh_p2wpkh_address(&pubkey, &mut out);
        assert_eq!(buf_str(&out), EXPECTED_BIP49);
    }

    #[test]
    fn p2wpkh_address_matches_published_vector_directly() {
        let pubkey = derive_pubkey(PathStandard::Bip84);
        let mut out = empty_buf();
        p2wpkh_address(&pubkey, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP84);
    }

    #[test]
    fn p2tr_address_matches_published_vector_directly() {
        let xonly = derive_xonly();
        let mut out = empty_buf();
        p2tr_address(&xonly, &mut out).unwrap();
        assert_eq!(buf_str(&out), EXPECTED_BIP86);
    }

    // ------------------------------------------------------------------
    // Pitfall regression tests (`IMPLEMENTATION_MAP.md` WP-14 pitfall
    // list, quoted in this module's header doc comment).
    // ------------------------------------------------------------------

    /// P2SH-P2WPKH must hash the *witness program script*
    /// (`0x00 0x14 || hash160(pubkey)`), not `hash160(pubkey)` directly.
    /// This is the classic bug the pitfall list calls out; check it by
    /// constructing the (wrong) direct-hash payload independently and
    /// confirming it does NOT match [`p2sh_p2wpkh_address`]'s output.
    #[test]
    fn p2sh_hashes_witness_script_not_pubkey_hash_directly() {
        let pubkey = derive_pubkey(PathStandard::Bip49);

        let mut correct = empty_buf();
        p2sh_p2wpkh_address(&pubkey, &mut correct);

        // The (incorrect) alternative: base58check(0x05 || hash160(pubkey))
        // directly, skipping the witness-script wrapping step.
        let mut wrong_payload = [0u8; 21];
        wrong_payload[0] = MAINNET_P2SH_VERSION;
        wrong_payload[1..].copy_from_slice(&hash160(&pubkey));
        let mut wrong = empty_buf();
        write_base58check(&wrong_payload, &mut wrong);

        assert_ne!(
            buf_str(&correct),
            buf_str(&wrong),
            "p2sh_p2wpkh_address must not degrade to hashing the pubkey directly"
        );
        assert_eq!(buf_str(&correct), EXPECTED_BIP49);
    }

    /// P2TR must bech32m-encode the BIP341-*tweaked* output key, not the
    /// raw internal x-only key.
    #[test]
    fn p2tr_uses_tweaked_key_not_internal_key() {
        let xonly = derive_xonly();

        let mut correct = empty_buf();
        p2tr_address(&xonly, &mut correct).unwrap();
        assert_eq!(buf_str(&correct), EXPECTED_BIP86);

        // The (incorrect) alternative: bech32m-encode the raw internal
        // x-only key directly, skipping the taproot tweak.
        let mut untweaked = empty_buf();
        bech32::encode(MAINNET_HRP, 1, &xonly, &mut untweaked).unwrap();

        assert_ne!(
            buf_str(&correct),
            buf_str(&untweaked),
            "p2tr_address must not encode the untweaked internal key"
        );
    }

    // ------------------------------------------------------------------
    // Encoding-form sanity: version bytes / HRPs / witness versions
    // produce the documented address prefixes (SPEC §24.3 display table).
    // ------------------------------------------------------------------

    #[test]
    fn address_prefixes_match_spec_display_table() {
        assert!(EXPECTED_BIP44.starts_with('1'));
        assert!(EXPECTED_BIP49.starts_with('3'));
        assert!(EXPECTED_BIP84.starts_with("bc1q"));
        assert!(EXPECTED_BIP86.starts_with("bc1p"));
    }

    /// Bech32 (v0, P2WPKH) and Bech32m (v1, P2TR) must never be
    /// cross-applied (SPEC §24.2/§24.3; the underlying encoder's own
    /// pitfall, re-exercised end-to-end here through this module's
    /// public functions). Swapping the checksum constant would still
    /// produce a plausible-looking but invalid address string; the
    /// concrete published vectors above already pin the correct value,
    /// this test just isolates *why* by checking the shared program
    /// bytes decode consistently under each function's own witness
    /// version.
    #[test]
    fn p2wpkh_and_p2tr_use_different_witness_versions() {
        let pubkey = derive_pubkey(PathStandard::Bip84);
        let mut wpkh_out = empty_buf();
        p2wpkh_address(&pubkey, &mut wpkh_out).unwrap();
        assert!(buf_str(&wpkh_out).starts_with("bc1q"));

        let xonly = derive_xonly();
        let mut tr_out = empty_buf();
        p2tr_address(&xonly, &mut tr_out).unwrap();
        assert!(buf_str(&tr_out).starts_with("bc1p"));
    }

    // ------------------------------------------------------------------
    // `first_address` error propagation sanity: an all-zero seed still
    // derives successfully (BIP32 invalid-key rejection is
    // cryptographically negligible for any concrete seed, including this
    // one — the master key HMAC output for an all-zero seed is not
    // itself zero or out-of-range), confirming `first_address` does not
    // spuriously error on a boundary-ish input.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // `address_at` (general builder, SPEC_DERIVATION_OPTIONS §A.7.1 #3):
    // (1) index-0 preset leaf is byte-identical to `first_address`;
    // (2) non-zero index and the internal change chain match BIP84's own
    //     published test vectors for this exact mnemonic (bip-0084.mediawiki
    //     "Test vectors" — the iancoleman-style receive/change addresses).
    // ------------------------------------------------------------------

    use crate::bip32::preset_path;

    // BIP84 mediawiki published vectors for the "abandon abandon ... about"
    // mnemonic, empty passphrase (same seed as EXPECTED_BIP84 above):
    //   m/84'/0'/0'/0/0 = first receive  (== EXPECTED_BIP84)
    //   m/84'/0'/0'/0/1 = second receive
    //   m/84'/0'/0'/1/0 = first change
    const BIP84_RECEIVE_INDEX_1: &str = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
    const BIP84_CHANGE_INDEX_0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

    #[test]
    fn address_at_index_zero_matches_first_address() {
        let seed = test_seed();
        for standard in [
            PathStandard::Bip44,
            PathStandard::Bip49,
            PathStandard::Bip84,
            PathStandard::Bip86,
        ] {
            let mut a = empty_buf();
            first_address(&seed, standard, &mut a).unwrap();

            let mut b = empty_buf();
            address_at(
                &seed,
                ScriptType::for_standard(standard),
                &preset_path(standard, 0, 0, 0),
                &mut b,
            )
            .unwrap();

            assert_eq!(buf_str(&a), buf_str(&b), "{standard:?}: address_at index-0 must equal first_address");
        }
    }

    #[test]
    fn address_at_matches_published_bip84_second_receive_address() {
        let seed = test_seed();
        let mut out = empty_buf();
        address_at(
            &seed,
            ScriptType::for_standard(PathStandard::Bip84),
            &preset_path(PathStandard::Bip84, 0, 0, 1),
            &mut out,
        )
        .unwrap();
        assert_eq!(buf_str(&out), BIP84_RECEIVE_INDEX_1);
    }

    #[test]
    fn address_at_matches_published_bip84_first_change_address() {
        let seed = test_seed();
        let mut out = empty_buf();
        address_at(
            &seed,
            ScriptType::for_standard(PathStandard::Bip84),
            &preset_path(PathStandard::Bip84, 0, 1, 0),
            &mut out,
        )
        .unwrap();
        assert_eq!(buf_str(&out), BIP84_CHANGE_INDEX_0);
    }

    #[test]
    fn script_type_for_standard_maps_preset_purposes() {
        assert_eq!(ScriptType::for_standard(PathStandard::Bip44), ScriptType::P2pkh);
        assert_eq!(ScriptType::for_standard(PathStandard::Bip49), ScriptType::P2shP2wpkh);
        assert_eq!(ScriptType::for_standard(PathStandard::Bip84), ScriptType::P2wpkh);
        assert_eq!(ScriptType::for_standard(PathStandard::Bip86), ScriptType::P2tr);
    }

    #[test]
    fn first_address_all_zero_seed_succeeds_for_every_standard() {
        let seed = [0u8; 64];
        for standard in [
            PathStandard::Bip44,
            PathStandard::Bip49,
            PathStandard::Bip84,
            PathStandard::Bip86,
        ] {
            let mut out = empty_buf();
            assert!(first_address(&seed, standard, &mut out).is_ok());
            assert!(out.len() > 0);
        }
    }
}
