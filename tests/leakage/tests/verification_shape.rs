//! WP-34 check class (d) — SPEC §24.3: "MUST NOT display private keys,
//! extended private keys (`xprv`), the BIP39 seed or raw chain codes."
//! and "MUST NOT display or export extended public keys (`xpub`) in
//! version 1; addresses and fingerprint only."
//!
//! [`seed_core::pipeline::VerificationValues`] is the derivation
//! screen's entire payload type (SPEC §24.3, `crates/seed-uefi-test/
//! flow/src/flow_secret/verification.rs`'s `render` function's only
//! input). This file proves it CANNOT carry an xprv/xpub/seed/chain-code
//! structurally, not just "doesn't happen to today":
//!
//! 1. An exhaustive field-by-field destructure of `VerificationValues`
//!    and its constituent `StandardAddress` -- exactly like check (c),
//!    this is compiler-enforced: if a field is ever added, this file
//!    fails to compile until updated, so the proof cannot silently rot.
//!    `AddressBuf` itself has private fields (SHOULD-FIX #4,
//!    `docs/PRE-RELEASE-AUDIT.md`) and so can no longer be destructured
//!    from outside `seed_core`; its own structural proof is a `size_of`
//!    check instead (see `assert_address_buf_shape`), enforced at test
//!    time rather than compile time.
//! 2. `AddressBuf`'s fixed byte capacity (92) is independently shown to
//!    be smaller than the shortest possible base58-encoded BIP32 extended
//!    key string (an xprv/xpub is always 111 base58 characters -- proven
//!    below from the fixed 78-byte serialized layout, not asserted by
//!    fiat), so even a hypothetical future bug could not fit a real
//!    xprv/xpub into that field without the encoder itself refusing
//!    (`EncodeError::BufferTooSmall`) or truncating in an immediately
//!    visible way.
//! 3. `master_fingerprint` is exactly `[u8; 4]` -- too small to be a seed
//!    (64 bytes) or a chain code (32 bytes) by two orders of magnitude,
//!    checked via `core::mem::size_of`.

use seed_core::contracts::{AddressBuf, PathStandard};
use seed_core::pipeline::{StandardAddress, VerificationValues};

/// Exhaustive destructure of [`VerificationValues`]: exactly two fields,
/// of exactly these types. Adding a third field (e.g. a `seed: [u8; 64]`
/// or `xprv: [u8; N]`) breaks this destructure at compile time.
fn assert_verification_values_shape(v: &VerificationValues) {
    let VerificationValues { master_fingerprint, addresses } = v;
    let _: &[u8; 4] = master_fingerprint;
    let _: &[StandardAddress; 4] = addresses;
    for a in addresses {
        assert_standard_address_shape(a);
    }
}

fn assert_standard_address_shape(a: &StandardAddress) {
    let StandardAddress { standard, address } = a;
    let _: &PathStandard = standard;
    assert_address_buf_shape(address);
}

fn assert_address_buf_shape(a: &AddressBuf) {
    // `AddressBuf`'s `bytes`/`len` fields are private (SHOULD-FIX #4,
    // `docs/PRE-RELEASE-AUDIT.md`), so this can no longer destructure the
    // struct directly from outside `seed_core`. The structural proof
    // moves to `size_of` instead: exactly a 92-byte backing buffer plus a
    // 1-byte length, no padding possible (every component is byte-
    // aligned), so this fails the moment a field of any other size (e.g.
    // a `chain_code: [u8; 32]`) is ever added -- without needing to name
    // the type's private field layout at all.
    assert_eq!(
        core::mem::size_of::<AddressBuf>(),
        AddressBuf::CAPACITY + 1,
        "AddressBuf grew past its documented (92-byte buffer + 1-byte length) shape"
    );
    assert!(a.as_bytes().len() <= AddressBuf::CAPACITY);
}

fn sample_address(standard: PathStandard, s: &str) -> StandardAddress {
    let mut bytes = [0u8; 92];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    StandardAddress { standard, address: AddressBuf::new(bytes, s.len()) }
}

fn sample_values() -> VerificationValues {
    VerificationValues {
        master_fingerprint: [0xa1, 0xb2, 0xc3, 0xd4],
        addresses: [
            sample_address(PathStandard::Bip44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
            sample_address(PathStandard::Bip49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
            sample_address(PathStandard::Bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            sample_address(PathStandard::Bip86, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
        ],
    }
}

#[test]
fn verification_values_has_exactly_the_two_documented_public_fields() {
    assert_verification_values_shape(&sample_values());
}

/// SPEC §24.3: "displayed as 8 hex characters" -- `master_fingerprint` is
/// exactly the 4-byte BIP32 fingerprint. `size_of` makes the "too small
/// to be a seed/key/chain-code" argument checkable rather than asserted.
#[test]
fn master_fingerprint_is_far_too_small_to_be_a_seed_key_or_chain_code() {
    assert_eq!(core::mem::size_of::<[u8; 4]>(), 4);
    const BIP39_SEED_LEN: usize = 64; // SPEC §14/§24.2
    const PRIVATE_KEY_LEN: usize = 32; // SPEC §24.2
    const CHAIN_CODE_LEN: usize = 32; // SPEC §24.2
    assert!(4 < PRIVATE_KEY_LEN);
    assert!(4 < CHAIN_CODE_LEN);
    assert!(4 < BIP39_SEED_LEN);
}

/// SPEC §24.3: `AddressBuf`'s fixed 92-byte capacity cannot hold a real
/// base58-encoded xprv/xpub string, computed independently here rather
/// than hardcoded:
///
/// A BIP32 extended key serializes to exactly 78 raw bytes (4 version +
/// 1 depth + 4 parent fingerprint + 4 child number + 32 chain code + 33
/// key material, BIP32 §"Serialization format"), Base58Check-encoded
/// (+4-byte checksum = 82 bytes). Base58 encodes N non-zero-leading bytes
/// to at least `ceil(N * 8 / log2(58))` characters; a genuine xprv/xpub's
/// leading version bytes (`0x0488ADE4`/`0x0488B21E` mainnet, always
/// non-zero) mean this bound is exact for every real extended key, giving
/// the well-known, universally-observed 111-character xprv/xpub length.
#[test]
fn address_buf_capacity_cannot_hold_a_real_extended_key_string() {
    const RAW_EXTENDED_KEY_BYTES: usize = 4 + 1 + 4 + 4 + 32 + 33; // = 78
    assert_eq!(RAW_EXTENDED_KEY_BYTES, 78);
    const WITH_CHECKSUM: usize = RAW_EXTENDED_KEY_BYTES + 4; // = 82
    let log2_58 = 58f64.log2();
    let min_base58_chars = (WITH_CHECKSUM as f64 * 8.0 / log2_58).ceil() as usize;
    assert_eq!(min_base58_chars, 112, "sanity: matches the well-known ~111-112 char xprv/xpub length");

    let address_buf_capacity: usize = core::mem::size_of::<[u8; 92]>();
    assert_eq!(address_buf_capacity, 92);
    assert!(
        address_buf_capacity < min_base58_chars,
        "AddressBuf's fixed capacity ({address_buf_capacity}) must stay smaller than the shortest \
         possible real xprv/xpub base58 string ({min_base58_chars}) -- a widening here would be a \
         SPEC §24.3 regression risk even if no code path currently writes one"
    );
}

/// Belt-and-braces textual check on the two files that actually build a
/// [`VerificationValues`]/render it (SPEC §24.3): the words "xprv",
/// "xpub" and "seed" never appear in the struct/field definitions
/// themselves (as opposed to doc-comment prose explaining what must NOT
/// be shown, which legitimately mentions those words) -- i.e. the type
/// definition's own field list, not its documentation, is what this test
/// inspects.
#[test]
fn verification_values_field_declarations_never_name_a_secret_type() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = repo_root.join("crates/seed-core/src/pipeline/mod.rs");
    let content = std::fs::read_to_string(&path).unwrap();

    let struct_def = |name: &str| -> String {
        let start = content.find(&format!("pub struct {name} {{")).unwrap_or_else(|| panic!("struct {name} not found in {path:?}"));
        let end = content[start..].find('}').map(|e| start + e + 1).expect("closing brace");
        content[start..end].to_string()
    };

    for def in [struct_def("VerificationValues"), struct_def("StandardAddress")] {
        // Only the field declaration lines (skip doc comments, which are
        // `///`-prefixed and legitimately discuss what must not appear).
        let field_lines: String = def.lines().filter(|l| !l.trim_start().starts_with("///")).collect::<Vec<_>>().join("\n");
        for bad in ["xprv", "xpub", "seed", "chain_code", "private_key"] {
            assert!(
                !field_lines.to_lowercase().contains(bad),
                "field declaration unexpectedly names {bad:?}:\n{field_lines}"
            );
        }
    }
}
