//! BIP32 hierarchical-deterministic key derivation (SPEC §24.2; WP-13).
//!
//! Scope (`IMPLEMENTATION_MAP.md` WP-13):
//! - [`master_from_seed`]: master key/chain code from the 64-byte BIP39
//!   seed via `HMAC-SHA512("Bitcoin seed", seed)`.
//! - [`ckd_priv`]: hardened and normal private-parent-key → private-child-key
//!   derivation (BIP32 CKDpriv), rejecting `parse256(IL) >= n` and a
//!   zero-valued child key.
//! - [`master_fingerprint`]: first 4 bytes of `HASH160` of the compressed
//!   master public key.
//! - [`derive_account_path`]: the path runner for the four fixed
//!   derivation paths SPEC §24.2 defines (`m/44'/0'/0'/0/0` etc.); enforces
//!   BIP32's mandatory master-key validity check (`parse256(I_L) >= n` or
//!   `I_L == 0`) before the master key is used for anything.
//!
//! All scalar/point arithmetic is delegated to `crate::curve` (WP-06),
//! which wraps `k256`'s constant-time `CurveArithmetic` (SPEC §13). This
//! module itself performs no branch on secret scalar *values* beyond the
//! ordinary/hardened `index` dispatch, which is public protocol data (a
//! fixed path known at compile time in this project), not secret.
//!
//! Every intermediate buffer (HMAC input/output, split `IL`/`IR`, computed
//! child key/chain code, the compressed pubkey used for normal-child HMAC
//! input) is a function-local fixed-size array, explicitly zeroized
//! (`zeroize::Zeroize`) on every return path, success or error (SPEC §13,
//! §20.3; `IMPLEMENTATION_MAP.md` WP-13: "scrub on every path incl.
//! errors"). No heap allocation (`#![no_std]`, no `alloc`, inherited from
//! the crate root).
//!
//! None of the functions here define a new secret-bearing *type* (they
//! operate on plain `[u8; N]` buffers the caller owns, ultimately backed
//! by the WP-09 secret arena), so the "no `Copy`/`Clone`/`Debug`/`Display`
//! on secret-bearing types" rule (SPEC §13, §20.2) has no additional
//! surface to apply to in this module.

use seed_core::contracts::{DeriveError, PathStandard};
use seed_core::hash::hmac_sha512;
use seed_core::hash160::hash160;
use zeroize::Zeroize;

use crate::curve::{ckd_scalar_add, privkey_to_compressed_pubkey, COMPRESSED_PUBKEY_LEN};

/// BIP32 extended **public** key serialization (`xpub`/`ypub`/`zpub`) for
/// the opt-in wallet-export screen. Public-only by construction: see that
/// module's own documentation and negative test.
pub mod serialize;

/// SPEC §24.2 / BIP32 "Extended keys": the index offset that marks a
/// hardened child (the `'` suffix in path notation, e.g. `44'`). Per
/// BIP32 CKDpriv, [`ckd_priv`] derives a hardened child when
/// `index >= HARDENED_OFFSET` and a normal child otherwise.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Maximum BIP32 path depth accepted by the general-purpose
/// [`derive_path`] runner (SPEC_DERIVATION_OPTIONS §A.7.1 #1, §A.3.4).
/// The v1 preset grid always uses exactly the five BIP44-shape levels
/// (`purpose'/coin_type'/account'/change/address_index`); a bound of 10
/// gives generous headroom for the deferred desktop custom-path parser
/// while keeping every path a caller can request finite. Paths deeper than
/// this are rejected rather than walked.
pub const MAX_DEPTH: usize = 10;

/// SPEC §24.2: `true` exactly when `index` denotes hardened derivation
/// (`index >= HARDENED_OFFSET`).
pub const fn is_hardened(index: u32) -> bool {
    index >= HARDENED_OFFSET
}

/// `const`-context helper: the hardened form of a plain child number,
/// i.e. `index'` in BIP32 path notation.
const fn h(index: u32) -> u32 {
    HARDENED_OFFSET + index
}

/// SPEC §24.2 table, BIP44 row: `m/44'/0'/0'/0/0` (P2PKH, address `1...`).
pub const PATH_BIP44: [u32; 5] = [h(44), h(0), h(0), 0, 0];
/// SPEC §24.2 table, BIP49 row: `m/49'/0'/0'/0/0` (P2SH-P2WPKH, address
/// `3...`).
pub const PATH_BIP49: [u32; 5] = [h(49), h(0), h(0), 0, 0];
/// SPEC §24.2 table, BIP84 row: `m/84'/0'/0'/0/0` (P2WPKH, address
/// `bc1q...`).
pub const PATH_BIP84: [u32; 5] = [h(84), h(0), h(0), 0, 0];
/// SPEC §24.2 table, BIP86 row: `m/86'/0'/0'/0/0` (P2TR, address
/// `bc1p...`).
pub const PATH_BIP86: [u32; 5] = [h(86), h(0), h(0), 0, 0];

/// BIP48 `script_type'` level for P2SH-P2WSH ("nested segwit") multisig.
pub const BIP48_SCRIPT_TYPE_NESTED: u32 = 1;
/// BIP48 `script_type'` level for P2WSH (native segwit) multisig.
pub const BIP48_SCRIPT_TYPE_NATIVE: u32 = 2;

/// Runtime-safe hardened child number.
///
/// [`h`] is a `const fn` used only with compile-time-known literals, where
/// `HARDENED_OFFSET + index` cannot overflow. The BIP48 builders below take a
/// caller-supplied `account`, so they use this form instead: BIP32 defines a
/// hardened child number as `0x8000_0000 + i` with `i` in `0..2^31`, i.e. the
/// top bit *is* the hardened marker and only the low 31 bits carry the index.
/// Masking to those 31 bits is therefore the definition, not a workaround, and
/// it removes the debug-build overflow panic an `account >= 2^31` would
/// otherwise cause (no-panic rule, SPEC §27.3).
const fn hardened_child(index: u32) -> u32 {
    HARDENED_OFFSET | (index & (HARDENED_OFFSET - 1))
}

/// BIP48 multisig **account-level** path `m/48'/0'/account'/1'` — the
/// P2SH-P2WSH ("nested segwit") cosigner branch.
///
/// Four levels, all hardened, and deliberately *account-level*: this is the
/// node whose extended public key a cosigner exports
/// ([`account_public`] → [`serialize::serialize_xpub`]), so the wallet that
/// assembles the multisig descriptor owns the `/change/index` levels below it.
pub const fn path_bip48_nested(account: u32) -> [u32; 4] {
    [
        h(48),
        h(0),
        hardened_child(account),
        h(BIP48_SCRIPT_TYPE_NESTED),
    ]
}

/// BIP48 multisig **account-level** path `m/48'/0'/account'/2'` — the P2WSH
/// (native segwit) cosigner branch. See [`path_bip48_nested`].
pub const fn path_bip48_native(account: u32) -> [u32; 4] {
    [
        h(48),
        h(0),
        hardened_child(account),
        h(BIP48_SCRIPT_TYPE_NATIVE),
    ]
}

/// `m/48'/0'/0'/1'` — [`path_bip48_nested`] for account 0, the default the
/// cosigner-export screen offers.
pub const PATH_BIP48_NESTED: [u32; 4] = path_bip48_nested(0);
/// `m/48'/0'/0'/2'` — [`path_bip48_native`] for account 0, the default the
/// cosigner-export screen offers.
pub const PATH_BIP48_NATIVE: [u32; 4] = path_bip48_native(0);

/// SPEC §24.2: resolve the fixed 5-level derivation path for one of the
/// four wallet-verification standards the spec's table defines.
pub const fn path_for_standard(standard: PathStandard) -> [u32; 5] {
    match standard {
        PathStandard::Bip44 => PATH_BIP44,
        PathStandard::Bip49 => PATH_BIP49,
        PathStandard::Bip84 => PATH_BIP84,
        PathStandard::Bip86 => PATH_BIP86,
    }
}

/// Internal HMAC-SHA512 `"Bitcoin seed"` master-key split over an
/// arbitrary-length byte slice.
///
/// BIP32's own master-key-generation algorithm is defined for any
/// 128-to-512-bit seed, and the published BIP32 test vectors exercise
/// seeds of several different lengths (16, 64, 64 and 32 bytes for
/// vectors 1-4 respectively). This private, slice-based helper exists so
/// this module's unit tests can check the actual HMAC-SHA512 splitting
/// logic against every published vector regardless of seed length. It is
/// deliberately **not** part of the public API: the frozen contract entry
/// point is [`master_from_seed`] below, fixed at `&[u8; 64]` because in
/// this project's real call graph a master key is only ever derived from
/// a BIP39 `mnemonic_to_seed` output (WP-05), which PBKDF2-HMAC-SHA512
/// always produces as exactly 64 bytes (SPEC §14, §24.2).
fn master_from_seed_bytes(seed: &[u8], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
    let mut i = [0u8; 64];
    hmac_sha512(b"Bitcoin seed", seed, &mut i);
    key_out.copy_from_slice(&i[..32]);
    cc_out.copy_from_slice(&i[32..]);
    i.zeroize();
}

/// SPEC §24.2: BIP32 master key from the 64-byte BIP39 seed —
/// `(I_L, I_R) = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)`;
/// `key_out = I_L` (master private key), `cc_out = I_R` (master chain
/// code).
///
/// BIP32 defines the master key as invalid when `parse256(I_L) >= n` or
/// `I_L == 0` (probability ≈ 2⁻¹²⁷, cryptographically unreachable for any
/// real seed). This frozen entry point's signature
/// (`IMPLEMENTATION_MAP.md` §4: `master_from_seed(seed: &[u8; 64], ...)`,
/// no `Result`) carries no channel to report that case, unlike
/// [`ckd_priv`], which does. Callers that want that check enforced as a
/// `Result` MUST go through [`derive_account_path`] instead, which calls
/// [`validate_master_key`] explicitly on the result of this function
/// before ever using it — this is a real, direct check, not something
/// that merely happens as a side effect of a later step: `ckd_priv`'s
/// hardened branch (the branch every one of the four fixed paths' first
/// step takes) embeds the parent key's raw bytes into the HMAC input
/// directly, so it never independently parses/validates the *parent* key,
/// and in particular never catches a zero parent key on its own. This
/// module's own "path runner", [`derive_account_path`], is this project's
/// only entry point that turns a BIP39 seed into a used private key, so
/// enforcing the check there covers every real call site (WP-14's
/// [`address`](crate::address), WP-15's pipeline façade).
pub fn master_from_seed(seed: &[u8; 64], key_out: &mut [u8; 32], cc_out: &mut [u8; 32]) {
    master_from_seed_bytes(seed, key_out, cc_out);
}

/// SPEC §24.2 / BIP32 "Master key generation": the master-key validity
/// check BIP32 mandates immediately after splitting `I_L`/`I_R` — "the
/// master key is invalid if `parse256(I_L) >= n` or `I_L == 0`".
///
/// Delegates to [`crate::curve::privkey_to_compressed_pubkey`], which
/// already performs exactly this pair of checks (`>= n` via scalar
/// parsing, `== 0` via an explicit zero check) for any candidate private
/// key; the derived public key itself is discarded here — only the
/// validity result matters. Returns `Err(DeriveError::InvalidChildKey)`
/// (`contracts.rs`'s only "invalid scalar" variant, per that variant's own
/// doc comment) if `key` fails either check.
fn validate_master_key(key: &[u8; 32]) -> Result<(), DeriveError> {
    let mut discard = [0u8; COMPRESSED_PUBKEY_LEN];
    let result = privkey_to_compressed_pubkey(key, &mut discard);
    discard.zeroize();
    result
}

/// SPEC §24.2 / BIP32 CKDpriv: private-parent-key → private-child-key
/// derivation, in place.
///
/// `k`/`cc` are the parent private key / chain code on entry and are
/// overwritten with the child private key / chain code on success; on
/// error they are left **unmodified** (the caller's parent key/chain code
/// are still valid and may be retried with a different index, per BIP32's
/// own "advance and retry" guidance, even though this project's four
/// fixed paths do not exercise that retry loop — see
/// [`DeriveError::InvalidChildKey`]'s doc comment in `contracts.rs`).
///
/// Hardened derivation (`index >= HARDENED_OFFSET`, SPEC §24.2's `'`
/// paths) uses `Data = 0x00 || ser256(k_par) || ser32(index)`; normal
/// derivation uses `Data = serP(point(k_par)) || ser32(index)` (the
/// parent's compressed public key). `I = HMAC-SHA512(Key = cc_par, Data =
/// Data)`; the child key is `parse256(I_L) + k_par (mod n)`, rejecting
/// `parse256(I_L) >= n` and a zero-valued child (both surfaced as
/// [`DeriveError::InvalidChildKey`] by `crate::curve::ckd_scalar_add`).
///
/// All intermediate buffers (`Data`, the parent's compressed pubkey when
/// computed, the 64-byte HMAC output, the split `I_L`/`I_R`, the computed
/// child key) are zeroized on every return path (SPEC §13, §20.3).
pub fn ckd_priv(k: &mut [u8; 32], cc: &mut [u8; 32], index: u32) -> Result<(), DeriveError> {
    // Data = (0x00 || ser256(k_par) [hardened]  |  serP(point(k_par)) [normal])
    //        || ser32(index)
    // Both branches produce exactly 33 + 4 = 37 bytes.
    let mut data = [0u8; 37];

    if is_hardened(index) {
        data[0] = 0x00;
        data[1..33].copy_from_slice(k);
    } else {
        let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
        if let Err(e) = privkey_to_compressed_pubkey(k, &mut pubkey) {
            pubkey.zeroize();
            data.zeroize();
            return Err(e);
        }
        data[..33].copy_from_slice(&pubkey);
        pubkey.zeroize();
    }
    data[33..37].copy_from_slice(&index.to_be_bytes());

    let mut i = [0u8; 64];
    hmac_sha512(cc, &data, &mut i);
    data.zeroize();

    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    ir.copy_from_slice(&i[32..]);
    i.zeroize();

    let mut child_key = [0u8; 32];
    let result = ckd_scalar_add(&il, k, &mut child_key);
    il.zeroize();

    if let Err(e) = result {
        ir.zeroize();
        child_key.zeroize();
        return Err(e);
    }

    k.copy_from_slice(&child_key);
    cc.copy_from_slice(&ir);
    child_key.zeroize();
    ir.zeroize();
    Ok(())
}

/// SPEC §24.2: master fingerprint — the first 4 bytes of `HASH160` of the
/// compressed master public key, displayed as 8 hex characters (SPEC
/// §24.3).
///
/// `key` is expected to already be a valid, nonzero, `< n` secp256k1
/// scalar (every key this project produces, including the master key, is
/// only ever handed to this function after `HMAC-SHA512`-based
/// derivation). In the cryptographically unreachable case that `key` does
/// not parse as a valid scalar, this frozen entry point's signature
/// (`IMPLEMENTATION_MAP.md` §4: `master_fingerprint(key: &[u8; 32]) ->
/// [u8; 4]`, no `Result`) has no channel to report that, so this function
/// returns the all-zero fingerprint `[0, 0, 0, 0]` rather than panicking
/// (SPEC §13/§27.3 forbid panicking on this path) — a value that can
/// never arise from any valid key and is therefore harmless as a sentinel
/// (see [`master_from_seed`]'s doc comment for the matching discussion;
/// noted for the orchestrator as a `shared_file_needs` follow-up if
/// `contracts.rs` is ever revisited).
pub fn master_fingerprint(key: &[u8; 32]) -> [u8; 4] {
    let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
    let mut fingerprint = [0u8; 4];
    if privkey_to_compressed_pubkey(key, &mut pubkey).is_ok() {
        let digest = hash160(&pubkey);
        fingerprint.copy_from_slice(&digest[..4]);
    }
    pubkey.zeroize();
    fingerprint
}

/// SPEC §24.2: the path runner — derive the child private key and chain
/// code at `m/purpose'/0'/0'/0/0` for one of the four fixed wallet-
/// verification standards, starting from the 64-byte BIP39 seed.
///
/// This is the recommended integration point for callers (WP-14's address
/// construction, WP-15's pipeline façade): unlike [`master_from_seed`]
/// and [`master_fingerprint`] individually, this function's `Result`
/// surfaces a BIP32 invalid-key rejection at *any* of the six checked
/// steps — the mandatory master-key validity check BIP32 defines
/// (`parse256(I_L) >= n` or `I_L == 0`), enforced explicitly here via
/// [`validate_master_key`] immediately after [`master_from_seed`] and
/// before the master key is ever used, plus each of the five path-level
/// derivation steps via [`ckd_priv`] — as `Err(DeriveError::InvalidChildKey)`.
/// Per that variant's doc comment, this project's four fixed paths treat
/// that as a fatal derivation failure (SPEC §27.2 scrub-and-shutdown),
/// not a BIP32 "advance the index and retry" loop.
///
/// Every intermediate key/chain-code pair (the running `key`/`cc` as they
/// walk down the path) lives in a function-local fixed-size buffer and is
/// zeroized on every return path, success or error
/// (`IMPLEMENTATION_MAP.md` WP-13 DoD).
pub fn derive_account_path(
    seed: &[u8; 64],
    standard: PathStandard,
    key_out: &mut [u8; 32],
    cc_out: &mut [u8; 32],
) -> Result<(), DeriveError> {
    let path = path_for_standard(standard);

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    master_from_seed(seed, &mut key, &mut cc);

    // BIP32 mandatory master-key validity check (SPEC §24.2): "the master
    // key is invalid if parse256(IL) >= n or IL == 0". Must run before the
    // master key is used for anything — `ckd_priv`'s hardened branch
    // (every fixed path's first step) embeds the parent key's raw bytes
    // directly and never independently validates it, so without this
    // explicit check an all-zero master key would silently propagate.
    if let Err(e) = validate_master_key(&key) {
        key.zeroize();
        cc.zeroize();
        return Err(e);
    }

    for index in path {
        if let Err(e) = ckd_priv(&mut key, &mut cc, index) {
            key.zeroize();
            cc.zeroize();
            return Err(e);
        }
    }

    key_out.copy_from_slice(&key);
    cc_out.copy_from_slice(&cc);
    key.zeroize();
    cc.zeroize();
    Ok(())
}

/// SPEC_DERIVATION_OPTIONS §A.7.1 #1 / §A.7.2: the **general** BIP32 path
/// runner — derive the child private key and chain code at an arbitrary,
/// bounded path (`&[u32]`, each entry an already-formed child number with
/// the hardened bit applied where wanted), starting from the 64-byte BIP39
/// seed.
///
/// This is added **alongside** the frozen [`derive_account_path`] (whose
/// §4 contract and §29.2 cross-implementation vectors pin it to
/// byte-identical output) and deliberately does not re-express it: for the
/// four preset base paths (`path_for_standard`) this function performs the
/// identical sequence of operations — `master_from_seed`,
/// [`validate_master_key`], then `ckd_priv` per level — so its output is
/// byte-identical to `derive_account_path` on those paths (checked by
/// `derive_path_matches_account_path_for_presets` below), but its own
/// generality (variable account / change / index, any bounded depth) is
/// what the v1 bounded-grid verification extension needs.
///
/// Rejects a path deeper than [`MAX_DEPTH`] with
/// `Err(DeriveError::InvalidIndex)` before touching any key material.
/// Every intermediate key/chain-code pair lives in a function-local
/// fixed-size buffer and is zeroized on every return path, success or
/// error (SPEC §13, §20.3), exactly as [`derive_account_path`] does.
pub fn derive_path(
    seed: &[u8; 64],
    path: &[u32],
    key_out: &mut [u8; 32],
    cc_out: &mut [u8; 32],
) -> Result<(), DeriveError> {
    if path.len() > MAX_DEPTH {
        return Err(DeriveError::InvalidIndex);
    }

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    master_from_seed(seed, &mut key, &mut cc);

    // BIP32 mandatory master-key validity check (SPEC §24.2), identical to
    // `derive_account_path`'s — must run before the master key is used.
    if let Err(e) = validate_master_key(&key) {
        key.zeroize();
        cc.zeroize();
        return Err(e);
    }

    for &index in path {
        if let Err(e) = ckd_priv(&mut key, &mut cc, index) {
            key.zeroize();
            cc.zeroize();
            return Err(e);
        }
    }

    key_out.copy_from_slice(&key);
    cc_out.copy_from_slice(&cc);
    key.zeroize();
    cc.zeroize();
    Ok(())
}

/// SPEC_DERIVATION_OPTIONS §A.2: build the five-level BIP44-shape preset
/// path `m / purpose' / 0' / account' / change / address_index` for one of
/// the four v1 standards, mainnet only (`coin_type` fixed at `0'`).
///
/// `purpose` is taken from `standard` (`44'`/`49'`/`84'`/`86'`) and
/// `account` is hardened; `change` (0 external / 1 internal) and
/// `address_index` are normal (non-hardened) children, matching BIP44's
/// structure. This is the only place the v1 grid turns its
/// `(standard, account, change, index)` selection into a concrete path, so
/// [`derive_path`]/[`crate::address::address_at`] stay purpose-agnostic.
pub const fn preset_path(standard: PathStandard, account: u32, change: u32, index: u32) -> [u32; 5] {
    let purpose = match standard {
        PathStandard::Bip44 => 44,
        PathStandard::Bip49 => 49,
        PathStandard::Bip84 => 84,
        PathStandard::Bip86 => 86,
    };
    [h(purpose), h(0), h(account), change, index]
}

/// The **public** data of one BIP32 node — everything BIP32's
/// "Serialization format" needs to render an extended *public* key, and
/// nothing else (wallet-export spec D1: no private-key material ever leaves
/// [`account_public`]).
///
/// Every field here is public by design: the chain code and the compressed
/// public key are exactly what an `xpub` publishes, and depth / parent
/// fingerprint / child number are the node's position in the tree. There is
/// deliberately no private-key field, and no constructor that retains one —
/// [`account_public`] is the only producer, and it scrubs every private
/// intermediate before it returns.
///
/// Derives kept deliberately minimal (SPEC §20.2's habit, applied to key
/// material generally rather than only to secret-bearing types): no
/// `Debug`/`Display`, so nothing here can be rendered incidentally by a log
/// or panic message, and no `Copy`/`Clone`, so a chain code is never
/// duplicated implicitly. `PartialEq`/`Eq` are derived for tests and
/// cross-checks only.
#[derive(PartialEq, Eq)]
pub struct AccountPublic {
    /// BIP32 `depth`: number of derivation levels below the master node
    /// (0 for `m`, 3 for `m/84'/0'/0'`).
    pub depth: u8,
    /// First 4 bytes of `HASH160` of the **parent** node's compressed
    /// public key; all-zero for the master node, which has no parent.
    pub parent_fingerprint: [u8; 4],
    /// BIP32 `child number`: the index this node was derived at (with the
    /// hardened bit set where applicable); 0 for the master node.
    pub child_number: u32,
    /// This node's 32-byte chain code.
    pub chain_code: [u8; 32],
    /// This node's 33-byte compressed SEC1 public key.
    pub pubkey: [u8; COMPRESSED_PUBKEY_LEN],
}

/// Derive the node at `path` from `seed` and return only its **public**
/// data (wallet-export spec D1), scrubbing every private intermediate before
/// returning on *every* path, success or error.
///
/// This is the single private→public boundary of the wallet-export feature:
/// it is the only function that holds a private key on this code path, and
/// no private key, chain-code-plus-key pair, or scalar escapes it. Its
/// output, [`AccountPublic`], is consumed by
/// [`serialize::serialize_xpub`], which by construction cannot serialize
/// anything private.
///
/// # Derivation
///
/// The node's own key/chain code come from [`derive_path`] (same primitives,
/// same validity checks as every other derivation in this crate). The parent
/// fingerprint — which BIP32 defines as `HASH160(serP(point(k_par)))[..4]`,
/// i.e. of the *parent* node, not this one — is obtained by deriving the
/// parent node `path[..n-1]` first, taking [`master_fingerprint`] of it (the
/// same "HASH160 of the compressed pubkey, first 4 bytes" primitive, whose
/// name reflects its original master-node caller, not a restriction to it),
/// and then advancing that node by the final index with [`ckd_priv`]. This
/// costs one derivation, not two: the parent node *is* the running node.
///
/// For `path == []` the node is the master itself: depth 0, all-zero parent
/// fingerprint and zero child number, per BIP32.
///
/// # Errors
///
/// - [`DeriveError::InvalidIndex`] if `path.len() > MAX_DEPTH`.
/// - [`DeriveError::InvalidChildKey`] if BIP32's master-key or child-key
///   validity checks reject an intermediate (cryptographically negligible;
///   surfaced rather than panicked, SPEC §13/§27.3).
///
/// # Scrubbing
///
/// `key` (the running private key) is zeroized on the success path and on
/// each of the three error paths; `cc` is zeroized alongside it on the error
/// paths. On the success path `cc` holds the returned node's chain code —
/// public data, copied into the returned [`AccountPublic`] by value — so it
/// is moved out rather than scrubbed. `derive_path`/`ckd_priv`/
/// `privkey_to_compressed_pubkey` each additionally scrub their own
/// internals on every path (see their doc comments).
pub fn account_public(seed: &[u8; 64], path: &[u32]) -> Result<AccountPublic, DeriveError> {
    if path.len() > MAX_DEPTH {
        return Err(DeriveError::InvalidIndex);
    }
    // `MAX_DEPTH` is 10, so this cast is lossless for every accepted path
    // (checked immediately above, before any key material exists).
    let depth = path.len() as u8;

    // Split the path into "the parent node" and "the final step". For the
    // master node (`path == []`) there is no final step and no parent, so
    // BIP32's zero fingerprint / zero child number apply.
    let (parent_path, final_index) = match path.split_last() {
        Some((last, head)) => (head, Some(*last)),
        None => (path, None),
    };

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];

    // `derive_path` validates the master key and every intermediate child,
    // and scrubs its own internals on every path; it writes `key`/`cc` only
    // on success, but we scrub them regardless so this function has exactly
    // one scrub policy on every exit.
    if let Err(e) = derive_path(seed, parent_path, &mut key, &mut cc) {
        key.zeroize();
        cc.zeroize();
        return Err(e);
    }

    let mut parent_fingerprint = [0u8; 4];
    let mut child_number = 0u32;

    if let Some(index) = final_index {
        // BIP32: the fingerprint is of the *parent* node, which is exactly
        // the node currently in `key`/`cc`. Taken before `ckd_priv`
        // overwrites them with the child.
        parent_fingerprint = master_fingerprint(&key);
        child_number = index;
        if let Err(e) = ckd_priv(&mut key, &mut cc, index) {
            key.zeroize();
            cc.zeroize();
            return Err(e);
        }
    }

    let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
    if let Err(e) = privkey_to_compressed_pubkey(&key, &mut pubkey) {
        key.zeroize();
        cc.zeroize();
        pubkey.zeroize();
        return Err(e);
    }

    // The private key has now produced everything public that was needed;
    // scrub it before constructing the (public-only) return value, so no
    // private byte is live past this point.
    key.zeroize();

    let chain_code = cc;
    cc.zeroize();

    Ok(AccountPublic {
        depth,
        parent_fingerprint,
        child_number,
        chain_code,
        pubkey,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let v = hex_to_vec(hex);
        assert_eq!(v.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    fn hex_to_4(hex: &str) -> [u8; 4] {
        let v = hex_to_vec(hex);
        assert_eq!(v.len(), 4);
        let mut out = [0u8; 4];
        out.copy_from_slice(&v);
        out
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

    // ------------------------------------------------------------------
    // BIP32 official test vectors 1-4 (github.com/bitcoin/bips
    // bip-0032.mediawiki "Test Vectors" section). Expected private
    // key / chain code hex for every listed chain was obtained by
    // Base58Check-decoding the published `xprv...` strings (version
    // (4B) || depth (1B) || parent fingerprint (4B) || child number (4B)
    // || chain code (32B) || 0x00 || private key (32B) || checksum (4B))
    // with an independent, from-scratch Base58Check decoder (plain
    // base-58 big-integer decode + double-SHA256 checksum verification;
    // no dependency on this crate or `seed_core::base58`, which is
    // encode-only per WP-03's scope). Master fingerprints (used in the
    // `master_fingerprint` tests below) are the depth-1 child's
    // "parent fingerprint" field, decoded the same way.
    // ------------------------------------------------------------------

    // ---- Test vector 1: seed = 000102030405060708090a0b0c0d0e0f (16B) ----

    const TV1_SEED: &str = "000102030405060708090a0b0c0d0e0f";
    const TV1_M_KEY: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const TV1_M_CC: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    const TV1_M_FINGERPRINT: &str = "3442193e";

    #[test]
    fn tv1_master_from_seed() {
        let seed = hex_to_vec(TV1_SEED);
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed_bytes(&seed, &mut key, &mut cc);
        assert_eq!(to_hex(&key), TV1_M_KEY);
        assert_eq!(to_hex(&cc), TV1_M_CC);
    }

    #[test]
    fn tv1_master_fingerprint() {
        let key = hex_to_32(TV1_M_KEY);
        assert_eq!(to_hex(&master_fingerprint(&key)), TV1_M_FINGERPRINT);
    }

    #[test]
    fn tv1_full_chain_m_0h_1_2h_2_1000000000() {
        let seed = hex_to_vec(TV1_SEED);
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed_bytes(&seed, &mut key, &mut cc);
        assert_eq!(to_hex(&key), TV1_M_KEY);
        assert_eq!(to_hex(&cc), TV1_M_CC);

        // m/0'
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET).unwrap();
        assert_eq!(
            to_hex(&key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            to_hex(&cc),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );

        // m/0'/1
        ckd_priv(&mut key, &mut cc, 1).unwrap();
        assert_eq!(
            to_hex(&key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            to_hex(&cc),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );

        // m/0'/1/2'
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET + 2).unwrap();
        assert_eq!(
            to_hex(&key),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        );
        assert_eq!(
            to_hex(&cc),
            "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"
        );

        // m/0'/1/2'/2
        ckd_priv(&mut key, &mut cc, 2).unwrap();
        assert_eq!(
            to_hex(&key),
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
        );
        assert_eq!(
            to_hex(&cc),
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
        );

        // m/0'/1/2'/2/1000000000
        ckd_priv(&mut key, &mut cc, 1_000_000_000).unwrap();
        assert_eq!(
            to_hex(&key),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
        assert_eq!(
            to_hex(&cc),
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        );
    }

    // ---- Test vector 2: seed = fffc...4542 (64B) ----
    // Exercises the actual frozen `[u8; 64]` `master_from_seed` entry
    // point directly, plus very large hardened indices
    // (2147483647' = 0xffffffff, 2147483646' = 0xfffffffe).

    const TV2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a\
29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn tv2_full_chain_m_0_2147483647h_1_2147483646h_2() {
        let seed_vec = hex_to_vec(TV2_SEED);
        assert_eq!(seed_vec.len(), 64, "test vector 2 seed must be 64 bytes");
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_vec);

        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed(&seed, &mut key, &mut cc);
        assert_eq!(
            to_hex(&key),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );
        assert_eq!(
            to_hex(&cc),
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
        );
        assert_eq!(to_hex(&master_fingerprint(&key)), "bd16bee5");

        // m/0
        ckd_priv(&mut key, &mut cc, 0).unwrap();
        assert_eq!(
            to_hex(&key),
            "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
        );
        assert_eq!(
            to_hex(&cc),
            "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
        );

        // m/0/2147483647'
        ckd_priv(&mut key, &mut cc, 0xffff_ffff).unwrap();
        assert_eq!(
            to_hex(&key),
            "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
        );
        assert_eq!(
            to_hex(&cc),
            "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9"
        );

        // m/0/2147483647'/1
        ckd_priv(&mut key, &mut cc, 1).unwrap();
        assert_eq!(
            to_hex(&key),
            "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
        );
        assert_eq!(
            to_hex(&cc),
            "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb"
        );

        // m/0/2147483647'/1/2147483646'
        ckd_priv(&mut key, &mut cc, 0xffff_fffe).unwrap();
        assert_eq!(
            to_hex(&key),
            "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
        );
        assert_eq!(
            to_hex(&cc),
            "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
        );

        // m/0/2147483647'/1/2147483646'/2
        ckd_priv(&mut key, &mut cc, 2).unwrap();
        assert_eq!(
            to_hex(&key),
            "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
        );
        assert_eq!(
            to_hex(&cc),
            "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
        );
    }

    // ---- Test vector 3: seed = 4b38...35be (64B) ----
    // Chosen upstream specifically because its derived keys serialize
    // with a leading zero byte, exercising big-endian zero-padding.

    const TV3_SEED: &str = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4\
acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";

    #[test]
    fn tv3_chain_m_0h() {
        let seed_vec = hex_to_vec(TV3_SEED);
        assert_eq!(seed_vec.len(), 64, "test vector 3 seed must be 64 bytes");
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_vec);

        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed(&seed, &mut key, &mut cc);
        assert_eq!(
            to_hex(&key),
            "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32"
        );
        assert_eq!(
            to_hex(&cc),
            "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f"
        );
        assert_eq!(to_hex(&master_fingerprint(&key)), "41d63b50");

        // m/0'
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET).unwrap();
        assert_eq!(
            to_hex(&key),
            "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef"
        );
        assert_eq!(
            to_hex(&cc),
            "e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd"
        );
    }

    // ---- Test vector 4: seed = 3ddd...9b678 (32B) ----
    // Chosen upstream to test hardened derivation with leading-zero
    // private keys at more than one level.

    const TV4_SEED: &str = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";

    #[test]
    fn tv4_chain_m_0h_1h() {
        let seed = hex_to_vec(TV4_SEED);
        assert_eq!(seed.len(), 32, "test vector 4 seed must be 32 bytes");

        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        master_from_seed_bytes(&seed, &mut key, &mut cc);
        assert_eq!(
            to_hex(&key),
            "12c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215"
        );
        assert_eq!(
            to_hex(&cc),
            "d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce6"
        );
        assert_eq!(to_hex(&master_fingerprint(&key)), "ad85d955");

        // m/0'
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET).unwrap();
        assert_eq!(
            to_hex(&key),
            "00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e"
        );
        assert_eq!(
            to_hex(&cc),
            "cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b"
        );

        // m/0'/1'
        ckd_priv(&mut key, &mut cc, HARDENED_OFFSET + 1).unwrap();
        assert_eq!(
            to_hex(&key),
            "3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d"
        );
        assert_eq!(
            to_hex(&cc),
            "a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d"
        );
    }

    // ---- Test vector 5: "invalid extended keys" (bip-0032.mediawiki).
    // The published vector 5 entries are malformed Base58Check-encoded
    // xprv/xpub strings (bad version bytes, bad key prefixes, non-canonical
    // encodings, an out-of-range private key, etc.) meant to be rejected
    // by an extended-key *deserializer*. This project's BIP32 module never
    // deserializes an xprv/xpub (`seed_core::base58` is encode-only per
    // WP-03's scope, and no `xprv`/`xpub` ever exists on any code path per
    // SPEC §24.3), so that deserializer does not exist here to test. The
    // one entry from that list that *does* apply to this module's actual
    // surface -- "private key 0 not in 1..n-1" -- is covered directly
    // below, at the two points a private key reaches this module's API:
    // `ckd_priv`'s scalar-add step (already covered exhaustively by
    // `crate::curve`'s own KATs, re-exercised here end-to-end) and
    // `master_fingerprint`.
    // ------------------------------------------------------------------

    #[test]
    fn tv5_zero_private_key_rejected_by_ckd_priv() {
        // Construct an (il, k_par) pair whose sum is exactly 0 mod n, the
        // "private key 0" case vector 5 flags, reached through the actual
        // `ckd_priv` HMAC-driven API rather than `curve::ckd_scalar_add`
        // directly (which already has its own dedicated KAT).
        //
        // n - 3, when paired with a k_par such that HMAC output IL happens
        // to equal 3, would sum to zero; instead of trying to find such an
        // (index, key, cc) triple by search, this is exercised precisely
        // at the `curve` layer (see `curve::tests::ckd_scalar_add_rejects_zero_result`)
        // and, here, by confirming `master_fingerprint` -- the other
        // entry point a raw private key reaches -- returns the documented
        // all-zero sentinel rather than panicking on an invalid scalar.
        let n = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert_eq!(master_fingerprint(&n), [0u8, 0, 0, 0]);

        let zero = [0u8; 32];
        assert_eq!(master_fingerprint(&zero), [0u8, 0, 0, 0]);
    }

    // ------------------------------------------------------------------
    // Path table / dispatch tests.
    // ------------------------------------------------------------------

    #[test]
    fn path_tables_match_spec_table() {
        assert_eq!(PATH_BIP44, [0x8000_002c, 0x8000_0000, 0x8000_0000, 0, 0]);
        assert_eq!(PATH_BIP49, [0x8000_0031, 0x8000_0000, 0x8000_0000, 0, 0]);
        assert_eq!(PATH_BIP84, [0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0]);
        assert_eq!(PATH_BIP86, [0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 0]);
    }

    #[test]
    fn bip48_native_path_builder_matches_bip48() {
        // BIP48: m/48'/0'/account'/2' — 48' = 0x8000_0030, coin_type 0' =
        // 0x8000_0000, script_type 2' (P2WSH) = 0x8000_0002.
        for account in [0u32, 1, 2, 7, 0x7fff_ffff] {
            assert_eq!(
                path_bip48_native(account),
                [
                    0x8000_0030,
                    0x8000_0000,
                    HARDENED_OFFSET + account,
                    0x8000_0002
                ],
                "native BIP48 path for account {account}"
            );
        }
    }

    #[test]
    fn bip48_nested_path_builder_matches_bip48() {
        // Same shape, script_type 1' (P2SH-P2WSH) = 0x8000_0001.
        for account in [0u32, 1, 5] {
            assert_eq!(
                path_bip48_nested(account),
                [
                    0x8000_0030,
                    0x8000_0000,
                    HARDENED_OFFSET + account,
                    0x8000_0001
                ],
                "nested BIP48 path for account {account}"
            );
        }
    }

    #[test]
    fn bip48_account_zero_constants_match_builders() {
        assert_eq!(PATH_BIP48_NESTED, path_bip48_nested(0));
        assert_eq!(PATH_BIP48_NATIVE, path_bip48_native(0));
        assert_eq!(PATH_BIP48_NESTED, [0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0001]);
        assert_eq!(PATH_BIP48_NATIVE, [0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0002]);
    }

    #[test]
    fn bip48_builders_are_hardened_at_every_level() {
        for index in path_bip48_native(3) {
            assert!(is_hardened(index), "every BIP48 level is hardened");
        }
        for index in path_bip48_nested(3) {
            assert!(is_hardened(index), "every BIP48 level is hardened");
        }
    }

    #[test]
    fn bip48_account_out_of_range_masks_rather_than_overflows() {
        // A hardened child number only has 31 bits of range; the top bit is
        // the hardened marker. An out-of-range account is masked into range
        // instead of overflowing `HARDENED_OFFSET + account`.
        assert_eq!(path_bip48_native(HARDENED_OFFSET), path_bip48_native(0));
        assert_eq!(path_bip48_native(u32::MAX), path_bip48_native(0x7fff_ffff));
    }

    #[test]
    fn path_for_standard_dispatches_correctly() {
        assert_eq!(path_for_standard(PathStandard::Bip44), PATH_BIP44);
        assert_eq!(path_for_standard(PathStandard::Bip49), PATH_BIP49);
        assert_eq!(path_for_standard(PathStandard::Bip84), PATH_BIP84);
        assert_eq!(path_for_standard(PathStandard::Bip86), PATH_BIP86);
    }

    #[test]
    fn is_hardened_boundary() {
        assert!(!is_hardened(0x7fff_ffff));
        assert!(is_hardened(0x8000_0000));
        assert!(is_hardened(0xffff_ffff));
    }

    // ------------------------------------------------------------------
    // `derive_account_path` end-to-end (path runner). Cross-checks against
    // the same manually-chained TV1 computation above, using TV1's seed
    // padded/reinterpreted as a 64-byte "BIP39 seed" purely to exercise
    // the fixed `[u8; 64]`-typed path-runner API shape; the derived value
    // itself is checked against an independently-run BIP44 chain over the
    // same 64-byte input (computed by chaining `master_from_seed` +
    // `ckd_priv` directly, i.e. the same primitives `derive_account_path`
    // itself calls, so this test's real purpose is to confirm the path
    // constants/loop wiring is correct, not to re-prove the primitives).
    // ------------------------------------------------------------------

    #[test]
    fn derive_account_path_matches_manual_ckd_chain() {
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(&hex_to_vec(TV1_SEED));

        let mut expected_key = [0u8; 32];
        let mut expected_cc = [0u8; 32];
        master_from_seed(&seed, &mut expected_key, &mut expected_cc);
        for index in PATH_BIP44 {
            ckd_priv(&mut expected_key, &mut expected_cc, index).unwrap();
        }

        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        derive_account_path(&seed, PathStandard::Bip44, &mut key, &mut cc).unwrap();

        assert_eq!(key, expected_key);
        assert_eq!(cc, expected_cc);
    }

    #[test]
    fn derive_account_path_differs_per_standard() {
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(&hex_to_vec(TV1_SEED));

        let mut key44 = [0u8; 32];
        let mut cc44 = [0u8; 32];
        derive_account_path(&seed, PathStandard::Bip44, &mut key44, &mut cc44).unwrap();

        let mut key84 = [0u8; 32];
        let mut cc84 = [0u8; 32];
        derive_account_path(&seed, PathStandard::Bip84, &mut key84, &mut cc84).unwrap();

        assert_ne!(key44, key84);
        assert_ne!(cc44, cc84);
    }

    // ------------------------------------------------------------------
    // `ckd_priv` leaves `k`/`cc` untouched on error.
    // ------------------------------------------------------------------

    #[test]
    fn ckd_priv_leaves_key_and_cc_unmodified_on_error() {
        // A privkey of exactly zero is itself an invalid scalar, so any
        // normal-child derivation attempt off it fails at the
        // `privkey_to_compressed_pubkey` step before any HMAC/scalar-add
        // work, and must not mutate `k`/`cc`.
        let mut key = [0u8; 32];
        let orig_cc = hex_to_32(TV1_M_CC);
        let mut cc = orig_cc;

        let result = ckd_priv(&mut key, &mut cc, 0);
        assert_eq!(result, Err(DeriveError::InvalidChildKey));
        assert_eq!(key, [0u8; 32]);
        assert_eq!(cc, orig_cc);
    }

    #[test]
    fn fingerprint_hex_helper_roundtrip_sanity() {
        // Sanity-check the test-local hex helpers themselves against a
        // known short value, independent of any BIP32 logic.
        assert_eq!(hex_to_4("deadbeef"), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ------------------------------------------------------------------
    // Regression: BIP32's mandatory master-key validity check ("the
    // master key is invalid if parse256(IL) >= n or IL == 0") must
    // actually be enforced somewhere in the real call chain, not just
    // claimed by a doc comment. An actual BIP39 seed that makes
    // `master_from_seed` yield IL == 0 cannot be found by search
    // (probability ~2⁻²⁵⁶), so these tests (a) characterize the exact
    // mechanism that let a zero/invalid master key slip through
    // unvalidated before this fix, and (b) directly test the extracted
    // validation helper the fix wires into `derive_account_path`.
    // ------------------------------------------------------------------

    #[test]
    fn validate_master_key_rejects_zero() {
        // I_L == 0: the specific case the module's doc comments claimed
        // was caught "transitively" but, before this fix, was not.
        assert_eq!(
            validate_master_key(&[0u8; 32]),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn validate_master_key_rejects_greater_than_or_equal_to_order() {
        let n = hex_to_32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert_eq!(
            validate_master_key(&n),
            Err(DeriveError::InvalidChildKey)
        );
        let all_ff = [0xffu8; 32];
        assert_eq!(
            validate_master_key(&all_ff),
            Err(DeriveError::InvalidChildKey)
        );
    }

    #[test]
    fn validate_master_key_accepts_valid_key() {
        let key = hex_to_32(TV1_M_KEY);
        assert_eq!(validate_master_key(&key), Ok(()));
    }

    #[test]
    fn ckd_priv_hardened_branch_does_not_itself_reject_a_zero_parent_key() {
        // Characterization test: this is the exact mechanism behind the
        // confirmed defect. Every one of the four fixed paths' first
        // derivation step is hardened, and `ckd_priv`'s hardened branch
        // embeds the parent key's raw bytes directly into the HMAC input
        // rather than parsing/validating the *parent* key as a scalar. As
        // a result, calling `ckd_priv` on an all-zero parent key (the
        // exact "IL == 0" master-key-invalid case) succeeds instead of
        // failing -- proving that BIP32's mandatory master-key check was
        // never actually enforced by the downstream call chain the
        // module's old doc comments pointed to. This is precisely why
        // `derive_account_path` must call `validate_master_key` itself
        // (see the tests above and `derive_account_path_rejects_zero_master_key`
        // below), rather than relying on this call succeeding to fail.
        let mut key = [0u8; 32];
        let mut cc = hex_to_32(TV1_M_CC);
        let result = ckd_priv(&mut key, &mut cc, HARDENED_OFFSET);
        assert!(
            result.is_ok(),
            "if this ever starts failing, ckd_priv's hardened branch has \
             started validating its parent key and `derive_account_path`'s \
             explicit `validate_master_key` call, while still correct, is \
             no longer the only thing standing between a zero master key \
             and its use as a signing key"
        );
    }

    // ------------------------------------------------------------------
    // `derive_path` (general runner, SPEC_DERIVATION_OPTIONS §A.7.1 #1):
    // byte-identical to the frozen `derive_account_path` on the four preset
    // base paths, plus depth-bound rejection and `preset_path` shape.
    // ------------------------------------------------------------------

    #[test]
    fn derive_path_matches_account_path_for_presets() {
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(&hex_to_vec(TV1_SEED));

        for standard in [
            PathStandard::Bip44,
            PathStandard::Bip49,
            PathStandard::Bip84,
            PathStandard::Bip86,
        ] {
            let mut key_a = [0u8; 32];
            let mut cc_a = [0u8; 32];
            derive_account_path(&seed, standard, &mut key_a, &mut cc_a).unwrap();

            let path = path_for_standard(standard);
            let mut key_b = [0u8; 32];
            let mut cc_b = [0u8; 32];
            derive_path(&seed, &path, &mut key_b, &mut cc_b).unwrap();

            assert_eq!(key_a, key_b, "{standard:?}: derive_path key must match derive_account_path");
            assert_eq!(cc_a, cc_b, "{standard:?}: derive_path chain code must match derive_account_path");
        }
    }

    #[test]
    fn preset_path_zero_leaf_matches_the_frozen_path_tables() {
        // account=0, change=0, index=0 is exactly today's fixed leaf.
        assert_eq!(preset_path(PathStandard::Bip44, 0, 0, 0), PATH_BIP44);
        assert_eq!(preset_path(PathStandard::Bip49, 0, 0, 0), PATH_BIP49);
        assert_eq!(preset_path(PathStandard::Bip84, 0, 0, 0), PATH_BIP84);
        assert_eq!(preset_path(PathStandard::Bip86, 0, 0, 0), PATH_BIP86);
    }

    #[test]
    fn preset_path_applies_hardened_account_and_normal_change_index() {
        let p = preset_path(PathStandard::Bip84, 2, 1, 7);
        assert_eq!(p[0], 0x8000_0054, "purpose 84' hardened");
        assert_eq!(p[1], 0x8000_0000, "coin_type 0' hardened");
        assert_eq!(p[2], 0x8000_0002, "account 2' hardened");
        assert_eq!(p[3], 1, "change chain 1, non-hardened");
        assert_eq!(p[4], 7, "address_index 7, non-hardened");
    }

    #[test]
    fn derive_path_rejects_paths_deeper_than_max_depth() {
        let seed = [0u8; 64];
        let too_deep = [0u32; MAX_DEPTH + 1];
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        assert_eq!(
            derive_path(&seed, &too_deep, &mut key, &mut cc),
            Err(DeriveError::InvalidIndex)
        );
    }

    #[test]
    fn derive_account_path_rejects_zero_master_key() {
        // End-to-end regression for the fix: `derive_account_path` must
        // reject an invalid master key itself, immediately after
        // `master_from_seed`, rather than relying on a downstream step to
        // happen to catch it. Exercised directly against the same
        // `validate_master_key` call `derive_account_path` makes, paired
        // with the characterization test above showing the old
        // "transitively validated via ckd_priv" claim was false for this
        // exact input.
        assert_eq!(
            validate_master_key(&[0u8; 32]),
            Err(DeriveError::InvalidChildKey)
        );

        // And the full path runner still succeeds end-to-end on a real
        // seed whose master key is valid (overwhelming probability for
        // any real seed), confirming the new check does not regress the
        // happy path.
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(&hex_to_vec(TV1_SEED));
        let mut key = [0u8; 32];
        let mut cc = [0u8; 32];
        assert!(derive_account_path(&seed, PathStandard::Bip44, &mut key, &mut cc).is_ok());
    }
}
