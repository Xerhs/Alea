//! BIP-380 output-script descriptors for the opt-in wallet-export screen.
//!
//! A descriptor is the portable, unambiguous statement of "which addresses
//! belong to this key": script type, key-origin (master fingerprint +
//! derivation path), the account extended **public** key, and the derivation
//! wildcard. Watch-only wallets import it directly, which is exactly the point
//! of the export screen — the user leaves with something a wallet can consume
//! without ever seeing a private key.
//!
//! # Public-only by construction
//!
//! Everything this module renders is public data. The key material it embeds
//! is the caller's already-serialized extended *public* key
//! ([`crate::bip32::serialize::serialize_xpub`]), and the only other inputs
//! are the master fingerprint (a truncated HASH160 of a public key) and the
//! derivation path (public protocol data). There is no code path here that can
//! touch a private key, because no function here accepts one — the same
//! structural guarantee wallet-export spec D1 places on
//! [`crate::bip32::account_public`].
//!
//! # Scope
//!
//! Single-signature templates only: `pkh`, `sh(wpkh(…))`, `wpkh`, `tr`. The
//! multisig cosigner screen displays a static `wsh(sortedmulti(…))` *caption*
//! describing what the exported BIP48 xpub is for; it does not assemble a real
//! multisig descriptor, which would need the other cosigners' keys this device
//! deliberately never sees.
//!
//! # `no_std`, allocation-free, panic-free
//!
//! Every buffer is a fixed-size array; rendering writes into a caller-owned
//! `[u8; DESCRIPTOR_MAX_LEN]` and reports a length. Nothing indexes a slice
//! with an unchecked value, so there is no panic path (SPEC §13, §27.3):
//! overflow and malformed input are reported as `0` / a non-verifying checksum
//! sentinel rather than aborting the firmware mid-ceremony.

use crate::bip32::serialize::XPUB_MAX_LEN;
use crate::bip32::HARDENED_OFFSET;

/// Maximum length of a rendered descriptor, `#checksum` included.
///
/// Size proof for the largest template this module emits — `sh(wpkh(…))` over
/// a BIP48 four-level account path:
/// `sh(wpkh(` 8 + `[` 1 + fingerprint 8 + `/48h/0h/0h/2h` 13 + `]` 1 +
/// xpub ([`crate::bip32::serialize::XPUB_MAX_LEN`]) 112 + `/0/*` 4 + `))` 2 +
/// `#` 1 + checksum 8 = **158**. 180 leaves headroom for a deeper or
/// larger-numbered origin path without changing the buffer type. Anything that
/// still would not fit is refused (see [`build_descriptor`]), never truncated:
/// a silently truncated descriptor would fail its own checksum, but a wrong
/// descriptor that *did* verify would be a funds-loss bug.
pub const DESCRIPTOR_MAX_LEN: usize = 180;

/// Length of a BIP-380 descriptor checksum, in characters.
pub const DESCRIPTOR_CHECKSUM_LEN: usize = 8;

/// Conservative length floor for a Base58Check-encoded extended key.
///
/// An extended key is a fixed 78-byte payload plus a 4-byte checksum; Base58
/// encodes 82 bytes into 111 characters in the overwhelmingly common case, and
/// never fewer than about 107 (leading zero bytes are the only source of
/// variation, and the 4-byte version prefix of every mainnet/SLIP-132 form is
/// non-zero, so in practice the length is always 111). 100 is deliberately
/// looser than the true floor: this is a *shape* check meant to catch missing
/// or truncated key material, not a Base58Check validator, and it must not
/// reject a legitimate key on an off-by-a-few argument.
const XPUB_MIN_LEN: usize = 100;

/// Reject an `xpub_b58` that cannot possibly be an extended key.
///
/// Without this, [`build_descriptor`] would happily render
/// `wpkh([d34db33f/84h/0h/0h]/0/*)#<valid checksum>` from an empty key — a
/// descriptor containing **no key material** that nonetheless passes its own
/// checksum and looks correct on screen. That is precisely the
/// "wrong-yet-verifying" failure mode the refuse-never-truncate rule exists to
/// prevent, so an empty or stunted key is refused at the same door.
///
/// Two cheap, conservative conditions:
/// - length within `XPUB_MIN_LEN..=XPUB_MAX_LEN` — catches empty, truncated
///   and over-long input, and the upper bound is exactly what
///   [`crate::bip32::serialize::serialize_xpub`] can produce;
/// - bytes 1..4 are `pub` — the shared tail of every extended *public* key
///   prefix this project emits (`xpub`, `ypub`, `zpub`), and of the testnet
///   forms (`tpub`, `upub`, `vpub`) besides. It is deliberately not a
///   whitelist of exact prefixes: the point is to catch "this is not an
///   extended key at all", not to police which SLIP-132 flavour was chosen.
///
/// This is not, and does not pretend to be, Base58Check verification — the
/// caller obtained `xpub_b58` from `serialize_xpub`, which constructs it
/// correctly by definition. It is a guard against a *missing* or *mangled*
/// argument reaching the screen.
fn is_plausible_extended_key(xpub_b58: &[u8]) -> bool {
    if xpub_b58.len() < XPUB_MIN_LEN || xpub_b58.len() > XPUB_MAX_LEN {
        return false;
    }
    match xpub_b58.get(1..4) {
        Some(tag) => tag == b"pub".as_slice(),
        None => false,
    }
}

/// BIP-380 `INPUT_CHARSET` — the 95 printable ASCII characters, permuted so
/// that characters likely to be confused with one another differ in their
/// high (group) bits as well as their low 5 bits. The permutation is
/// normative: the checksum is only interoperable if this exact ordering is
/// used. Copied from BIP-380 / Bitcoin Core `descriptor.cpp`.
const INPUT_CHARSET: &[u8] =
    b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// BIP-380 `CHECKSUM_CHARSET` — the Bech32 character set the 8 checksum
/// symbols are rendered in.
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Returned by [`descriptor_checksum`] for input that is not a descriptor
/// (any byte outside [`INPUT_CHARSET`]).
///
/// `#` is in `INPUT_CHARSET` but **not** in [`CHECKSUM_CHARSET`], so this
/// value can never be a real checksum and any conforming verifier rejects it.
/// That makes the failure loud at the point it matters (the importing wallet)
/// while keeping the signature infallible and panic-free.
const INVALID_CHECKSUM: [u8; DESCRIPTOR_CHECKSUM_LEN] = *b"########";

/// Lowercase hex digits for the key-origin fingerprint.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The four single-sig descriptor templates, one per script type
/// (1:1 with `PathStandard`/`ScriptType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorKind {
    /// `pkh(KEY)` — P2PKH, addresses `1...` (BIP44).
    Pkh,
    /// `sh(wpkh(KEY))` — P2SH-wrapped P2WPKH, addresses `3...` (BIP49).
    ShWpkh,
    /// `wpkh(KEY)` — native segwit v0, addresses `bc1q...` (BIP84).
    Wpkh,
    /// `tr(KEY)` — single-key taproot, addresses `bc1p...` (BIP86).
    Tr,
}

impl DescriptorKind {
    /// The template text before the key expression.
    const fn prefix(self) -> &'static [u8] {
        match self {
            DescriptorKind::Pkh => b"pkh(",
            DescriptorKind::ShWpkh => b"sh(wpkh(",
            DescriptorKind::Wpkh => b"wpkh(",
            DescriptorKind::Tr => b"tr(",
        }
    }

    /// The template text after the key expression — the matching close
    /// parentheses.
    const fn suffix(self) -> &'static [u8] {
        match self {
            DescriptorKind::ShWpkh => b"))",
            _ => b")",
        }
    }
}

/// BIP-380 `PolyMod` — one step of the BCH code over GF(32) whose generator
/// gives the 8-symbol checksum its error-detection properties. The five
/// constants are the generator's feedback terms; they are normative.
const fn polymod(c: u64, val: u64) -> u64 {
    let c0 = c >> 35;
    let mut c = ((c & 0x7_ffff_ffff) << 5) ^ val;
    if c0 & 1 != 0 {
        c ^= 0xf5de_e519_89;
    }
    if c0 & 2 != 0 {
        c ^= 0xa9fd_ca33_12;
    }
    if c0 & 4 != 0 {
        c ^= 0x1bab_10e3_2d;
    }
    if c0 & 8 != 0 {
        c ^= 0x3706_b167_7a;
    }
    if c0 & 16 != 0 {
        c ^= 0x644d_626f_fd;
    }
    c
}

/// Position of `b` in [`INPUT_CHARSET`], or `None` if `b` is not a descriptor
/// character.
fn charset_pos(b: u8) -> Option<u64> {
    // `position` yields an index < 95, so the widening cast is lossless.
    INPUT_CHARSET.iter().position(|&c| c == b).map(|p| p as u64)
}

/// BIP-380 `DescriptorChecksum`, fallible form: `None` when `s` contains a
/// byte outside [`INPUT_CHARSET`], i.e. when `s` is not a descriptor at all.
///
/// Each character contributes twice: once as its low 5 bits (a symbol of the
/// BCH code), and once — batched three characters at a time — as its
/// [`INPUT_CHARSET`] *group* number, packed base-3. That second channel is
/// what makes the code detect substitutions between visually similar
/// characters placed in different groups.
fn descriptor_checksum_checked(s: &[u8]) -> Option<[u8; DESCRIPTOR_CHECKSUM_LEN]> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u8 = 0;

    for &b in s {
        let pos = charset_pos(b)?;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }

    // Shift the 8 checksum symbols into place, then perturb so that appending
    // zero symbols cannot leave the checksum unchanged.
    for _ in 0..DESCRIPTOR_CHECKSUM_LEN {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut out = [0u8; DESCRIPTOR_CHECKSUM_LEN];
    for (j, slot) in out.iter_mut().enumerate() {
        let symbol = ((c >> (5 * (7 - j))) & 31) as usize;
        // `symbol` is masked to 0..=31 and `CHECKSUM_CHARSET` has 32 entries,
        // so this lookup always succeeds; `get` keeps it a total operation
        // rather than a potential panic.
        *slot = match CHECKSUM_CHARSET.get(symbol) {
            Some(ch) => *ch,
            None => return None,
        };
    }
    Some(out)
}

/// BIP-380 descriptor checksum of `s` (the descriptor text *without* its
/// trailing `#checksum`).
///
/// Returns the sentinel `########` if `s` contains a byte outside
/// the BIP-380 input character set — a value no conforming verifier accepts,
/// so bad input cannot masquerade as a good descriptor. The signature is
/// infallible by contract (Task 7 brief); callers that need to distinguish the
/// cases should use [`build_descriptor`], which refuses outright.
pub fn descriptor_checksum(s: &[u8]) -> [u8; DESCRIPTOR_CHECKSUM_LEN] {
    match descriptor_checksum_checked(s) {
        Some(checksum) => checksum,
        None => INVALID_CHECKSUM,
    }
}

/// Append `bytes` at `*n`, or report that it would not fit. Never panics: the
/// destination range is taken with `get_mut`, not indexed.
fn push(out: &mut [u8; DESCRIPTOR_MAX_LEN], n: &mut usize, bytes: &[u8]) -> bool {
    let end = match n.checked_add(bytes.len()) {
        Some(end) => end,
        None => return false,
    };
    match out.get_mut(*n..end) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            *n = end;
            true
        }
        None => false,
    }
}

/// Append `v` in decimal (no leading zeros; `0` renders as `"0"`).
fn push_u32_dec(out: &mut [u8; DESCRIPTOR_MAX_LEN], n: &mut usize, mut v: u32) -> bool {
    // `u32::MAX` is 4294967295 — 10 digits, so the scratch buffer can never
    // be exhausted; the `checked_sub` below keeps that a fact rather than an
    // assumption.
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        let digit = b'0' + (v % 10) as u8;
        v /= 10;
        i = match i.checked_sub(1) {
            Some(i) => i,
            None => return false,
        };
        match digits.get_mut(i) {
            Some(slot) => *slot = digit,
            None => return false,
        }
        if v == 0 {
            break;
        }
    }
    match digits.get(i..) {
        Some(rendered) => push(out, n, rendered),
        None => false,
    }
}

/// Append the key-origin path, `/48h/0h/0h/2h` style: each level as a decimal
/// child number with the hardened bit stripped, suffixed `h` when hardened.
///
/// BIP-380 accepts `h`, `H` and `'` as hardened markers; `h` is chosen because
/// `'` needs shell quoting when a user retypes the descriptor, and because it
/// is what Bitcoin Core emits.
fn push_origin_path(out: &mut [u8; DESCRIPTOR_MAX_LEN], n: &mut usize, path: &[u32]) -> bool {
    for &index in path {
        if !push(out, n, b"/") {
            return false;
        }
        let hardened = index >= HARDENED_OFFSET;
        let child = if hardened {
            index - HARDENED_OFFSET
        } else {
            index
        };
        if !push_u32_dec(out, n, child) {
            return false;
        }
        if hardened && !push(out, n, b"h") {
            return false;
        }
    }
    true
}

/// Append the master fingerprint as 8 lowercase hex digits.
fn push_fingerprint(out: &mut [u8; DESCRIPTOR_MAX_LEN], n: &mut usize, fp: &[u8; 4]) -> bool {
    let mut hex = [0u8; 8];
    // `chunks_mut(2)` over an 8-byte buffer yields exactly 4 two-byte chunks,
    // pairing 1:1 with the 4 fingerprint bytes — no indexing, no panic path.
    for (nibbles, &byte) in hex.chunks_mut(2).zip(fp.iter()) {
        // `>> 4` and `& 0x0f` are both in 0..=15 and `HEX_DIGITS` has 16
        // entries, so both lookups always succeed.
        let (hi, lo) = match (
            HEX_DIGITS.get((byte >> 4) as usize),
            HEX_DIGITS.get((byte & 0x0f) as usize),
        ) {
            (Some(hi), Some(lo)) => (*hi, *lo),
            _ => return false,
        };
        match nibbles {
            [a, b] => {
                *a = hi;
                *b = lo;
            }
            _ => return false,
        }
    }
    push(out, n, &hex)
}

/// Render the single-sig descriptor for `kind` over the account extended
/// public key `xpub_b58`, returning the number of bytes written to `out`.
///
/// Shape: `` <template>([<fingerprint>/<path>]<xpub>/0/*)#<checksum> `` — e.g.
/// `wpkh([73c5da0a/84h/0h/0h]xpub…/0/*)#hd2v475g`.
///
/// - `master_fingerprint` — [`crate::bip32::master_fingerprint`] of the master
///   node, rendered as 8 lowercase hex digits.
/// - `path` — the **account-level** derivation path of `xpub_b58`, e.g.
///   `PATH_BIP84[..3]` or [`crate::bip32::path_bip48_native`]. It must be the
///   path the xpub was actually derived at: the `/0/*` suffix this function
///   appends supplies the change and address-index levels, so passing a full
///   five-level address path would describe keys that do not exist.
/// - `xpub_b58` — the Base58Check text from
///   [`crate::bip32::serialize::serialize_xpub`]. Shape-checked before
///   assembly (see below); it is not enough for it to merely be *renderable*.
///
/// # Returns
///
/// The rendered length, or **`0` on refusal**. Refused when:
///
/// - `xpub_b58` does not have the shape of an extended key — empty, truncated,
///   over-long, or missing the `pub` prefix tag. Without this check an empty
///   key would still produce a checksum-valid, screen-displayable descriptor
///   containing no key material at all;
/// - an input byte lies outside the BIP-380 character set (a mangled
///   `xpub_b58`); or
/// - the rendered descriptor would not fit in [`DESCRIPTOR_MAX_LEN`].
///
/// `out`'s contents are unspecified when `0` is returned; callers must treat
/// `0` as "no descriptor" and never render a prefix of the buffer. Nothing is
/// ever truncated or emitted key-less: a plausible-looking descriptor that is
/// not the user's descriptor is a funds-loss hazard, so every one of these
/// cases refuses outright.
pub fn build_descriptor(
    kind: DescriptorKind,
    master_fingerprint: [u8; 4],
    path: &[u32],
    xpub_b58: &[u8],
    out: &mut [u8; DESCRIPTOR_MAX_LEN],
) -> usize {
    // Refuse before assembly: a descriptor whose key expression is empty or
    // stunted would still render and still checksum correctly.
    if !is_plausible_extended_key(xpub_b58) {
        return 0;
    }

    let mut n = 0usize;

    let body_written = push(out, &mut n, kind.prefix())
        && push(out, &mut n, b"[")
        && push_fingerprint(out, &mut n, &master_fingerprint)
        && push_origin_path(out, &mut n, path)
        && push(out, &mut n, b"]")
        && push(out, &mut n, xpub_b58)
        && push(out, &mut n, b"/0/*")
        && push(out, &mut n, kind.suffix());
    if !body_written {
        return 0;
    }

    // The checksum covers exactly the text written so far, `#` excluded.
    let checksum = match out.get(..n) {
        Some(body) => match descriptor_checksum_checked(body) {
            Some(checksum) => checksum,
            None => return 0,
        },
        None => return 0,
    };

    if !(push(out, &mut n, b"#") && push(out, &mut n, &checksum)) {
        return 0;
    }
    n
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::bip32::{path_bip48_native, PATH_BIP44, PATH_BIP49, PATH_BIP84, PATH_BIP86};

    /// Bitcoin Core `doc/descriptors.md`'s published descriptor/checksum pair.
    const CORE_XPUB: &[u8] = b"xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY";
    const CORE_BODY: &[u8] = b"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)";
    const CORE_FULL: &[u8] = b"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
    const CORE_CHECKSUM: &[u8; 8] = b"cjjspncu";
    const CORE_FINGERPRINT: [u8; 4] = [0xd3, 0x4d, 0xb3, 0x3f];
    /// `84h/0h/0h` — the account level of `PATH_BIP84`.
    const CORE_PATH: [u32; 3] = [0x8000_0054, 0x8000_0000, 0x8000_0000];

    fn as_str(bytes: &[u8]) -> &str {
        match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => "<non-utf8>",
        }
    }

    // ------------------------------------------------------------------
    // BIP-380 checksum.
    // ------------------------------------------------------------------

    #[test]
    fn checksum_matches_bitcoin_core_vector() {
        assert_eq!(&descriptor_checksum(CORE_BODY), CORE_CHECKSUM);
    }

    #[test]
    fn checksum_changes_when_any_single_character_changes() {
        let base = descriptor_checksum(CORE_BODY);
        let mut buf = [0u8; 256];
        let n = CORE_BODY.len();
        buf[..n].copy_from_slice(CORE_BODY);

        // Three single-character mutations at different offsets: the script
        // template, a path digit, and a base58 character deep in the xpub.
        for (offset, replacement) in [(0usize, b'p'), (10usize, b'8'), (60usize, b'Z')] {
            let original = buf[offset];
            assert_ne!(original, replacement, "offset {offset} must really change");
            buf[offset] = replacement;
            assert_ne!(
                descriptor_checksum(&buf[..n]),
                base,
                "checksum must change when byte {offset} changes"
            );
            buf[offset] = original;
        }
        // …and restoring every byte restores the checksum.
        assert_eq!(descriptor_checksum(&buf[..n]), base);
    }

    #[test]
    fn checksum_detects_transposition_and_length_change() {
        let base = descriptor_checksum(CORE_BODY);

        // Truncating the body must change the checksum (the `c ^= 1` step is
        // what stops trailing symbols from being free).
        assert_ne!(descriptor_checksum(&CORE_BODY[..CORE_BODY.len() - 1]), base);
        assert_ne!(descriptor_checksum(b""), base);

        // A true transposition — swapping two adjacent, distinct characters —
        // leaves the multiset of characters untouched, so only a
        // position-sensitive code detects it.
        let mut buf = [0u8; 256];
        let n = CORE_BODY.len();
        buf[..n].copy_from_slice(CORE_BODY);
        let mut transpositions = 0;
        for offset in [30usize, 62, 90, 100] {
            let (a, b) = (buf[offset], buf[offset + 1]);
            if a == b {
                // A doubled character is not a transposition at all.
                continue;
            }
            transpositions += 1;
            buf[offset] = b;
            buf[offset + 1] = a;
            assert_ne!(
                descriptor_checksum(&buf[..n]),
                base,
                "checksum must change when bytes {offset}/{} are swapped",
                offset + 1
            );
            buf[offset] = a;
            buf[offset + 1] = b;
        }
        assert!(transpositions >= 3, "need at least three real transpositions");
        assert_eq!(descriptor_checksum(&buf[..n]), base);
    }

    #[test]
    fn checksum_rejects_non_descriptor_bytes() {
        // A byte outside INPUT_CHARSET yields the sentinel, which is not in
        // CHECKSUM_CHARSET and therefore can never verify.
        assert_eq!(descriptor_checksum(b"wpkh(\x00)"), *b"########");
        assert_eq!(descriptor_checksum(b"wpkh(\xff)"), *b"########");
        assert_eq!(descriptor_checksum("wpkh(é)".as_bytes()), *b"########");
        for &ch in &INVALID_CHECKSUM {
            assert!(
                !CHECKSUM_CHARSET.contains(&ch),
                "the sentinel must be unrepresentable as a real checksum"
            );
        }
    }

    #[test]
    fn checksum_output_is_always_in_the_bech32_charset() {
        for body in [CORE_BODY, b"pkh(x)", b"", b"tr(0)"] {
            for ch in descriptor_checksum(body) {
                assert!(CHECKSUM_CHARSET.contains(&ch), "bad checksum char {ch}");
            }
        }
    }

    #[test]
    fn input_charset_is_a_permutation_of_printable_ascii() {
        assert_eq!(INPUT_CHARSET.len(), 95);
        assert_eq!(CHECKSUM_CHARSET.len(), 32);
        for byte in 0x20u8..=0x7e {
            assert_eq!(
                INPUT_CHARSET.iter().filter(|&&c| c == byte).count(),
                1,
                "printable byte {byte:#04x} must appear exactly once"
            );
        }
    }

    // ------------------------------------------------------------------
    // Descriptor assembly.
    // ------------------------------------------------------------------

    #[test]
    fn build_descriptor_reproduces_the_core_vector() {
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        let n = build_descriptor(
            DescriptorKind::Wpkh,
            CORE_FINGERPRINT,
            &CORE_PATH,
            CORE_XPUB,
            &mut out,
        );
        assert_eq!(as_str(&out[..n]), as_str(CORE_FULL));
    }

    #[test]
    fn every_template_wraps_the_same_key_expression() {
        let key = b"[d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*";
        for (kind, prefix, suffix) in [
            (DescriptorKind::Pkh, "pkh(", ")"),
            (DescriptorKind::ShWpkh, "sh(wpkh(", "))"),
            (DescriptorKind::Wpkh, "wpkh(", ")"),
            (DescriptorKind::Tr, "tr(", ")"),
        ] {
            let mut out = [0u8; DESCRIPTOR_MAX_LEN];
            let n = build_descriptor(kind, CORE_FINGERPRINT, &CORE_PATH, CORE_XPUB, &mut out);
            let rendered = as_str(&out[..n]);
            assert!(rendered.starts_with(prefix), "{kind:?}: {rendered}");
            // body = everything before the `#checksum`.
            let (body, checksum) = match rendered.split_once('#') {
                Some(parts) => parts,
                None => panic!("{kind:?}: no checksum separator in {rendered}"),
            };
            assert!(body.ends_with(suffix), "{kind:?}: {body}");
            assert_eq!(body, std::format!("{prefix}{}{suffix}", as_str(key)));
            assert_eq!(checksum.len(), DESCRIPTOR_CHECKSUM_LEN);
            assert_eq!(checksum.as_bytes(), descriptor_checksum(body.as_bytes()));
        }
    }

    #[test]
    fn origin_path_renders_hardened_and_normal_levels() {
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        // A deliberately mixed path: hardened, normal, hardened, normal.
        let n = build_descriptor(
            DescriptorKind::Pkh,
            [0x00, 0x0a, 0xff, 0x01],
            &[0x8000_0030, 7, 0x8000_0002, 0],
            b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            &mut out,
        );
        let rendered = as_str(&out[..n]);
        assert!(
            rendered.starts_with("pkh([000aff01/48h/7/2h/0]xpub661MyMwAqRbcF"),
            "{rendered}"
        );
        assert!(rendered.contains("/0/*)#"), "{rendered}");
    }

    #[test]
    fn fingerprint_renders_as_eight_lowercase_hex_digits() {
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        let n = build_descriptor(
            DescriptorKind::Wpkh,
            [0x00, 0x01, 0xab, 0xff],
            &CORE_PATH,
            CORE_XPUB,
            &mut out,
        );
        assert!(as_str(&out[..n]).starts_with("wpkh([0001abff/"), "{}", as_str(&out[..n]));
    }

    #[test]
    fn account_paths_of_all_four_presets_and_bip48_fit() {
        // The longest template over the longest realistic origin path must
        // still fit DESCRIPTOR_MAX_LEN with room for the checksum.
        let bip48 = path_bip48_native(0);
        let paths: [&[u32]; 5] = [
            &PATH_BIP44[..3],
            &PATH_BIP49[..3],
            &PATH_BIP84[..3],
            &PATH_BIP86[..3],
            &bip48,
        ];
        for path in paths {
            let mut out = [0u8; DESCRIPTOR_MAX_LEN];
            let n = build_descriptor(
                DescriptorKind::ShWpkh,
                [0xff, 0xff, 0xff, 0xff],
                path,
                CORE_XPUB,
                &mut out,
            );
            assert!(n > 0, "must fit: {path:?}");
            assert!(n <= DESCRIPTOR_MAX_LEN);
        }
    }

    #[test]
    fn build_descriptor_refuses_rather_than_truncates_when_too_long() {
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        // A path far longer than any real origin pushes past the buffer:
        // 10 levels of `/1852516352h` is 120 characters of origin alone.
        let long_path = [4_000_000_000u32; 10];
        assert_eq!(
            build_descriptor(
                DescriptorKind::ShWpkh,
                [0xff; 4],
                &long_path,
                CORE_XPUB,
                &mut out
            ),
            0
        );
        // The origin path is the only input that can overflow: the key is
        // capped at XPUB_MAX_LEN by the shape check, and even the longest
        // template over a key that long with an empty path is 141 bytes.
    }

    #[test]
    fn build_descriptor_refuses_a_key_with_non_descriptor_bytes() {
        // Shape-plausible (111 chars, `pub` tag) so it reaches the charset
        // check, but carries a byte outside INPUT_CHARSET.
        let mut mangled = [b'x'; 111];
        mangled[1..4].copy_from_slice(b"pub");
        mangled[50] = 0x00;
        assert!(
            is_plausible_extended_key(&mangled),
            "this case must be rejected by the charset check, not the shape check"
        );

        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        assert_eq!(
            build_descriptor(
                DescriptorKind::Wpkh,
                CORE_FINGERPRINT,
                &CORE_PATH,
                &mangled,
                &mut out
            ),
            0
        );
    }

    #[test]
    fn build_descriptor_refuses_an_implausible_extended_key() {
        // Without a shape check, an empty key still renders a checksum-valid,
        // screen-displayable descriptor with no key material in it:
        //   wpkh([d34db33f/84h/0h/0h]/0/*)#<real checksum>
        // Every one of these must return 0 instead.
        let short = [b'x'; 50];
        let mut just_under = [b'x'; XPUB_MIN_LEN - 1];
        just_under[1..4].copy_from_slice(b"pub");
        let mut just_over = [b'x'; XPUB_MAX_LEN + 1];
        just_over[1..4].copy_from_slice(b"pub");
        // Right length, but not an extended key: `puq`, not `pub`.
        let mut no_tag = [b'x'; 111];
        no_tag[..4].copy_from_slice(b"xpuq");

        let cases: [(&str, &[u8]); 6] = [
            ("empty", b""),
            ("50 chars", &short),
            ("one below the floor", &just_under),
            ("one above the ceiling", &just_over),
            ("no `pub` tag", &no_tag),
            ("prefix only", b"xpub"),
        ];
        for (label, key) in cases {
            assert!(!is_plausible_extended_key(key), "{label} must be implausible");
            let mut out = [0u8; DESCRIPTOR_MAX_LEN];
            for kind in [
                DescriptorKind::Pkh,
                DescriptorKind::ShWpkh,
                DescriptorKind::Wpkh,
                DescriptorKind::Tr,
            ] {
                assert_eq!(
                    build_descriptor(kind, CORE_FINGERPRINT, &CORE_PATH, key, &mut out),
                    0,
                    "{kind:?} must refuse a {label} key"
                );
            }
        }

        // …and the real vector is unaffected.
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        let n = build_descriptor(
            DescriptorKind::Wpkh,
            CORE_FINGERPRINT,
            &CORE_PATH,
            CORE_XPUB,
            &mut out,
        );
        assert_eq!(as_str(&out[..n]), as_str(CORE_FULL));
    }

    #[test]
    fn plausible_extended_key_accepts_every_slip132_flavour() {
        // The shape check must not police *which* extended-public-key prefix
        // was chosen — xpub/ypub/zpub all serialize from the same 78-byte
        // payload and differ only in their version bytes.
        for prefix in [b"xpub", b"ypub", b"zpub", b"tpub", b"upub", b"vpub"] {
            let mut key = [b'x'; 111];
            key[..4].copy_from_slice(prefix);
            assert!(
                is_plausible_extended_key(&key),
                "{} must be accepted",
                as_str(prefix)
            );
        }
        assert!(is_plausible_extended_key(CORE_XPUB));
    }

    #[test]
    fn empty_origin_path_still_renders_a_valid_descriptor() {
        // BIP-380 allows a key origin that is only a fingerprint (the master
        // node itself, depth 0).
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        let n = build_descriptor(
            DescriptorKind::Wpkh,
            CORE_FINGERPRINT,
            &[],
            CORE_XPUB,
            &mut out,
        );
        let rendered = as_str(&out[..n]);
        assert!(rendered.starts_with("wpkh([d34db33f]xpub"), "{rendered}");
        let (body, checksum) = match rendered.split_once('#') {
            Some(parts) => parts,
            None => panic!("no checksum in {rendered}"),
        };
        assert_eq!(checksum.as_bytes(), descriptor_checksum(body.as_bytes()));
    }

    #[test]
    fn rendered_descriptor_is_self_consistent_ascii() {
        let mut out = [0u8; DESCRIPTOR_MAX_LEN];
        let n = build_descriptor(
            DescriptorKind::Tr,
            CORE_FINGERPRINT,
            &CORE_PATH,
            CORE_XPUB,
            &mut out,
        );
        assert!(n > 0);
        for &b in &out[..n] {
            assert!((0x20..=0x7e).contains(&b), "descriptor must be printable ASCII");
        }
    }
}
