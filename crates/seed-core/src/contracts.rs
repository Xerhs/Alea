//! Frozen interface contracts (WP-00).
//!
//! This module is the API every downstream work package codes against.
//! It contains **types and traits only** — no function bodies for the
//! actual protocol/business-logic free functions. The free functions
//! that operate on these types (`sha256`, `hash160`,
//! `base58check_encode`, `entropy_to_indexes`, `master_from_seed`, ...) are
//! documented in `IMPLEMENTATION_MAP.md` §4 and implemented verbatim by
//! their owning work package inside its own module (SPEC §31, Ground
//! rule #2 in `AGENTS.md`).
//!
//! One narrow, deliberate exception: [`AddressBuf`]'s own small
//! constructor/accessor methods (`new`/`empty`/`set`/`as_bytes`/`as_str`/
//! `len`/`is_empty`/`full_bytes`) are declared alongside the type itself
//! (pre-release audit SHOULD-FIX #4, `docs/PRE-RELEASE-AUDIT.md`). These
//! enforce only `AddressBuf`'s own length invariant, are not owned by any
//! work package (`IMPLEMENTATION_MAP.md` has no separate entry for them),
//! and are required for the type's fields to be private at all — a
//! private field with no in-module accessor would make the type
//! unconstructible by any downstream crate.
//!
//! Changing anything in this file is an orchestrator-level decision, never
//! a unilateral edit by a leaf work package (`AGENTS.md` §1 rule 2).
//!
//! No secret-bearing type is defined in this file: no type below derives
//! `Copy`, `Clone`, `Debug`, `Display` or any serialization trait over
//! secret material (SPEC §13, §20.2). Every type here is a small
//! public/plain-data descriptor (word/bit-size tags, error enums, display
//! buffers, ...), so ordinary derives are safe to use.
//!
//! This file previously defined `PrefixResult`, whose `Unique(u16)`
//! variant carried a live secret BIP39 wordlist index through ordinary
//! `Debug`/`Clone`/`Copy`/`PartialEq`/`Eq` derives — contradicting the
//! claim above and SPEC §20.2 (pre-release audit MUST-FIX #1,
//! `docs/PRE-RELEASE-AUDIT.md`). It has been retired: all secret prefix
//! resolution (SPEC §12.3, §23.1) now goes exclusively through
//! `seed_core::bip39::resolve_prefix_into`, which writes the resolved
//! index into a caller-owned `&mut u16` and returns only the non-secret
//! `seed_core::bip39::PrefixOutcome` discriminant (never a type that can
//! carry the secret index by value).

#![allow(clippy::exhaustive_enums)]

// ============================================================================
// BIP39 / entropy sizing (SPEC §14, §17)
// ============================================================================

/// Supported BIP39 mnemonic lengths (SPEC §14). Version 1 supports exactly
/// these two; no other word count is a valid protocol output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 128 bits of entropy + 4-bit checksum = 132 encoded bits.
    Twelve = 12,
    /// 256 bits of entropy + 8-bit checksum = 264 encoded bits.
    TwentyFour = 24,
}

/// Requested final-entropy size in bits (SPEC §17.2, §19.3). Mirrors
/// [`WordCount`] but is the unit the physical-entropy budget and the
/// transcript-finalization step actually operate in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetBits {
    /// 12-word mnemonic.
    Bits128 = 128,
    /// 24-word mnemonic.
    Bits256 = 256,
}

// ============================================================================
// Word-entry / prefix resolution (SPEC §12.3, §23.1)
// ============================================================================
//
// This section formerly declared `PrefixResult` (see MUST-FIX #1,
// `docs/PRE-RELEASE-AUDIT.md`, and the file header above for why it was
// removed). Prefix resolution's non-secret outcome type
// (`bip39::PrefixOutcome`) is owned entirely by WP-05
// (`crates/seed-core/src/bip39/mod.rs`) instead of being declared here,
// since — unlike every other type in this file — no variant of it is
// itself part of a frozen cross-crate wire/ABI contract that needs to live
// in the orchestrator-owned contract file: it is purely a same-crate
// return type.

// ============================================================================
// Error types (SPEC §27.3: no error may carry secret values)
// ============================================================================

/// Errors from fixed-buffer encoders (Base58Check, Bech32/Bech32m).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The caller-provided output buffer is too small for the encoded
    /// result (see `MAX_B58` / `MAX_BECH32` for the sizes that are always
    /// sufficient for in-protocol payloads).
    BufferTooSmall,
    /// A Bech32/Bech32m witness version outside the supported range was
    /// requested (SPEC §24.2 only uses versions 0 and 1).
    InvalidVersion,
    /// The witness program length is invalid for the requested version.
    InvalidProgramLength,
}

/// Errors from BIP39 entropy/mnemonic conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// `entropy.len()` was not one of the two supported sizes (16 or 32
    /// bytes; SPEC §14).
    InvalidEntropyLength,
    /// The BIP39 checksum did not match (only reachable when reconstructing
    /// from externally supplied indexes, e.g. self-tests).
    ChecksumMismatch,
}

/// Errors from BIP32 child-key derivation and address construction
/// (SPEC §24.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    /// `parse256(IL) >= n` or the derived child key is zero (BIP32 CKD
    /// invalid-key case). The caller must advance and retry per BIP32; in
    /// this project's fixed four paths this is treated as a fatal
    /// self-test/derivation failure (SPEC §27.2), not a retry loop.
    InvalidChildKey,
    /// A hardened-derivation index was requested against a public-only
    /// (non-private) key context, or the index was otherwise malformed.
    InvalidIndex,
    /// An intermediate elliptic-curve point was the point at infinity.
    PointAtInfinity,
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
}

// ============================================================================
// Wallet-derivation verification (SPEC §24)
// ============================================================================

/// The four fixed single-sig derivation standards SPEC §24 displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStandard {
    /// `m/44'/0'/0'/0/0`, P2PKH, address form `1...`.
    Bip44,
    /// `m/49'/0'/0'/0/0`, P2SH-P2WPKH, address form `3...`.
    Bip49,
    /// `m/84'/0'/0'/0/0`, P2WPKH (native segwit), address form `bc1q...`.
    Bip84,
    /// `m/86'/0'/0'/0/0`, P2TR (taproot), address form `bc1p...`.
    Bip86,
}

/// A fixed-size, explicit-length buffer for one rendered address string
/// (SPEC §24.3: display-only, ASCII).
///
/// Size proof: the largest address form in scope is Bech32m P2TR
/// (`MAX_BECH32` = 64 bytes, see below); the largest Base58Check form is
/// `MAX_B58` = 35 bytes. 92 bytes is chosen as a single fixed size that
/// comfortably covers both today's forms and headroom for a longer HRP or
/// a future network prefix without changing the arena layout.
///
/// `bytes`/`len` are private (pre-release audit SHOULD-FIX #4,
/// `docs/PRE-RELEASE-AUDIT.md`): the previous public fields let any caller
/// construct `len > 92`, which would panic the post-secret wallet-
/// verification-display slice read `&bytes[..len]`. Every value now goes
/// through [`AddressBuf::new`]/[`AddressBuf::empty`]/[`AddressBuf::set`],
/// each of which enforces `len <= CAPACITY` once, at construction/write
/// time, so [`AddressBuf::as_bytes`]/[`AddressBuf::as_str`] can never slice
/// out of bounds. This is not secret-bearing data (SPEC §24.3: an address
/// is exactly what the wallet-verification-display screen shows), so the
/// small accessor methods below are declared alongside the type itself —
/// unlike the free functions this file's header describes (`sha256`,
/// `base58check_encode`, ...), these enforce only this type's own
/// length invariant and are not owned by any other work package
/// (`IMPLEMENTATION_MAP.md` has no separate WP entry for them).
#[derive(Clone, Copy)]
pub struct AddressBuf {
    /// Raw ASCII bytes. Only `bytes[..len]` is meaningful.
    bytes: [u8; 92],
    /// Number of valid bytes in `bytes`, always `<= CAPACITY`.
    len: u8,
}

impl AddressBuf {
    /// Fixed backing-buffer capacity in bytes (see the size proof above).
    pub const CAPACITY: usize = 92;

    /// An empty address buffer (`len == 0`), the placeholder every
    /// per-standard slot starts from before a real encoder fills it in.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bytes: [0u8; Self::CAPACITY], len: 0 }
    }

    /// Builds an `AddressBuf` from a full backing buffer and an explicit
    /// length, saturating `len` to [`AddressBuf::CAPACITY`] rather than
    /// accepting an out-of-range value (checked constructor, SHOULD-FIX
    /// #4).
    #[must_use]
    pub fn new(bytes: [u8; Self::CAPACITY], len: usize) -> Self {
        let len = if len > Self::CAPACITY { Self::CAPACITY } else { len };
        Self { bytes, len: len as u8 }
    }

    /// Overwrites this buffer's content from `data`, truncating to
    /// [`AddressBuf::CAPACITY`] if `data` is longer (same saturating
    /// discipline as [`AddressBuf::new`], so this can never store an
    /// out-of-range length) and zeroing every byte beyond the copied
    /// length (SPEC §13: no stale byte left unaccounted for). This is the
    /// accessor real encoders (`bech32::encode`, the Base58Check address
    /// constructors) write their rendered output through.
    pub fn set(&mut self, data: &[u8]) {
        let n = if data.len() > Self::CAPACITY { Self::CAPACITY } else { data.len() };
        self.bytes[..n].copy_from_slice(&data[..n]);
        for b in self.bytes[n..].iter_mut() {
            *b = 0;
        }
        self.len = n as u8;
    }

    /// Volatile-zero the whole backing buffer and reset `len` to 0.
    ///
    /// An address is not key material, but it is a wallet-identifying
    /// artifact, and the project's residency policy is that nothing that
    /// privacy-sensitive stays resident past the screen that showed it
    /// (see `pipeline`'s `ExportValues`/`ExtendedVerificationValues`). The
    /// SPEC §26 amendment (2026-08-08) menu-return path can leave the
    /// machine powered on, so these buffers must be actively cleared rather
    /// than left to the power-off's DRAM decay. Volatile writes plus a
    /// fence prevent the compiler from eliding the scrub when the buffer is
    /// about to be dropped.
    pub fn scrub(&mut self) {
        for b in self.bytes.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed `&mut u8` for the
            // duration of this write.
            unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // Verification read (same discipline as `pipeline::scrub_local`):
        // read every byte back volatilely so the compiler cannot pretend the
        // writes above happened without them actually landing.
        let mut observed = 0u8;
        for b in self.bytes.iter() {
            // SAFETY: same reasoning as the write loop above.
            observed |= unsafe { core::ptr::read_volatile(b as *const u8) };
        }
        debug_assert_eq!(core::hint::black_box(observed), 0, "AddressBuf::scrub left a non-zero byte");
        self.len = 0;
    }

    /// The valid address bytes (`bytes[..len]`). `len` is always
    /// `<= CAPACITY` by construction (validated once, not re-checked per
    /// call), so this can never slice out of bounds.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The entire fixed-size backing buffer (all `CAPACITY` bytes,
    /// including any unused tail beyond `len`), for callers that need to
    /// copy the whole fixed-size array out verbatim (e.g. embedding it in
    /// their own fixed-layout record type alongside `len()` separately)
    /// rather than working through the `len`-bounded [`AddressBuf::as_bytes`]
    /// view.
    #[must_use]
    pub fn full_bytes(&self) -> &[u8; Self::CAPACITY] {
        &self.bytes
    }

    /// [`AddressBuf::as_bytes`] interpreted as UTF-8 (every address form
    /// this project renders is pure ASCII, SPEC §24.3). Returns `None` if
    /// the stored bytes are somehow not valid UTF-8 (unreachable for any
    /// address this project's own encoders produce, but this function
    /// stays total rather than panicking).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// Number of valid bytes (`<= CAPACITY`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// `true` iff no bytes have been populated yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ============================================================================
// Entropy source tags (SPEC §19.1) — exact wire values, do not renumber.
// ============================================================================

/// Canonical, versioned entropy-source tags used in transcript source
/// records (SPEC §19.1). Values are the wire format; they are part of the
/// frozen protocol and MUST NOT be renumbered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTag {
    /// `source_bytes`: policy-approved `EFI_RNG_PROTOCOL` output.
    ApprovedEfiRng = 0x01,
    /// `source_bytes`: 64-bit `RDSEED` values, four or more per record.
    X86Rdseed64 = 0x02,
    /// `source_bytes`: supplementary-only `RDRAND` output (SPEC §15.3).
    X86RdrandSupplementary = 0x03,
    /// `source_bytes`: one byte per roll, `0x01..=0x06` (SPEC §17.1).
    DiceRolls = 0x10,
    /// `source_bytes`: one byte per flip, `0x00` = tails, `0x01` = heads.
    CoinFlips = 0x11,
    /// `source_bytes`: raw approved-USB-TRNG-device output, health-checked
    /// (SPEC_USB_TRNG.md §6.1). A machine source — no code branches on the
    /// tag band (`< 0x10` vs `>= 0x10`); the wire value is renumbered above
    /// `0x11` deliberately so appending it keeps [`crate::contracts`]'s
    /// consumer `CANONICAL_TAG_BYTES` (`seed-protocol`) ascending, which is
    /// what makes body-order == ascending-order == bitmap-position-order
    /// hold (SPEC_USB_TRNG.md §6.2). MUST NOT be renumbered to `0x04` or any
    /// value `< 0x10`.
    ApprovedUsbTrng = 0x12,
}

// ============================================================================
// Architecture identifier (SPEC §19.2 canonical transcript)
// ============================================================================

/// Architecture identifier mixed into the canonical entropy transcript
/// (SPEC §19.2). Version 1 supports only `X86_64` (SPEC §5); other
/// variants are reserved for a deferred AArch64 target and MUST NOT be
/// reachable from production code paths in version 1.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchId {
    /// The only architecture version 1 may generate on (SPEC §5, §6).
    X86_64 = 1,
}

// ============================================================================
// Rendering (SPEC §12.2)
// ============================================================================

/// A caller-owned linear framebuffer surface. Implemented once per backend
/// (UEFI GOP in `seed-gop-ui::gop`, `winit`+`softbuffer` in
/// `seed-desktop-test`, and an in-memory `Vec<u32>` test double for host
/// unit tests) so `draw_text`/`draw_word`/`scrub_fill` (SPEC §12.2) are
/// written exactly once against this trait.
pub trait Framebuffer {
    /// Current surface dimensions in pixels, `(width, height)`.
    fn dims(&self) -> (u32, u32);
    /// Write one horizontal run of packed `0xRRGGBB`-ish pixels (backend
    /// decides exact packing) starting at `(x, y)`.
    fn put_row(&mut self, x: u32, y: u32, px: &[u32]);
}

/// Fixed text-rendering style for the embedded bitmap font (SPEC §12.2: no
/// external font files, fixed application-owned rendering routines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Foreground (glyph) color, backend pixel packing.
    pub fg: u32,
    /// Background (fill) color, backend pixel packing.
    pub bg: u32,
}

// ============================================================================
// Fixed buffer-size constants
//
// Every constant below is derived, not guessed, with the derivation left
// in the doc comment so a reviewer can re-check the arithmetic. These are
// the sizes every fixed (`no_alloc`) buffer in the project is built
// against (SPEC §13, §19.1, §20.1); changing one is an orchestrator-level
// contract change exactly like any other item in this file.
// ============================================================================

/// Base58Check output bound (SPEC §24.2/§24.3: P2PKH/P2SH addresses).
///
/// Derivation: the payload is 1 version byte + 20-byte `hash160` + 4-byte
/// checksum = 25 bytes. Base58 expands `n` bytes to at most
/// `n * 138 / 100 + 1` characters (the standard bound used by Bitcoin
/// Core's own `base58.cpp`, itself a safe rounding of
/// `log(256)/log(58) ≈ 1.3657`): `25 * 138 / 100 + 1 = 34 + 1 = 35`.
pub const MAX_B58: usize = 35;

/// Bech32/Bech32m output bound (SPEC §24.2/§24.3: P2WPKH/P2TR addresses).
///
/// Derivation, worst case = the 32-byte v1 (taproot) witness program:
/// `hrp` ("bc"/"tb", reserving up to 4 bytes for headroom) = 4
/// + separator `'1'` = 1
/// + witness-version data character = 1
/// + program converted to 5-bit groups: `ceil(32 * 8 / 5)` = 52
/// + 6-character checksum = 6
/// total = 4 + 1 + 1 + 52 + 6 = 64.
pub const MAX_BECH32: usize = 64;

/// Bound on a machine-source `algorithm_identifier` byte string inside a
/// transcript source record (SPEC §19.1). No protocol-defined identifier
/// (EFI RNG algorithm GUIDs rendered as text, `"RDSEED64"`,
/// `"RDRAND"`) approaches this; 32 bytes leaves generous headroom.
pub const MAX_ALGO_ID: usize = 32;

/// Bound on the raw byte length of a single machine-source record's
/// `source_bytes` (SPEC §15.1, §15.2, §15.3). The largest defined machine
/// payload is the RDSEED64 record, which carries BOTH of its SPEC §16
/// health-checked 256-bit blocks (source block ‖ diagnostic block = 512
/// raw bits = 64 bytes; audit finding L2 — feeding the diagnostic block
/// into the record doubles the raw entropy behind the 256-bit conditioned
/// seed instead of scrubbing it, so there is over-collection margin if
/// RDSEED runs slightly below full entropy). Every other machine source
/// (EFI RNG, RDRAND, USB-TRNG) still emits a single 256-bit block = 32
/// bytes; this is their shared *upper* bound, not their size.
pub const MAX_MACHINE_SOURCE_BYTES: usize = 64;

/// Capacity of the shared dice+coin physical-event history buffer
/// (SPEC §17.3, one fixed-size buffer for the whole session). The
/// SPEC §17.2 *recommended* (not minimum) margin for a 24-word mnemonic
/// tops out at 128 rolls or 320 flips; 512 one-byte events comfortably
/// exceeds either single-method recommended margin with room to spare
/// before the capacity-stop behavior (SPEC §17.3) engages.
pub const MAX_PHYSICAL_EVENTS: usize = 512;

/// Maximum number of source records SPEC §19.1 defines that can
/// realistically appear in one transcript: `ApprovedEfiRng` + `X86Rdseed64`
/// + `X86RdrandSupplementary` + `DiceRolls` + `CoinFlips` +
/// `ApprovedUsbTrng` (SPEC_USB_TRNG.md §6.1, §6.3) = 6.
pub const MAX_SOURCE_RECORDS: usize = 6;

/// Fixed capacity of the canonical entropy transcript buffer
/// (SPEC §19.1, §19.2: "the complete transcript fits a fixed reviewed
/// buffer").
///
/// Derivation:
/// - domain string `b"Alea/Entropy/v1\0"` = 16 bytes
/// - header fields: `architecture_identifier` (2) + `requested_entropy_bits`
///   (2) + `entropy_policy_version` (2) + `source_presence_bitmap` (2,
///   headroom beyond the 6 currently defined tags) + `source_record_count`
///   (1) = 9 bytes
/// - per-record fixed overhead (`source_tag` + `algo_id_length` +
///   `algo_id` + `source_length`) = `1 + 1 + MAX_ALGO_ID + 2` = 36 bytes;
///   up to 4 machine-source records (`ApprovedEfiRng`, `X86Rdseed64`,
///   `X86RdrandSupplementary`, `ApprovedUsbTrng` — SPEC_USB_TRNG.md §6.3) =
///   144 bytes
/// - machine-source payloads: up to 4 records × `MAX_MACHINE_SOURCE_BYTES`
///   (64, since audit finding L2 gave the RDSEED64 record its second
///   256-bit block) = 256 bytes
/// - physical-source records: 2 records (dice + coin) × 36 bytes overhead
///   = 72 bytes, sharing at most `MAX_PHYSICAL_EVENTS` (512) total payload
///   bytes between them
///
/// Raw minimum = 16 + 9 + 144 + 256 + 72 + 512 = 1009 bytes (rose from 881
/// when `MAX_MACHINE_SOURCE_BYTES` doubled 32 → 64 for finding L2). Rounded
/// up to 1024 (a power of two) for alignment headroom and to absorb small
/// protocol-metadata growth without a contract change; 1024 still covers
/// the 1009-byte minimum with no value change.
pub const TRANSCRIPT_CAPACITY: usize = 1024;

#[cfg(test)]
extern crate std;

// ============================================================================
// Tests: AddressBuf encapsulation (pre-release audit SHOULD-FIX #4,
// `docs/PRE-RELEASE-AUDIT.md`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: an over-long construction must saturate rather
    /// than panic. Before this fix, `bytes`/`len` were public and nothing
    /// stopped a caller from setting `len > 92` directly, which would
    /// panic the first `&bytes[..len]` slice read (e.g. the wallet-
    /// verification-display reader). `AddressBuf::new` is now the only
    /// construction path and must saturate `len` to `CAPACITY` instead.
    #[test]
    fn new_saturates_an_over_long_length_instead_of_panicking() {
        let bytes = [0x41u8; 92]; // all b'A'
        let buf = AddressBuf::new(bytes, 1000);

        assert_eq!(buf.len(), AddressBuf::CAPACITY);
        // The real regression: this must not panic.
        assert_eq!(buf.as_bytes().len(), AddressBuf::CAPACITY);
        assert_eq!(buf.as_str(), Some("A".repeat(AddressBuf::CAPACITY)).as_deref());
    }

    /// `set` must apply the same saturating discipline for over-long
    /// input data, and must zero any bytes beyond the copied length.
    #[test]
    fn set_saturates_over_long_data_and_zeroes_the_tail() {
        let mut buf = AddressBuf::empty();
        let too_long = [0x62u8; 200]; // all b'b', longer than CAPACITY
        buf.set(&too_long);

        assert_eq!(buf.len(), AddressBuf::CAPACITY);
        assert_eq!(buf.as_bytes().len(), AddressBuf::CAPACITY);
        assert!(buf.as_bytes().iter().all(|&b| b == 0x62));

        // Re-`set` with something shorter must zero the previously
        // populated tail, not leave stale bytes past the new length.
        buf.set(b"hi");
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.as_bytes(), b"hi");
    }

    #[test]
    fn empty_has_zero_length_and_empty_bytes() {
        let buf = AddressBuf::empty();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes(), &[] as &[u8]);
        assert_eq!(buf.as_str(), Some(""));
    }

    #[test]
    fn new_within_capacity_round_trips_exactly() {
        let mut bytes = [0u8; 92];
        bytes[..5].copy_from_slice(b"hello");
        let buf = AddressBuf::new(bytes, 5);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_str(), Some("hello"));
        assert!(!buf.is_empty());
    }
}
