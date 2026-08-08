//! BIP39 passphrase secret type (SPEC_PASSPHRASE §3, §5).
//!
//! `#![no_std]`, no `alloc`: a fixed-size, secret-bearing buffer holding an
//! optional user-chosen BIP39 passphrase (the "25th word", SPEC_PASSPHRASE
//! §1.1). Restricted to **printable ASCII** (`0x20`–`0x7E`), over which
//! Unicode NFKD is the identity map, so the typed bytes ARE the
//! NFKD-normalized salt bytes with zero normalization code
//! (SPEC_PASSPHRASE §3.2). Non-ASCII input is REJECTED, never silently
//! derived into a mismatching wallet (SPEC_PASSPHRASE §3.2 rationale).
//!
//! ## Secret discipline (SPEC §20.2 / SPEC_PASSPHRASE §5.1)
//!
//! [`PassphraseAscii`] follows the same discipline as
//! `seed_flow::flow_secret::physical::PhysicalStaging`: it implements
//! **none** of `Copy`, `Clone`, `Debug`, `Display`, serialization, or a
//! content-equality trait (`PartialEq`/`Eq`) that could early-exit on
//! secret bytes. The only comparison is the dedicated **constant-time**
//! [`PassphraseAscii::ct_eq`] used for the SPEC_PASSPHRASE §4.1 confirm
//! check. It is passed by reference only, never by value, and carries a
//! [`Drop`] scrub (via [`crate::arena::scrub_slice`]) as a
//! defense-in-depth backstop on normal returns.
//!
//! ## Arena residency (SPEC_PASSPHRASE §5.1, M3)
//!
//! The seed-equivalent committed passphrase is intended to live inside the
//! [`crate::arena::SecretArena`] (as its `passphrase`/`passphrase_confirm`
//! fields), so the SPEC §26 whole-arena shutdown scrub AND the SPEC §20.4
//! `#[panic_handler]` whole-arena scrub both reach it deterministically —
//! `panic = "abort"` skips `Drop`, so `Drop` alone is not relied upon for
//! the abort path (SPEC_PASSPHRASE §5.2).

use crate::arena::scrub_slice;

/// Maximum passphrase length in bytes (SPEC_PASSPHRASE §3.3). Printable
/// ASCII is 1 byte per character, so this is 128 characters — ~840 bits of
/// theoretical space, vastly beyond the seed's own entropy, so it never
/// bottlenecks security while keeping the fixed buffer small. Single named
/// constant so a future bump is a one-line change.
pub const MAX_PASSPHRASE_LEN: usize = 128;

/// The fixed PBKDF2 salt prefix (SPEC_PASSPHRASE §2.2: `salt = b"mnemonic"
/// || normalized_passphrase`). With an empty passphrase the salt is exactly
/// this literal, byte-identical to the pre-feature `SALT` constant.
pub const SALT_PREFIX: &[u8] = b"mnemonic";

/// Length in bytes of [`SALT_PREFIX`] (`"mnemonic"` = 8 bytes).
pub const SALT_PREFIX_LEN: usize = 8;

/// Lowest / highest accepted printable-ASCII byte (SPEC_PASSPHRASE §3.2).
const ASCII_MIN: u8 = 0x20; // SPACE
const ASCII_MAX: u8 = 0x7E; // '~'

/// `true` iff `byte` is printable ASCII (`0x20`–`0x7E`), the exact range
/// over which NFKD is the identity map (SPEC_PASSPHRASE §3.2). Every other
/// byte — control chars (incl. Tab `0x09`), DEL (`0x7F`), and anything
/// `>= 0x80` (non-ASCII / multi-byte UTF-8) — is rejected.
#[must_use]
pub const fn is_printable_ascii(byte: u8) -> bool {
    byte >= ASCII_MIN && byte <= ASCII_MAX
}

/// Why a keystroke was refused by [`PassphraseAscii::push_char`] /
/// [`PassphraseAscii::push_ascii`]. Non-secret (a plain discriminant), so
/// ordinary derives are fine (SPEC §27.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseInputError {
    /// The byte was outside printable ASCII `0x20`–`0x7E`
    /// (SPEC_PASSPHRASE §3.2): rejected, never silently accepted.
    NotPrintableAscii,
    /// The buffer already held [`MAX_PASSPHRASE_LEN`] bytes
    /// (SPEC_PASSPHRASE §3.3): refused, never truncated.
    Full,
}

/// A secret-bearing, printable-ASCII BIP39 passphrase buffer
/// (SPEC_PASSPHRASE §5.1). See the module doc comment for the type
/// discipline it upholds.
///
/// Invariant: every byte at or beyond `len` is zero (`push_char` writes
/// exactly one cell, `backspace` scrubs exactly the removed cell, and
/// `scrub` zeroes the whole buffer). This makes the full-region
/// [`PassphraseAscii::ct_eq`] equivalent to a length+prefix comparison, and
/// keeps `as_bytes()` free of stale trailing content.
pub struct PassphraseAscii {
    buf: [u8; MAX_PASSPHRASE_LEN],
    len: usize,
}

impl PassphraseAscii {
    /// A fresh, empty passphrase — the byte-identical-to-today default
    /// (SPEC_PASSPHRASE §2.2). `const` so it can initialize the
    /// [`crate::arena::SecretArena`] const constructor.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: [0u8; MAX_PASSPHRASE_LEN], len: 0 }
    }

    /// Current length in bytes / printable-ASCII characters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` iff no passphrase has been entered (the empty / skip case,
    /// byte-identical to today — SPEC_PASSPHRASE §2.2).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `true` iff the buffer is at [`MAX_PASSPHRASE_LEN`] and cannot accept
    /// another byte (SPEC_PASSPHRASE §3.3).
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == MAX_PASSPHRASE_LEN
    }

    /// The entered bytes (`&self.buf[..self.len]`) — exactly the
    /// NFKD-normalized passphrase bytes appended to the PBKDF2 salt
    /// (SPEC_PASSPHRASE §2.2/§3.2). Empty for the default/skip case.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Append one already-`u8` byte, validating it is printable ASCII and
    /// that space remains (SPEC_PASSPHRASE §3.2/§3.3). On `Err` the buffer
    /// is left completely unchanged (no partial/spurious write).
    ///
    /// # Errors
    ///
    /// [`PassphraseInputError::NotPrintableAscii`] if `byte` is outside
    /// `0x20`–`0x7E`; [`PassphraseInputError::Full`] if the buffer is
    /// already at [`MAX_PASSPHRASE_LEN`].
    pub fn push_ascii(&mut self, byte: u8) -> Result<(), PassphraseInputError> {
        if !is_printable_ascii(byte) {
            return Err(PassphraseInputError::NotPrintableAscii);
        }
        if self.is_full() {
            return Err(PassphraseInputError::Full);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    /// Append one `char`, rejecting any non-printable-ASCII code point
    /// (SPEC_PASSPHRASE §3.2). A multi-byte / non-ASCII `char` is refused
    /// with [`PassphraseInputError::NotPrintableAscii`] — Alea never
    /// silently accepts a byte it cannot guarantee is NFKD-stable.
    ///
    /// # Errors
    ///
    /// As [`PassphraseAscii::push_ascii`]; additionally any non-ASCII
    /// `char` maps to [`PassphraseInputError::NotPrintableAscii`].
    pub fn push_char(&mut self, c: char) -> Result<(), PassphraseInputError> {
        if !c.is_ascii() {
            return Err(PassphraseInputError::NotPrintableAscii);
        }
        self.push_ascii(c as u8)
    }

    /// Remove and volatile-scrub the last byte (Backspace / undo,
    /// SPEC_PASSPHRASE §4.3/§5.2 "scrub the removed byte cell"). A no-op on
    /// an empty buffer.
    pub fn backspace(&mut self) {
        if self.len == 0 {
            return;
        }
        self.len -= 1;
        scrub_slice(core::slice::from_mut(&mut self.buf[self.len]));
    }

    /// Volatile-scrub the whole buffer and reset to empty
    /// (SPEC_PASSPHRASE §5.2). Uses the reviewed volatile-write + fence +
    /// verification-read primitive [`scrub_slice`].
    pub fn scrub(&mut self) {
        scrub_slice(&mut self.buf);
        self.len = 0;
    }

    /// Constant-time equality of two passphrases (SPEC_PASSPHRASE §4.1
    /// confirm compare). Runs over the **full padded [`MAX_PASSPHRASE_LEN`]
    /// region** with no early exit, folding the length difference into the
    /// same accumulator, so timing is uniform regardless of content or
    /// length (SPEC §20.2). `black_box` prevents the accumulator loop from
    /// being short-circuited.
    ///
    /// This is a cleanliness/consistency property (there is no remote
    /// timing channel in a local one-shot ceremony), keeping the
    /// secret-compare discipline uniform with the rest of §20.2.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut acc: u8 = 0;
        for i in 0..MAX_PASSPHRASE_LEN {
            acc |= self.buf[i] ^ other.buf[i];
        }
        // Fold the length difference in (defense in depth: with the
        // "no interior zeros" invariant the buffers already differ on a
        // length mismatch, but folding length keeps the check total).
        let len_diff = (self.len ^ other.len) as u64;
        let mut folded = 0u8;
        let mut shift = 0;
        while shift < 64 {
            folded |= (len_diff >> shift) as u8;
            shift += 8;
        }
        acc |= folded;
        core::hint::black_box(acc) == 0
    }
}

impl Default for PassphraseAscii {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PassphraseAscii {
    /// Defense-in-depth scrub on normal returns (SPEC_PASSPHRASE §5.2).
    /// `panic = "abort"` skips this, which is why the committed passphrase
    /// lives in the arena and is also covered by the whole-arena / panic
    /// scrub (SPEC_PASSPHRASE §5.1/§5.2, M3).
    fn drop(&mut self) {
        self.scrub();
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty_and_zeroed() {
        let p = PassphraseAscii::new();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        assert_eq!(p.as_bytes(), &[] as &[u8]);
        assert!(p.buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn push_accepts_every_printable_ascii_byte() {
        for byte in 0x20u8..=0x7E {
            let mut p = PassphraseAscii::new();
            assert_eq!(p.push_ascii(byte), Ok(()));
            assert_eq!(p.as_bytes(), &[byte]);
        }
    }

    #[test]
    fn push_rejects_representative_non_ascii_and_control_bytes_without_mutating() {
        // SPEC_PASSPHRASE §10.4: 0x00, Tab 0x09, 0x1F, DEL 0x7F, 0x80, and
        // the two UTF-8 bytes of `é` (0xC3 0xA9) are all refused, leaving
        // the buffer untouched.
        for byte in [0x00u8, 0x09, 0x1F, 0x7F, 0x80, 0xC3, 0xA9] {
            let mut p = PassphraseAscii::new();
            p.push_ascii(b'a').unwrap();
            assert_eq!(p.push_ascii(byte), Err(PassphraseInputError::NotPrintableAscii));
            assert_eq!(p.as_bytes(), b"a", "a rejected byte must not mutate the buffer");
        }
    }

    #[test]
    fn push_char_rejects_non_ascii_char() {
        let mut p = PassphraseAscii::new();
        assert_eq!(p.push_char('é'), Err(PassphraseInputError::NotPrintableAscii));
        assert_eq!(p.push_char('\t'), Err(PassphraseInputError::NotPrintableAscii));
        assert!(p.is_empty());
        assert_eq!(p.push_char('A'), Ok(()));
        assert_eq!(p.push_char(' '), Ok(()));
        assert_eq!(p.push_char('~'), Ok(()));
        assert_eq!(p.as_bytes(), b"A ~");
    }

    #[test]
    fn exactly_max_len_accepted_one_more_refused_not_truncated() {
        let mut p = PassphraseAscii::new();
        for _ in 0..MAX_PASSPHRASE_LEN {
            p.push_ascii(b'x').unwrap();
        }
        assert!(p.is_full());
        assert_eq!(p.len(), MAX_PASSPHRASE_LEN);
        assert_eq!(p.push_ascii(b'y'), Err(PassphraseInputError::Full));
        assert_eq!(p.len(), MAX_PASSPHRASE_LEN, "must not truncate/overwrite");
        assert!(p.as_bytes().iter().all(|&b| b == b'x'));
    }

    #[test]
    fn backspace_scrubs_removed_cell_and_keeps_no_interior_bytes() {
        let mut p = PassphraseAscii::new();
        for &b in b"abc" {
            p.push_ascii(b).unwrap();
        }
        p.backspace();
        assert_eq!(p.as_bytes(), b"ab");
        // The removed cell is volatile-scrubbed to zero, upholding the
        // "no bytes at or beyond len" invariant.
        assert_eq!(p.buf[2], 0);
        p.backspace();
        p.backspace();
        p.backspace(); // no-op on empty
        assert!(p.is_empty());
        assert!(p.buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn scrub_zeroes_everything() {
        let mut p = PassphraseAscii::new();
        for &b in b"Correct Horse 42!" {
            p.push_ascii(b).unwrap();
        }
        p.scrub();
        assert!(p.is_empty());
        assert!(p.buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn ct_eq_true_for_identical_and_false_for_any_difference() {
        let mk = |s: &[u8]| {
            let mut p = PassphraseAscii::new();
            for &b in s {
                p.push_ascii(b).unwrap();
            }
            p
        };
        assert!(mk(b"Correct Horse 42!").ct_eq(&mk(b"Correct Horse 42!")));
        assert!(mk(b"").ct_eq(&mk(b"")));
        assert!(!mk(b"Correct Horse 42!").ct_eq(&mk(b"Correct Horse 42?")));
        assert!(!mk(b"abc").ct_eq(&mk(b"abcd")), "length mismatch must not compare equal");
        assert!(!mk(b"abc").ct_eq(&mk(b"")), "non-empty vs empty must differ");
    }
}
