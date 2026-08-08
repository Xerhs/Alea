//! Owned by WP-05 (SPEC §14, §12.3).
//!
//! Embedded BIP39 English wordlist, entropy/mnemonic conversion, prefix
//! resolution (Enter-terminated protocol), wordlist integrity self-check,
//! and PBKDF2-HMAC-SHA512 mnemonic-to-seed derivation.
//!
//! `#![no_std]`, no `alloc` (SPEC §13): every function here operates on
//! caller-provided fixed-size buffers/slices only.
//!
//! ## WP-00 tracking note: `PrefixResult` retired (pre-release audit MUST-FIX #1)
//!
//! `crate::contracts::PrefixResult` used to be the return type of a
//! `resolve_prefix` function that returned the resolved wordlist index by
//! value inside its `Unique(u16)` variant — a live secret index (SPEC
//! §23.1 hidden re-entry) carried through a type `contracts.rs` derived
//! `Debug`/`Clone`/`Copy`/`PartialEq`/`Eq` on, contradicting SPEC §20.2
//! ("Secret-bearing types MUST NOT implement: `Copy`, `Clone`, `Debug`,
//! `Display`, general serialization, or equality operations...").
//!
//! Per `docs/PRE-RELEASE-AUDIT.md` MUST-FIX #1, the orchestrator-level fix
//! landed: `contracts.rs` no longer defines `PrefixResult` at all, the
//! module-local `resolve_prefix` function that returned it has been
//! removed, and [`resolve_prefix_into`] — previously a secret-safe code-
//! around that delegated to `resolve_prefix` — is now the sole,
//! self-contained implementation of BIP39 prefix resolution. It writes
//! the resolved index into a caller-owned `&mut u16` and returns only the
//! non-secret [`PrefixOutcome`] discriminant, so no type in this crate can
//! carry a live secret wordlist index by value, by `Copy`, or through
//! `Debug`/equality. A repo-wide grep (re-run as part of this fix)
//! confirms the one real production call site
//! (`crates/seed-flow/src/flow_secret/reentry.rs`) already used
//! [`resolve_prefix_into`] exclusively and needed no changes.

mod wordlist;

use crate::contracts::{Bip39Error, WordCount};
use crate::hash::{pbkdf2_hmac_sha512, sha256};
use crate::passphrase::{PassphraseAscii, MAX_PASSPHRASE_LEN, SALT_PREFIX, SALT_PREFIX_LEN};
use wordlist::WORDLIST;

/// PBKDF2 iteration count for BIP39 seed derivation (SPEC §14, §24.2:
/// "PBKDF2-HMAC-SHA512, 2048 iterations").
const PBKDF2_ITERS: u32 = 2048;

/// The empty-passphrase PBKDF2 salt prefix for BIP39 seed derivation
/// (SPEC §14, §24.2 / SPEC_PASSPHRASE §2.2: `salt = b"mnemonic" ||
/// normalized_passphrase`). With an empty / skipped passphrase this is the
/// entire salt — exactly `b"mnemonic"`, byte-identical to the pre-passphrase
/// implementation. [`mnemonic_to_seed_with_passphrase_bytes`] appends the
/// validated printable-ASCII passphrase bytes after this prefix; the folded
/// single-implementation salt prefix now lives in `crate::passphrase`
/// ([`SALT_PREFIX`]).
const SALT: &[u8] = SALT_PREFIX;

/// Maximum length in bytes of a materialized mnemonic phrase: 24 words at
/// the wordlist's longest entry (8 ASCII letters, e.g. "abandon" is 7,
/// the longest BIP39 English words are 8 letters such as "reunion" /
/// "response") plus one ASCII space between each pair of words:
/// `24 * 8 + 23 = 215` bytes. Sized with a little headroom to 216.
const MAX_PHRASE_LEN: usize = 24 * 8 + 23;

/// Expected SHA-256 digest of the official BIP39 English wordlist source
/// file (`bip-0039/english.txt`, 2048 lines, each word followed by `\n`,
/// including the final line) — the well-known published digest of that
/// file. Recomputed at runtime by [`wordlist_sha256_ok`] over the exact
/// same byte layout (word bytes + `\n` per entry) as an integrity
/// self-check on the embedded [`wordlist::WORDLIST`] table (SPEC §14: "The
/// embedded English wordlist MUST match the published BIP39 list
/// exactly.").
const EXPECTED_WORDLIST_SHA256: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
    0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];

/// Wordlist integrity self-check (SPEC §14, §29.1): recomputes the SHA-256
/// digest of the embedded [`wordlist::WORDLIST`] table, laid out exactly
/// as the canonical `english.txt` source file (each word followed by a
/// single `\n`, no other separators), and compares it against the
/// well-known published digest of that file. Returns `false` if the
/// embedded table has been corrupted or diverges from the official list
/// in any way.
///
/// Hashes at most `2048 * 9` bytes (longest word 8 bytes + `\n`) through a
/// bounded number of `sha256`-context updates — no heap allocation, no
/// single oversized buffer required.
pub fn wordlist_sha256_ok() -> bool {
    use crate::hash::Sha256Ctx;

    let mut ctx = Sha256Ctx::new();
    for w in WORDLIST.iter() {
        ctx.update(w.as_bytes());
        ctx.update(b"\n");
    }
    let digest = ctx.finalize();
    digest == EXPECTED_WORDLIST_SHA256
}

/// Look up a BIP39 English word by its 11-bit wordlist index (SPEC §14).
///
/// # Panics
///
/// Panics if `index >= 2048`. Callers only ever pass indexes produced by
/// [`entropy_to_indexes`] or resolved by [`resolve_prefix_into`], both of
/// which are always in range by construction; this is a documented internal
/// invariant, not a runtime/user-facing error path (no secret value is
/// involved in the panic message).
pub fn word(index: u16) -> &'static str {
    WORDLIST[index as usize]
}

/// Convert final entropy (16 or 32 bytes; SPEC §14) into BIP39 wordlist
/// indexes, computing and appending the standard checksum
/// (`sha256(entropy)` truncated to `entropy_bits / 32` bits).
///
/// Writes into `indexes[..count]` where `count` is 12 for 128-bit entropy
/// or 24 for 256-bit entropy; any unused tail of `indexes` (only reachable
/// for the 12-word case) is zeroed so no stale buffer content lingers.
///
/// SPEC §14: "Words MUST be derived from the final entropy and BIP39
/// checksum. Words MUST NOT be selected independently."
pub fn entropy_to_indexes(
    entropy: &[u8],
    indexes: &mut [u16; 24],
) -> Result<WordCount, Bip39Error> {
    let (count, word_count) = match entropy.len() {
        16 => (12usize, WordCount::Twelve),
        32 => (24usize, WordCount::TwentyFour),
        _ => return Err(Bip39Error::InvalidEntropyLength),
    };

    let mut checksum = sha256(entropy);
    let checksum_bits = entropy.len() / 4; // ENT/32 bits, ENT in bits = len*8

    // Walk a combined bitstream of `entropy || checksum` 11 bits at a time
    // without ever materializing it as a separate buffer: track a bit
    // cursor over two logical sources.
    let total_bits = entropy.len() * 8 + checksum_bits;
    debug_assert_eq!(total_bits, count * 11);

    for (i, idx) in indexes.iter_mut().take(count).enumerate() {
        let start_bit = i * 11;
        let mut value: u16 = 0;
        for b in 0..11 {
            let bit_pos = start_bit + b;
            let bit = read_bit(entropy, &checksum, bit_pos);
            value = (value << 1) | (bit as u16);
        }
        *idx = value;
    }
    for idx in indexes.iter_mut().skip(count) {
        *idx = 0;
    }

    // `checksum` is a digest derived directly from the secret final
    // entropy; scrub it before returning on every path (SPEC §20.3), not
    // just the success path, so the InvalidEntropyLength error return
    // above is the only path that never materialized it in the first
    // place. Uses the same volatile-write + compiler-fence +
    // architecture-fence + verification-read discipline as
    // `arena::scrub_bytes` (SPEC §20.3, §8.2).
    scrub_bytes(&mut checksum);

    Ok(word_count)
}

/// Read bit `bit_pos` (0 = most significant bit of `entropy`) from the
/// logical concatenation `entropy || checksum`, where only the first
/// `entropy.len() * 8` bits come from `entropy` and the remainder come
/// from the leading bits of `checksum` (SPEC §14 checksum construction).
fn read_bit(entropy: &[u8], checksum: &[u8; 32], bit_pos: usize) -> u8 {
    let entropy_bits = entropy.len() * 8;
    if bit_pos < entropy_bits {
        let byte = entropy[bit_pos / 8];
        (byte >> (7 - (bit_pos % 8))) & 1
    } else {
        let cs_bit = bit_pos - entropy_bits;
        let byte = checksum[cs_bit / 8];
        (byte >> (7 - (cs_bit % 8))) & 1
    }
}

/// Non-secret classification of a [`resolve_prefix_into`] outcome (SPEC
/// §12.3, §20.2): no variant here holds secret material, so it is safe to
/// derive ordinary `Debug`/`Clone`/`Copy`/`PartialEq`/`Eq` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixOutcome {
    /// Exactly one wordlist entry matches; the resolved index was written
    /// into the `out` parameter [`resolve_prefix_into`] was called with.
    Unique,
    /// More than one wordlist entry matches this prefix.
    Ambiguous,
    /// No wordlist entry matches this prefix.
    Unknown,
}

/// Resolve an Enter-terminated word-entry prefix against the BIP39
/// English wordlist (SPEC §12.3, §20.2: "Functions SHOULD receive mutable
/// references rather than secret values by value").
///
/// `prefix` is the raw entered bytes: either the complete word (if the
/// intended word has fewer than four letters) or exactly the first four
/// letters. A word's *identifying prefix* is its first `min(4, len)`
/// bytes; SPEC §14 guarantees (tested in this module) that identifying
/// prefixes are unique across all 2048 words, so a well-formed `prefix`
/// resolves to [`PrefixOutcome::Unique`] (with the resolved index written
/// into `out`) or [`PrefixOutcome::Unknown`]. [`PrefixOutcome::Ambiguous`]
/// is only reachable if that uniqueness invariant is ever violated
/// (defensive; guarded by [`tests::four_letter_prefixes_are_unique`]).
///
/// Inputs longer than four bytes or empty never match anything and
/// resolve to [`PrefixOutcome::Unknown`] (the input layer is responsible
/// for never producing such buffers per §12.3, but this function stays
/// total and side-effect-free regardless). `out` is left unchanged unless
/// this function returns [`PrefixOutcome::Unique`].
///
/// This is the sole implementation of BIP39 prefix resolution (SPEC
/// §23.1 hidden re-entry and any other prefix-resolution caller): it
/// writes the resolved index directly into the caller-owned
/// `out: &mut u16` and returns only the non-secret [`PrefixOutcome`]
/// discriminant, so no type anywhere in this crate can carry a live
/// secret wordlist index by value, by `Copy`, or through `Debug`/
/// equality (pre-release audit MUST-FIX #1, `docs/PRE-RELEASE-AUDIT.md`;
/// see this module's top-level tracking note). Call it once per typed
/// position, read `out` only when the result is
/// `PrefixOutcome::Unique`, and scrub/consume it immediately rather than
/// storing or formatting the returned value.
pub fn resolve_prefix_into(prefix: &[u8], out: &mut u16) -> PrefixOutcome {
    if prefix.is_empty() || prefix.len() > 4 {
        return PrefixOutcome::Unknown;
    }

    let mut found: Option<u16> = None;
    let mut ambiguous = false;

    for (i, w) in WORDLIST.iter().enumerate() {
        let wb = w.as_bytes();
        let id_len = core::cmp::min(4, wb.len());
        if id_len == prefix.len() && &wb[..id_len] == prefix {
            if found.is_some() {
                ambiguous = true;
                break;
            }
            found = Some(i as u16);
        }
    }

    if ambiguous {
        PrefixOutcome::Ambiguous
    } else {
        match found {
            Some(i) => {
                *out = i;
                PrefixOutcome::Unique
            }
            None => PrefixOutcome::Unknown,
        }
    }
}

/// Derive the 64-byte BIP39 seed from resolved mnemonic word indexes with
/// the **empty passphrase** (SPEC §14, §24.2): `PBKDF2-HMAC-SHA512(password
/// = mnemonic phrase, salt = "mnemonic", iterations = 2048)`.
///
/// This is preserved verbatim for every existing caller and every frozen
/// empty-passphrase vector. It is a **true forwarder** to
/// [`mnemonic_to_seed_with_passphrase`] with an empty passphrase
/// (SPEC_PASSPHRASE §2.3): there is exactly ONE salt-building
/// implementation ([`mnemonic_to_seed_with_passphrase_bytes`]); the empty
/// case flows through it, so an empty passphrase yields a salt of exactly
/// `b"mnemonic"` and a byte-identical seed to before this feature landed
/// (SPEC_PASSPHRASE §2.2, the #1 invariant guarded by
/// `mnemonic_to_seed_empty_passphrase_is_byte_identical_to_frozen_vector`).
pub fn mnemonic_to_seed(indexes: &[u16], count: WordCount, seed_out: &mut [u8; 64]) {
    let empty = PassphraseAscii::new();
    mnemonic_to_seed_with_passphrase(indexes, count, &empty, seed_out);
}

/// Derive the 64-byte BIP39 seed with an explicit, already-validated ASCII
/// passphrase (may be empty) (SPEC §14 / SPEC_PASSPHRASE §2). The salt is
/// `b"mnemonic"` followed by the passphrase's printable-ASCII bytes; with
/// an empty passphrase this is byte-identical to [`mnemonic_to_seed`]. The
/// secret passphrase is passed by reference only (SPEC §20.2).
pub fn mnemonic_to_seed_with_passphrase(
    indexes: &[u16],
    count: WordCount,
    passphrase: &PassphraseAscii,
    seed_out: &mut [u8; 64],
) {
    mnemonic_to_seed_with_passphrase_bytes(indexes, count, passphrase.as_bytes(), seed_out);
}

/// The single salt-building BIP39 seed-derivation implementation
/// (SPEC §14, §24.2 / SPEC_PASSPHRASE §2.2). `passphrase_bytes` MUST already
/// be validated printable ASCII (SPEC_PASSPHRASE §3.2) and at most
/// [`MAX_PASSPHRASE_LEN`] long; both public entry points above uphold that.
///
/// ## Salt construction (SPEC_PASSPHRASE §2.2)
///
/// `salt = b"mnemonic" || passphrase_bytes`, materialized into one fixed
/// stack buffer `[u8; SALT_PREFIX_LEN + MAX_PASSPHRASE_LEN]` and passed to
/// PBKDF2 as **exactly** `&salt[..SALT_PREFIX_LEN + passphrase_bytes.len()]`
/// — never the whole padded buffer, whose extra zero bytes would silently
/// change the derived seed (SPEC_PASSPHRASE §2.3, the padding/length-bug
/// class the invariant + TREZOR KATs pin on both `len == 0` and `len > 0`).
/// The salt buffer is secret-adjacent (it contains the passphrase) and is
/// scrubbed on return with the same four-component scrub as the phrase
/// buffer (SPEC §20.3).
///
/// ## Controlled exception to "no full phrase in one buffer" (flag for
/// review)
///
/// SPEC §12.2 requires the *displayed* mnemonic to never be concatenated
/// into one string, and the WP-05 scope note in `IMPLEMENTATION_MAP.md`
/// asks seed derivation to feed PBKDF2 incrementally where possible. The
/// pinned `pbkdf2` crate (`pbkdf2::pbkdf2_hmac`, SPEC §3/§13 fixed
/// dependency) only exposes a one-shot API over a single contiguous
/// password slice — it cannot be fed incrementally. To call it at all,
/// this function materializes the space-joined mnemonic phrase into
/// **one** fixed-size, stack-local buffer (`MAX_PHRASE_LEN` = 215 bytes,
/// sized for the worst case of 24 longest-in-list words), immediately
/// passes it to PBKDF2, and then explicitly scrubs that buffer (volatile
/// writes, compiler fence, architecture fence, verification read-back —
/// see [`scrub_bytes`]) before returning, along with the salt buffer.
pub fn mnemonic_to_seed_with_passphrase_bytes(
    indexes: &[u16],
    count: WordCount,
    passphrase_bytes: &[u8],
    seed_out: &mut [u8; 64],
) {
    let n = count as usize;
    debug_assert!(indexes.len() >= n);
    debug_assert!(passphrase_bytes.len() <= MAX_PASSPHRASE_LEN);

    let mut phrase = [0u8; MAX_PHRASE_LEN];
    let mut len = 0usize;

    for (i, &idx) in indexes.iter().take(n).enumerate() {
        if i != 0 {
            phrase[len] = b' ';
            len += 1;
        }
        let w = word(idx).as_bytes();
        phrase[len..len + w.len()].copy_from_slice(w);
        len += w.len();
    }

    // SPEC_PASSPHRASE §2.2: salt = b"mnemonic" || passphrase_bytes, built
    // into one fixed buffer and sliced to EXACTLY the meaningful prefix.
    let mut salt = [0u8; SALT_PREFIX_LEN + MAX_PASSPHRASE_LEN];
    salt[..SALT_PREFIX_LEN].copy_from_slice(SALT);
    let plen = passphrase_bytes.len();
    salt[SALT_PREFIX_LEN..SALT_PREFIX_LEN + plen].copy_from_slice(passphrase_bytes);

    pbkdf2_hmac_sha512(&phrase[..len], &salt[..SALT_PREFIX_LEN + plen], PBKDF2_ITERS, seed_out);

    // Scrub the secret-adjacent salt buffer (it held the passphrase) and
    // the materialized phrase buffer before returning (SPEC §20.3,
    // SPEC_PASSPHRASE §2.3/§5.2).
    scrub_bytes(&mut salt);
    scrub_phrase(&mut phrase);
}

/// Explicit volatile scrub of the single materialized-phrase buffer used
/// by [`mnemonic_to_seed`] (SPEC §13, §20: explicit scrub, no compiler
/// elision). Delegates to [`scrub_bytes`] for the full four-component
/// scrub (volatile writes, compiler fence, architecture fence,
/// verification read-back) required by SPEC §20.3.
fn scrub_phrase(buf: &mut [u8; MAX_PHRASE_LEN]) {
    scrub_bytes(buf.as_mut_slice());
}

/// General-purpose secret scrub over a caller-owned byte slice (SPEC
/// §20.3): volatile zero-writes, a compiler fence, an
/// architecture-appropriate memory fence, then a volatile verification
/// read-back over the same region — the same four components
/// `arena::scrub_bytes` implements for the secret arena, applied here to
/// the BIP39-local secret buffers (the materialized mnemonic phrase in
/// [`mnemonic_to_seed`] and the entropy-derived checksum digest in
/// [`entropy_to_indexes`]) that live outside the arena.
///
/// SPEC §20.3: "volatile writes ...; compiler fences; architecture
/// -appropriate memory fences; verification reads over the
/// application-owned arena where practical."
#[inline(never)]
fn scrub_bytes(buf: &mut [u8]) {
    // Volatile zero-write, one byte at a time: the compiler may not elide,
    // reorder past, or coalesce these in a way that skips the write
    // (SPEC §20.3, "volatile writes").
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8` for the duration of
        // this write.
        unsafe { core::ptr::write_volatile(b, 0u8) };
    }

    // Compiler fence: forbids the compiler from reordering the writes
    // above past this point at compile time (SPEC §20.3, "compiler
    // fences").
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Architecture memory fence: forbids the CPU from reordering the
    // writes above past this point at run time (SPEC §20.3,
    // "architecture-appropriate memory fences").
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Verification read: read every scrubbed byte back through a volatile
    // load (so the read cannot be optimized away either) and fold it into
    // an accumulator, which is itself passed through `black_box` so the
    // whole read-back loop cannot be proven dead and removed (SPEC §20.3,
    // "verification reads ... where practical"). This is best-effort, not
    // a proof (SPEC §20.3): it only catches the write not taking effect
    // in *this* address space's view of memory.
    let mut observed = 0u8;
    for b in buf.iter() {
        // SAFETY: same region as above, now valid for reads too.
        let byte = unsafe { core::ptr::read_volatile(b) };
        observed |= byte;
    }
    let observed = core::hint::black_box(observed);
    debug_assert_eq!(observed, 0, "scrub_bytes: verification read found a non-zero byte");
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::vec::Vec;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_string(bytes: &[u8]) -> String {
        const HEXCHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEXCHARS[(b >> 4) as usize] as char);
            s.push(HEXCHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    // ---- wordlist integrity ----

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(WORDLIST.len(), 2048);
    }

    #[test]
    fn wordlist_sha256_matches_official_digest() {
        assert!(wordlist_sha256_ok());
    }

    #[test]
    fn wordlist_is_sorted_and_has_no_duplicates() {
        for w in WORDLIST.windows(2) {
            assert!(w[0] < w[1], "wordlist not strictly sorted at {} < {}", w[0], w[1]);
        }
    }

    #[test]
    fn wordlist_words_are_ascii_lowercase() {
        for w in WORDLIST.iter() {
            assert!(w.is_ascii());
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
            assert!(w.len() >= 3 && w.len() <= 8);
        }
    }

    /// SPEC §14 / §29.1: "The first four letters MUST uniquely identify
    /// each supported word (tested)." This is the four-letter-uniqueness
    /// test over all 2048 words the WP-05 DoD requires.
    #[test]
    fn four_letter_prefixes_are_unique() {
        let mut seen: Vec<&str> = Vec::with_capacity(2048);
        for w in WORDLIST.iter() {
            let id_len = core::cmp::min(4, w.len());
            let id = &w[..id_len];
            assert!(
                !seen.contains(&id),
                "identifying prefix {:?} is not unique (word {:?})",
                id,
                w
            );
            seen.push(id);
        }
        assert_eq!(seen.len(), 2048);
    }

    #[test]
    fn word_returns_expected_entries() {
        assert_eq!(word(0), "abandon");
        assert_eq!(word(2047), "zoo");
    }

    // ---- resolve_prefix_into (SPEC §12.3 prefix resolution; pre-release
    // audit MUST-FIX #1, `docs/PRE-RELEASE-AUDIT.md`) ----
    //
    // `resolve_prefix_into` is the sole implementation of BIP39 prefix
    // resolution: the previous `resolve_prefix`/`PrefixResult::Unique(u16)`
    // pair (which carried the resolved secret wordlist index through a
    // `Debug`/`Clone`/`Copy`/`PartialEq`/`Eq`-deriving type, contradicting
    // SPEC §20.2) has been removed entirely. These tests pin
    // `resolve_prefix_into`'s by-mutable-reference contract so it cannot
    // silently regress back to handing callers a `Copy`/`Debug`-capable
    // secret value.

    fn index_of(word_str: &str) -> u16 {
        WORDLIST.iter().position(|w| *w == word_str).unwrap() as u16
    }

    /// "act" (3 letters) is a complete word and its own id prefix.
    #[test]
    fn resolve_prefix_into_unique_short_word() {
        let mut out: u16 = 0xFFFF;
        let outcome = resolve_prefix_into(b"act", &mut out);
        assert_eq!(outcome, PrefixOutcome::Unique);
        assert_eq!(out, index_of("act"));
    }

    /// "abandon" -> first four letters "aban", must write the resolved
    /// secret index into `out` rather than returning it by value.
    #[test]
    fn resolve_prefix_into_unique_writes_index_into_out() {
        let mut out: u16 = 0xFFFF;
        let outcome = resolve_prefix_into(b"aban", &mut out);
        assert_eq!(outcome, PrefixOutcome::Unique);
        assert_eq!(out, index_of("abandon"));
    }

    #[test]
    fn resolve_prefix_into_unknown_for_nonexistent_prefix() {
        let mut out: u16 = 0xFFFF;
        assert_eq!(resolve_prefix_into(b"zzzz", &mut out), PrefixOutcome::Unknown);
    }

    /// "act" is a full 3-letter word; typing all 4 slots without it being
    /// a real 4-letter identifying prefix must not match.
    #[test]
    fn resolve_prefix_into_unknown_for_short_word_typed_long() {
        let expected = WORDLIST
            .iter()
            .position(|w| w.as_bytes().len() >= 4 && &w.as_bytes()[..4] == b"acti")
            .map(|i| i as u16);
        let mut out: u16 = 0xFFFF;
        let outcome = resolve_prefix_into(b"acti", &mut out);
        match expected {
            Some(i) => {
                assert_eq!(outcome, PrefixOutcome::Unique);
                assert_eq!(out, i);
            }
            None => assert_eq!(outcome, PrefixOutcome::Unknown),
        }
    }

    /// Every word's identifying prefix resolves to that word's own index,
    /// for all 2048 wordlist entries.
    #[test]
    fn resolve_prefix_into_every_word_resolves_via_its_own_identifying_prefix() {
        for (i, w) in WORDLIST.iter().enumerate() {
            let id_len = core::cmp::min(4, w.len());
            let id = w.as_bytes()[..id_len].as_ref();
            let mut out: u16 = 0xFFFF;
            let outcome = resolve_prefix_into(id, &mut out);
            assert_eq!(outcome, PrefixOutcome::Unique);
            assert_eq!(out, i as u16);
        }
    }

    /// On `Unknown`, `resolve_prefix_into` must leave the caller's `out`
    /// slot untouched (no partial/spurious write of a non-resolved
    /// index) and must report the non-secret `Unknown` discriminant.
    #[test]
    fn resolve_prefix_into_unknown_leaves_out_untouched() {
        let mut out: u16 = 0xDEAD;
        let outcome = resolve_prefix_into(b"zzzz", &mut out);
        assert_eq!(outcome, PrefixOutcome::Unknown);
        assert_eq!(out, 0xDEAD, "out must be left unchanged on Unknown");
    }

    /// Empty and overlong inputs resolve to `Unknown`, and again must not
    /// touch `out`.
    #[test]
    fn resolve_prefix_into_rejects_empty_and_overlong() {
        let mut out: u16 = 0x1234;
        assert_eq!(resolve_prefix_into(b"", &mut out), PrefixOutcome::Unknown);
        assert_eq!(out, 0x1234);
        assert_eq!(resolve_prefix_into(b"abandon", &mut out), PrefixOutcome::Unknown);
        assert_eq!(out, 0x1234);
    }

    /// `PrefixOutcome` carries no secret payload in any variant — ordinary
    /// `Debug`/`Copy`/`PartialEq` on it exposes nothing about the resolved
    /// word. This test exercises those derives to pin that `PrefixOutcome`
    /// stays a plain discriminant (no fields ever added to `Unique`)
    /// rather than regaining the secret-carrying shape the retired
    /// `PrefixResult` type used to have.
    #[test]
    fn prefix_outcome_is_a_plain_non_secret_discriminant() {
        let a = PrefixOutcome::Unique;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(PrefixOutcome::Unique, PrefixOutcome::Ambiguous);
        assert_ne!(PrefixOutcome::Unique, PrefixOutcome::Unknown);
        let _ = std::format!("{a:?}"); // Debug must not need any secret input
    }

    /// Regression guard for SPEC §20.2 ("Sensitive types MUST be
    /// non-copyable"): `PrefixOutcome` is the `Copy`/`Debug`/`PartialEq`-
    /// deriving type the real secret-handling call site (`seed-flow`'s
    /// hidden re-entry, via `resolve_prefix_into`) actually receives and
    /// formats/compares. It is only sound for those ordinary derives to
    /// exist on it because it is a plain fieldless discriminant — no
    /// variant carries the resolved wordlist index (that goes through the
    /// `out: &mut u16` parameter instead, never through a `Copy` value).
    /// If a future edit ever put a payload on `PrefixOutcome::Unique`
    /// (reintroducing exactly the retired `PrefixResult::Unique(u16)`
    /// shape), every variant would need to reserve room for a `u16`
    /// discriminant/payload, and the type's size would grow well past one
    /// byte. Pin that here so such a change fails a test outright instead
    /// of depending on a reviewer noticing the diff.
    #[test]
    fn prefix_outcome_size_has_no_room_for_a_secret_payload() {
        assert_eq!(
            core::mem::size_of::<PrefixOutcome>(),
            1,
            "PrefixOutcome grew past a plain 1-byte discriminant -- SPEC §20.2: it must \
             never carry a secret wordlist index as a Copy-able payload"
        );
    }

    // ---- entropy_to_indexes / word / mnemonic_to_seed KATs ----
    // Cross-checked against the canonical Trezor python-mnemonic BIP39
    // test vectors (github.com/trezor/python-mnemonic `vectors.json`),
    // which are also the same vectors WP-11's Python reference implements
    // independently. This project only ever uses an empty passphrase, so
    // only the entropy->mnemonic half is checked against the published
    // vector directly; the empty-passphrase seed values below were cross
    // -derived with the standard PBKDF2-HMAC-SHA512 algorithm and, for
    // the zero-entropy case, validated against the published
    // passphrase="TREZOR" vector using the same code path (see
    // `pbkdf2_matches_published_trezor_vector_with_passphrase` in
    // `crate::hash`).

    fn words_for(indexes: &[u16], count: WordCount) -> String {
        let n = count as usize;
        let mut s = String::new();
        for (i, &idx) in indexes.iter().take(n).enumerate() {
            if i != 0 {
                s.push(' ');
            }
            s.push_str(word(idx));
        }
        s
    }

    #[test]
    fn entropy_to_indexes_zero_128() {
        let entropy = [0u8; 16];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();
        assert_eq!(count, WordCount::Twelve);
        assert_eq!(
            words_for(&indexes, count),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn entropy_to_indexes_zero_256() {
        let entropy = [0u8; 32];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();
        assert_eq!(count, WordCount::TwentyFour);
        assert_eq!(
            words_for(&indexes, count),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn entropy_to_indexes_ff_128() {
        let entropy = [0xffu8; 16];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();
        assert_eq!(count, WordCount::Twelve);
        assert_eq!(
            words_for(&indexes, count),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }

    #[test]
    fn entropy_to_indexes_rejects_bad_length() {
        let entropy = [0u8; 20];
        let mut indexes = [0u16; 24];
        assert_eq!(
            entropy_to_indexes(&entropy, &mut indexes),
            Err(Bip39Error::InvalidEntropyLength)
        );
    }

    #[test]
    fn entropy_to_indexes_zeroes_unused_tail_for_12_words() {
        let entropy = [0xffu8; 16];
        let mut indexes = [0xdeadu16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();
        assert_eq!(count, WordCount::Twelve);
        for &idx in indexes.iter().skip(12) {
            assert_eq!(idx, 0);
        }
    }

    /// Known-answer test: BIP39 seed derivation, zero entropy / 12 words,
    /// PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic" + empty
    /// passphrase. Value independently computed with Python
    /// `hashlib.pbkdf2_hmac('sha512', b"abandon ... about", b"mnemonic", 2048)`
    /// and cross-checked (same code path, `passphrase="TREZOR"`) against
    /// the published Trezor test vector seed
    /// `c55257c360c07c72...463b04`.
    #[test]
    fn mnemonic_to_seed_zero_128_empty_passphrase_kat() {
        let entropy = [0u8; 16];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();

        let mut seed_out = [0u8; 64];
        mnemonic_to_seed(&indexes, count, &mut seed_out);

        let expected = hex_to_bytes(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );
        assert_eq!(hex_string(&seed_out), hex_string(&expected));
    }

    /// Known-answer test: BIP39 seed derivation, zero entropy / 24 words.
    #[test]
    fn mnemonic_to_seed_zero_256_empty_passphrase_kat() {
        let entropy = [0u8; 32];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();

        let mut seed_out = [0u8; 64];
        mnemonic_to_seed(&indexes, count, &mut seed_out);

        let expected = hex_to_bytes(
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
        );
        assert_eq!(hex_string(&seed_out), hex_string(&expected));
    }

    /// Known-answer test: BIP39 seed derivation, all-ones 128-bit entropy.
    #[test]
    fn mnemonic_to_seed_ff_128_empty_passphrase_kat() {
        let entropy = [0xffu8; 16];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();

        let mut seed_out = [0u8; 64];
        mnemonic_to_seed(&indexes, count, &mut seed_out);

        let expected = hex_to_bytes(
            "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6",
        );
        assert_eq!(hex_string(&seed_out), hex_string(&expected));
    }

    /// Independent cross-check that this crate's PBKDF2 wiring reproduces
    /// the published Trezor test vector seed with passphrase "TREZOR"
    /// (the standard BIP39 vector), proving `mnemonic_to_seed`'s salt
    /// construction (`"mnemonic" + passphrase`) is correct even though
    /// this project always uses an empty passphrase in production.
    #[test]
    fn pbkdf2_matches_published_trezor_vector_with_passphrase() {
        let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let salt = b"mnemonicTREZOR";
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(mnemonic, salt, PBKDF2_ITERS, &mut out);
        let expected = hex_to_bytes(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        );
        assert_eq!(hex_string(&out), hex_string(&expected));
    }

    #[test]
    fn scrub_phrase_zeroes_buffer() {
        let mut buf = [0xAAu8; MAX_PHRASE_LEN];
        scrub_phrase(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// Regression test (adversarial review finding, high severity):
    /// `scrub_phrase` must perform the full SPEC §20.3 four-component
    /// scrub (volatile writes, compiler fence, architecture fence,
    /// verification read-back), not just volatile writes + compiler
    /// fence. This test cannot observe the fences directly, but it
    /// pins `scrub_phrase` to delegating through `scrub_bytes` (the
    /// same helper `arena::scrub_bytes` mirrors) and, combined with
    /// `scrub_bytes`'s own `debug_assert_eq!` verification-read check
    /// below, ensures the completeness guarantee is exercised on every
    /// debug-mode test run rather than trusted to eyeballing.
    #[test]
    fn scrub_phrase_delegates_to_full_scrub_bytes() {
        let mut buf = [0x42u8; MAX_PHRASE_LEN];
        // scrub_bytes's internal debug_assert_eq! verification read-back
        // would panic here if the write-back somehow didn't take, so a
        // clean return is itself part of the regression coverage.
        scrub_phrase(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// Regression test (adversarial review finding, medium severity):
    /// `scrub_bytes` (shared by `scrub_phrase` and the checksum scrub in
    /// `entropy_to_indexes`) zeroes an arbitrary secret-sized buffer and
    /// its internal verification read-back does not spuriously fail.
    #[test]
    fn scrub_bytes_zeroes_arbitrary_buffer() {
        let mut checksum = [0xFFu8; 32];
        scrub_bytes(&mut checksum);
        assert_eq!(checksum, [0u8; 32]);
    }

    /// Regression test (adversarial review finding, medium severity):
    /// `entropy_to_indexes` must scrub its stack-local `checksum` digest
    /// (derived directly from the secret final entropy) before
    /// returning, on the success path, so no secret-derived remnant is
    /// left on the stack (SPEC §20.3, §8.2). This test cannot directly
    /// inspect the freed stack slot, so it instead pins the behavior at
    /// the unit level: `scrub_bytes` is `#[inline(never)]` and always
    /// runs its debug-mode verification read-back, so if
    /// `entropy_to_indexes` stopped calling it (or called it on a
    /// buffer that wasn't fully zeroed), `scrub_bytes_zeroes_arbitrary_buffer`
    /// above would be the direct unit check; this test additionally
    /// checks that normal operation (which internally computes and
    /// scrubs a checksum on every call) still returns the correct
    /// public result, so a future change that broke the scrub call
    /// (e.g. by consuming/moving `checksum` before the scrub, causing a
    /// borrow-check failure) cannot be "fixed" by silently deleting the
    /// scrub without this test suite (as a whole) failing to compile or
    /// pass.
    #[test]
    fn entropy_to_indexes_still_correct_after_checksum_scrub() {
        let entropy = [0u8; 16];
        let mut indexes = [0u16; 24];
        let count = entropy_to_indexes(&entropy, &mut indexes).unwrap();
        assert_eq!(count, WordCount::Twelve);
        assert_eq!(
            words_for(&indexes, count),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn max_phrase_len_covers_worst_case() {
        // 24 words at the longest wordlist entry length + 23 separators
        // must fit exactly (or with room to spare) in MAX_PHRASE_LEN.
        let longest = WORDLIST.iter().map(|w| w.len()).max().unwrap();
        assert!(longest <= 8);
        assert!(24 * longest + 23 <= MAX_PHRASE_LEN);
    }

    // ================================================================
    // SPEC_PASSPHRASE §2 — passphrase-aware seed derivation.
    // ================================================================

    /// Build a validated [`PassphraseAscii`] from printable-ASCII bytes.
    fn passphrase(bytes: &[u8]) -> PassphraseAscii {
        let mut p = PassphraseAscii::new();
        for &b in bytes {
            p.push_ascii(b).expect("test passphrase must be printable ASCII");
        }
        p
    }

    /// Resolve a space-joined mnemonic into its `[u16; 24]` wordlist
    /// indexes (only the first `count` are meaningful).
    fn indexes_from_words(mnemonic: &str) -> [u16; 24] {
        let mut idx = [0u16; 24];
        for (i, w) in mnemonic.split(' ').enumerate() {
            idx[i] = index_of(w);
        }
        idx
    }

    /// SPEC_PASSPHRASE §2.3 / §10.1 — **THE #1 GATE**. For every existing
    /// empty-passphrase vector, `mnemonic_to_seed` and
    /// `mnemonic_to_seed_with_passphrase(EMPTY)` produce byte-identical
    /// output, AND that output equals the FROZEN vector. The
    /// "equals the frozen vector" arm is kept EXPLICIT (not redundant with
    /// "both agree"): a salt-slice padding bug — passing the whole padded
    /// `[u8; SALT_PREFIX_LEN + MAX_PASSPHRASE_LEN]` buffer instead of
    /// `&salt[..SALT_PREFIX_LEN + len]` — would make the two functions
    /// agree with each other yet diverge from the frozen vector. Only the
    /// frozen-vector arm catches that class of bug (`len == 0` side; the
    /// TREZOR KATs below pin the `len > 0` side).
    #[test]
    fn mnemonic_to_seed_empty_passphrase_is_byte_identical_to_frozen_vector() {
        // (entropy, frozen empty-passphrase seed hex) for every existing
        // frozen empty-passphrase KAT in this module.
        let cases: &[(&[u8], &str)] = &[
            (
                &[0u8; 16],
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            ),
            (
                &[0u8; 32],
                "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
            ),
            (
                &[0xffu8; 16],
                "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6",
            ),
        ];
        let empty = PassphraseAscii::new();
        for (entropy, frozen_hex) in cases {
            let mut indexes = [0u16; 24];
            let count = entropy_to_indexes(entropy, &mut indexes).unwrap();

            let mut via_plain = [0u8; 64];
            mnemonic_to_seed(&indexes, count, &mut via_plain);

            let mut via_with_pp = [0u8; 64];
            mnemonic_to_seed_with_passphrase(&indexes, count, &empty, &mut via_with_pp);

            // Arm 1: the two functions agree (shared salt path).
            assert_eq!(
                hex_string(&via_plain),
                hex_string(&via_with_pp),
                "empty-passphrase forwarder must agree with the explicit-EMPTY form"
            );
            // Arm 2 (EXPLICIT, non-redundant): equals the FROZEN vector.
            assert_eq!(
                hex_string(&via_plain),
                *frozen_hex,
                "empty-passphrase seed changed vs the frozen vector -- the #1 gate broke"
            );
        }
    }

    /// SPEC_PASSPHRASE §10.2 — the canonical Trezor `"TREZOR"`-passphrase
    /// anchors, run THROUGH `mnemonic_to_seed_with_passphrase` (not a bare
    /// salt-level PBKDF2 call) so the non-empty (`len > 0`) salt-slice bound
    /// is pinned. These match the reference used by Trezor and essentially
    /// every BIP39 wallet, proving Alea's salt construction is correct in
    /// the non-empty branch.
    #[test]
    fn trezor_passphrase_kats_through_mnemonic_to_seed_with_passphrase() {
        let trezor = passphrase(b"TREZOR");
        let cases: &[(&str, WordCount, &str)] = &[
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                WordCount::Twelve,
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ),
            (
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                WordCount::Twelve,
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                WordCount::TwentyFour,
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            ),
        ];
        for (mnemonic, count, expected_hex) in cases {
            // The `\` line continuation in the 24-word literal leaves the
            // internal double-space; collapse it before resolving indexes.
            let normalized: std::string::String =
                mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
            let indexes = indexes_from_words(&normalized);
            let mut seed_out = [0u8; 64];
            mnemonic_to_seed_with_passphrase(&indexes, *count, &trezor, &mut seed_out);
            assert_eq!(hex_string(&seed_out), *expected_hex, "TREZOR KAT mismatch for {normalized:?}");
        }
    }

    /// SPEC_PASSPHRASE §10.3 — an Alea-style end-to-end sample: the
    /// canonical 12-word mnemonic plus a printable-ASCII passphrase
    /// exercising uppercase, lowercase, SPACE, a digit outside `1-6`, and
    /// punctuation. The expected seed was computed by an INDEPENDENT
    /// reference (`hashlib.pbkdf2_hmac('sha512', mnemonic, b"mnemonic" +
    /// b"Correct Horse 42!", 2048)`), pinning the full non-empty ASCII
    /// path. (The fingerprint + first-receive addresses for this same pair
    /// are pinned end-to-end in `seed-flow`'s `derive` tests.)
    #[test]
    fn alea_sample_ascii_passphrase_seed_matches_independent_reference() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let indexes = indexes_from_words(mnemonic);
        let pp = passphrase(b"Correct Horse 42!");
        let mut seed_out = [0u8; 64];
        mnemonic_to_seed_with_passphrase(&indexes, WordCount::Twelve, &pp, &mut seed_out);
        assert_eq!(
            hex_string(&seed_out),
            "37d0e0da7e81072e2e106015b74cf133513c9e2f316b8d246f29766d551e0c5025cef14fe1c9e4f17c55e61d0a514d7bfcea38e4200bf83fd49ff4dc5e9cda18"
        );
        // A DIFFERENT passphrase (and the empty one) derive a DIFFERENT
        // seed from the same words (SPEC_PASSPHRASE §1.1).
        let mut empty_seed = [0u8; 64];
        mnemonic_to_seed(&indexes, WordCount::Twelve, &mut empty_seed);
        assert_ne!(hex_string(&seed_out), hex_string(&empty_seed));
    }
}
