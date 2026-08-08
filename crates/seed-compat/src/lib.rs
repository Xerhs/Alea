//! `seed-compat` — cross-device dice/coin **verification** mode
//! (SPEC_COMPAT.md, "Method A": `SHA256(ASCII event string)` -> BIP39).
//!
//! Owned by WP-C1 (IMPLEMENTATION_MAP_COMPAT.md §4). This crate reproduces
//! the *documented* preimage math of three real wallets (COLDCARD dice,
//! SeedSigner dice, SeedSigner coin flips) plus one internal digest oracle
//! (Ian Coleman BIP39 tool in Hex mode), so a user can type the same
//! dice/coin events into `tools/compat-verify` (WP-C4, not this crate) and
//! confirm their device's math matches the vendor's own published
//! algorithm. It is **not** an Alea seed generator: every value this
//! crate produces is a reproduction of a *foreign* preimage over
//! caller-declared public/throwaway events (SPEC_COMPAT §2, §4).
//!
//! ## Scope and isolation (SPEC_COMPAT §9, IMPLEMENTATION_MAP_COMPAT.md §1
//! rule 4 / §6)
//!
//! - `#![no_std]`, no `alloc`: every function here operates on
//!   caller-provided fixed-size buffers/slices only, matching `seed-core`'s
//!   own discipline (SPEC §13).
//! - Depends only on `seed-core` (SHA-256, BIP39 entropy->indexes). Does
//!   **not** depend on `seed-protocol` (transcript/policy) or any
//!   machine-RNG code, and is not reachable from `seed-uefi-production`
//!   (enforced by WP-C5's scanner + `cargo tree` check, not by this crate
//!   itself — this crate simply never introduces the dependency edge).
//! - Closed enum discipline (SPEC_COMPAT §6): [`CompatMethod`] is a closed
//!   set. [`CompatMethod::Sha256AsciiDigest`] (**Method A**) is the digest
//!   construction the four [`PROFILES`] use. [`CompatMethod::EntropyEncodingRaw`]
//!   (**Method C**, SPEC_COMPAT_ENTROPY.md) is the verification-only
//!   raw-entropy front end for the six `iancoleman/bip39` typed encodings —
//!   it lives in the [`entropy_encoding`] module, is NOT a `PROFILES` entry
//!   (it is encoding-selected, not device-profiled), and reuses the SAME
//!   `seed_core::bip39` pipeline unchanged (SPEC_COMPAT_ENTROPY §5.7). The
//!   legacy Method-B deferral (Ian Coleman native base-6 raw entropy,
//!   SPEC_COMPAT §5.2) is superseded by Method C's Dice/Base-6 slice
//!   (SPEC_COMPAT_ENTROPY §4), which promotes it to an implemented,
//!   verification-only target.
//!
//! ## Verification-only isolation (SPEC_COMPAT_ENTROPY §2)
//!
//! Method C is a cross-device VERIFICATION path, never a production
//! generation source: typed symbols are unwitnessed/uncounted. The
//! authoritative isolation is the dependency graph —
//! `seed-uefi-production` MUST NOT depend on `seed-compat` (verified by
//! `cargo tree`), so this code physically cannot appear in the production
//! binary. The binary-policy scanner is defense-in-depth keyed on the
//! *distinctive* [`entropy_encoding::METHOD_ID`] / watermark tokens, never
//! the generic encoding-id words.
//!
//! ## F1 — the whole point (SPEC_COMPAT §5.1.2/§5.1.3/§6, review F1)
//!
//! SeedSigner does not treat word count as a free caller choice: it is a
//! pure function of the exact input length, and the real device/CLI
//! *refuses* any length outside the canonical set. [`compat_derive`] mirrors
//! that refusal exactly for [`WordCountRule::DerivedFromLength`] profiles —
//! it never fabricates a phrase for a count the real device would reject.
//! This is the single most important correctness property of this crate;
//! see the `f1_refusal_*` tests below.
#![no_std]

use seed_core::contracts::WordCount as CoreWordCount;
use seed_core::hash::sha256;

/// Method C — `EntropyEncodingRaw`: the verification-only raw-entropy front
/// end for the six `iancoleman/bip39` typed encodings (SPEC_COMPAT_ENTROPY.md).
pub mod entropy_encoding;

// ============================================================================
// Frozen contracts (IMPLEMENTATION_MAP_COMPAT.md §3; SPEC_COMPAT §6, §12)
// ============================================================================

/// Closed set of reviewed entropy-preimage constructions (SPEC_COMPAT §6,
/// SPEC_COMPAT_ENTROPY §4). Adding a variant is a reviewed code +
/// external-review change, never a data-driven addition
/// (IMPLEMENTATION_MAP_COMPAT.md §1 rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatMethod {
    /// **Method A.** `entropy = SHA256(ascii event string)`, truncated to
    /// `digest[..16]` (12 words) or used in full as `digest[..32]` (24
    /// words); then standard BIP39 (SPEC §14). This is the **digest step
    /// only** — how the 12-vs-24 choice is made is governed by
    /// [`WordCountRule`], not by this enum (SPEC_COMPAT §5.1, §6). The four
    /// [`PROFILES`] all use this variant.
    Sha256AsciiDigest,
    /// **Method C** (SPEC_COMPAT_ENTROPY.md). The `iancoleman/bip39`
    /// **raw-entropy** front end: a per-symbol `eventBits` bit-table lookup
    /// + concatenation over one of the six typed encodings
    /// ([`entropy_encoding::Encoding`]), the last-32·k-bit leading-discard
    /// truncation, then the SAME `seed_core::bip39` pipeline unchanged
    /// (**no SHA-256** on the concatenated bits — that hashed branch is
    /// Method A). This is a **verification-only** construction
    /// (SPEC_COMPAT_ENTROPY §2), never a production generation source, and
    /// is encoding-selected rather than device-profiled — so it is NOT a
    /// [`PROFILES`] entry; the front end lives in [`entropy_encoding`].
    /// It supersedes the education-only Method-B deferral (SPEC_COMPAT §5.2)
    /// for the Dice/Base-6 slice (SPEC_COMPAT_ENTROPY §4).
    EntropyEncodingRaw,
}

/// The alphabet of ASCII characters a profile's event string is validated
/// against before hashing (SPEC_COMPAT §5.1, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAlphabet {
    /// Physical dice digits `'1'..='6'`, ASCII, hashed **as-is** — digit
    /// `'6'` (`0x36`) is never remapped to `'0'`/`0x30` (SPEC_COMPAT §5.1.2,
    /// review F8).
    Dice1to6,
    /// Coin flips, literal ASCII `'0'` / `'1'` characters (SPEC_COMPAT
    /// §5.1.3).
    Coin01,
}

/// How a profile selects word count from an event string (SPEC_COMPAT §6,
/// review F1). This changes the *output words themselves*, so it is part of
/// the reviewed profile record, never a free caller parameter applied
/// uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCountRule {
    /// Word count is a pure function of the exact input length, and any
    /// length outside the canonical set is **refused** — never coerced,
    /// never shown as a fabricated phrase (SPEC_COMPAT §5.1.2/§5.1.3, review
    /// F1). Matches SeedSigner `mnemonic_generation.py` /
    /// `tools/mnemonic.py`: `len == len12` -> 12 words (`digest[..16]`);
    /// `len == len24` -> 24 words (full digest); any other length ->
    /// [`CompatError::Refused`].
    DerivedFromLength {
        /// Exact event-string length that selects 12 words (e.g. 50 dice
        /// rolls, 128 coin flips).
        len12: u16,
        /// Exact event-string length that selects 24 words (e.g. 99 dice
        /// rolls, 256 coin flips).
        len24: u16,
    },
    /// The caller chooses 12 or 24 words via `requested`; the canonical
    /// counts below are **advisory minimums only** — never enforced, never
    /// a refusal (SPEC_COMPAT §5.1.1, §6). Matches COLDCARD's separate
    /// `rolls12.py` / `rolls.py` scripts and the `iancoleman-hex` digest
    /// oracle.
    FreeChoice {
        /// Vendor-stated advisory minimum event count for a 12-word
        /// mnemonic (not enforced).
        advisory_min_12: u16,
        /// Vendor-stated advisory minimum event count for a 24-word
        /// mnemonic (not enforced).
        advisory_min_24: u16,
    },
}

/// A single reviewed device/method profile (SPEC_COMPAT §6). The full set
/// lives in the `const` table [`PROFILES`]; profiles are never constructed
/// ad hoc or driven by external data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatProfile {
    /// Stable identifier, e.g. `"seedsigner-dice"` (also the string the
    /// WP-C5 binary-policy scanner denies from the production build).
    pub id: &'static str,
    /// Human-readable label for CLI display, e.g. `"SeedSigner — dice"`.
    pub display_name: &'static str,
    /// Vendor/project name, e.g. `"SeedSigner"`.
    pub vendor: &'static str,
    /// Preimage (digest) construction (always [`CompatMethod::Sha256AsciiDigest`]
    /// in v0.6.1).
    pub method: CompatMethod,
    /// Accepted event-string alphabet.
    pub alphabet: EventAlphabet,
    /// Whether this profile supports coin-flip entry.
    pub coins_supported: bool,
    /// Per-profile word-count selection/refusal rule (SPEC_COMPAT §6,
    /// review F1).
    pub word_count_rule: WordCountRule,
    /// `true` only for `coldcard-dice` (SPEC_COMPAT §5.1.1, §6, review
    /// F2/Q7; **repurposed in v0.6.2**). Only a physical device can reveal
    /// whether it took the reproducible dice-only path or the
    /// non-reproducible mix/TRNG path — but as of v0.6.2 that is a
    /// **runtime-advisory** fact, not a freeze gate: `coldcard-dice`'s
    /// algorithm vectors freeze against Coinkite's own `rolls.py`/
    /// `rolls12.py` (§10.3), no hardware required. This flag now means
    /// "the CLI/docs must tell the user to confirm dice-only mode on
    /// their own device before trusting a match" (a TRNG-mix seed
    /// legitimately mismatches); this crate does not itself gate anything
    /// on this flag — it is metadata for the CLI/vector tooling.
    pub requires_hw_confirmation: bool,
    /// Primary cited source URL (SPEC_COMPAT §5.1), rendered verbatim on
    /// the WP-C4 CLI method screen.
    pub source_url: &'static str,
    /// The doc/commit revision this profile's preimage was pinned to
    /// (SPEC_COMPAT §5.1: "the profile records the doc revision it was
    /// pinned to").
    pub source_pinned_rev: &'static str,
    /// Caveats rendered verbatim on the method screen (SPEC_COMPAT §6, §7):
    /// e.g. mix-mode reproducibility limits, the `6`-not-remapped-to-`0`
    /// note, UNVERIFIED markers.
    pub caveats: &'static [&'static str],
}

/// Identifier used by [`profile`] to exclude `iancoleman-hex` from the
/// user-facing lookup (SPEC_COMPAT §5.1.4, §7: it is a digest oracle only,
/// never a user-selectable profile, and must never stand in for a
/// SeedSigner oracle).
const INTERNAL_ORACLE_ONLY_IDS: &[&str] = &["iancoleman-hex"];

/// The reviewed profile table (SPEC_COMPAT §5.4, §6): a `const` array,
/// reviewed like the BIP39 wordlist, never data-driven at runtime.
///
/// Contains all four profiles described in SPEC_COMPAT §5: the three
/// user-facing profiles (`coldcard-dice`, `seedsigner-dice`,
/// `seedsigner-coin`) plus `iancoleman-hex`, present here as the shared
/// digest-oracle record but excluded from [`profile`]'s user-facing lookup
/// (SPEC_COMPAT §5.1.4: "a valid independent oracle for the digest only...
/// must not stand in for `tools/mnemonic.py`").
pub const PROFILES: &[CompatProfile] = &[
    // ---- coldcard-dice (SPEC_COMPAT §5.1.1) ----
    CompatProfile {
        id: "coldcard-dice",
        display_name: "COLDCARD — dice",
        vendor: "Coinkite (COLDCARD)",
        method: CompatMethod::Sha256AsciiDigest,
        alphabet: EventAlphabet::Dice1to6,
        coins_supported: false,
        word_count_rule: WordCountRule::FreeChoice {
            advisory_min_12: 50,
            advisory_min_24: 99,
        },
        requires_hw_confirmation: true,
        source_url: "https://coldcard.com/docs/verifying-dice-roll-math/",
        source_pinned_rev: "verifying-dice-roll-math doc (Mk4/Q-era) + rolls.py/rolls12.py hash-pinned at github.com/Coldcard/firmware commit 05ac389349c4f5ad80c036bce4e4111a746e4c86 (sha256 4348a520e57df665e0ab57baa369a95ace0f9b5fba355b3f22b0b9b2c2e6cd30 / 533daff58437cdc9a482d16cd181ba9b0fe6f86a6839b792343d39b496034c85), per SPEC_COMPAT.md v0.6.2 §10.3",
        caveats: &[
            "RUNTIME STEP -- confirm on your own physical device BEFORE trusting a match: your Coldcard must be on the dice-only path (New Seed Words > Advanced > 12/24 Word Dice Roll). A seed made via the Mix/\"Middle Ground\" path (dice folded on top of TRNG bits) or plain TRNG will LEGITIMATELY mismatch -- that is expected, not alarming, and this profile cannot detect which path your device used.",
            "The algorithm itself is frozen against Coinkite's own rolls.py/rolls12.py (SPEC_COMPAT v0.6.2, no hardware required for that part); only the dice-only-vs-mix path check above needs the physical device.",
            "50/99 rolls are vendor-stated advisory minimums, not enforced by the standalone rolls.py/rolls12.py scripts -- 12 vs 24 words is a free choice here.",
            "Dice digits 1-6 are hashed as-is; '6' is NOT remapped to '0'.",
        ],
    },
    // ---- seedsigner-dice (SPEC_COMPAT §5.1.2) ----
    CompatProfile {
        id: "seedsigner-dice",
        display_name: "SeedSigner — dice",
        vendor: "SeedSigner",
        method: CompatMethod::Sha256AsciiDigest,
        alphabet: EventAlphabet::Dice1to6,
        coins_supported: false,
        word_count_rule: WordCountRule::DerivedFromLength {
            len12: 50,
            len24: 99,
        },
        requires_hw_confirmation: false,
        source_url: "https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/helpers/mnemonic_generation.py",
        source_pinned_rev: "mnemonic_generation.py + tools/mnemonic.py + dice_verification.md, dev branch as pinned in SPEC_COMPAT.md v0.6.1",
        caveats: &[
            "Dice digits 1-6 are hashed as-is; '6' is NOT remapped to '0' (do not use Ian Coleman's native 'dice' input format, which does remap).",
            "Word count is set by the roll count: exactly 50 rolls -> 12 words, exactly 99 rolls -> 24 words; any other count is refused, matching tools/mnemonic.py.",
        ],
    },
    // ---- seedsigner-coin (SPEC_COMPAT §5.1.3) ----
    CompatProfile {
        id: "seedsigner-coin",
        display_name: "SeedSigner — coin flips",
        vendor: "SeedSigner",
        method: CompatMethod::Sha256AsciiDigest,
        alphabet: EventAlphabet::Coin01,
        coins_supported: true,
        word_count_rule: WordCountRule::DerivedFromLength {
            len12: 128,
            len24: 256,
        },
        requires_hw_confirmation: false,
        source_url: "https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/helpers/mnemonic_generation.py",
        source_pinned_rev: "mnemonic_generation.py + tools/mnemonic.py, dev branch as pinned in SPEC_COMPAT.md v0.6.1",
        caveats: &[
            "Enter the exact '0'/'1' characters your device recorded; which physical face is labeled '1' vs '0' is an unverified UI convention, not fixed by the hash preimage.",
            "Word count is set by the flip count: exactly 128 flips -> 12 words, exactly 256 flips -> 24 words; any other count is refused, matching tools/mnemonic.py.",
        ],
    },
    // ---- iancoleman-hex (SPEC_COMPAT §5.1.4) — internal digest oracle only ----
    CompatProfile {
        id: "iancoleman-hex",
        display_name: "Ian Coleman BIP39 tool (Hex mode) — digest oracle",
        vendor: "iancoleman/bip39",
        method: CompatMethod::Sha256AsciiDigest,
        alphabet: EventAlphabet::Dice1to6,
        coins_supported: true,
        word_count_rule: WordCountRule::FreeChoice {
            advisory_min_12: 50,
            advisory_min_24: 99,
        },
        requires_hw_confirmation: false,
        source_url: "https://github.com/iancoleman/bip39",
        source_pinned_rev: "src/js/index.js setMnemonicFromEntropy, current as pinned in SPEC_COMPAT.md v0.6.1",
        caveats: &[
            "Digest oracle only for Method A -- NOT a SeedSigner oracle. Must never stand in for tools/mnemonic.py when validating seedsigner-* word-count/refusal behavior (SPEC_COMPAT §5.1.4).",
            "On the live tool: Entropy Type must be set to Hex (not 'Dice', which remaps 6->0) with a numeric Mnemonic Length (not 'raw').",
            "Not offered as a user-selectable profile by profile() -- internal oracle only.",
        ],
    },
];

/// Look up a user-facing profile by id (SPEC_COMPAT §7: the CLI's profile
/// menu offers only the three real-device profiles). Excludes internal
/// oracle-only entries such as `iancoleman-hex` (SPEC_COMPAT §5.1.4) even
/// though they are present in [`PROFILES`].
pub fn profile(id: &str) -> Option<&'static CompatProfile> {
    if INTERNAL_ORACLE_ONLY_IDS.contains(&id) {
        return None;
    }
    PROFILES.iter().find(|p| p.id == id)
}

/// Requested/derived BIP39 word count for a `compat_derive` call
/// (SPEC_COMPAT §3, §12). Distinct from `seed_core::contracts::WordCount`
/// (this crate's own frozen contract shape, IMPLEMENTATION_MAP_COMPAT.md
/// §3) even though the two enums carry the same two cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 12-word mnemonic (128-bit entropy, `digest[..16]`).
    W12,
    /// 24-word mnemonic (256-bit entropy, full `digest[..32]`).
    W24,
}

/// Result of a successful [`compat_derive`] call (SPEC_COMPAT §3, §12).
/// Carries only the mnemonic word indexes — verification values
/// (fingerprint + addresses) are computed by the WP-C4 CLI via the existing
/// `seed-derive` API from the mnemonic, not re-implemented here
/// (IMPLEMENTATION_MAP_COMPAT.md §3).
///
/// ## Secret-handling discipline (SPEC_COMPAT §9, audit finding #5)
///
/// `mnemonic_indexes` is a real, reproduced mnemonic in this crate's
/// primary (device-reproduction) use case, even though the *inputs* that
/// produce it are caller-declared public/throwaway events (SPEC_COMPAT §2,
/// §4) — so this type deliberately implements none of `Debug`, `Clone`,
/// `Copy`, `PartialEq`, or `Eq`, mirroring `seed_core::arena::SecretArena`'s
/// type restrictions (SPEC §20.2). [`CompatOutput::scrub`] and this type's
/// `Drop` impl best-effort zero `mnemonic_indexes` via
/// `seed_core::arena::scrub_slice`, the same reviewed volatile-write +
/// fence + verify primitive `SecretArena` uses internally. This is hygiene
/// and consistency with the rest of the codebase, not a live secret-leak
/// fix — these values are declared public/throwaway.
pub struct CompatOutput {
    /// The word count this call produced.
    pub word_count: WordCount,
    /// BIP39 wordlist indexes; only the first `word_count` entries
    /// (12 or 24) are meaningful. Look up words with
    /// `seed_core::bip39::word`.
    pub mnemonic_indexes: [u16; 24],
    /// Number of event characters actually hashed (`events.len()`), for the
    /// caller to compare against a `FreeChoice` profile's advisory minimums
    /// when deciding whether to show an under-count warning (SPEC_COMPAT
    /// §6: "a WARNING below the vendor's stated minimum, never a refusal or
    /// a silent recount" — that comparison/warning itself is a WP-C4 CLI
    /// concern; this crate only reports the length it used).
    pub used_len: u16,
}

impl CompatOutput {
    /// Best-effort zero of `mnemonic_indexes` (SPEC_COMPAT §9, audit
    /// finding #5). Uses `seed_core::arena::scrub_slice` — the same
    /// reviewed volatile-write + compiler-fence + memory-fence + verify
    /// primitive `seed_core::arena::SecretArena` uses for its own
    /// mnemonic-index field — by reinterpreting the `[u16; 24]` field as
    /// its 48 constituent bytes.
    ///
    /// Called automatically on `Drop`; callers needing an earlier scrub
    /// point (e.g. right after copying words/seed out) may call this
    /// explicitly.
    pub fn scrub(&mut self) {
        // SAFETY: `mnemonic_indexes` is `[u16; 24]`; reinterpreting it as
        // `24 * 2 = 48` bytes through a `u8` pointer is always valid (`u8`
        // has no alignment or padding constraints and every byte of a
        // `u16` is part of its object representation), and the pointer
        // stays within the bounds of this exclusively-borrowed field.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.mnemonic_indexes.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&self.mnemonic_indexes),
            )
        };
        seed_core::arena::scrub_slice(bytes);
    }
}

impl Drop for CompatOutput {
    /// Defense-in-depth best-effort scrub, mirroring
    /// `seed_core::arena::SecretArena`'s `Drop` impl (SPEC §20.1, §20.4).
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Errors from [`compat_derive`] (SPEC_COMPAT §3, §12). No variant carries
/// a rendered mnemonic — refusal is always a distinct outcome from success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatError {
    /// `events` contained a byte outside `profile.alphabet` at byte offset
    /// `at`.
    BadAlphabet {
        /// Byte offset of the first invalid character.
        at: usize,
    },
    /// The device this profile emulates would refuse this input — either
    /// because a `DerivedFromLength` profile's event-string length is
    /// outside its canonical `{len12, len24}` set, or because `requested`
    /// asked for a word count that does not match what the length would
    /// produce (SPEC_COMPAT §5.1.2/§5.1.3, review F1: "a 99-roll string
    /// asked as '12 words'... must never render a mnemonic the device
    /// cannot produce"), or because a `FreeChoice` profile was called
    /// without a `requested` count to honor. **Never** paired with a
    /// rendered mnemonic — this is the F1 fix.
    Refused {
        /// Number of events actually entered.
        entered: u16,
        /// Human-readable explanation, safe to render verbatim in the CLI.
        reason: &'static str,
    },
    /// `events` was empty; there is nothing to hash.
    Empty,
}

/// SPEC_COMPAT §12. Reproduce a device/method profile's documented BIP39
/// derivation over a caller-declared, public/throwaway event string.
///
/// `requested` is honored **only** for [`WordCountRule::FreeChoice`]
/// profiles; for [`WordCountRule::DerivedFromLength`] profiles the input
/// length decides the word count, and:
/// - a length outside `{len12, len24}` is refused (F1: the classic
///   under/over-roll case, e.g. 40 or 60 dice rolls for `seedsigner-dice`);
/// - a length that *does* match `len12`/`len24` but is paired with a
///   `requested` that disagrees with the length-derived count is *also*
///   refused (F1: the "99 rolls asked as 12 words" phantom pairing that the
///   real device can never produce — refusing this is the entire point of
///   `DerivedFromLength`, not an incidental side effect).
///
/// Steps (SPEC_COMPAT §12):
/// 1. reject an empty `events` string ([`CompatError::Empty`]);
/// 2. validate `events` against `profile.alphabet`
///    ([`CompatError::BadAlphabet`]);
/// 3. apply `profile.word_count_rule` to `events.len()` and `requested`
///    ([`CompatError::Refused`] on any mismatch, as above);
/// 4. compute `digest = seed_core::hash::sha256(events.as_bytes())` over the
///    ASCII bytes **as-is** (digit `'6'` stays `0x36`, never remapped —
///    SPEC_COMPAT §5.1.2, review F8);
/// 5. `entropy = digest[..16]` (12w) or `digest[..32]` (24w);
/// 6. call `seed_core::bip39::entropy_to_indexes` — the **same** conversion
///    production uses (SPEC §14).
pub fn compat_derive(
    profile: &CompatProfile,
    events: &str,
    requested: Option<WordCount>,
) -> Result<CompatOutput, CompatError> {
    if events.is_empty() {
        return Err(CompatError::Empty);
    }

    if let Some(at) = first_bad_byte(events, profile.alphabet) {
        return Err(CompatError::BadAlphabet { at });
    }

    let entered = clamp_u16(events.len());
    let word_count = select_word_count(profile.word_count_rule, events.len(), requested, entered)?;

    // Step 4/5 (SPEC_COMPAT §5.1: "digest step, normative, shared by all
    // Method-A profiles"). `sha256` hashes the raw ASCII bytes as-is; no
    // character remapping of any kind happens anywhere in this crate.
    let digest = sha256(events.as_bytes());
    let entropy: &[u8] = match word_count {
        WordCount::W12 => &digest[..16],
        WordCount::W24 => &digest[..32],
    };

    let mut indexes = [0u16; 24];
    // `entropy` is always exactly 16 or 32 bytes by construction above, so
    // `entropy_to_indexes` (SPEC §14) cannot fail here.
    let core_count = seed_core::bip39::entropy_to_indexes(entropy, &mut indexes)
        .expect("entropy slice is always 16 or 32 bytes by construction");
    debug_assert_eq!(
        matches!(core_count, CoreWordCount::Twelve),
        matches!(word_count, WordCount::W12),
        "seed_core::bip39::entropy_to_indexes word count disagreed with the profile's own selection"
    );

    Ok(CompatOutput {
        word_count,
        mnemonic_indexes: indexes,
        used_len: entered,
    })
}

/// Resolve the word count for this call, applying the F1 refusal rules
/// (see [`compat_derive`] doc comment) for `DerivedFromLength`, or honoring
/// `requested` for `FreeChoice`.
fn select_word_count(
    rule: WordCountRule,
    len: usize,
    requested: Option<WordCount>,
    entered: u16,
) -> Result<WordCount, CompatError> {
    match rule {
        WordCountRule::DerivedFromLength { len12, len24 } => {
            let derived = if len == len12 as usize {
                WordCount::W12
            } else if len == len24 as usize {
                WordCount::W24
            } else {
                return Err(CompatError::Refused {
                    entered,
                    reason: "this profile's real device sets word count from the exact event \
                             count and refuses any count outside its two canonical values",
                });
            };
            if let Some(req) = requested {
                if req != derived {
                    // The F1 phantom pairing: a canonical length paired
                    // with a *disagreeing* requested word count. The real
                    // device can never produce this combination.
                    return Err(CompatError::Refused {
                        entered,
                        reason: "the requested word count does not match what this profile's \
                                 real device derives from this exact event count",
                    });
                }
            }
            Ok(derived)
        }
        WordCountRule::FreeChoice { .. } => requested.ok_or(CompatError::Refused {
            entered,
            reason: "this profile requires an explicit requested word count (12 or 24); it is \
                     not derived from the event count",
        }),
    }
}

/// Byte offset of the first character in `events` outside `alphabet`, if
/// any.
fn first_bad_byte(events: &str, alphabet: EventAlphabet) -> Option<usize> {
    events.bytes().position(|b| !alphabet_allows(alphabet, b))
}

fn alphabet_allows(alphabet: EventAlphabet, b: u8) -> bool {
    match alphabet {
        EventAlphabet::Dice1to6 => (b'1'..=b'6').contains(&b),
        EventAlphabet::Coin01 => b == b'0' || b == b'1',
    }
}

/// Saturating cast used only for the non-secret, display-only `entered` /
/// `used_len` fields (event counts here are physical dice rolls or coin
/// flips; no realistic input approaches `u16::MAX`).
fn clamp_u16(len: usize) -> u16 {
    if len > u16::MAX as usize {
        u16::MAX
    } else {
        len as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Extracts the `Err` variant of a `compat_derive` result without
    /// requiring `Result::unwrap_err`/`expect_err`, both of which need
    /// `CompatOutput: Debug` on the `Ok` side -- a bound this type
    /// deliberately does not satisfy (SPEC_COMPAT §9, audit finding #5).
    fn expect_err(result: Result<CompatOutput, CompatError>, msg: &str) -> CompatError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("{msg}"),
        }
    }

    fn words_for(indexes: &[u16; 24], count: WordCount) -> Vec<&'static str> {
        let n = match count {
            WordCount::W12 => 12,
            WordCount::W24 => 24,
        };
        indexes[..n].iter().map(|&i| seed_core::bip39::word(i)).collect()
    }

    // ---- PROFILES table shape (IMPLEMENTATION_MAP_COMPAT.md §4 WP-C1) ----

    #[test]
    fn profiles_table_has_exactly_four_entries() {
        assert_eq!(PROFILES.len(), 4);
    }

    #[test]
    fn all_profiles_use_the_sole_closed_method_variant() {
        for p in PROFILES {
            assert_eq!(p.method, CompatMethod::Sha256AsciiDigest);
        }
    }

    #[test]
    fn coldcard_dice_is_free_choice_50_99() {
        let p = profile("coldcard-dice").expect("coldcard-dice must be user-facing");
        assert_eq!(
            p.word_count_rule,
            WordCountRule::FreeChoice { advisory_min_12: 50, advisory_min_24: 99 }
        );
        assert_eq!(p.alphabet, EventAlphabet::Dice1to6);
        assert!(!p.coins_supported);
        assert!(p.requires_hw_confirmation);
    }

    #[test]
    fn seedsigner_dice_is_derived_from_length_50_99() {
        let p = profile("seedsigner-dice").expect("seedsigner-dice must be user-facing");
        assert_eq!(
            p.word_count_rule,
            WordCountRule::DerivedFromLength { len12: 50, len24: 99 }
        );
        assert_eq!(p.alphabet, EventAlphabet::Dice1to6);
        assert!(!p.requires_hw_confirmation);
    }

    #[test]
    fn seedsigner_coin_is_derived_from_length_128_256() {
        let p = profile("seedsigner-coin").expect("seedsigner-coin must be user-facing");
        assert_eq!(
            p.word_count_rule,
            WordCountRule::DerivedFromLength { len12: 128, len24: 256 }
        );
        assert_eq!(p.alphabet, EventAlphabet::Coin01);
        assert!(p.coins_supported);
    }

    #[test]
    fn iancoleman_hex_present_in_table_but_not_returned_by_profile() {
        assert!(PROFILES.iter().any(|p| p.id == "iancoleman-hex"));
        assert!(profile("iancoleman-hex").is_none());
    }

    #[test]
    fn profile_lookup_unknown_id_is_none() {
        assert!(profile("totally-not-a-profile").is_none());
    }

    #[test]
    fn profile_lookup_returns_only_the_three_user_facing_ids() {
        let ids: Vec<&str> = ["coldcard-dice", "seedsigner-dice", "seedsigner-coin"]
            .iter()
            .filter(|id| profile(id).is_some())
            .copied()
            .collect();
        assert_eq!(ids.len(), 3);
    }

    // ---- SeedSigner published KATs (SPEC_COMPAT §5.1.2) ----
    //
    // Both vectors are the vendor's own published cross-check examples
    // (`docs/dice_verification.md`), independently reproduced with
    // `hashlib.sha256` + the project's own `reference/python/wordlist_english.txt`
    // during implementation (not copied from any Rust code path) before
    // being hardcoded here.

    #[test]
    fn seedsigner_dice_50_rolls_vendor_example_12w() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        assert_eq!(events.len(), 50);

        let out = compat_derive(p, events, None).expect("50 canonical rolls must succeed");
        assert_eq!(out.word_count, WordCount::W12);
        assert_eq!(out.used_len, 50);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "hole", "luggage", "safe", "present", "express", "tragic", "orbit", "shed",
                "switch", "metal", "identify", "path",
            ]
        );
    }

    #[test]
    fn seedsigner_dice_99_rolls_vendor_example_24w() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
        assert_eq!(events.len(), 99);

        let out = compat_derive(p, events, None).expect("99 canonical rolls must succeed");
        assert_eq!(out.word_count, WordCount::W24);
        assert_eq!(out.used_len, 99);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "eyebrow", "obvious", "such", "suggest", "poet", "seven", "breeze", "blame",
                "virtual", "frown", "dynamic", "donor", "harsh", "pigeon", "express", "broccoli",
                "easy", "apology", "scatter", "force", "recipe", "shadow", "claim", "radio",
            ]
        );
    }

    // ---- digit '6' present, hashed as-is (SPEC_COMPAT §5.1.1, review F8) ----
    //
    // COLDCARD's own docs cite `sha256(b'123456').hexdigest() ==
    // 8d969eef...c6c92`; reproduced independently here and cross-checked
    // against the FreeChoice (coldcard-dice) path end to end.

    #[test]
    fn digit_six_is_hashed_as_ascii_0x36_not_remapped_to_zero() {
        // sha256(b"123456") is a fixed, independently well-known digest
        // (also the exact value COLDCARD's docs cite for this preimage).
        let digest = sha256(b"123456");
        let mut hex = std::string::String::new();
        for b in digest {
            hex.push_str(&std::format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        );
    }

    #[test]
    fn coldcard_dice_123456_free_choice_12w() {
        let p = profile("coldcard-dice").unwrap();
        let out = compat_derive(p, "123456", Some(WordCount::W12)).expect("free choice 12w");
        assert_eq!(out.word_count, WordCount::W12);
        assert_eq!(out.used_len, 6);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "mirror", "reject", "rookie", "talk", "pudding", "throw", "happy", "era", "myth",
                "already", "payment", "owner",
            ]
        );
    }

    #[test]
    fn coldcard_dice_123456_free_choice_24w() {
        let p = profile("coldcard-dice").unwrap();
        let out = compat_derive(p, "123456", Some(WordCount::W24)).expect("free choice 24w");
        assert_eq!(out.word_count, WordCount::W24);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "mirror", "reject", "rookie", "talk", "pudding", "throw", "happy", "era", "myth",
                "already", "payment", "own", "sentence", "push", "head", "sting", "video",
                "explain", "letter", "bomb", "casual", "hotel", "rather", "garment",
            ]
        );
    }

    // ---- coin case (SPEC_COMPAT §5.1.3) ----

    #[test]
    fn seedsigner_coin_128_flips_12w() {
        let p = profile("seedsigner-coin").unwrap();
        let events = "01".repeat(64); // 128 chars
        assert_eq!(events.len(), 128);

        let out = compat_derive(p, &events, None).expect("128 canonical flips must succeed");
        assert_eq!(out.word_count, WordCount::W12);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "shove", "scene", "domain", "glow", "coast", "decade", "dwarf", "dress", "blood",
                "avocado", "only", "cargo",
            ]
        );
    }

    #[test]
    fn seedsigner_coin_256_flips_24w() {
        let p = profile("seedsigner-coin").unwrap();
        let events = "0110".repeat(64); // 256 chars
        assert_eq!(events.len(), 256);

        let out = compat_derive(p, &events, None).expect("256 canonical flips must succeed");
        assert_eq!(out.word_count, WordCount::W24);
        assert_eq!(
            words_for(&out.mnemonic_indexes, out.word_count),
            std::vec![
                "pelican", "trap", "simple", "address", "rebuild", "topple", "sign", "exit",
                "morning", "palace", "spirit", "parent", "stomach", "regular", "wage", "broken",
                "company", "lift", "inform", "electric", "insect", "cattle", "wool", "stick",
            ]
        );
    }

    // ---- F1 refusal cases (SPEC_COMPAT §5.1.2, review F1) — never a phrase ----

    #[test]
    fn f1_refusal_40_rolls_under_canonical() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "1".repeat(40);
        let err = expect_err(compat_derive(p, &events, None), "40 rolls must be refused");
        match err {
            CompatError::Refused { entered, .. } => assert_eq!(entered, 40),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn f1_refusal_60_rolls_between_canonical_values() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "1".repeat(60);
        let err = expect_err(compat_derive(p, &events, None), "60 rolls must be refused");
        match err {
            CompatError::Refused { entered, .. } => assert_eq!(entered, 60),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn f1_refusal_99_rolls_requested_as_12_words() {
        // The exact F1 phantom pairing: a canonical 99-roll (24-word)
        // length explicitly asked for as 12 words. The real SeedSigner
        // device can never produce this combination; compat_derive must
        // refuse it, not silently produce a 12-word phrase from
        // digest[..16] the way the pre-F1-fix code did.
        let p = profile("seedsigner-dice").unwrap();
        let events = "655152231316521321611331544441236164664431121534415633\
526456254462245546236542364246312613322234612";
        assert_eq!(events.len(), 99);

        let err = expect_err(
            compat_derive(p, events, Some(WordCount::W12)),
            "99 rolls requested as 12 words must be refused, never a phrase",
        );
        match err {
            CompatError::Refused { entered, .. } => assert_eq!(entered, 99),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn f1_refusal_never_pairs_with_a_mnemonic() {
        // Belt-and-suspenders over the three cases above: whichever error
        // variant is returned, it is always `Refused`, never a disguised
        // success -- `Result<CompatOutput, CompatError>` makes this
        // structurally impossible to get wrong, but pin it as an explicit
        // regression test anyway.
        let p = profile("seedsigner-dice").unwrap();
        for events in ["1".repeat(40), "1".repeat(60)] {
            assert!(matches!(
                compat_derive(p, &events, None),
                Err(CompatError::Refused { .. })
            ));
        }
    }

    // ---- alphabet validation ----

    #[test]
    fn bad_alphabet_dice_rejects_zero() {
        let p = profile("seedsigner-dice").unwrap();
        let mut events = std::string::String::from("1".repeat(49));
        events.push('0'); // '0' is not valid dice ('1'..='6' only)
        let err = expect_err(compat_derive(p, &events, None), "expected BadAlphabet");
        assert_eq!(err, CompatError::BadAlphabet { at: 49 });
    }

    #[test]
    fn bad_alphabet_dice_rejects_seven() {
        let p = profile("seedsigner-dice").unwrap();
        // '1', '2', '7' -- '7' (index 2) is outside '1'..='6'.
        let err = expect_err(compat_derive(p, "127", None), "expected BadAlphabet");
        assert_eq!(err, CompatError::BadAlphabet { at: 2 });
    }

    #[test]
    fn bad_alphabet_coin_rejects_non_binary_digit() {
        let p = profile("seedsigner-coin").unwrap();
        // '0', '1', '0', '2' -- '2' (index 3) is outside {'0', '1'}.
        let err = expect_err(compat_derive(p, "0102", None), "expected BadAlphabet");
        assert_eq!(err, CompatError::BadAlphabet { at: 3 });
    }

    // ---- empty input ----

    #[test]
    fn empty_events_is_rejected() {
        let p = profile("seedsigner-dice").unwrap();
        assert_eq!(expect_err(compat_derive(p, "", None), "expected Empty"), CompatError::Empty);
    }

    // ---- FreeChoice without a requested count ----

    #[test]
    fn free_choice_without_requested_is_refused_not_defaulted() {
        let p = profile("coldcard-dice").unwrap();
        let err = expect_err(compat_derive(p, "123456", None), "expected Refused");
        assert!(matches!(err, CompatError::Refused { .. }));
    }

    // ---- FreeChoice ignores canonical-count enforcement (SPEC_COMPAT §5.1.1) ----

    #[test]
    fn free_choice_accepts_under_advisory_minimum() {
        // COLDCARD's standalone scripts do not enforce the 50/99 advisory
        // minimums -- an under-count must still succeed (just potentially
        // warned about by the CLI layer, not this crate).
        let p = profile("coldcard-dice").unwrap();
        let out = compat_derive(p, "123456", Some(WordCount::W12));
        assert!(out.is_ok());
    }

    // ---- cross-check: digest step matches seed_core::hash::sha256 directly ----

    #[test]
    fn digest_step_uses_seed_core_sha256_directly() {
        let events = "65515223131652132161133154444123616466443112153441";
        let expected = sha256(events.as_bytes());
        let p = profile("seedsigner-dice").unwrap();
        let out = compat_derive(p, events, None).unwrap();
        let mut indexes = [0u16; 24];
        seed_core::bip39::entropy_to_indexes(&expected[..16], &mut indexes).unwrap();
        assert_eq!(out.mnemonic_indexes, indexes);
    }

    // ---- secret-handling discipline (SPEC_COMPAT §9, audit finding #5) ----

    /// Regression test for audit finding #5: `CompatOutput::scrub` must
    /// actually zero `mnemonic_indexes` in place.
    #[test]
    fn scrub_zeroes_mnemonic_indexes() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        let mut out = compat_derive(p, events, None).unwrap();
        assert!(out.mnemonic_indexes.iter().any(|&w| w != 0), "fixture produced an all-zero mnemonic");

        out.scrub();

        assert!(out.mnemonic_indexes.iter().all(|&w| w == 0), "scrub left a non-zero mnemonic index");
    }

    /// Regression test for audit finding #5: dropping a `CompatOutput`
    /// must run its `Drop` impl (which calls `scrub()`) to completion
    /// without panicking, mirroring `SecretArena::drop_scrubs_automatically`.
    /// The functional proof that scrubbing actually zeroes the field is
    /// `scrub_zeroes_mnemonic_indexes` above -- reading a dropped local's
    /// former memory would itself be a use-after-drop bug, so this test
    /// only exercises that the `Drop` path runs cleanly.
    #[test]
    fn drop_scrubs_automatically() {
        let p = profile("seedsigner-dice").unwrap();
        let events = "65515223131652132161133154444123616466443112153441";
        let out = compat_derive(p, events, None).unwrap();
        drop(out);
    }
}
