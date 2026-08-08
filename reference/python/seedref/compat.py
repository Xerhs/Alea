"""seed-compat reference implementation — Method A only (SPEC_COMPAT
v0.6.1 §5, §6, §12).

Independent Python reference for the "compatibility verification" mode:
reproduces the *documented* dice/coin -> BIP39 preimage of a curated set
of third-party wallet tools (COLDCARD, SeedSigner), so a user can audit
whether the real device's arithmetic is faithful to its own published
method. This module is written from SPEC_COMPAT.md and the cited vendor
sources ONLY (COLDCARD `rolls.py`/`rolls12.py` + docs, SeedSigner
`mnemonic_generation.py`/`tools/mnemonic.py`/`dice_verification.md`, and
the Ian Coleman `bip39` tool `index.js`) — the Rust `seed-compat` crate
was never read while writing this file. That independence is the whole
point of the WP-C3 freeze barrier (IMPLEMENTATION_MAP_COMPAT.md §2): two
implementations written from the same normative text, cross-checked
against each other and then against the real vendor tools.

seed-compat NEVER participates in Alea's own production seed
ceremony (SPEC_COMPAT §0.2, §9). It reuses this package's existing BIP39
entropy->mnemonic conversion (`seedref.bip39`) unchanged — the *only*
thing that differs from production is the preimage that produces the
entropy bytes (SPEC_COMPAT §0.1).

Method A digest step (SPEC_COMPAT §5.1, normative, shared by every
profile below):

    digest      = SHA256( event_string_ascii_bytes )      # 32 bytes
    entropy_12w = digest[0:16]
    entropy_24w = digest[0:32]
    mnemonic    = BIP39(entropy)   # standard checksum, SPEC §14

Word-count *selection* is explicitly NOT part of the shared digest step
(SPEC_COMPAT §5.1, review F1) — it is a per-profile `WordCountRule`:

  - `DerivedFromLength` (SeedSigner dice/coin): word count is a pure
    function of the exact input length; any length outside the
    canonical `{len12, len24}` pair is REFUSED, never coerced into a
    fabricated phrase (SPEC_COMPAT §5.1.2/§5.1.3, review F1 -- this is
    the whole point of the feature, IMPLEMENTATION_MAP_COMPAT.md §1.6).
  - `FreeChoice` (COLDCARD, Ian-Coleman-Hex): the caller picks 12 or 24
    words; the vendor's stated minimums are advisory only, not enforced
    by the standalone scripts (SPEC_COMPAT §5.1.1/§5.1.4).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from .addresses import PathStandard, first_address, master_fingerprint
from .bip32 import master_from_seed
from .bip39 import entropy_to_indexes, indexes_to_words, mnemonic_to_seed
from .hashes import sha256


class CompatMethod(Enum):
    """Closed set of reviewed preimage (digest) constructions
    (SPEC_COMPAT §6). In v0.6.1 there is exactly one variant -- Method B
    (Ian Coleman native base-6 raw entropy) was removed from the enum by
    review F4/Q4 and is education-only (SPEC_COMPAT §5.2), never an
    implemented code path here."""

    SHA256_ASCII_DIGEST = "Sha256AsciiDigest"


class EventAlphabet(Enum):
    """The two event-character alphabets a profile accepts (SPEC_COMPAT
    §5, §6). Digits are hashed exactly as entered -- notably `'6'` is
    NEVER remapped to `'0'` for any Method-A profile (SPEC_COMPAT
    §5.1.2, the "6->0 trap" is a *different*, education-only tool
    setting, §5.2/§11.4)."""

    DICE_1_TO_6 = "dice_1_to_6"  # '1'..'6'
    COIN_0_1 = "coin_0_1"  # '0','1'


_ALPHABET_CHARS = {
    EventAlphabet.DICE_1_TO_6: frozenset("123456"),
    EventAlphabet.COIN_0_1: frozenset("01"),
}


class WordCount(Enum):
    """Output mnemonic length."""

    W12 = 12
    W24 = 24


@dataclass(frozen=True)
class DerivedFromLength:
    """Word count is a pure function of the exact input length
    (SPEC_COMPAT §6, review F1). `len12` characters -> 12 words
    (`digest[:16]`); `len24` characters -> 24 words (full digest); any
    other length is REFUSED -- never coerced, never a fabricated phrase.
    Matches SeedSigner `mnemonic_generation.py` + `tools/mnemonic.py`."""

    len12: int
    len24: int


@dataclass(frozen=True)
class FreeChoice:
    """The caller chooses 12 or 24 words; the vendor's stated minimums
    are advisory only, never enforced as a refusal (SPEC_COMPAT §6).
    Matches COLDCARD's separate `rolls12.py`/`rolls.py` scripts and the
    Ian Coleman tool in Hex-entropy mode."""

    advisory_min_12: int
    advisory_min_24: int


#: `WordCountRule` is the closed union of the two dataclasses above
#: (SPEC_COMPAT §6). Python has no closed sum type at the language
#: level; the two dataclasses stand in for the Rust enum's two variants,
#: and `compat_derive` dispatches on `isinstance`.
WordCountRule = object  # documents the union; see DerivedFromLength / FreeChoice


@dataclass(frozen=True)
class CompatProfile:
    """One reviewed device/method record (SPEC_COMPAT §6). Profiles are
    NOT free-form, caller-driven data -- the fields below are the
    complete, closed set of parameters a profile may vary; adding a new
    *method* or *word-count rule* is a reviewed code change, never a
    data drop."""

    id: str
    display_name: str
    vendor: str
    method: CompatMethod
    alphabet: EventAlphabet
    coins_supported: bool
    word_count_rule: WordCountRule
    requires_hw_confirmation: bool
    source_url: str
    source_pinned_rev: str
    caveats: Tuple[str, ...]


class CompatError(Exception):
    """Base class for the closed `CompatError` result (SPEC_COMPAT §12).
    `compat_derive` never returns a mnemonic when one of these applies
    -- in particular `Refused` for a `DerivedFromLength` profile at a
    non-canonical length is the F1 fix and must never be bypassed by
    fabricating a phrase (IMPLEMENTATION_MAP_COMPAT.md §1.6)."""


class BadAlphabet(CompatError):
    """`events` contains a character outside the profile's
    `EventAlphabet` at index `at` (0-based)."""

    def __init__(self, at: int):
        self.at = at
        super().__init__(f"invalid event character at position {at}")


class Refused(CompatError):
    """A `DerivedFromLength` profile was given a non-canonical input
    length. `entered` is the number of characters actually entered;
    `reason` is a human-readable explanation mirroring the real tool's
    own refusal message (SPEC_COMPAT §7)."""

    def __init__(self, entered: int, reason: str):
        self.entered = entered
        self.reason = reason
        super().__init__(reason)


class Empty(CompatError):
    """`events` is the empty string. Distinct from `Refused` because it
    is a precondition failure independent of any profile's word-count
    rule -- there is nothing to audit. (The empty string's digest,
    `e3b0c442...b855`, is well known and is *not* itself invalid; this
    error only reflects that seed-compat declines to derive a mnemonic
    from zero entered events. Per SPEC_COMPAT §10.4 the empty string is
    kept only as a `math_boundary_no_oracle` documentation fixture, not
    a vendor-confirmed case.)"""

    def __init__(self):
        super().__init__("event string is empty")


@dataclass(frozen=True)
class CompatOutput:
    """Result of a successful `compat_derive` call (SPEC_COMPAT §12).
    `mnemonic_indexes` is always length 24; only the first
    `word_count.value` entries are meaningful (the rest are zero
    padding), mirroring the Rust `[u16; 24]` fixed-size contract.
    `used_len` is the exact number of event characters that were
    hashed."""

    word_count: WordCount
    mnemonic_indexes: Tuple[int, ...]
    used_len: int

    @property
    def mnemonic_words(self) -> List[str]:
        return indexes_to_words(list(self.mnemonic_indexes[: self.word_count.value]))


# ---------------------------------------------------------------------------
# Profile catalog (SPEC_COMPAT §5.4, §6)
# ---------------------------------------------------------------------------

_COLDCARD_DICE = CompatProfile(
    id="coldcard-dice",
    display_name="COLDCARD — dice",
    vendor="Coinkite (COLDCARD)",
    method=CompatMethod.SHA256_ASCII_DIGEST,
    alphabet=EventAlphabet.DICE_1_TO_6,
    coins_supported=False,
    word_count_rule=FreeChoice(advisory_min_12=50, advisory_min_24=99),
    requires_hw_confirmation=True,  # SPEC_COMPAT §5.1.1/§10.3, review F2/Q7;
    # REPURPOSED in v0.6.2 -- runtime-advisory only, NOT a freeze gate (see
    # caveats below and SPEC_COMPAT's v0.6.1 -> v0.6.2 revision log).
    source_url="https://coldcard.com/docs/verifying-dice-roll-math/",
    source_pinned_rev=(
        "COLDCARD docs 'Verifying Dice Roll Math' (Mk4/Q-era) + "
        "rolls.py/rolls12.py hash-pinned at github.com/Coldcard/firmware "
        "commit 05ac389349c4f5ad80c036bce4e4111a746e4c86 "
        "(sha256 4348a520e57df665e0ab57baa369a95ace0f9b5fba355b3f22b0b9b2c2e6cd30 / "
        "533daff58437cdc9a482d16cd181ba9b0fe6f86a6839b792343d39b496034c85), "
        "per SPEC_COMPAT v0.6.2 §10.3; older firmware revisions are UNVERIFIED"
    ),
    caveats=(
        "RUNTIME STEP -- confirm on your own physical device BEFORE "
        "trusting a match: your Coldcard must be on the dice-only path "
        "(New Seed Words > Advanced > 12/24 Word Dice Roll). A seed made "
        "via the Mix/'Middle Ground' path (dice folded on top of TRNG "
        "bits) or plain TRNG will LEGITIMATELY mismatch -- expected, not "
        "alarming, and this profile cannot detect which path your device "
        "used (SPEC_COMPAT §5.1.1, review F2)",
        "the algorithm itself is frozen against Coinkite's own "
        "rolls.py/rolls12.py (SPEC_COMPAT v0.6.2 §10.3) -- no hardware "
        "required for that part; only the dice-only-vs-mix path check "
        "above needs the physical device",
        "digits 1-6 hashed as-is, no 6->0 remap",
        "50/99 rolls are advisory minimums only -- not enforced by "
        "rolls.py/rolls12.py",
    ),
)

_SEEDSIGNER_DICE = CompatProfile(
    id="seedsigner-dice",
    display_name="SeedSigner — dice",
    vendor="SeedSigner",
    method=CompatMethod.SHA256_ASCII_DIGEST,
    alphabet=EventAlphabet.DICE_1_TO_6,
    coins_supported=False,
    word_count_rule=DerivedFromLength(len12=50, len24=99),
    requires_hw_confirmation=False,
    source_url=(
        "https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/"
        "helpers/mnemonic_generation.py"
    ),
    source_pinned_rev=(
        "SeedSigner dev branch: mnemonic_generation.py "
        "(generate_mnemonic_from_dice), tools/mnemonic.py, "
        "docs/dice_verification.md (SPEC_COMPAT v0.6.1 citation)"
    ),
    caveats=(
        "digits 1-6 hashed as-is, no 6->0 remap",
        "word count is set by roll count, not a free choice: exactly 50 "
        "rolls -> 12 words, exactly 99 rolls -> 24 words",
        "any other roll count is REFUSED by tools/mnemonic.py, and by "
        "this reference implementation (review F1)",
        "default entry requires '1'..'6' and rejects a '0' digit unless "
        "the (unimplemented here) --zero-indexed-dice mode is used "
        "(SPEC_COMPAT §5.1.2, review F8)",
    ),
)

_SEEDSIGNER_COIN = CompatProfile(
    id="seedsigner-coin",
    display_name="SeedSigner — coin flips",
    vendor="SeedSigner",
    method=CompatMethod.SHA256_ASCII_DIGEST,
    alphabet=EventAlphabet.COIN_0_1,
    coins_supported=True,
    word_count_rule=DerivedFromLength(len12=128, len24=256),
    requires_hw_confirmation=False,
    source_url=(
        "https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/"
        "helpers/mnemonic_generation.py"
    ),
    source_pinned_rev=(
        "SeedSigner dev branch: mnemonic_generation.py "
        "(generate_mnemonic_from_coin_flips), tools/mnemonic.py "
        "(SPEC_COMPAT v0.6.1 citation)"
    ),
    caveats=(
        "word count is set by flip count, not a free choice: exactly "
        "128 flips -> 12 words, exactly 256 flips -> 24 words",
        "any other flip count is REFUSED by tools/mnemonic.py, and by "
        "this reference implementation (review F1)",
        "which physical face is '1' vs '0' is an UNVERIFIED UI "
        "convention -- enter the same characters the device recorded "
        "(SPEC_COMPAT §5.1.3, review F8/Q3)",
    ),
)

#: Internal Method-A *digest* reconciliation oracle only (SPEC_COMPAT
#: §5.1.4, §5.4). It shares COLDCARD/SeedSigner's SHA256(ascii) digest
#: step, which is why it can corroborate that step independently, but it
#: also shares COLDCARD's free-word-count behavior -- NOT SeedSigner's
#: derive-from-length + refuse wrapper. Using it as a stand-in for the
#: `seedsigner-*` oracle would reproduce review F1's phantom pairings
#: identically-yet-wrongly (SPEC_COMPAT §10.2). It is therefore excluded
#: from `profile()` (below) -- never a user-selectable profile
#: (SPEC_COMPAT §7).
_IANCOLEMAN_HEX = CompatProfile(
    id="iancoleman-hex",
    display_name="Ian Coleman BIP39 tool — Hex entropy (digest oracle only)",
    vendor="iancoleman/bip39",
    method=CompatMethod.SHA256_ASCII_DIGEST,
    alphabet=EventAlphabet.DICE_1_TO_6,
    coins_supported=True,
    word_count_rule=FreeChoice(advisory_min_12=50, advisory_min_24=99),
    requires_hw_confirmation=False,
    source_url="https://github.com/iancoleman/bip39/blob/master/src/js/index.js",
    source_pinned_rev=(
        "iancoleman/bip39 src/js/index.js (setMnemonicFromEntropy) + "
        "src/js/entropy.js, Entropy Type=Hex / Mnemonic Length=12 or 24 "
        "Words setting (SPEC_COMPAT §5.1.4 citation)"
    ),
    caveats=(
        "digest oracle only -- shares the Method-A SHA256(ascii) digest "
        "step but NOT SeedSigner's derive-from-length/refuse wrapper",
        "must never be used to validate seedsigner-dice or "
        "seedsigner-coin word-count behavior (SPEC_COMPAT §10.2, review "
        "F1/F3)",
        "requires selecting Hex entropy type on the real tool -- 'Dice' "
        "entropy type remaps 6->0 and is a different (Method B, "
        "education-only) construction (SPEC_COMPAT §5.1.4/§5.2)",
    ),
)

#: Full catalog, including the internal oracle. Ordering matches
#: SPEC_COMPAT §5.4's table.
PROFILES: Tuple[CompatProfile, ...] = (
    _COLDCARD_DICE,
    _SEEDSIGNER_DICE,
    _SEEDSIGNER_COIN,
    _IANCOLEMAN_HEX,
)

#: The three user-facing profiles only (SPEC_COMPAT §7's menu) --
#: `iancoleman-hex` is deliberately excluded, it is never offered as a
#: selectable profile.
_USER_FACING_IDS = frozenset(
    {p.id for p in PROFILES if p.id != _IANCOLEMAN_HEX.id}
)


def profile(profile_id: str) -> Optional[CompatProfile]:
    """Look up a user-facing profile by id (SPEC_COMPAT §12). Excludes
    the internal oracle profile `iancoleman-hex`, which is never
    user-selectable (SPEC_COMPAT §7)."""

    if profile_id not in _USER_FACING_IDS:
        return None
    for p in PROFILES:
        if p.id == profile_id:
            return p
    return None


def oracle_profile(profile_id: str) -> Optional[CompatProfile]:
    """Look up ANY profile, including the internal `iancoleman-hex`
    digest oracle -- for vector-generation / reconciliation use only
    (SPEC_COMPAT §5.1.4, §10.3), never for the user-facing selection
    menu (`profile()` above)."""

    for p in PROFILES:
        if p.id == profile_id:
            return p
    return None


# ---------------------------------------------------------------------------
# Digest + derivation (SPEC_COMPAT §5.1, §6, §12)
# ---------------------------------------------------------------------------


def _validate_alphabet(events: str, alphabet: EventAlphabet) -> None:
    allowed = _ALPHABET_CHARS[alphabet]
    for i, ch in enumerate(events):
        if ch not in allowed:
            raise BadAlphabet(at=i)


def _digest(events: str) -> bytes:
    """SHA256 of the ASCII bytes of `events`, taken as-is -- notably
    `'6'` is never remapped (SPEC_COMPAT §5.1, normative digest step).
    `events` must already be alphabet-validated ASCII, so
    `events.encode('ascii')` cannot raise."""

    return sha256(events.encode("ascii"))


def compat_derive(
    profile_: CompatProfile,
    events: str,
    requested: Optional[WordCount] = None,
) -> CompatOutput:
    """Reproduce `profile_`'s documented preimage over `events`, then run
    the standard BIP39 entropy->mnemonic conversion (SPEC_COMPAT §12).

    `requested` is honored ONLY for `FreeChoice` profiles; for
    `DerivedFromLength` profiles the exact input length alone decides
    which digest bytes are used, exactly as the real device does. If
    `requested` is also given for a `DerivedFromLength` profile it is
    used purely as an ASSERTION -- never as a second way to pick the
    digest: a non-canonical length is always refused, and so is a
    canonical length paired with a `requested` that disagrees with what
    that length actually produces (e.g. 99 rolls -- which SeedSigner
    ties to 24 words -- "requested" as 12 words). That second case is
    the exact "phantom pairing" v0.6 fabricated (SPEC_COMPAT §10.1
    example, §11.1 item 1, review F1) and is why this reference refuses
    rather than silently honoring the caller's `requested` over the
    device's own length-derived answer -- never fabricating a mnemonic
    the real device could not produce (IMPLEMENTATION_MAP_COMPAT.md
    §1.6).

    Raises `Empty` if `events` is empty, `BadAlphabet` if it contains a
    character outside `profile_.alphabet`, or `Refused` for a
    `DerivedFromLength` profile given a non-canonical length, or a
    canonical length whose `requested` disagrees with the length-derived
    word count. For a `FreeChoice` profile, `requested` must be given (a
    Python-level `ValueError`, not a `CompatError`, if omitted -- this is
    a caller contract violation, not a domain refusal).
    """

    if len(events) == 0:
        raise Empty()

    _validate_alphabet(events, profile_.alphabet)

    rule = profile_.word_count_rule
    n = len(events)

    if isinstance(rule, DerivedFromLength):
        unit = "rolls" if profile_.alphabet == EventAlphabet.DICE_1_TO_6 else "flips"

        if n == rule.len12:
            length_word_count = WordCount.W12
        elif n == rule.len24:
            length_word_count = WordCount.W24
        else:
            reason = (
                f"{profile_.display_name} sets word count from the {unit[:-1]} "
                f"count: {rule.len12} {unit} -> 12 words, {rule.len24} {unit} "
                f"-> 24 words, and it refuses any other number of {unit}. "
                f"You entered {n} {unit}; enter exactly {rule.len12} or "
                f"{rule.len24}."
            )
            raise Refused(entered=n, reason=reason)

        if requested is not None and requested != length_word_count:
            reason = (
                f"{n} {unit} cannot produce {requested.value} words on "
                f"{profile_.display_name}. {profile_.display_name} sets word "
                f"count from the {unit[:-1]} count: {rule.len12} {unit} -> 12 "
                f"words, {rule.len24} {unit} -> 24 words, and it refuses any "
                f"other pairing. This tool refuses the same inputs the "
                f"device refuses, on purpose."
            )
            raise Refused(entered=n, reason=reason)

        word_count = length_word_count
    elif isinstance(rule, FreeChoice):
        if requested is None:
            raise ValueError(
                f"profile {profile_.id!r} is FreeChoice; `requested` "
                "(WordCount.W12 or WordCount.W24) must be given"
            )
        word_count = requested
    else:  # pragma: no cover -- closed set, defensive only
        raise TypeError(f"unknown word_count_rule: {rule!r}")

    digest = _digest(events)
    entropy = digest[:16] if word_count == WordCount.W12 else digest[:32]
    indexes = entropy_to_indexes(entropy)
    padded = tuple(indexes) + (0,) * (24 - len(indexes))

    return CompatOutput(word_count=word_count, mnemonic_indexes=padded, used_len=n)


# ---------------------------------------------------------------------------
# Candidate vector generation + checking (SPEC_COMPAT §10.1, §10.4)
#
# Produces `tests/vectors/compat/candidates/*.json`. Per
# IMPLEMENTATION_MAP_COMPAT.md §1.3, files here are CANDIDATES until the
# WP-C3 vector-freeze barrier reconciles them against the Rust
# `seed-compat` crate AND the profile's own real vendor tool (§10.2) --
# Rust-Python agreement alone never freezes a case (review F3). This
# module is only the candidate GENERATOR; it honestly records
# `oracle_kind` reflecting what ground truth WP-C2 itself has in hand
# (the vendor's own published doc examples), never claiming a
# `vendor_tool` confirmation this package did not perform.
# ---------------------------------------------------------------------------

SCHEMA_NAME = "alea-compat-vectors-v1"

_STANDARD_KEYS = {
    "bip44": "bip44",
    "bip49": "bip49",
    "bip84": "bip84",
    "bip86": "bip86",
}


def _dice_events(n: int, start: int = 1) -> str:
    """Deterministic public test dice-roll string: `'1'..'6'` repeating
    from `start` (mirrors the main corpus's `_dice_bytes` pattern in
    `seedref/vectors.py`, restated here in ASCII-digit form)."""
    return "".join(str(((start - 1 + i) % 6) + 1) for i in range(n))


def _coin_events(n: int, start: int = 0) -> str:
    """Deterministic public test coin-flip string: alternating `'0'/'1'`
    from `start`."""
    return "".join(str((start + i) % 2) for i in range(n))


def _derivation_fields(output: CompatOutput) -> dict:
    """SPEC §24.2 verification values (master fingerprint + all four
    first receive addresses), reused unchanged from the existing
    reference BIP39/BIP32/address code -- SPEC_COMPAT §12 states these
    are NOT reimplemented for seed-compat."""
    indexes = list(output.mnemonic_indexes[: output.word_count.value])
    seed = mnemonic_to_seed(indexes)
    master = master_from_seed(seed)
    fp = master_fingerprint(master).hex()
    addrs = {
        _STANDARD_KEYS[std.value]: first_address(seed, std) for std in PathStandard
    }
    return {
        "bip39_seed_hex": seed.hex(),
        "master_fingerprint_hex": fp,
        "addresses": addrs,
    }


def build_mnemonic_case(
    name: str,
    profile_id: str,
    events: str,
    requested: Optional[WordCount],
    oracle_kind: str,
    ground_truth: List[str],
) -> dict:
    """Build one `expected: "mnemonic"` case dict (§10.1 schema). Raises
    if `compat_derive` does NOT succeed -- a generator that silently
    swallowed an unexpected refusal here would defeat the point of a
    from-spec-only reference (a case meant to demonstrate a valid
    mnemonic must actually produce one)."""

    prof = oracle_profile(profile_id)
    if prof is None:
        raise ValueError(f"unknown profile id: {profile_id!r}")

    output = compat_derive(prof, events, requested)
    words = output.mnemonic_words

    case = {
        "name": name,
        "profile": profile_id,
        "method": prof.method.value,
        "events": events,
        "event_count": len(events),
        "expected": "mnemonic",
        "word_count": output.word_count.value,
        "mnemonic_indexes": list(output.mnemonic_indexes[: output.word_count.value]),
        "mnemonic_words": words,
        "oracle_kind": oracle_kind,
        "ground_truth": list(ground_truth),
    }
    if requested is not None:
        case["requested_word_count"] = requested.value
    case.update(_derivation_fields(output))
    return case


def build_refusal_case(
    name: str,
    profile_id: str,
    events: str,
    requested: Optional[WordCount],
    oracle_kind: str,
    ground_truth: List[str],
    expect: type = CompatError,
) -> dict:
    """Build one `expected: "refusal"` case dict (§10.1 schema). Raises
    if `compat_derive` does NOT raise `expect` -- a generator that
    silently accepted a mnemonic here would hide exactly the F1 defect
    this corpus exists to catch (IMPLEMENTATION_MAP_COMPAT.md §1.6)."""

    prof = oracle_profile(profile_id)
    if prof is None:
        raise ValueError(f"unknown profile id: {profile_id!r}")

    try:
        compat_derive(prof, events, requested)
    except expect as exc:
        reason = getattr(exc, "reason", str(exc))
        error_kind = type(exc).__name__
    else:
        raise AssertionError(
            f"candidate case {name!r} expected a refusal but compat_derive "
            "succeeded -- this would be exactly the F1 defect"
        )

    case = {
        "name": name,
        "profile": profile_id,
        "method": prof.method.value,
        "events": events,
        "event_count": len(events),
        "expected": "refusal",
        "error_kind": error_kind,
        "reason": reason,
        "oracle_kind": oracle_kind,
        "ground_truth": list(ground_truth),
    }
    if requested is not None:
        case["requested_word_count"] = requested.value
    return case


# The two vendor-published SeedSigner examples (SPEC_COMPAT §5.1.2,
# `docs/dice_verification.md`) -- the highest-value cases in the corpus
# because they are third-party-published, not self-computed.
_SEEDSIGNER_50_ROLLS = "65515223131652132161133154444123616466443112153441"
_SEEDSIGNER_99_ROLLS = (
    "655152231316521321611331544441236164664431121534415633"
    "526456254462245546236542364246312613322234612"
)

_SEEDSIGNER_DOC_GROUND_TRUTH = [
    "vendor_doc:dice_verification.md",
]


def generate_candidate_cases() -> List[dict]:
    """The candidate corpus (SPEC_COMPAT §10.4 minimum contents): the two
    vendor-published SeedSigner examples; a 12w/24w/digit-6 case per
    profile; a coin case for SeedSigner; the required F1 regression
    refusal cases per `DerivedFromLength` profile; and the empty-string
    `math_boundary_no_oracle` fixture (§10.2, never counted as
    vendor-confirmed)."""

    cases: List[dict] = []

    # --- Vendor-published SeedSigner examples (highest-value) ---------
    cases.append(
        build_mnemonic_case(
            "seedsigner_dice_12w_vendor_example",
            "seedsigner-dice",
            _SEEDSIGNER_50_ROLLS,
            None,
            "vendor_doc",
            _SEEDSIGNER_DOC_GROUND_TRUTH,
        )
    )
    cases.append(
        build_mnemonic_case(
            "seedsigner_dice_24w_vendor_example",
            "seedsigner-dice",
            _SEEDSIGNER_99_ROLLS,
            None,
            "vendor_doc",
            _SEEDSIGNER_DOC_GROUND_TRUTH,
        )
    )

    # --- seedsigner-dice: digit '6' present (6->0 regression guard) ---
    cases.append(
        build_mnemonic_case(
            "seedsigner_dice_digit6_present_12w",
            "seedsigner-dice",
            _dice_events(50, start=1),
            None,
            "pending_vendor_tool",
            ["pending:seedsigner_cli_mnemonic_py"],
        )
    )

    # --- seedsigner-coin: 12w / 24w ------------------------------------
    cases.append(
        build_mnemonic_case(
            "seedsigner_coin_12w_case1",
            "seedsigner-coin",
            _coin_events(128),
            None,
            "pending_vendor_tool",
            ["pending:seedsigner_cli_mnemonic_py"],
        )
    )
    cases.append(
        build_mnemonic_case(
            "seedsigner_coin_24w_case1",
            "seedsigner-coin",
            _coin_events(256, start=1),
            None,
            "pending_vendor_tool",
            ["pending:seedsigner_cli_mnemonic_py"],
        )
    )

    # --- coldcard-dice: 12w / 24w / digit-6 / advisory-only underroll --
    # Reuses the SAME vendor dice strings: the Method-A digest step is
    # byte-for-byte shared (SPEC_COMPAT §5.1), so coldcard-dice's
    # FreeChoice selection at (50,12w)/(99,24w) reproduces the identical
    # mnemonic as the SeedSigner cases above -- demonstrating the shared
    # digest, distinct word-count wrapper (SPEC_COMPAT §5.4).
    cases.append(
        build_mnemonic_case(
            "coldcard_dice_12w_case1",
            "coldcard-dice",
            _SEEDSIGNER_50_ROLLS,
            WordCount.W12,
            "pending_vendor_tool",
            ["pending:rolls12.py"],
        )
    )
    cases.append(
        build_mnemonic_case(
            "coldcard_dice_24w_case1",
            "coldcard-dice",
            _SEEDSIGNER_99_ROLLS,
            WordCount.W24,
            "pending_vendor_tool",
            ["pending:rolls.py"],
        )
    )
    cases.append(
        build_mnemonic_case(
            "coldcard_dice_digit6_present_12w",
            "coldcard-dice",
            _dice_events(50, start=3),
            WordCount.W12,
            "pending_vendor_tool",
            ["pending:rolls12.py"],
        )
    )
    cases.append(
        build_mnemonic_case(
            "coldcard_dice_advisory_underroll_12w",
            "coldcard-dice",
            _dice_events(40, start=2),
            WordCount.W12,
            "pending_vendor_tool",
            [
                "pending:rolls12.py",
                "vendor_doc:verifying-dice-roll-math (50/99 are advisory minimums, not enforced)",
            ],
        )
    )

    # --- iancoleman-hex: Method-A digest cross-check only --------------
    # (SPEC_COMPAT §5.1.4/§10.3: never a seedsigner-* oracle, only a
    # digest reconciliation path.)
    cases.append(
        build_mnemonic_case(
            "iancoleman_hex_digest_crosscheck_12w",
            "iancoleman-hex",
            _SEEDSIGNER_50_ROLLS,
            WordCount.W12,
            "pending_vendor_tool",
            ["pending:iancoleman_bip39_hex_mode"],
        )
    )
    cases.append(
        build_mnemonic_case(
            "iancoleman_hex_digest_crosscheck_24w",
            "iancoleman-hex",
            _SEEDSIGNER_99_ROLLS,
            WordCount.W24,
            "pending_vendor_tool",
            ["pending:iancoleman_bip39_hex_mode"],
        )
    )

    # --- F1 regression: DerivedFromLength profiles REFUSE non-canonical
    # counts, and refuse a canonical length paired with a mismatched
    # `requested` (the exact phantom pairing v0.6 fabricated) ----------
    cases.append(
        build_refusal_case(
            "seedsigner_dice_40rolls_refusal",
            "seedsigner-dice",
            _dice_events(40, start=1),
            None,
            "pending_vendor_tool_refusal",
            ["pending_refusal:seedsigner_cli_mnemonic_py"],
            expect=Refused,
        )
    )
    cases.append(
        build_refusal_case(
            "seedsigner_dice_60rolls_refusal",
            "seedsigner-dice",
            _dice_events(60, start=1),
            None,
            "pending_vendor_tool_refusal",
            ["pending_refusal:seedsigner_cli_mnemonic_py"],
            expect=Refused,
        )
    )
    cases.append(
        build_refusal_case(
            "seedsigner_dice_99rolls_asked_12w_refusal",
            "seedsigner-dice",
            _SEEDSIGNER_99_ROLLS,
            WordCount.W12,
            "pending_vendor_tool_refusal",
            ["pending_refusal:seedsigner_cli_mnemonic_py"],
            expect=Refused,
        )
    )
    cases.append(
        build_refusal_case(
            "seedsigner_coin_100flips_refusal",
            "seedsigner-coin",
            _coin_events(100),
            None,
            "pending_vendor_tool_refusal",
            ["pending_refusal:seedsigner_cli_mnemonic_py"],
            expect=Refused,
        )
    )
    cases.append(
        build_refusal_case(
            "seedsigner_coin_128flips_asked_24w_refusal",
            "seedsigner-coin",
            _coin_events(128),
            WordCount.W24,
            "pending_vendor_tool_refusal",
            ["pending_refusal:seedsigner_cli_mnemonic_py"],
            expect=Refused,
        )
    )

    # --- math_boundary_no_oracle: empty string (§10.2, §10.4) ----------
    # Documented/regression fixture only -- never counted as
    # vendor-confirmed, per SPEC_COMPAT §10.2's explicit instruction.
    cases.append(
        build_refusal_case(
            "seedsigner_dice_empty_string_no_oracle",
            "seedsigner-dice",
            "",
            None,
            "math_boundary_no_oracle",
            [],
            expect=Empty,
        )
    )
    cases.append(
        build_refusal_case(
            "coldcard_dice_empty_string_no_oracle",
            "coldcard-dice",
            "",
            WordCount.W12,
            "math_boundary_no_oracle",
            [],
            expect=Empty,
        )
    )

    return cases


def write_candidates(out_dir) -> List[str]:
    """Generate the candidate corpus and write one JSON file per case
    (`tests/vectors/compat/candidates/<case-name>.json`, SPEC_COMPAT
    §10.1 schema), returning the written file paths."""

    os.makedirs(out_dir, exist_ok=True)
    cases = generate_candidate_cases()
    names = [c["name"] for c in cases]
    if len(set(names)) != len(names):
        raise RuntimeError("duplicate candidate case names")

    paths = []
    for case in cases:
        doc = {"schema": SCHEMA_NAME, "cases": [case]}
        path = os.path.join(out_dir, f"{case['name']}.json")
        with open(path, "w", encoding="ascii") as f:
            json.dump(doc, f, indent=2, sort_keys=False)
            f.write("\n")
        paths.append(path)
    return paths


def check_file(path: str) -> List[str]:
    """Re-run `compat_derive` over every case in a vector file and report
    mismatches against the stored fields. Returns a list of
    human-readable problem descriptions; empty means every case
    round-trips (SPEC_COMPAT §10, mirroring `seedref.vectors.check_file`
    for the main corpus)."""

    problems: List[str] = []
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)

    if doc.get("schema") != SCHEMA_NAME:
        return [f"schema mismatch: expected {SCHEMA_NAME!r}, got {doc.get('schema')!r}"]

    for case in doc.get("cases", []):
        name = case.get("name", "<unnamed>")
        prof = oracle_profile(case.get("profile", ""))
        if prof is None:
            problems.append(f"{name}: unknown profile {case.get('profile')!r}")
            continue

        events = case.get("events", "")
        requested = None
        if "requested_word_count" in case:
            requested = WordCount(case["requested_word_count"])

        expected = case.get("expected")
        try:
            output = compat_derive(prof, events, requested)
        except CompatError as exc:
            if expected != "refusal":
                problems.append(
                    f"{name}: expected {expected!r} but compat_derive refused "
                    f"({type(exc).__name__}: {exc})"
                )
            continue
        else:
            if expected != "mnemonic":
                problems.append(
                    f"{name}: expected {expected!r} but compat_derive produced "
                    "a mnemonic"
                )
                continue

        if output.word_count.value != case.get("word_count"):
            problems.append(f"{name}: field 'word_count' mismatch")
        if output.mnemonic_words != case.get("mnemonic_words"):
            problems.append(f"{name}: field 'mnemonic_words' mismatch")

        recomputed = _derivation_fields(output)
        for field in ("bip39_seed_hex", "master_fingerprint_hex", "addresses"):
            if recomputed[field] != case.get(field):
                problems.append(f"{name}: field {field!r} mismatch")

    return problems
