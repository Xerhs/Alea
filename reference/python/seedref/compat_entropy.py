"""seed-compat reference implementation — Method C: EntropyEncodingRaw
(SPEC_COMPAT_ENTROPY.md).

Independent Python reference for the **verification-only** raw-entropy
front end that reproduces `iancoleman/bip39`'s six typed entropy
encodings — Binary, Base-6, Dice, Base-10, Hex, Cards — byte-for-byte, so
a user can CONFIRM a seed another tool made from the same symbols. Written
from SPEC_COMPAT_ENTROPY.md and the cited iancoleman source
(`src/js/entropy.js` `eventBits`/`fromString`, `src/js/index.js`
`setMnemonicFromEntropy` `raw` branch) ONLY — the Rust `seed-compat`
`entropy_encoding` module was never read while writing this file. That
independence is the whole point of the reference oracle (mirrors how
Method A is doubly implemented).

This path NEVER participates in Alea's own production seed ceremony
(SPEC_COMPAT_ENTROPY §2). Typed symbols are unwitnessed/uncounted, so it
is verification-only, never a generation source. It reuses this package's
existing BIP39 entropy->mnemonic conversion (`seedref.bip39`) unchanged —
the *only* new logic is the encoding-string -> entropy-bytes front end.

The exact algorithm (SPEC_COMPAT_ENTROPY §5):

  1. match entropy characters with the encoding's alphabet; ignore the rest
  2. Dice: face 6 -> base-6 digit 0 ("00"); faces 1-5 -> base-6 table
  3. map each symbol via the verbatim `eventBits` table to a fixed
     VARIABLE-length bit-string and concatenate (per-symbol table lookup,
     NOT a BigInteger base-conversion, NOT log2(base)*count)
  4. retain the LAST floor(len/32)*32 bits (leading excess discarded)
  5. if retained not in {128, 256} -> refuse (never fabricate a phrase)
  6. pack retained bits MSB-first into 16 or 32 entropy bytes
  7. feed to the existing BIP39 pipeline (SHA-256 checksum, 11-bit words)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from .bip39 import entropy_to_indexes, indexes_to_words


#: The distinctive Method-C identifier (SPEC_COMPAT_ENTROPY §2 item 3): the
#: token the binary-policy scanner keys on, never the generic encoding words.
METHOD_ID = "EntropyEncodingRaw"

#: Bounded maximum concatenated eventBits length (SPEC_COMPAT_ENTROPY §7).
MAX_ENTROPY_BITS = 2048


class Encoding(Enum):
    """The six iancoleman/bip39 entropy input encodings
    (SPEC_COMPAT_ENTROPY §5.3). Closed set — adding one is a reviewed code
    change, never data-driven (SPEC_COMPAT §6)."""

    BINARY = "binary"
    BASE6 = "base6"
    DICE = "dice"
    BASE10 = "base10"
    HEX = "hex"
    CARDS = "cards"


# eventBits tables, verbatim from SPEC_COMPAT_ENTROPY §5.3.
_BASE6 = {"0": "00", "1": "01", "2": "10", "3": "11", "4": "0", "5": "1"}
# Dice [1-6]: face 6 -> base-6 digit 0; faces 1-5 -> base-6 table (§5.2).
_DICE = {"1": "01", "2": "10", "3": "11", "4": "0", "5": "1", "6": "00"}
_BASE10 = {
    "0": "000", "1": "001", "2": "010", "3": "011", "4": "100",
    "5": "101", "6": "110", "7": "111", "8": "0", "9": "1",
}
_HEX = {c: format(int(c, 16), "04b") for c in "0123456789abcdef"}

_CARD_RANKS = "A23456789TJQK"
_CARD_SUITS = "CDHS"


def _card_bits(idx: int) -> str:
    """eventBits["card"] for sequential index idx = suit*13 + rank
    (SPEC_COMPAT_ENTROPY §5.3): 0-31 -> 5-bit, 32-47 -> 4-bit, 48-51 ->
    2-bit."""
    if idx < 32:
        return format(idx, "05b")
    if idx < 48:
        return format(idx - 32, "04b")
    return format(idx - 48, "02b")


class EntropyEncodingError(Exception):
    """Base class for a Method-C refusal (SPEC_COMPAT_ENTROPY §5.5). Never
    paired with a fabricated mnemonic."""


class NoSymbols(EntropyEncodingError):
    def __init__(self, ignored_chars: int):
        self.ignored_chars = ignored_chars
        super().__init__("no symbols matched the selected encoding")


class TooLong(EntropyEncodingError):
    def __init__(self):
        super().__init__("input exceeds the bounded entropy buffer")


class UnsupportedLength(EntropyEncodingError):
    """Retained bits not in {128, 256}. `iancoleman_words` is the
    non-standard word count iancoleman WOULD emit (retained/32*3)."""

    def __init__(self, retained_bits: int, total_bits: int, accepted_symbols: int, ignored_chars: int):
        self.retained_bits = retained_bits
        self.total_bits = total_bits
        self.accepted_symbols = accepted_symbols
        self.ignored_chars = ignored_chars
        self.iancoleman_words = retained_bits // 32 * 3
        super().__init__(
            f"{retained_bits} retained bits is not 128 or 256; iancoleman "
            f"would emit a {self.iancoleman_words}-word non-standard phrase"
        )


@dataclass(frozen=True)
class EntropyEncodingOutput:
    encoding: Encoding
    entropy: bytes            # 16 or 32 bytes
    mnemonic_indexes: Tuple[int, ...]
    accepted_symbols: int
    ignored_chars: int
    retained_bits: int
    total_bits: int

    @property
    def word_count(self) -> int:
        return len(self.entropy) * 8 // 32 * 3  # 12 or 24

    @property
    def mnemonic_words(self) -> List[str]:
        return indexes_to_words(list(self.mnemonic_indexes))

    @property
    def entropy_hex(self) -> str:
        return self.entropy.hex()


def encoding_from_id(enc_id: str) -> Optional[Encoding]:
    """Closed lookup by id — no autodetect (SPEC_COMPAT_ENTROPY §5.1)."""
    for e in Encoding:
        if e.value == enc_id:
            return e
    return None


def _symbol_bits(encoding: Encoding, ch: str) -> Optional[str]:
    """The eventBits string for a single-character symbol, or None if `ch`
    is outside the encoding's alphabet (silently ignored)."""
    if encoding is Encoding.BINARY:
        return {"0": "0", "1": "1"}.get(ch)
    if encoding is Encoding.BASE6:
        return _BASE6.get(ch)
    if encoding is Encoding.DICE:
        return _DICE.get(ch)
    if encoding is Encoding.BASE10:
        return _BASE10.get(ch)
    if encoding is Encoding.HEX:
        return _HEX.get(ch.lower())
    return None  # cards handled separately


def entropy_encoding_derive(encoding: Encoding, input_str: str) -> EntropyEncodingOutput:
    """Reproduce iancoleman/bip39's raw-entropy derivation for `input_str`
    under the explicitly selected `encoding` (SPEC_COMPAT_ENTROPY §7).
    Raises `NoSymbols`, `TooLong`, or `UnsupportedLength` rather than
    fabricating a phrase."""

    bits: List[str] = []
    accepted = 0
    consumed_chars = 0
    total_chars = len(input_str)

    if encoding is Encoding.CARDS:
        # Two-character tokens [A2-9TJQK][CDHS], scanned left-to-right like
        # iancoleman's global `card` regex. No dedup / no replacement logic
        # in the bit path (§6): duplicates contribute their bits again.
        i = 0
        n = len(input_str)
        while i < n:
            r = input_str[i].upper()
            if r in _CARD_RANKS and i + 1 < n:
                s = input_str[i + 1].upper()
                if s in _CARD_SUITS:
                    idx = _CARD_SUITS.index(s) * 13 + _CARD_RANKS.index(r)
                    bits.append(_card_bits(idx))
                    accepted += 1
                    consumed_chars += 2
                    i += 2
                    continue
            i += 1
    else:
        for ch in input_str:
            b = _symbol_bits(encoding, ch)
            if b is not None:
                bits.append(b)
                accepted += 1
                consumed_chars += 1

    ignored_chars = total_chars - consumed_chars

    if accepted == 0:
        raise NoSymbols(ignored_chars=ignored_chars)

    binary_str = "".join(bits)
    total_bits = len(binary_str)
    if total_bits > MAX_ENTROPY_BITS:
        raise TooLong()

    # §5.5: keep the LAST floor(len/32)*32 bits; discard the LEADING excess.
    retained = (total_bits // 32) * 32
    if retained not in (128, 256):
        raise UnsupportedLength(
            retained_bits=retained,
            total_bits=total_bits,
            accepted_symbols=accepted,
            ignored_chars=ignored_chars,
        )

    start = total_bits - retained
    tail = binary_str[start:]
    entropy = int(tail, 2).to_bytes(retained // 8, "big")

    indexes = tuple(entropy_to_indexes(entropy))
    return EntropyEncodingOutput(
        encoding=encoding,
        entropy=entropy,
        mnemonic_indexes=indexes,
        accepted_symbols=accepted,
        ignored_chars=ignored_chars,
        retained_bits=retained,
        total_bits=total_bits,
    )
