"""BIP39 mnemonic encoding and seed derivation (SPEC §14, §24.2).

Loads the official 2048-word English wordlist (pinned by SHA-256, self
checked at import time) and implements entropy<->indexes conversion with
the BIP39 checksum, plus the BIP39 seed KDF.
"""

from __future__ import annotations

import os
from typing import List

from .hashes import pbkdf2_hmac_sha512, sha256

#: The official BIP39 English wordlist SHA-256 (bitcoin/bips
#: `bip-0039/english.txt`), pinned so a corrupted or substituted wordlist
#: file fails loudly instead of silently producing wrong mnemonics.
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlist_english.txt")


def _load_wordlist() -> List[str]:
    with open(_WORDLIST_PATH, "rb") as f:
        raw = f.read()
    digest = sha256(raw).hex()
    if digest != WORDLIST_SHA256:
        raise RuntimeError(
            f"BIP39 English wordlist integrity check failed: "
            f"expected sha256={WORDLIST_SHA256}, got {digest}"
        )
    words = raw.decode("ascii").splitlines()
    if len(words) != 2048:
        raise RuntimeError(f"BIP39 English wordlist has {len(words)} entries, expected 2048")
    return words


WORDLIST: List[str] = _load_wordlist()
assert len(set(WORDLIST)) == 2048, "wordlist must have no duplicate entries"


def word(index: int) -> str:
    """The BIP39 English word at `index` (0..2047)."""
    return WORDLIST[index]


def entropy_to_indexes(entropy: bytes) -> List[int]:
    """Convert raw entropy (16 or 32 bytes -- SPEC §14) to BIP39 word
    indexes, appending the checksum bits per BIP39.
    """
    if len(entropy) not in (16, 32):
        raise ValueError("entropy must be 16 or 32 bytes")
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32
    checksum_byte = sha256(entropy)[0]
    # Take the top `checksum_bits` bits of the checksum byte.
    checksum = checksum_byte >> (8 - checksum_bits)

    total_bits = entropy_bits + checksum_bits
    acc = (int.from_bytes(entropy, "big") << checksum_bits) | checksum
    n_words = total_bits // 11
    indexes = []
    for i in range(n_words):
        shift = total_bits - 11 * (i + 1)
        idx = (acc >> shift) & 0x7FF
        indexes.append(idx)
    return indexes


def indexes_to_words(indexes: List[int]) -> List[str]:
    """Render BIP39 word indexes as English words."""
    return [WORDLIST[i] for i in indexes]


def verify_checksum(indexes: List[int]) -> bool:
    """Reconstruct entropy from `indexes` and check the BIP39 checksum
    matches (used only for self-tests / KATs -- not needed on the normal
    entropy -> mnemonic path).
    """
    n_words = len(indexes)
    if n_words not in (12, 24):
        raise ValueError("only 12- or 24-word mnemonics are supported")
    total_bits = n_words * 11
    entropy_bits = (n_words * 32) // 3
    checksum_bits = total_bits - entropy_bits

    acc = 0
    for idx in indexes:
        acc = (acc << 11) | idx
    entropy_int = acc >> checksum_bits
    checksum = acc & ((1 << checksum_bits) - 1)
    entropy = entropy_int.to_bytes(entropy_bits // 8, "big")

    checksum_byte = sha256(entropy)[0]
    expected = checksum_byte >> (8 - checksum_bits)
    return checksum == expected


def mnemonic_to_seed(indexes: List[int], passphrase: str = "") -> bytes:
    """BIP39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase,
    2048 iterations)` (SPEC §14, §24.2). Always the empty passphrase in
    this project (SPEC §5 excludes BIP39 passphrase entry); the parameter
    exists only so tests can exercise the official BIP39 vectors, which
    include a non-empty "TREZOR" passphrase case.

    Feeds the space-joined mnemonic words as the PBKDF2 password -- this
    is the standalone reference implementation, not the arena-constrained
    Rust production path (SPEC §12.2's no-materialized-phrase constraint
    binds the UEFI implementation, not this independent test tool).
    """
    mnemonic = " ".join(indexes_to_words(indexes))
    password = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return pbkdf2_hmac_sha512(password, salt, 2048)
