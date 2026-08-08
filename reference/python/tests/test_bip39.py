import json
import os
import unittest

from seedref.bip39 import (
    WORDLIST,
    WORDLIST_SHA256,
    entropy_to_indexes,
    indexes_to_words,
    mnemonic_to_seed,
    verify_checksum,
    word,
)

_VECTORS_PATH = os.path.join(os.path.dirname(__file__), "bip39_official_vectors.json")


class TestWordlist(unittest.TestCase):
    def test_2048_entries(self) -> None:
        self.assertEqual(len(WORDLIST), 2048)

    def test_no_duplicates(self) -> None:
        self.assertEqual(len(set(WORDLIST)), 2048)

    def test_known_hash_pinned(self) -> None:
        self.assertEqual(
            WORDLIST_SHA256,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
        )

    def test_first_and_last_word(self) -> None:
        self.assertEqual(word(0), "abandon")
        self.assertEqual(word(2047), "zoo")

    def test_four_letter_prefix_uniqueness(self) -> None:
        """SPEC §12.3: prefix resolution needs every 4-letter prefix (for
        words with length >= 4) to identify at most the words that share
        it; more importantly, no two *different* words share their full
        first-4-letters AND both be <4 letters (which would make the
        short one ambiguous with itself). This test just documents/locks
        the wordlist property this project depends on: grouping by
        4-letter prefix and checking every group is internally
        consistent for the exactly-4-or-shorter matching rule."""
        prefixes = {}
        for w in WORDLIST:
            key = w[:4]
            prefixes.setdefault(key, []).append(w)
        # Every word of length < 4 must be the *only* word with that
        # exact spelling as a prefix key (else "complete word if <4
        # letters" would be ambiguous against a longer word sharing the
        # same leading letters -- BIP39 English wordlist is known to
        # satisfy this).
        for w in WORDLIST:
            if len(w) < 4:
                group = prefixes[w[:4]]
                self.assertEqual(group, [w], f"short word {w!r} ambiguous with {group!r}")


class TestEntropyConversion(unittest.TestCase):
    def test_all_zero_128(self) -> None:
        indexes = entropy_to_indexes(bytes(16))
        words = indexes_to_words(indexes)
        self.assertEqual(
            words,
            ["abandon"] * 11 + ["about"],
        )

    def test_all_zero_256(self) -> None:
        indexes = entropy_to_indexes(bytes(32))
        words = indexes_to_words(indexes)
        self.assertEqual(words, ["abandon"] * 23 + ["art"])

    def test_invalid_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            entropy_to_indexes(bytes(15))
        with self.assertRaises(ValueError):
            entropy_to_indexes(bytes(20))

    def test_checksum_roundtrip(self) -> None:
        entropy = bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        indexes = entropy_to_indexes(entropy)
        self.assertTrue(verify_checksum(indexes))
        # Corrupt one index -> checksum should (almost certainly) fail.
        bad = list(indexes)
        bad[0] = bad[0] ^ 1
        self.assertFalse(verify_checksum(bad))


class TestOfficialBip39Vectors(unittest.TestCase):
    """https://github.com/trezor/python-mnemonic vectors.json, `english`
    list: each entry is [entropy_hex, mnemonic, seed_hex, bip32_xprv].
    Passphrase for seed derivation is the fixed string "TREZOR" (test
    fixture convention, not a real project passphrase -- SPEC §5 excludes
    passphrase entry from the real workflow; this is purely to validate
    the PBKDF2 KDF against a fixture that isn't empty-passphrase-only)."""

    @classmethod
    def setUpClass(cls) -> None:
        with open(_VECTORS_PATH, "r", encoding="utf-8") as f:
            cls.vectors = json.load(f)["english"]

    def test_entropy_to_mnemonic_and_seed(self) -> None:
        # SPEC §5 supports only 12-word (128-bit) and 24-word (256-bit)
        # mnemonics; the official fixture also includes 15/18/21-word
        # (160/192/224-bit) cases which are out of this project's scope
        # (and out of `entropy_to_indexes`'s supported-length contract),
        # so only the 16- and 32-byte-entropy rows are exercised here.
        for entropy_hex, mnemonic, seed_hex, _xprv in self.vectors:
            if len(entropy_hex) not in (32, 64):
                continue
            with self.subTest(entropy=entropy_hex):
                entropy = bytes.fromhex(entropy_hex)
                indexes = entropy_to_indexes(entropy)
                words = indexes_to_words(indexes)
                self.assertEqual(" ".join(words), mnemonic)
                self.assertTrue(verify_checksum(indexes))

                seed = mnemonic_to_seed(indexes, passphrase="TREZOR")
                self.assertEqual(seed.hex(), seed_hex)


if __name__ == "__main__":
    unittest.main()
