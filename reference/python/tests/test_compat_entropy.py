"""Tests for seedref.compat_entropy (Method C — EntropyEncodingRaw,
SPEC_COMPAT_ENTROPY.md §8).

Freezes the same §8 vectors the Rust `tools/compat-verify` corpus freezes,
as an INDEPENDENT oracle (this reference was written from the spec + the
cited iancoleman source only). Covers the per-encoding bit tables, the
dice 6->0 remap, the last-32k-bit leading-discard truncation, the refusal
path, and the silently-ignored-characters behavior.
"""

import unittest

from seedref import compat_entropy as ce
from seedref.compat_entropy import Encoding


ABANDON_ABOUT = "abandon " * 11 + "about"
ZOO_WRONG = "zoo " * 11 + "wrong"
LEGAL_WINNER = "legal winner thank year wave sausage worth useful legal winner thank yellow"
LETTER_ADVICE = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
FETCH_PRIMARY = "fetch primary fetch primary fetch primary fetch primary fetch primary fetch problem"
ABLE_CANOE = "able canoe lunch model census force strong vacuum gown sport remind custom"

ZERO16 = "00" * 16
FF16 = "ff" * 16
FIVES = "55" * 16

# id, encoding, input, retained, entropy_hex, mnemonic, anchored?
VECTORS = [
    # 8.1 Binary
    ("B1", Encoding.BINARY, "0" * 128, 128, ZERO16, ABANDON_ABOUT, True),
    ("B2", Encoding.BINARY, "1" * 128, 128, FF16, ZOO_WRONG, True),
    ("B3", Encoding.BINARY, "0" * 130, 128, ZERO16, ABANDON_ABOUT, True),
    ("B4", Encoding.BINARY, "1" + "0" * 128, 128, ZERO16, ABANDON_ABOUT, True),
    # 8.2 Hex
    ("H1", Encoding.HEX, "0" * 32, 128, ZERO16, ABANDON_ABOUT, True),
    ("H2", Encoding.HEX, "f" * 32, 128, FF16, ZOO_WRONG, True),
    ("H3", Encoding.HEX, "7f" * 16, 128, "7f" * 16, LEGAL_WINNER, True),
    ("H4", Encoding.HEX, "80" * 16, 128, "80" * 16, LETTER_ADVICE, True),
    # 8.3 Dice (face 6 -> 0)
    ("D1", Encoding.DICE, "1" * 64, 128, FIVES, FETCH_PRIMARY, False),
    ("D2", Encoding.DICE, "6" * 64, 128, ZERO16, ABANDON_ABOUT, True),
    ("D3", Encoding.DICE, "5" * 128, 128, FF16, ZOO_WRONG, True),
    # 8.4 Base-6
    ("S1", Encoding.BASE6, "0" * 64, 128, ZERO16, ABANDON_ABOUT, True),
    ("S2", Encoding.BASE6, "3" * 64, 128, FF16, ZOO_WRONG, True),
    ("S3", Encoding.BASE6, "1" * 64, 128, FIVES, FETCH_PRIMARY, False),
    # 8.5 Base-10
    ("T1", Encoding.BASE10, "8" * 128, 128, ZERO16, ABANDON_ABOUT, True),
    ("T2", Encoding.BASE10, "9" * 128, 128, FF16, ZOO_WRONG, True),
    ("T3", Encoding.BASE10, "0" * 43, 128, ZERO16, ABANDON_ABOUT, True),
    # 8.6 Cards
    ("C1", Encoding.CARDS, "KS" * 64, 128, FF16, ZOO_WRONG, True),
    ("C2", Encoding.CARDS, "TS" * 64, 128, ZERO16, ABANDON_ABOUT, True),
    ("C3", Encoding.CARDS, "JS" * 64, 128, FIVES, FETCH_PRIMARY, False),
    (
        "C4",
        Encoding.CARDS,
        "AC 2C 3C 4C 5C 6C 7C 8C 9C TC JC QC KC AD 2D 3D 4D 5D 6D 7D 8D 9D TD JD TS JS QS KS",
        128,
        "00443214c74254b635cf84653a56d71b",
        ABLE_CANOE,
        False,
    ),
]


class TestFrozenEntropyVectors(unittest.TestCase):
    def test_all_vectors_reproduce_byte_exact(self):
        anchored = 0
        pending = 0
        for vid, enc, inp, retained, ehex, mnem, is_anchored in VECTORS:
            out = ce.entropy_encoding_derive(enc, inp)
            self.assertEqual(out.retained_bits, retained, f"{vid} retained")
            self.assertEqual(out.entropy_hex, ehex, f"{vid} entropy hex")
            self.assertEqual(" ".join(out.mnemonic_words), mnem, f"{vid} mnemonic")
            anchored += 1 if is_anchored else 0
            pending += 0 if is_anchored else 1
        self.assertEqual(len(VECTORS), 21)
        self.assertEqual(anchored, 17)
        self.assertEqual(pending, 4)

    def test_5555_case_agrees_across_three_encodings(self):
        for enc, inp in [
            (Encoding.DICE, "1" * 64),
            (Encoding.BASE6, "1" * 64),
            (Encoding.CARDS, "JS" * 64),
        ]:
            out = ce.entropy_encoding_derive(enc, inp)
            self.assertEqual(out.entropy_hex, FIVES)
            self.assertEqual(out.mnemonic_words[0], "fetch")
            self.assertEqual(out.mnemonic_words[11], "problem")


class TestTruncationAndRefusals(unittest.TestCase):
    def test_leading_discard_b4(self):
        out = ce.entropy_encoding_derive(Encoding.BINARY, "1" + "0" * 128)
        self.assertEqual(out.total_bits, 129)
        self.assertEqual(out.entropy_hex, ZERO16)  # NOT 80..00

    def test_refuses_160_bits_naming_divergence(self):
        with self.assertRaises(ce.UnsupportedLength) as cm:
            ce.entropy_encoding_derive(Encoding.BINARY, "1" * 160)
        self.assertEqual(cm.exception.retained_bits, 160)
        self.assertEqual(cm.exception.iancoleman_words, 15)

    def test_refuses_below_128(self):
        with self.assertRaises(ce.UnsupportedLength) as cm:
            ce.entropy_encoding_derive(Encoding.BINARY, "1" * 96)
        self.assertEqual(cm.exception.retained_bits, 96)

    def test_no_symbols(self):
        with self.assertRaises(ce.NoSymbols):
            ce.entropy_encoding_derive(Encoding.HEX, "xyz zzz!")

    def test_too_long(self):
        with self.assertRaises(ce.TooLong):
            ce.entropy_encoding_derive(Encoding.HEX, "f" * 3000)


class TestBitTables(unittest.TestCase):
    def test_dice_six_becomes_base6_zero(self):
        self.assertEqual(ce._symbol_bits(Encoding.DICE, "6"), "00")
        self.assertIsNone(ce._symbol_bits(Encoding.DICE, "0"))  # 0 outside [1-6]

    def test_base6_variable_width(self):
        self.assertEqual(ce._symbol_bits(Encoding.BASE6, "3"), "11")
        self.assertEqual(ce._symbol_bits(Encoding.BASE6, "4"), "0")

    def test_hex_case_insensitive(self):
        self.assertEqual(ce._symbol_bits(Encoding.HEX, "A"), "1010")
        self.assertEqual(ce._symbol_bits(Encoding.HEX, "a"), "1010")

    def test_card_widths(self):
        self.assertEqual(ce._card_bits(0), "00000")   # ac
        self.assertEqual(ce._card_bits(32), "0000")   # 7h
        self.assertEqual(ce._card_bits(51), "11")     # ks

    def test_ignored_chars_counted(self):
        out = ce.entropy_encoding_derive(Encoding.HEX, " ".join(["80"] * 16))
        self.assertEqual(out.accepted_symbols, 32)
        self.assertEqual(out.ignored_chars, 15)
        self.assertEqual(out.entropy_hex, "80" * 16)


if __name__ == "__main__":
    unittest.main()
