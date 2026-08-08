import json
import os
import tempfile
import unittest
from pathlib import Path

from seedref import vectors

#: tests/vectors/frozen/ relative to the repo root (reference/python/tests/
#: test_vectors.py -> repo root is three levels up). WP-16-frozen;
#: read-only here -- used only to assert byte-for-byte non-perturbation.
_FROZEN_DIR = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "frozen"


class TestCandidateCorpusGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = vectors.generate_candidate_cases()

    def test_at_least_20_cases(self) -> None:
        self.assertGreaterEqual(len(self.cases), 20)

    def test_unique_names(self) -> None:
        names = [c["name"] for c in self.cases]
        self.assertEqual(len(names), len(set(names)))

    def test_categories_present(self) -> None:
        names = " ".join(c["name"] for c in self.cases)
        for needle in (
            "dice_only_12w",
            "dice_only_24w",
            "coins_only_12w",
            "coins_only_24w",
            "mixed_dice_coins",
            "machine_",
            "usb_trng_",
        ):
            self.assertIn(needle, names)

    def test_both_word_counts_present(self) -> None:
        bits = {c["bits"] for c in self.cases}
        self.assertEqual(bits, {128, 256})

    def test_hex_fields_lowercase(self) -> None:
        for c in self.cases:
            for field in ("transcript_hex", "final_entropy_hex", "bip39_seed_hex", "master_fingerprint_hex"):
                value = c[field]
                self.assertEqual(value, value.lower(), f"{c['name']}.{field} not lowercase")
            for src in c["sources"]:
                self.assertEqual(src["tag"], src["tag"].lower())
                self.assertEqual(src["bytes_hex"], src["bytes_hex"].lower())
            for addr in c["addresses"].values():
                # Addresses are case-sensitive by design (Base58Check is
                # mixed-case, bech32 is lowercase); only check bech32 ones.
                if addr.startswith("bc1"):
                    self.assertEqual(addr, addr.lower())

    def test_mnemonic_word_count_matches_bits(self) -> None:
        for c in self.cases:
            expected = 12 if c["bits"] == 128 else 24
            self.assertEqual(len(c["mnemonic_indexes"]), expected)
            self.assertEqual(len(c["mnemonic_words"]), expected)

    def test_final_entropy_length_matches_bits(self) -> None:
        for c in self.cases:
            expected_len = c["bits"] // 8
            self.assertEqual(len(bytes.fromhex(c["final_entropy_hex"])), expected_len)

    def test_seed_always_64_bytes(self) -> None:
        for c in self.cases:
            self.assertEqual(len(bytes.fromhex(c["bip39_seed_hex"])), 64)

    def test_fingerprint_always_4_bytes(self) -> None:
        for c in self.cases:
            self.assertEqual(len(bytes.fromhex(c["master_fingerprint_hex"])), 4)

    def test_all_four_address_kinds_present(self) -> None:
        for c in self.cases:
            self.assertEqual(set(c["addresses"].keys()), {"bip44", "bip49", "bip84", "bip86"})


class TestUsbTrngCandidates(unittest.TestCase):
    """WP-U6 (IMPLEMENTATION_MAP_USB_TRNG.md §4/§5): 0x12 candidate
    vectors for the WP-U1 transcript-freeze barrier."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {c["name"]: c for c in vectors.generate_candidate_cases()}
        cls.usb_cases = {n: c for n, c in cls.cases.items() if n.startswith("usb_trng_")}

    def test_at_least_one_dice_coin_usb_reinforced_session(self) -> None:
        """The mandatory dice+coin+usb reinforced-session candidate (map
        §5 item 2) is present, uses all three tags, and is the exact
        arch/bits/policy_version triple from the SPEC_USB_TRNG §6.2 byte-
        layout proof."""
        case = self.cases["usb_trng_reinforced_dice_coin_24w_spec_proof"]
        tags = {s["tag"] for s in case["sources"]}
        self.assertEqual(tags, {"0x10", "0x11", "0x12"})
        self.assertEqual(case["bits"], 256)
        self.assertEqual(case["policy_version"], 2)
        self.assertEqual(case["arch"], "x86_64")

    def test_usb_cases_present_and_named(self) -> None:
        self.assertGreaterEqual(len(self.usb_cases), 5)

    def test_usb_source_tag_and_algo_id_fixed(self) -> None:
        for case in self.usb_cases.values():
            usb_sources = [s for s in case["sources"] if s["tag"] == "0x12"]
            self.assertEqual(len(usb_sources), 1, case["name"])
            self.assertEqual(usb_sources[0]["algo"], vectors.USB_TRNG_ALGO_ID)

    def test_usb_cases_round_trip_via_check_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = vectors.write_candidates(tmp)
            usb_paths = [p for p in paths if os.path.basename(p).startswith("usb_trng_")]
            self.assertGreaterEqual(len(usb_paths), 5)
            for p in usb_paths:
                problems = vectors.check_file(p)
                self.assertEqual(problems, [], f"{p}: {problems}")

    def test_pre_existing_frozen_cases_byte_identical_after_0x12_addition(self) -> None:
        """The two MANDATORY regressions (map §5): adding the 0x12
        candidate category must not perturb a single byte of any of the
        23 pre-existing (USB-absent) frozen cases. Compares the freshly
        generated `transcript_hex`/`final_entropy_hex` for every name
        already present under `tests/vectors/frozen/` against the file
        on disk, field-by-field."""
        if not _FROZEN_DIR.is_dir():
            self.skipTest(f"frozen corpus not found at {_FROZEN_DIR}")
        frozen_files = sorted(_FROZEN_DIR.glob("*.json"))
        self.assertGreaterEqual(len(frozen_files), 20)
        checked = 0
        for path in frozen_files:
            with open(path, "r", encoding="ascii") as f:
                frozen_doc = json.load(f)
            frozen_case = frozen_doc["cases"][0]
            name = frozen_case["name"]
            self.assertIn(name, self.cases, f"{name}: no longer generated after 0x12 addition")
            fresh = self.cases[name]
            for field in (
                "sources",
                "arch",
                "bits",
                "policy_version",
                "transcript_hex",
                "final_entropy_hex",
                "mnemonic_indexes",
                "mnemonic_words",
                "bip39_seed_hex",
                "master_fingerprint_hex",
                "addresses",
            ):
                self.assertEqual(fresh[field], frozen_case[field], f"{name}.{field} changed by 0x12 addition")
            checked += 1
        self.assertEqual(checked, len(frozen_files))


class TestWriteAndCheckRoundtrip(unittest.TestCase):
    def test_write_then_check_all_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = vectors.write_candidates(tmp)
            self.assertGreaterEqual(len(paths), 20)
            for p in paths:
                problems = vectors.check_file(p)
                self.assertEqual(problems, [], f"{p}: {problems}")

    def test_check_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = vectors.write_candidates(tmp)
            target = paths[0]
            with open(target, "r", encoding="ascii") as f:
                doc = json.load(f)
            doc["cases"][0]["final_entropy_hex"] = "00" * 16
            with open(target, "w", encoding="ascii") as f:
                json.dump(doc, f)
            problems = vectors.check_file(target)
            self.assertTrue(any("final_entropy_hex" in p for p in problems))

    def test_check_rejects_bad_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="ascii") as f:
                json.dump({"schema": "not-the-right-schema", "cases": []}, f)
            problems = vectors.check_file(path)
            self.assertEqual(len(problems), 1)
            self.assertIn("schema mismatch", problems[0])


if __name__ == "__main__":
    unittest.main()
