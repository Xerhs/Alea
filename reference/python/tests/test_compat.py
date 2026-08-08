"""Tests for seedref.compat (SPEC_COMPAT v0.6.1, WP-C2).

Covers the two SeedSigner vendor-published examples (§5.1.2), the
per-profile word-count rules (§6), and -- most importantly -- the F1
refusal behavior (review F1): a `DerivedFromLength` profile given a
non-canonical count, or a canonical count paired with a mismatched
`requested`, MUST raise `Refused`, never return a fabricated mnemonic.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from seedref import compat


# The two vendor-published SeedSigner examples (SPEC_COMPAT §5.1.2,
# docs/dice_verification.md).
_SEEDSIGNER_50_ROLLS = "65515223131652132161133154444123616466443112153441"
_SEEDSIGNER_99_ROLLS = (
    "655152231316521321611331544441236164664431121534415633"
    "526456254462245546236542364246312613322234612"
)


class TestVendorPublishedExamples(unittest.TestCase):
    """The two locked SeedSigner vendor examples (SPEC_COMPAT §5.1.2)."""

    def test_50_rolls_12w(self) -> None:
        prof = compat.profile("seedsigner-dice")
        self.assertIsNotNone(prof)
        out = compat.compat_derive(prof, _SEEDSIGNER_50_ROLLS)
        self.assertEqual(out.word_count, compat.WordCount.W12)
        self.assertEqual(out.used_len, 50)
        self.assertEqual(
            out.mnemonic_words,
            [
                "hole", "luggage", "safe", "present", "express", "tragic",
                "orbit", "shed", "switch", "metal", "identify", "path",
            ],
        )

    def test_99_rolls_24w(self) -> None:
        prof = compat.profile("seedsigner-dice")
        out = compat.compat_derive(prof, _SEEDSIGNER_99_ROLLS)
        self.assertEqual(out.word_count, compat.WordCount.W24)
        self.assertEqual(out.used_len, 99)
        self.assertEqual(
            out.mnemonic_words,
            [
                "eyebrow", "obvious", "such", "suggest", "poet", "seven",
                "breeze", "blame", "virtual", "frown", "dynamic", "donor",
                "harsh", "pigeon", "express", "broccoli", "easy", "apology",
                "scatter", "force", "recipe", "shadow", "claim", "radio",
            ],
        )

    def test_empty_string_well_known_digest(self) -> None:
        # SPEC_COMPAT §5.1: "The empty event string hashes to the
        # well-known e3b0c442...b855" -- verify the digest primitive
        # directly (compat_derive itself refuses empty input, tested
        # separately below).
        self.assertEqual(
            compat._digest("").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


class TestDerivedFromLengthRefusals(unittest.TestCase):
    """F1 regression: DerivedFromLength profiles REFUSE non-canonical
    counts and mismatched (length, requested) pairings -- never a
    fabricated phrase (review F1, IMPLEMENTATION_MAP_COMPAT.md §1.6)."""

    def test_40_rolls_refused(self) -> None:
        prof = compat.profile("seedsigner-dice")
        events = compat._dice_events(40)
        with self.assertRaises(compat.Refused) as ctx:
            compat.compat_derive(prof, events)
        self.assertEqual(ctx.exception.entered, 40)

    def test_60_rolls_refused(self) -> None:
        prof = compat.profile("seedsigner-dice")
        events = compat._dice_events(60)
        with self.assertRaises(compat.Refused) as ctx:
            compat.compat_derive(prof, events)
        self.assertEqual(ctx.exception.entered, 60)

    def test_99_rolls_asked_as_12_words_refused(self) -> None:
        """The exact phantom pairing v0.6 fabricated: 99 rolls (which
        SeedSigner ties to 24 words) explicitly requested as 12 words
        MUST be refused, not silently coerced to either 12 or 24
        words."""
        prof = compat.profile("seedsigner-dice")
        with self.assertRaises(compat.Refused):
            compat.compat_derive(prof, _SEEDSIGNER_99_ROLLS, compat.WordCount.W12)
        # Sanity: the SAME events with no explicit request (or the
        # correct request) succeed -- proving the refusal above is
        # specifically about the mismatched pairing, not the input.
        out = compat.compat_derive(prof, _SEEDSIGNER_99_ROLLS)
        self.assertEqual(out.word_count, compat.WordCount.W24)
        out2 = compat.compat_derive(prof, _SEEDSIGNER_99_ROLLS, compat.WordCount.W24)
        self.assertEqual(out2.word_count, compat.WordCount.W24)

    def test_50_rolls_asked_as_24_words_refused(self) -> None:
        prof = compat.profile("seedsigner-dice")
        with self.assertRaises(compat.Refused):
            compat.compat_derive(prof, _SEEDSIGNER_50_ROLLS, compat.WordCount.W24)

    def test_seedsigner_coin_non_canonical_refused(self) -> None:
        prof = compat.profile("seedsigner-coin")
        events = compat._coin_events(100)
        with self.assertRaises(compat.Refused):
            compat.compat_derive(prof, events)

    def test_refused_is_not_a_mnemonic(self) -> None:
        """Defensive: confirm Refused/Empty are never accidentally
        raised as a subclass that also carries mnemonic-shaped data --
        the error must be the ONLY outcome, no partial phrase."""
        prof = compat.profile("seedsigner-dice")
        try:
            compat.compat_derive(prof, compat._dice_events(40))
        except compat.Refused as exc:
            self.assertFalse(hasattr(exc, "mnemonic_words"))
            self.assertFalse(hasattr(exc, "mnemonic_indexes"))
        else:
            self.fail("expected Refused")


class TestF1StructurallyNeverReachesDigest(unittest.TestCase):
    """Review F1 (confirmed, low-severity hardening): the existing
    discrete-value tests (40, 60, 99-asked-as-12, 100 flips) prove the
    *outcome* is `Refused` for a few chosen lengths, but not that the
    property holds for *every* non-canonical length, nor that the
    refusal happens structurally -- before any digest/entropy work is
    even attempted, so a fabricated phrase is architecturally
    impossible, not merely avoided by the specific inputs tried so far.

    This class patches `compat._digest` and `compat.entropy_to_indexes`
    (the two calls a fabricated-phrase bug would have to reach, per
    `compat_derive` lines ~475/477) to raise if invoked at all, then
    sweeps every non-canonical length in a wide range -- including the
    off-by-one boundaries immediately adjacent to the canonical lengths,
    where an indexing slip is most likely -- for both
    `DerivedFromLength` profiles (`seedsigner-dice`, `seedsigner-coin`).
    If any of these ever produced a mnemonic, or ever reached the digest
    step before raising, this test fails."""

    def _assert_refused_without_reaching_digest(self, prof, events, n) -> None:
        with mock.patch.object(
            compat, "_digest", side_effect=AssertionError(
                f"_digest() was reached for non-canonical length {n} "
                f"(profile {prof.id!r}) -- this is exactly the F1 defect"
            )
        ), mock.patch.object(
            compat, "entropy_to_indexes", side_effect=AssertionError(
                f"entropy_to_indexes() was reached for non-canonical "
                f"length {n} (profile {prof.id!r}) -- this is exactly "
                "the F1 defect"
            )
        ):
            with self.assertRaises(compat.Refused) as ctx:
                compat.compat_derive(prof, events)
            self.assertEqual(ctx.exception.entered, n)

    def test_seedsigner_dice_sweep_never_reaches_digest(self) -> None:
        prof = compat.profile("seedsigner-dice")
        canonical = {prof.word_count_rule.len12, prof.word_count_rule.len24}
        for n in range(1, 140):
            if n in canonical:
                continue
            with self.subTest(n=n):
                self._assert_refused_without_reaching_digest(
                    prof, compat._dice_events(n), n
                )

    def test_seedsigner_coin_sweep_never_reaches_digest(self) -> None:
        prof = compat.profile("seedsigner-coin")
        canonical = {prof.word_count_rule.len12, prof.word_count_rule.len24}
        for n in range(1, 270):
            if n in canonical:
                continue
            with self.subTest(n=n):
                self._assert_refused_without_reaching_digest(
                    prof, compat._coin_events(n), n
                )

    def test_boundary_adjacent_lengths_refused(self) -> None:
        """The single characters immediately next to each canonical
        length -- the most likely spot for an off-by-one regression --
        explicitly, on top of the broad sweeps above."""
        dice = compat.profile("seedsigner-dice")
        for n in (49, 51, 98, 100):
            with self.subTest(profile="seedsigner-dice", n=n):
                self._assert_refused_without_reaching_digest(
                    dice, compat._dice_events(n), n
                )

        coin = compat.profile("seedsigner-coin")
        for n in (127, 129, 255, 257):
            with self.subTest(profile="seedsigner-coin", n=n):
                self._assert_refused_without_reaching_digest(
                    coin, compat._coin_events(n), n
                )

    def test_canonical_lengths_do_reach_digest(self) -> None:
        """Sanity control for the sweeps above: patching `_digest` to
        raise must NOT suppress success at the canonical lengths --
        otherwise the sweep tests would pass vacuously by breaking
        everything rather than by proving the refusal boundary."""
        prof = compat.profile("seedsigner-dice")
        with mock.patch.object(
            compat, "_digest", wraps=compat._digest
        ) as spy_digest:
            out = compat.compat_derive(prof, compat._dice_events(50))
            self.assertEqual(out.word_count, compat.WordCount.W12)
            spy_digest.assert_called_once()


class TestFreeChoiceProfiles(unittest.TestCase):
    """COLDCARD / iancoleman-hex: free 12-vs-24 choice, advisory-only
    minimums (SPEC_COMPAT §5.1.1/§5.1.4, §6)."""

    def test_coldcard_dice_requires_requested(self) -> None:
        prof = compat.profile("coldcard-dice")
        with self.assertRaises(ValueError):
            compat.compat_derive(prof, _SEEDSIGNER_50_ROLLS)

    def test_coldcard_dice_shares_digest_with_seedsigner(self) -> None:
        """Method A's digest step is byte-for-byte shared across
        profiles (SPEC_COMPAT §5.1) -- only the word-count wrapper
        differs."""
        cc = compat.profile("coldcard-dice")
        ss = compat.profile("seedsigner-dice")
        out_cc = compat.compat_derive(cc, _SEEDSIGNER_50_ROLLS, compat.WordCount.W12)
        out_ss = compat.compat_derive(ss, _SEEDSIGNER_50_ROLLS)
        self.assertEqual(out_cc.mnemonic_words, out_ss.mnemonic_words)

    def test_coldcard_dice_advisory_minimum_not_enforced(self) -> None:
        """SPEC_COMPAT §5.1.1: the 50/99 counts are advisory minimums,
        NOT enforced by the standalone scripts -- an under-count MUST
        still succeed for coldcard-dice, unlike seedsigner-dice at the
        same length (tested above)."""
        prof = compat.profile("coldcard-dice")
        events = compat._dice_events(40)
        out = compat.compat_derive(prof, events, compat.WordCount.W12)
        self.assertEqual(out.word_count, compat.WordCount.W12)

    def test_iancoleman_hex_is_not_user_facing(self) -> None:
        self.assertIsNone(compat.profile("iancoleman-hex"))
        self.assertIsNotNone(compat.oracle_profile("iancoleman-hex"))


class TestAlphabetValidation(unittest.TestCase):
    def test_dice_rejects_zero(self) -> None:
        prof = compat.profile("seedsigner-dice")
        with self.assertRaises(compat.BadAlphabet) as ctx:
            compat.compat_derive(prof, "0" * 50)
        self.assertEqual(ctx.exception.at, 0)

    def test_dice_rejects_non_digit(self) -> None:
        prof = compat.profile("coldcard-dice")
        events = "1" * 25 + "x" + "1" * 24
        with self.assertRaises(compat.BadAlphabet) as ctx:
            compat.compat_derive(prof, events, compat.WordCount.W12)
        self.assertEqual(ctx.exception.at, 25)

    def test_coin_rejects_dice_digit(self) -> None:
        prof = compat.profile("seedsigner-coin")
        events = "01" * 63 + "6"  # 127 chars, last one invalid for coin
        with self.assertRaises(compat.BadAlphabet):
            compat.compat_derive(prof, events)

    def test_digit_six_not_remapped(self) -> None:
        """The '6'->'0' trap is a DIFFERENT (education-only, Method B)
        tool setting -- Method A hashes '6' as-is (SPEC_COMPAT §5.1.2).
        A string with '6' replaced by '0' must hash differently."""
        prof = compat.profile("seedsigner-dice")
        out_with_6 = compat.compat_derive(prof, _SEEDSIGNER_50_ROLLS)
        remapped = _SEEDSIGNER_50_ROLLS.replace("6", "0")
        # The remapped string now contains '0', which the default
        # SeedSigner alphabet rejects outright (SPEC_COMPAT §5.1.2,
        # review F8) -- confirming '0' is never silently accepted as a
        # stand-in for '6'.
        with self.assertRaises(compat.BadAlphabet):
            compat.compat_derive(prof, remapped)
        self.assertNotEqual(
            compat._digest(_SEEDSIGNER_50_ROLLS), compat._digest(remapped)
        )


class TestEmptyString(unittest.TestCase):
    def test_empty_raises_empty_not_refused(self) -> None:
        prof = compat.profile("seedsigner-dice")
        with self.assertRaises(compat.Empty):
            compat.compat_derive(prof, "")

    def test_empty_is_a_compat_error(self) -> None:
        self.assertTrue(issubclass(compat.Empty, compat.CompatError))
        self.assertTrue(issubclass(compat.Refused, compat.CompatError))
        self.assertTrue(issubclass(compat.BadAlphabet, compat.CompatError))


class TestProfileCatalog(unittest.TestCase):
    def test_three_user_facing_profiles(self) -> None:
        for pid in ("coldcard-dice", "seedsigner-dice", "seedsigner-coin"):
            self.assertIsNotNone(compat.profile(pid), pid)

    def test_unknown_profile_id(self) -> None:
        self.assertIsNone(compat.profile("nonexistent"))
        self.assertIsNone(compat.oracle_profile("nonexistent"))

    def test_word_count_rules_match_spec(self) -> None:
        cc = compat.profile("coldcard-dice")
        self.assertIsInstance(cc.word_count_rule, compat.FreeChoice)
        self.assertEqual(cc.word_count_rule.advisory_min_12, 50)
        self.assertEqual(cc.word_count_rule.advisory_min_24, 99)

        ssd = compat.profile("seedsigner-dice")
        self.assertIsInstance(ssd.word_count_rule, compat.DerivedFromLength)
        self.assertEqual(ssd.word_count_rule.len12, 50)
        self.assertEqual(ssd.word_count_rule.len24, 99)

        ssc = compat.profile("seedsigner-coin")
        self.assertIsInstance(ssc.word_count_rule, compat.DerivedFromLength)
        self.assertEqual(ssc.word_count_rule.len12, 128)
        self.assertEqual(ssc.word_count_rule.len24, 256)

    def test_coldcard_requires_hw_confirmation(self) -> None:
        self.assertTrue(compat.profile("coldcard-dice").requires_hw_confirmation)
        self.assertFalse(compat.profile("seedsigner-dice").requires_hw_confirmation)
        self.assertFalse(compat.profile("seedsigner-coin").requires_hw_confirmation)

    def test_closed_method_enum_single_variant(self) -> None:
        self.assertEqual(len(list(compat.CompatMethod)), 1)
        self.assertEqual(compat.CompatMethod.SHA256_ASCII_DIGEST.value, "Sha256AsciiDigest")


class TestCandidateVectorGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = compat.generate_candidate_cases()

    def test_minimum_corpus_size(self) -> None:
        self.assertGreaterEqual(len(self.cases), 14)

    def test_unique_names(self) -> None:
        names = [c["name"] for c in self.cases]
        self.assertEqual(len(names), len(set(names)))

    def test_vendor_examples_present(self) -> None:
        names = {c["name"] for c in self.cases}
        self.assertIn("seedsigner_dice_12w_vendor_example", names)
        self.assertIn("seedsigner_dice_24w_vendor_example", names)

    def test_f1_refusal_cases_present_per_derived_from_length_profile(self) -> None:
        refusal_cases = [c for c in self.cases if c["expected"] == "refusal"]
        dice_refusals = [c for c in refusal_cases if c["profile"] == "seedsigner-dice"]
        coin_refusals = [c for c in refusal_cases if c["profile"] == "seedsigner-coin"]
        self.assertGreaterEqual(len(dice_refusals), 2)
        self.assertGreaterEqual(len(coin_refusals), 1)

    def test_no_refusal_case_carries_mnemonic_fields(self) -> None:
        for c in self.cases:
            if c["expected"] == "refusal":
                self.assertNotIn("mnemonic_words", c)
                self.assertNotIn("word_count", c)

    def test_no_mnemonic_case_missing_derivation_fields(self) -> None:
        for c in self.cases:
            if c["expected"] == "mnemonic":
                self.assertIn("bip39_seed_hex", c)
                self.assertIn("master_fingerprint_hex", c)
                self.assertIn("addresses", c)
                self.assertEqual(
                    set(c["addresses"].keys()), {"bip44", "bip49", "bip84", "bip86"}
                )

    def test_math_boundary_no_oracle_cases_labeled(self) -> None:
        boundary = [c for c in self.cases if c["oracle_kind"] == "math_boundary_no_oracle"]
        self.assertGreaterEqual(len(boundary), 1)
        for c in boundary:
            self.assertEqual(c["expected"], "refusal")
            self.assertEqual(c["ground_truth"], [])

    def test_no_case_claims_unearned_vendor_tool_confirmation(self) -> None:
        """WP-C2 never ran a real vendor tool -- only the two SeedSigner
        doc-published examples may claim `vendor_doc`; nothing may claim
        `vendor_tool` (that confirmation belongs to WP-C3, SPEC_COMPAT
        §10.2/§10.3)."""
        for c in self.cases:
            self.assertNotIn(c["oracle_kind"], ("vendor_tool", "vendor_tool_refusal"))


class TestWriteAndCheckRoundtrip(unittest.TestCase):
    def test_write_then_check_all_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = compat.write_candidates(tmp)
            self.assertGreaterEqual(len(paths), 14)
            for p in paths:
                problems = compat.check_file(p)
                self.assertEqual(problems, [], f"{p}: {problems}")

    def test_check_detects_mnemonic_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = compat.write_candidates(tmp)
            target = next(
                p for p in paths if "seedsigner_dice_12w_vendor_example" in p
            )
            with open(target, "r", encoding="ascii") as f:
                doc = json.load(f)
            doc["cases"][0]["mnemonic_words"][0] = "zoo"
            with open(target, "w", encoding="ascii") as f:
                json.dump(doc, f)
            problems = compat.check_file(target)
            self.assertTrue(any("mnemonic_words" in p for p in problems))

    def test_check_detects_wrongly_flipped_expectation(self) -> None:
        """A candidate that claims 'refusal' but whose stored events
        would actually succeed (or vice versa) must be caught -- this is
        exactly the class of defect F1 shipped."""
        with tempfile.TemporaryDirectory() as tmp:
            paths = compat.write_candidates(tmp)
            target = next(
                p for p in paths if "seedsigner_dice_40rolls_refusal" in p
            )
            with open(target, "r", encoding="ascii") as f:
                doc = json.load(f)
            doc["cases"][0]["expected"] = "mnemonic"
            with open(target, "w", encoding="ascii") as f:
                json.dump(doc, f)
            problems = compat.check_file(target)
            self.assertTrue(any("expected" in p for p in problems))

    def test_check_rejects_bad_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="ascii") as f:
                json.dump({"schema": "not-the-right-schema", "cases": []}, f)
            problems = compat.check_file(path)
            self.assertEqual(len(problems), 1)
            self.assertIn("schema mismatch", problems[0])


if __name__ == "__main__":
    unittest.main()
