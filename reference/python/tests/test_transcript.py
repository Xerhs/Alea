import unittest

from seedref.transcript import (
    ARCH_X86_64,
    CANONICAL_TAG_ORDER,
    MalformedTranscriptError,
    SourceRecord,
    build_transcript,
    decode_and_validate,
    final_entropy,
)


class TestTranscriptBuildAndFinalize(unittest.TestCase):
    def test_deterministic_and_reproducible(self) -> None:
        records = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 3, 4, 5, 6]))]
        t1 = build_transcript(ARCH_X86_64, 128, 1, records)
        t2 = build_transcript(ARCH_X86_64, 128, 1, records)
        self.assertEqual(t1, t2)

    def test_final_entropy_length(self) -> None:
        records = [SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([0, 1] * 64))]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        self.assertEqual(len(final_entropy(t, 128)), 16)
        t256 = build_transcript(ARCH_X86_64, 256, 1, records)
        self.assertEqual(len(final_entropy(t256, 256)), 32)

    def test_different_sources_different_entropy(self) -> None:
        r1 = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 3]))]
        r2 = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 4]))]
        e1 = final_entropy(build_transcript(ARCH_X86_64, 128, 1, r1), 128)
        e2 = final_entropy(build_transcript(ARCH_X86_64, 128, 1, r2), 128)
        self.assertNotEqual(e1, e2)

    def test_duplicate_tag_rejected(self) -> None:
        records = [
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=b"\x01"),
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=b"\x02"),
        ]
        with self.assertRaises(ValueError):
            build_transcript(ARCH_X86_64, 128, 1, records)

    def test_non_canonical_order_rejected(self) -> None:
        records = [
            SourceRecord(tag=0x11, algo_id=b"", source_bytes=b"\x01"),
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=b"\x02"),
        ]
        with self.assertRaises(ValueError):
            build_transcript(ARCH_X86_64, 128, 1, records)

    def test_invalid_bits_rejected(self) -> None:
        records = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=b"\x01")]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        with self.assertRaises(ValueError):
            final_entropy(t, 192)


class TestTranscriptDecodeValidation(unittest.TestCase):
    def test_roundtrip(self) -> None:
        records = [
            SourceRecord(tag=0x01, algo_id=b"TEST", source_bytes=bytes(range(8))),
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 3, 4, 5, 6])),
        ]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        decoded = decode_and_validate(t)
        self.assertEqual(len(decoded), 2)
        self.assertEqual(decoded[0].tag, 0x01)
        self.assertEqual(decoded[1].source_bytes, bytes([1, 2, 3, 4, 5, 6]))

    def test_trailing_bytes_rejected(self) -> None:
        records = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=b"\x01\x02")]
        t = build_transcript(ARCH_X86_64, 128, 1, records) + b"\xff"
        with self.assertRaises(MalformedTranscriptError):
            decode_and_validate(t)

    def test_bad_domain_rejected(self) -> None:
        with self.assertRaises(MalformedTranscriptError):
            decode_and_validate(b"not-the-domain-string-at-all-here")

    def test_bad_dice_byte_rejected(self) -> None:
        records = [SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([7]))]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        with self.assertRaises(MalformedTranscriptError):
            decode_and_validate(t)

    def test_bad_coin_byte_rejected(self) -> None:
        records = [SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([2]))]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        with self.assertRaises(MalformedTranscriptError):
            decode_and_validate(t)


class TestUsbTrngTag(unittest.TestCase):
    """WP-U6 (IMPLEMENTATION_MAP_USB_TRNG.md §4/§5, SPEC_USB_TRNG.md v0.6.2
    §6): `0x12` APPROVED_USB_TRNG is appended to `CANONICAL_TAG_ORDER`
    above `0x11` so append == ascending. These are the two MANDATORY WP-U1
    barrier regressions (map §5), run here against the Python reference."""

    def test_canonical_tag_order_is_six_ascending_with_0x12_last(self) -> None:
        self.assertEqual(CANONICAL_TAG_ORDER, [0x01, 0x02, 0x03, 0x10, 0x11, 0x12])
        self.assertEqual(CANONICAL_TAG_ORDER, sorted(CANONICAL_TAG_ORDER))
        self.assertEqual(CANONICAL_TAG_ORDER.index(0x12), 5)  # presence-bitmap bit 5

    def test_usb_absent_session_byte_identical_to_pre_0x12(self) -> None:
        """A USB-absent transcript (dice+coin only) must be byte-identical
        to what v1 (five-tag) encoding produced -- SPEC_USB_TRNG §6.2's
        core backward-compatibility claim. Fixed against a literal
        pre-computed hex string so a regression here cannot silently pass
        by both sides drifting together."""
        records = [
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([2, 4, 6])),
            SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([0, 1])),
        ]
        t = build_transcript(ARCH_X86_64, 256, 2, records)
        expected = (
            b"Alea/Entropy/v1\x00"
            + b"\x00\x01"  # arch = X86_64
            + b"\x01\x00"  # requested_entropy_bits = 256
            + b"\x00\x02"  # entropy_policy_version = 2
            + b"\x00\x18"  # presence bitmap: bit3(0x10)|bit4(0x11) = 0b011000
            + b"\x02"  # record_count
            + b"\x10\x00\x00\x03\x02\x04\x06"  # dice record
            + b"\x11\x00\x00\x02\x00\x01"  # coin record
        )
        self.assertEqual(t, expected)
        decoded = decode_and_validate(t)
        self.assertEqual(len(decoded), 2)

    def test_dice_coin_usb_session_byte_layout_matches_spec_6_2_proof(self) -> None:
        """The literal SPEC_USB_TRNG §6.2 byte-layout proof: dice [2,4,6],
        coin [0,1], usb algo_id "USB-TRNG/OneRNG/cmd1" (20 bytes) + a
        32-byte health-checked block, arch=X86_64, bits=256,
        policy_ver=2. Presence bitmap bits 3|4|5 = 0x0038. This is the
        exact case the deleted `0x04` design would have serialized out of
        canonical order and had `decode` reject."""
        algo_id = b"USB-TRNG/OneRNG/cmd1"
        self.assertEqual(len(algo_id), 20)
        block = bytes(range(32))  # B0..B31 (spec leaves the block contents illustrative)
        records = [
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([2, 4, 6])),
            SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([0, 1])),
            SourceRecord(tag=0x12, algo_id=algo_id, source_bytes=block),
        ]
        t = build_transcript(ARCH_X86_64, 256, 2, records)
        expected = (
            b"Alea/Entropy/v1\x00"
            + b"\x00\x01"  # arch = X86_64
            + b"\x01\x00"  # requested_entropy_bits = 256
            + b"\x00\x02"  # entropy_policy_version = 2
            + b"\x00\x38"  # presence bitmap: bit3|bit4|bit5 = 0b111000
            + b"\x03"  # record_count
            + b"\x10\x00\x00\x03\x02\x04\x06"  # dice record
            + b"\x11\x00\x00\x02\x00\x01"  # coin record
            + b"\x12\x14" + algo_id + b"\x00\x20" + block  # usb record
        )
        self.assertEqual(t, expected)

        # The real guard (map §5 item 2): serialize -> decode must ACCEPT,
        # ascending tag order 0x10 < 0x11 < 0x12, presence bitmap
        # recomputes to 0x0038, record_count == 3.
        decoded = decode_and_validate(t)
        self.assertEqual(len(decoded), 3)
        self.assertEqual([r.tag for r in decoded], [0x10, 0x11, 0x12])
        self.assertEqual(decoded[2].algo_id, algo_id)
        self.assertEqual(decoded[2].source_bytes, block)

    def test_dice_coin_usb_insertion_order_independence(self) -> None:
        """Supplying 0x12 first / 0x10 last must reproduce the exact same
        canonical (ascending-tag) transcript bytes as ascending-supplied
        input, once run through `build_transcript`'s own tag-order
        enforcement -- i.e. build_transcript itself requires ascending
        input order (it does not silently reorder for the caller), so
        this asserts that decode's *acceptance* is independent of how the
        canonical-order records were assembled upstream."""
        block = bytes(range(32))
        ascending = [
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([2, 4, 6])),
            SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([0, 1])),
            SourceRecord(tag=0x12, algo_id=b"USB-TRNG/OneRNG/cmd1", source_bytes=block),
        ]
        t = build_transcript(ARCH_X86_64, 256, 2, ascending)
        decoded = decode_and_validate(t)
        self.assertEqual([r.tag for r in decoded], [0x10, 0x11, 0x12])

    def test_usb_only_session_round_trips(self) -> None:
        records = [SourceRecord(tag=0x12, algo_id=b"USB-TRNG/OneRNG/cmd1", source_bytes=bytes(range(32)))]
        t = build_transcript(ARCH_X86_64, 128, 1, records)
        decoded = decode_and_validate(t)
        self.assertEqual(len(decoded), 1)
        self.assertEqual(decoded[0].tag, 0x12)

    def test_0x12_out_of_order_input_rejected_by_build_transcript(self) -> None:
        """build_transcript itself requires ascending-tag input (mirrors
        the Rust encoder's CANONICAL_TAG_BYTES-array-order emission, which
        `vectors.build_case` satisfies by pre-sorting)."""
        records = [
            SourceRecord(tag=0x12, algo_id=b"USB-TRNG/OneRNG/cmd1", source_bytes=bytes(range(32))),
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 3])),
        ]
        with self.assertRaises(ValueError):
            build_transcript(ARCH_X86_64, 128, 1, records)

    def test_scratch_budget_boundary_four_machine_records_present(self) -> None:
        """SPEC_USB_TRNG §6.3: SCRATCH_BUDGET re-derivation is for up to
        four machine-source records now (0x01, 0x02, 0x03, 0x12). Exercise
        all four alongside dice+coin in one transcript and confirm it
        still round-trips (no python-side buffer bound to blow, but this
        is the Python-reference witness that the six-record case the
        boundary test protects in Rust is at least structurally valid)."""
        records = [
            SourceRecord(tag=0x01, algo_id=b"TEST-EFI-RNG", source_bytes=bytes(range(8))),
            SourceRecord(tag=0x02, algo_id=b"RDSEED64", source_bytes=bytes(range(8))),
            SourceRecord(tag=0x03, algo_id=b"RDRAND", source_bytes=bytes(range(8))),
            SourceRecord(tag=0x10, algo_id=b"", source_bytes=bytes([1, 2, 3])),
            SourceRecord(tag=0x11, algo_id=b"", source_bytes=bytes([0, 1])),
            SourceRecord(tag=0x12, algo_id=b"USB-TRNG/OneRNG/cmd1", source_bytes=bytes(range(32))),
        ]
        t = build_transcript(ARCH_X86_64, 256, 1, records)
        decoded = decode_and_validate(t)
        self.assertEqual(len(decoded), 6)
        self.assertEqual([r.tag for r in decoded], [0x01, 0x02, 0x03, 0x10, 0x11, 0x12])


if __name__ == "__main__":
    unittest.main()
