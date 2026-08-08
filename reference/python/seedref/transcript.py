"""Canonical entropy transcript and final derivation (SPEC §19).

Builds the SPEC §19.2 canonical transcript:

    "Alea/Entropy/v1\\0"
    || architecture_identifier
    || requested_entropy_bits
    || entropy_policy_version
    || source_presence_bitmap
    || source_record_count
    || source_record_1
    || source_record_2
    || ...

and finalizes it per SPEC §19.3: `final_entropy = SHA256(transcript)`,
truncated to 16 bytes (12 words) or 32 bytes (24 words).

Field widths and byte order are not spelled out character-by-character in
SPEC.md's §19 prose; this module fixes them the same way
`IMPLEMENTATION_MAP.md` §4's `TRANSCRIPT_CAPACITY` derivation comment and
its WP-08 scope line ("big-endian integers") describe the Rust side, so
that WP-16 has a reasonable chance of reconciling the two without a
protocol redesign:

    architecture_identifier   u16 big-endian   (ArchId, SPEC §5: X86_64=1)
    requested_entropy_bits    u16 big-endian   (128 or 256)
    entropy_policy_version    u16 big-endian
    source_presence_bitmap    u16 big-endian   (bit i = record i of the
                                                 canonical tag order below
                                                 is present)
    source_record_count       u8
    per record:
        source_tag             u8   (SPEC §19.1 wire value)
        algo_id_length          u8
        algorithm_identifier    algo_id_length bytes (ASCII)
        source_length           u16 big-endian
        source_bytes            source_length bytes

Record order, and the presence-bitmap bit order, is canonical ascending
`source_tag` order (SPEC §19.1: "record order is canonical and
independent of discovery order") over the six defined tags:
`0x01, 0x02, 0x03, 0x10, 0x11, 0x12`. This is a candidate-corpus encoding
choice pending WP-16 freeze/reconciliation against the Rust side, not
itself a SPEC.md requirement beyond "canonical" and "documented" (SPEC
§19.1).

`0x12` (`APPROVED_USB_TRNG`, SPEC_USB_TRNG.md v0.6.2 §6.1) was added above
`0x11` -- not in the documentary "machine band `0x01..0x0F`" -- specifically
so that appending it to the end of `CANONICAL_TAG_ORDER` keeps the array
ascending (SPEC_USB_TRNG §6.2). That single fact is what makes body order
(array-iteration order, see `build_transcript` below), the presence-bitmap
bit-position order, and the ascending-tag order `decode_and_validate` walks
all the *same* order -- append == ascending. A USB-absent transcript's
bytes are therefore untouched by this addition: `0x12`'s presence bit is
bit 5, sitting above the five pre-existing bits, and `build_transcript`
simply never emits a record for a tag that has no corresponding source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .hashes import sha256

DOMAIN = b"Alea/Entropy/v1\x00"

#: Canonical ascending order of the six SPEC §19.1 / SPEC_USB_TRNG §6.1
#: source tags. `0x12` (APPROVED_USB_TRNG) is appended at the end -- its
#: wire value was deliberately chosen above `0x11` so this array stays
#: ascending (SPEC_USB_TRNG §6.2: "append == ascending"). Do not insert
#: `0x12` anywhere but the end, and do not renumber it below `0x11`.
CANONICAL_TAG_ORDER = [0x01, 0x02, 0x03, 0x10, 0x11, 0x12]

ARCH_X86_64 = 1


@dataclass
class SourceRecord:
    tag: int
    algo_id: bytes
    source_bytes: bytes

    def __post_init__(self) -> None:
        if not (0 <= self.tag <= 0xFF):
            raise ValueError("tag must fit in one byte")
        if len(self.algo_id) > 0xFF:
            raise ValueError("algo_id too long")
        if len(self.source_bytes) > 0xFFFF:
            raise ValueError("source_bytes too long")

    def encode(self) -> bytes:
        return (
            bytes([self.tag])
            + bytes([len(self.algo_id)])
            + self.algo_id
            + len(self.source_bytes).to_bytes(2, "big")
            + self.source_bytes
        )


class MalformedTranscriptError(ValueError):
    """Raised by `decode_and_validate` on any structurally invalid input
    (SPEC §19.1: "unknown fields are not silently ignored")."""


def build_transcript(
    arch_id: int,
    requested_entropy_bits: int,
    entropy_policy_version: int,
    sources: List[SourceRecord],
) -> bytes:
    """Build the canonical transcript from an already-canonically-ordered
    (ascending tag) list of source records.

    Raises `ValueError` if `sources` contains a duplicate tag or is not
    in ascending-tag canonical order (SPEC §19.1: "source tags are unique
    ... record order is canonical").
    """
    tags = [s.tag for s in sources]
    if len(set(tags)) != len(tags):
        raise ValueError("duplicate source tag")
    if tags != sorted(tags):
        raise ValueError("source records must be in canonical (ascending tag) order")

    bitmap = 0
    for s in sources:
        try:
            bit_index = CANONICAL_TAG_ORDER.index(s.tag)
        except ValueError as exc:
            raise ValueError(f"unknown source tag 0x{s.tag:02x}") from exc
        bitmap |= 1 << bit_index

    header = (
        DOMAIN
        + arch_id.to_bytes(2, "big")
        + requested_entropy_bits.to_bytes(2, "big")
        + entropy_policy_version.to_bytes(2, "big")
        + bitmap.to_bytes(2, "big")
        + len(sources).to_bytes(1, "big")
    )
    body = b"".join(s.encode() for s in sources)
    return header + body


def final_entropy(transcript: bytes, target_bits: int) -> bytes:
    """`SHA256(transcript)` truncated to `target_bits // 8` bytes
    (SPEC §19.3). `target_bits` must be 128 or 256."""
    if target_bits not in (128, 256):
        raise ValueError("target_bits must be 128 or 256")
    digest = sha256(transcript)
    return digest[: target_bits // 8]


def decode_and_validate(data: bytes) -> List[SourceRecord]:
    """Parse and structurally validate a canonical transcript, returning
    its source records. Used only by tests to exercise both directions of
    the encoding (SPEC §19.1 requires "malformed input rejection":
    trailing bytes, duplicate tags, bad roll/flip values).

    Raises `MalformedTranscriptError` on any structural problem.
    """
    if not data.startswith(DOMAIN):
        raise MalformedTranscriptError("bad domain prefix")
    off = len(DOMAIN)
    if len(data) < off + 9:
        raise MalformedTranscriptError("truncated header")
    arch_id = int.from_bytes(data[off : off + 2], "big")
    off += 2
    _requested_bits = int.from_bytes(data[off : off + 2], "big")
    off += 2
    _policy_version = int.from_bytes(data[off : off + 2], "big")
    off += 2
    bitmap = int.from_bytes(data[off : off + 2], "big")
    off += 2
    record_count = data[off]
    off += 1

    if arch_id != ARCH_X86_64:
        raise MalformedTranscriptError(f"unknown architecture id {arch_id}")

    records: List[SourceRecord] = []
    expected_bitmap = 0
    for _ in range(record_count):
        if off + 2 > len(data):
            raise MalformedTranscriptError("truncated record header")
        tag = data[off]
        algo_len = data[off + 1]
        off += 2
        if off + algo_len + 2 > len(data):
            raise MalformedTranscriptError("truncated algo id / source length")
        algo_id = data[off : off + algo_len]
        off += algo_len
        src_len = int.from_bytes(data[off : off + 2], "big")
        off += 2
        if off + src_len > len(data):
            raise MalformedTranscriptError("truncated source bytes")
        src_bytes = data[off : off + src_len]
        off += src_len

        if tag not in CANONICAL_TAG_ORDER:
            raise MalformedTranscriptError(f"unknown source tag 0x{tag:02x}")
        bit_index = CANONICAL_TAG_ORDER.index(tag)
        if expected_bitmap & (1 << bit_index):
            raise MalformedTranscriptError("duplicate source tag")
        expected_bitmap |= 1 << bit_index

        if tag == 0x10:  # DICE_ROLLS
            if any(not (0x01 <= b <= 0x06) for b in src_bytes):
                raise MalformedTranscriptError("invalid dice roll byte")
        if tag == 0x11:  # COIN_FLIPS
            if any(b not in (0x00, 0x01) for b in src_bytes):
                raise MalformedTranscriptError("invalid coin flip byte")

        records.append(SourceRecord(tag=tag, algo_id=bytes(algo_id), source_bytes=bytes(src_bytes)))

    if off != len(data):
        raise MalformedTranscriptError("trailing bytes after last record")
    if bitmap != expected_bitmap:
        raise MalformedTranscriptError("presence bitmap does not match records")

    return records
