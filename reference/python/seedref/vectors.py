"""Candidate test-vector generation and checking (SPEC §29.2, §4.4).

Produces `tests/vectors/candidates/*.json` per `tests/vectors/SCHEMA.md`.
Per that schema's "Rules" §2, files under `tests/vectors/` are
*candidates* until the WP-16 golden-vector-freeze barrier passes, and
WP-11 (this package) is the designated generator of that candidate
corpus -- WP-16 later reconciles Rust vs Python output over these files
and freezes them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List

from .addresses import PathStandard, first_address, master_from_seed, master_fingerprint
from .bip39 import entropy_to_indexes, indexes_to_words, mnemonic_to_seed
from .transcript import SourceRecord, build_transcript, final_entropy

SCHEMA_NAME = "alea-vectors-v1"

_STANDARD_KEYS = {
    PathStandard.BIP44: "bip44",
    PathStandard.BIP49: "bip49",
    PathStandard.BIP84: "bip84",
    PathStandard.BIP86: "bip86",
}


@dataclass
class RawSource:
    tag: int
    algo: str
    source_bytes: bytes


def build_case(
    name: str,
    sources: List[RawSource],
    bits: int,
    policy_version: int = 1,
) -> Dict:
    """Build one vector-file case dict (SCHEMA.md shape) from raw source
    inputs, running the full protocol: transcript -> final entropy ->
    BIP39 mnemonic -> BIP39 seed -> BIP32 master + all four addresses.
    """
    if bits not in (128, 256):
        raise ValueError("bits must be 128 or 256")

    ordered = sorted(sources, key=lambda s: s.tag)
    records = [SourceRecord(tag=s.tag, algo_id=s.algo.encode("ascii"), source_bytes=s.source_bytes) for s in ordered]

    arch_id = 1  # ArchId::X86_64
    transcript = build_transcript(arch_id, bits, policy_version, records)
    entropy = final_entropy(transcript, bits)

    indexes = entropy_to_indexes(entropy)
    words = indexes_to_words(indexes)
    seed = mnemonic_to_seed(indexes)

    master = master_from_seed(seed)
    fp = master_fingerprint(master).hex()
    addrs = {_STANDARD_KEYS[std]: first_address(seed, std) for std in PathStandard}

    return {
        "name": name,
        "sources": [
            {"tag": f"0x{s.tag:02x}", "algo": s.algo, "bytes_hex": s.source_bytes.hex()} for s in ordered
        ],
        "arch": "x86_64",
        "bits": bits,
        "policy_version": policy_version,
        "transcript_hex": transcript.hex(),
        "final_entropy_hex": entropy.hex(),
        "mnemonic_indexes": indexes,
        "mnemonic_words": words,
        "bip39_seed_hex": seed.hex(),
        "master_fingerprint_hex": fp,
        "addresses": addrs,
    }


def _dice_bytes(n: int, start: int = 1) -> bytes:
    """Deterministic public test dice-roll sequence: `1..6` repeating."""
    return bytes(((start - 1 + i) % 6) + 1 for i in range(n))


def _coin_bytes(n: int, start: int = 0) -> bytes:
    """Deterministic public test coin-flip sequence: alternating T/H."""
    return bytes((start + i) % 2 for i in range(n))


def _machine_bytes(tag_byte: int, n: int = 32) -> bytes:
    """Deterministic, clearly-synthetic public test machine-source bytes
    (never real hardware entropy -- SPEC §4.4: "operate only on public
    test vectors")."""
    return bytes((tag_byte * 7 + i * 13) % 256 for i in range(n))


#: SPEC_USB_TRNG.md v0.6.2 §6.1 fixed approved-device-profile descriptor
#: (`algorithm_identifier`, not a raw device string -- SPEC_USB_TRNG §6.1,
#: §19.2). 20 ASCII bytes.
USB_TRNG_ALGO_ID = "USB-TRNG/OneRNG/cmd1"


def generate_candidate_cases() -> List[Dict]:
    """The full >=20-case candidate corpus (SPEC §29.2 categories:
    dice-only 12w/24w, coins-only 12w/24w, mixed dice+coins, machine-
    tagged records, budget edge cases) plus a `0x12` APPROVED_USB_TRNG
    category (SPEC_USB_TRNG.md v0.6.2 §6, IMPLEMENTATION_MAP_USB_TRNG.md
    §5) feeding the WP-U1 transcript-freeze barrier. The `0x12` cases are
    *appended*, after the pre-existing tags-0x01..0x11 cases: their
    presence must not perturb the byte-for-byte content of any case that
    does not itself carry a `0x12` source (SPEC_USB_TRNG §6.2)."""
    cases: List[Dict] = []

    # --- Dice-only ---------------------------------------------------
    cases.append(build_case("dice_only_12w_min_budget", [RawSource(0x10, "", _dice_bytes(50))], 128))
    cases.append(build_case("dice_only_12w_recommended", [RawSource(0x10, "", _dice_bytes(64))], 128))
    cases.append(build_case("dice_only_12w_all_ones", [RawSource(0x10, "", bytes([1] * 50))], 128))
    cases.append(build_case("dice_only_24w_min_budget", [RawSource(0x10, "", _dice_bytes(100))], 256))
    cases.append(build_case("dice_only_24w_recommended", [RawSource(0x10, "", _dice_bytes(128))], 256))
    cases.append(build_case("dice_only_24w_extra_margin", [RawSource(0x10, "", _dice_bytes(150, start=3))], 256))

    # --- Coins-only ----------------------------------------------------
    cases.append(build_case("coins_only_12w_min_budget", [RawSource(0x11, "", _coin_bytes(128))], 128))
    cases.append(build_case("coins_only_12w_recommended", [RawSource(0x11, "", _coin_bytes(160))], 128))
    cases.append(build_case("coins_only_12w_all_heads", [RawSource(0x11, "", bytes([1] * 128))], 128))
    cases.append(build_case("coins_only_24w_min_budget", [RawSource(0x11, "", _coin_bytes(256))], 256))
    cases.append(build_case("coins_only_24w_recommended", [RawSource(0x11, "", _coin_bytes(320))], 256))
    cases.append(build_case("coins_only_24w_all_tails", [RawSource(0x11, "", bytes([0] * 256))], 256))

    # --- Mixed dice + coins --------------------------------------------
    cases.append(
        build_case(
            "mixed_dice_coins_12w_case1",
            [RawSource(0x10, "", _dice_bytes(30)), RawSource(0x11, "", _coin_bytes(50))],
            128,
        )
    )
    cases.append(
        build_case(
            "mixed_dice_coins_12w_case2",
            [RawSource(0x10, "", _dice_bytes(10, start=4)), RawSource(0x11, "", _coin_bytes(115, start=1))],
            128,
        )
    )
    cases.append(
        build_case(
            "mixed_dice_coins_24w_case1",
            [RawSource(0x10, "", _dice_bytes(60)), RawSource(0x11, "", _coin_bytes(100))],
            256,
        )
    )
    cases.append(
        build_case(
            "mixed_dice_coins_24w_case2",
            [RawSource(0x10, "", _dice_bytes(80, start=2)), RawSource(0x11, "", _coin_bytes(40, start=1))],
            256,
        )
    )

    # --- Machine-tagged records -----------------------------------------
    cases.append(
        build_case(
            "machine_efi_rng_only_12w",
            [RawSource(0x01, "TEST-EFI-RNG", _machine_bytes(0x01))],
            128,
        )
    )
    cases.append(
        build_case(
            "machine_rdseed_only_24w",
            [RawSource(0x02, "RDSEED64", _machine_bytes(0x02))],
            256,
        )
    )
    cases.append(
        build_case(
            "machine_rdrand_supplementary_with_dice_12w",
            [
                RawSource(0x03, "RDRAND", _machine_bytes(0x03, 8)),
                RawSource(0x10, "", _dice_bytes(50)),
            ],
            128,
        )
    )
    cases.append(
        build_case(
            "machine_reinforced_efi_rng_plus_physical_24w",
            [
                RawSource(0x01, "TEST-EFI-RNG", _machine_bytes(0x01)),
                RawSource(0x10, "", _dice_bytes(60, start=5)),
                RawSource(0x11, "", _coin_bytes(80, start=1)),
            ],
            256,
        )
    )
    cases.append(
        build_case(
            "machine_all_three_sources_no_physical_12w",
            [
                RawSource(0x01, "TEST-EFI-RNG", _machine_bytes(0x01)),
                RawSource(0x02, "RDSEED64", _machine_bytes(0x02)),
                RawSource(0x03, "RDRAND", _machine_bytes(0x03, 8)),
            ],
            128,
        )
    )

    # --- Budget edge cases (exact minimums, already exercised above via
    # min_budget cases; add a couple of just-over/just-under-margin ones
    # for completeness) -----------------------------------------------
    cases.append(build_case("dice_only_12w_51_rolls_just_over_min", [RawSource(0x10, "", _dice_bytes(51))], 128))
    cases.append(
        build_case("coins_only_24w_257_flips_just_over_min", [RawSource(0x11, "", _coin_bytes(257))], 256)
    )

    # --- USB TRNG (0x12 APPROVED_USB_TRNG, SPEC_USB_TRNG.md v0.6.2 §6) ---
    # WP-U1 transcript-freeze barrier candidates (IMPLEMENTATION_MAP_USB_
    # TRNG.md §5): every USB-absent case above must stay byte-identical
    # (verified by TestUsbTrngCandidatesDoNotPerturbExisting in
    # test_vectors.py); these cases exercise `0x12` alone, `0x12` mixed
    # with dice/coin, and `0x12` alongside the other machine sources.
    # `usb_trng_reinforced_dice_coin_24w_spec_proof` reproduces the exact
    # dice[2,4,6]+coin[0,1]+usb reinforced session used as the SPEC_USB_
    # TRNG §6.2 byte-layout proof (presence bitmap 0x0038, record_count 3,
    # ascending tag order 0x10 < 0x11 < 0x12) -- see
    # test_transcript.py::TestUsbTrngTag for the literal byte assertions.
    cases.append(
        build_case(
            "usb_trng_only_12w",
            [RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12))],
            128,
        )
    )
    cases.append(
        build_case(
            "usb_trng_only_24w",
            [RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12, 32))],
            256,
        )
    )
    cases.append(
        build_case(
            "usb_trng_reinforced_dice_coin_12w",
            [
                RawSource(0x10, "", _dice_bytes(50)),
                RawSource(0x11, "", _coin_bytes(80)),
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
            ],
            128,
        )
    )
    cases.append(
        build_case(
            "usb_trng_reinforced_dice_coin_24w_spec_proof",
            [
                RawSource(0x10, "", bytes([2, 4, 6])),
                RawSource(0x11, "", bytes([0, 1])),
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
            ],
            256,
            policy_version=2,
        )
    )
    cases.append(
        build_case(
            "usb_trng_reinforced_dice_coin_insertion_order_independence",
            [
                # Deliberately supplied 0x12-first / 0x10-last: build_case
                # sorts by tag before encoding, so this must reproduce the
                # same canonical (ascending-tag) bytes as if the sources
                # had been supplied in ascending order to begin with
                # (SPEC_USB_TRNG §6.2 "canonical reordering" case).
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
                RawSource(0x11, "", _coin_bytes(80, start=1)),
                RawSource(0x10, "", _dice_bytes(50, start=3)),
            ],
            128,
        )
    )
    cases.append(
        build_case(
            "usb_trng_with_dice_only_24w",
            [
                RawSource(0x10, "", _dice_bytes(100)),
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
            ],
            256,
        )
    )
    cases.append(
        build_case(
            "usb_trng_with_coin_only_12w",
            [
                RawSource(0x11, "", _coin_bytes(128)),
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
            ],
            128,
        )
    )
    cases.append(
        build_case(
            "usb_trng_all_machine_sources_no_physical_12w",
            [
                RawSource(0x01, "TEST-EFI-RNG", _machine_bytes(0x01)),
                RawSource(0x02, "RDSEED64", _machine_bytes(0x02)),
                RawSource(0x03, "RDRAND", _machine_bytes(0x03, 8)),
                RawSource(0x12, USB_TRNG_ALGO_ID, _machine_bytes(0x12)),
            ],
            128,
        )
    )

    return cases


def write_candidates(out_dir) -> List[str]:
    """Generate the candidate corpus and write one JSON file per case
    (SCHEMA.md compliant, `tests/vectors/candidates/<case-name>.json`),
    returning the written file paths."""
    import os

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
    """Re-run the full protocol over every case in a vector file and
    report mismatches (SPEC §29.2 cross-implementation check machinery,
    Python side). Returns a list of human-readable problem descriptions;
    empty means every case round-trips.
    """
    problems: List[str] = []
    with open(path, "r", encoding="ascii") as f:
        doc = json.load(f)

    if doc.get("schema") != SCHEMA_NAME:
        return [f"schema mismatch: expected {SCHEMA_NAME!r}, got {doc.get('schema')!r}"]

    for case in doc.get("cases", []):
        name = case.get("name", "<unnamed>")
        try:
            sources = [
                RawSource(
                    tag=int(s["tag"], 16),
                    algo=s["algo"],
                    source_bytes=bytes.fromhex(s["bytes_hex"]),
                )
                for s in case["sources"]
            ]
            recomputed = build_case(name, sources, case["bits"], case["policy_version"])
        except Exception as exc:  # noqa: BLE001 -- report, don't crash the run
            problems.append(f"{name}: exception during recompute: {exc!r}")
            continue

        for field in (
            "transcript_hex",
            "final_entropy_hex",
            "mnemonic_indexes",
            "mnemonic_words",
            "bip39_seed_hex",
            "master_fingerprint_hex",
            "addresses",
        ):
            if recomputed[field] != case.get(field):
                problems.append(f"{name}: field {field!r} mismatch")

    return problems
