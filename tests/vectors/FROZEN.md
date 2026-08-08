# GOLDEN VECTOR FREEZE — WP-16 stamp

Status: **FROZEN** (SPEC §29.2; `IMPLEMENTATION_MAP.md` §5 WP-16 barrier).

| Field | Value |
| --- | --- |
| Schema version | `alea-vectors-v1` (`tests/vectors/SCHEMA.md`) |
| Frozen corpus | `tests/vectors/frozen/*.json` |
| Case count | 23 |
| Freeze date | 2026-08-04 |
| Generator | `reference/python/ref.py generate-candidates` (WP-11, SPEC §4.4) |
| Cross-checked against | Rust pipeline: `seed-protocol::transcript` (WP-08) + `seed-core::pipeline` (WP-15) + `seed-core::bip39` (WP-05) + `seed-derive::{bip32,address}` (WP-13/WP-14), via `cargo test -p seed-test-vectors` (WP-16) |
| Result | Bit-for-bit match on all 23 cases: transcript bytes, final entropy (128/256-bit), mnemonic indexes and words, BIP39 seeds, master fingerprints, all four first addresses (BIP44/49/84/86) |

## Coverage

- Dice-only: 12w and 24w — minimum budget (50 / 100 rolls), recommended,
  just-over-minimum (51 rolls @12w), extra margin, all-ones degenerate.
- Coins-only: 12w and 24w — minimum budget (128 / 256 flips), recommended,
  just-over-minimum (257 flips @24w), all-heads / all-tails degenerate.
- Mixed dice + coins: two cases per word count.
- Machine-tagged: EFI RNG only, RDSEED only, RDRAND-supplementary with
  dice, reinforced EFI RNG + physical, all three machine sources.

## Rules now in force (`AGENTS.md` §1 rule 3; `SCHEMA.md` rule 2)

1. The files under `tests/vectors/frozen/` are **law**. No downstream work
   package may edit, rename, or delete them. A required change is an
   orchestrator-level decision routed back through WP-16.
2. `tests/vectors/candidates/` remains the reference generator's working
   output directory (`ref.py generate-candidates` default). At freeze time
   it was regenerated and verified bit-identical to `frozen/`; the frozen
   copies are the normative ones.
3. Consumers (`crates/seed-test-vectors`, desktop test edition, UEFI test
   edition) MUST read the frozen files where a filesystem exists, and MUST
   treat any schema mismatch or parse failure as a hard error
   (`SCHEMA.md` rule 4).
