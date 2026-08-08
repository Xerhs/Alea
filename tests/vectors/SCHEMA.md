# Alea test-vector schema

Owned by WP-16 (`IMPLEMENTATION_MAP.md` §4, §5 WP-16; SPEC §29.2). This
file fixes the JSON schema every implementation (Rust `seed-test-vectors`,
`reference/python`, the desktop test edition) reads and produces. It is
reproduced verbatim from `IMPLEMENTATION_MAP.md` §4.

## Schema

```json
{
  "schema": "alea-vectors-v1",
  "cases": [{
    "name": "dice_only_12w_case1",
    "sources": [{"tag": "0x10", "algo": "", "bytes_hex": "040602..."}],
    "arch": "x86_64", "bits": 128, "policy_version": 1,
    "transcript_hex": "...", "final_entropy_hex": "...",
    "mnemonic_indexes": [/* u16 */], "mnemonic_words": ["...", "..."],
    "bip39_seed_hex": "...", "master_fingerprint_hex": "a1b2c3d4",
    "addresses": {"bip44": "1...", "bip49": "3...", "bip84": "bc1q...", "bip86": "bc1p..."}
  }]
}
```

## Field notes

- `schema` — literal string `"alea-vectors-v1"`; a mismatch is a
  hard parse failure, not a warning.
- `cases[].name` — unique, stable, descriptive (method(s), word count,
  case purpose). Renaming a frozen case is a contract change.
- `cases[].sources` — one entry per SPEC §19.1 source record, in the
  canonical order the transcript itself uses. `tag` is the SPEC §19.1 wire
  value formatted as `"0xNN"` (lowercase hex digits). `algo` is the
  `algorithm_identifier` string (empty string for tags that carry none,
  e.g. dice/coin). `bytes_hex` is `source_bytes`.
- `arch` — one of the `ArchId` variant names (`contracts.rs`), lowercase
  with underscores as shown (`"x86_64"`).
- `bits` — `128` or `256` (matches `TargetBits`/`WordCount`), not a string.
- `policy_version` — the `entropy_policy_version` mixed into the
  transcript (SPEC §19.2); integer.
- `transcript_hex` — the complete canonical transcript (SPEC §19.2) before
  hashing.
- `final_entropy_hex` — `SHA256(canonical_transcript)`, truncated per SPEC
  §19.3 (16 bytes for 128-bit cases, 32 bytes for 256-bit cases).
- `mnemonic_indexes` — the raw BIP39 word indexes (`u16`, 0..2048), in
  order.
- `mnemonic_words` — the same indexes rendered as BIP39 English words, in
  order; a derived/redundant field kept for human review and
  cross-implementation diffing.
- `bip39_seed_hex` — `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048
  iterations)` with the empty passphrase (SPEC §14, §24.2); always 64
  bytes.
- `master_fingerprint_hex` — first 4 bytes of `HASH160(master_pubkey)`, 8
  lowercase hex characters (SPEC §24.2).
- `addresses.{bip44,bip49,bip84,bip86}` — first external receive address
  (account 0, index 0) for each standard (SPEC §24.2 table).

## Rules

1. **All hex fields are lowercase.** No uppercase hex digits anywhere in
   the corpus; this is mechanically checked, not a style preference,
   because it is one of the diff-stability properties WP-16 relies on when
   comparing Rust vs Python output byte-for-byte.
2. **Candidate vs frozen status.** Before the WP-16 golden-vector freeze
   barrier passes, every file under `tests/vectors/` is a *candidate*:
   WP-11 (Python reference) generates it, WP-15 (Rust pipeline) is
   reconciled against it, and mismatches are root-caused and fixed in
   whichever side is wrong per spec/BIP text — the vector file itself may
   still change. Once WP-16 freezes the corpus, these files are **law**:
   no downstream work package may edit them; a required change is an
   orchestrator-level decision routed back through WP-16 (`AGENTS.md` §1
   rules 2–3).
3. No case may contain live/production-derived secret material — every
   vector is drawn from public, deliberately-disclosed test entropy (dice/
   coin sequences, machine-source bytes, or the standard published BIP39
   test mnemonics) and is safe to publish.
4. A vector file that fails to parse against this schema, or whose
   `schema` field does not match exactly, MUST be treated as a hard error
   by every consumer, not silently skipped.
