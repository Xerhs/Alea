# Alea Python reference implementation (WP-11)

SPEC §4.4: a small, independent reference implementation used to produce
and cross-check the golden test-vector corpus (`tests/vectors/`). Written
directly from `SPEC.md` and the public BIP documents (BIP32, BIP39,
BIP49, BIP84, BIP86, BIP141, BIP173, BIP340, BIP341, BIP350) — the Rust
implementation in `crates/` was deliberately **not** read while writing
this package, so the two implementations are independent enough for the
WP-16 golden-vector-freeze cross-check to mean something.

Pure Python, standard library only (`hashlib`, `hmac`, `json`, ...). No
third-party dependencies. secp256k1 point arithmetic, Base58Check,
Bech32/Bech32m and RIPEMD-160 are all implemented in this package rather
than imported from a crypto library (RIPEMD-160 is vendored from a
public-domain-equivalent MIT-licensed source rather than hand-derived,
noted in `seedref/ripemd160.py`).

Never used as a production seed generator (SPEC §4.4): it has no secret
lifecycle/scrubbing story at all, and is meant to run only on public test
vectors.

## Layout

```
reference/python/
  ref.py                    CLI entry point
  wordlist_english.txt      official BIP39 English wordlist (sha256-pinned)
  seedref/                  the implementation package
    hashes.py               SHA-256 / HMAC-SHA512 / PBKDF2-HMAC-SHA512
    ripemd160.py            RIPEMD-160 (vendored, MIT) + hash160
    secp256k1.py            curve point math, x-only pubkeys, taproot tweak
    base58.py               Base58Check (encode)
    bech32.py                Bech32 / Bech32m (encode)
    bip39.py                 entropy <-> mnemonic, BIP39 seed KDF
    bip32.py                 master key, CKD-priv, fingerprint
    addresses.py             BIP44/49/84/86 address construction
    physical.py               dice/coin session + entropy budget (SPEC §17)
    transcript.py             canonical entropy transcript (SPEC §19)
    vectors.py                candidate-corpus generation + check
  tests/                     unittest suite (KATs + property tests)
```

## CLI

```bash
# Generate the candidate vector corpus into tests/vectors/candidates/
python3 ref.py generate-candidates

# Generate into an arbitrary directory
python3 ref.py generate-candidates /path/to/out

# Re-run the protocol over one or more vector files and report mismatches
python3 ref.py check tests/vectors/candidates/*.json
```

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

Covers: RIPEMD-160 ISO/IEC 10118-3 KATs, secp256k1 generator-multiple and
BIP340 tagged-hash KATs, Base58Check against a BIP49 published address
vector, Bech32/Bech32m against the full BIP173/BIP350 valid-address
lists, the BIP39 English wordlist integrity/uniqueness properties plus
the official `trezor/python-mnemonic` vectors, all four BIP32
`bip-0032.mediawiki` test-vector chains (serialized and compared as
`xprv`/`xpub` strings), the BIP84/BIP86 published address vectors (plus a
BIP44/BIP49 mainnet cross-check against known, independently-confirmed
on-chain addresses for the standard `abandon...about` test mnemonic),
the physical-session entropy-budget formula and undo/clear properties,
canonical-transcript build/finalize/decode round-tripping and malformed-
input rejection, and the >=20-case candidate-corpus generator itself
(schema shape, lowercase-hex rule, write+check round-trip).

## Candidate vs. frozen vectors

Per `tests/vectors/SCHEMA.md`, everything this CLI writes under
`tests/vectors/candidates/` is a **candidate** until the WP-16
golden-vector-freeze barrier passes. WP-16 reconciles this Python
output against the Rust `seed-core`/`seed-derive` pipeline and freezes
the corpus; this package does not decide what's frozen.
