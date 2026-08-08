# seed-compat frozen vector corpus — WP-C3 stamp

**Schema:** `alea-compat-vectors-v1` (SPEC_COMPAT §10.1)
**Barrier:** WP-C3 vector freeze (IMPLEMENTATION_MAP_COMPAT.md §4; SPEC_COMPAT
§10.2 de-circularized ground-truth rule, review F3).
**Frozen on:** 2026-08-04 (seedsigner-dice / seedsigner-coin); coldcard-dice
added 2026-08-04 (SPEC_COMPAT v0.6.2, the `rolls.py`/`rolls12.py`
de-circularization finding — see the v0.6.1 → v0.6.2 revision log at the top
of SPEC_COMPAT.md).
**Case count:** 14 (9 `mnemonic`, 5 `refusal`) across 3 profiles.

A case is frozen here ONLY if it cleared BOTH legs of the §10.2 rule:

1. **Rust ≡ Python** — the Rust `seed-compat` crate (`compat_derive`, digest +
   `WordCountRule` + refusal) and the independent Python reference
   (`reference/python/seedref/compat.py`, WP-C2) agree bit-for-bit. Enforced
   as `#[test]`s in `crates/seed-compat-vectors/` and by
   `python3 reference/python/ref.py compat check`.
2. **Vendor-oracle confirmation** — the case matches the profile's OWN tool,
   not merely Rust ≡ Python (which is exactly how F1 shipped). See oracle
   method below.

Rust ≡ Python alone did NOT freeze any case here.

## Frozen cases

| Case | Profile | Kind | Vendor verdict |
| --- | --- | --- | --- |
| seedsigner_dice_12w_vendor_example | seedsigner-dice | mnemonic (12w) | identical phrase (`hole…path`) |
| seedsigner_dice_24w_vendor_example | seedsigner-dice | mnemonic (24w) | identical phrase (`eyebrow…radio`) |
| seedsigner_dice_digit6_present_12w | seedsigner-dice | mnemonic (12w) | identical phrase |
| seedsigner_coin_12w_case1 | seedsigner-coin | mnemonic (12w) | identical phrase |
| seedsigner_coin_24w_case1 | seedsigner-coin | mnemonic (24w) | identical phrase |
| seedsigner_dice_40rolls_refusal | seedsigner-dice | refusal | tool refuses (not 50/99 rolls) |
| seedsigner_dice_60rolls_refusal | seedsigner-dice | refusal | tool refuses (not 50/99 rolls) |
| seedsigner_dice_99rolls_asked_12w_refusal | seedsigner-dice | refusal | phantom pairing: tool derives 24w from 99 rolls |
| seedsigner_coin_100flips_refusal | seedsigner-coin | refusal | tool refuses (not 128/256 flips) |
| seedsigner_coin_128flips_asked_24w_refusal | seedsigner-coin | refusal | phantom pairing: tool derives 12w from 128 flips |
| coldcard_dice_12w_case1 | coldcard-dice | mnemonic (12w) | identical phrase (`hole…path`) |
| coldcard_dice_24w_case1 | coldcard-dice | mnemonic (24w) | identical phrase (`eyebrow…radio`) |
| coldcard_dice_digit6_present_12w | coldcard-dice | mnemonic (12w) | identical phrase (digit `6` hashed as-is, not remapped) |
| coldcard_dice_advisory_underroll_12w | coldcard-dice | mnemonic (12w, 40 rolls) | identical phrase; vendor script WARNS ("only 103 bits of entropy") but still emits it -- WARNING, not a refusal |

## Per-profile oracle method (honest provenance)

- **seedsigner-dice — REAL TOOL RUN (independent BIP39 backend).**
  Oracle = SeedSigner's own `generate_mnemonic_from_dice` (from
  `src/seedsigner/helpers/mnemonic_generation.py`, `dev`) plus the dice
  refusal gate from `tools/mnemonic.py` (`dev`), copied VERBATIM and executed
  against the third-party **embit** BIP39 library (git-cloned from
  `diybitcoinhardware/embit`; the environment has no `pip`, so embit was
  vendored from source rather than pip-installed — recorded honestly). embit is
  independent of both Alea's Python `seedref` and the Rust crate, so the
  F3 de-circularization holds. The two vendor-example cases are ADDITIONALLY
  corroborated by the vendor's published vectors in `dice_verification.md`
  (SPEC_COMPAT §5.1.2): `hole…path` (50 rolls, 12w), `eyebrow…radio` (99 rolls,
  24w). Refusals confirmed by running the tool's gate at 40/60 rolls and at the
  99-roll input (which yields 24 words, so the requested-12w pairing cannot
  exist on the device).
- **seedsigner-coin — REAL TOOL RUN (independent BIP39 backend).**
  Same method with `generate_mnemonic_from_coin_flips` + the coin gate;
  no vendor-published coin example exists, so provenance is the tool run only.
  Refusals confirmed at 100 flips and at the phantom 128-flips-as-24w pairing.
- **coldcard-dice — REAL VENDOR TOOL RUN, `rolls.py`/`rolls12.py` (SPEC_COMPAT
  v0.6.2, §5.1.1/§10.3, supersedes the v0.6.1 hardware-to-freeze rule).**
  Oracle = Coinkite's own unmodified verification scripts, fetched from the
  primary `github.com/Coldcard/firmware` repository (byte-identical to the
  `coldcard.com/docs/` mirror cited in SPEC_COMPAT §5.1.1):
  - `docs/rolls.py` (24-word) —
    <https://github.com/Coldcard/firmware/blob/master/docs/rolls.py>,
    `sha256 4348a520e57df665e0ab57baa369a95ace0f9b5fba355b3f22b0b9b2c2e6cd30`.
  - `docs/rolls12.py` (12-word) —
    <https://github.com/Coldcard/firmware/blob/master/docs/rolls12.py>,
    `sha256 533daff58437cdc9a482d16cd181ba9b0fe6f86a6839b792343d39b496034c85`.
  - Both files are unchanged since commit `05ac389349c4f5ad80c036bce4e4111a746e4c86`
    ("add rolls12.py", 2022-12-19); `master` HEAD at freeze time
    (`c849c4e04a978335937a0fd0c96e76f5bd70bbb6`) still serves byte-identical
    content (hash-pinned above, not merely URL-pinned).
  - The scripts are genuinely standalone (`hashlib` only, no third-party
    dependency, no embit needed) and were run **unmodified**, piping each
    case's `events` string to `python3 rolls12.py` (12w cases) or
    `python3 rolls.py` (24w case) via stdin, exactly as Coinkite's own
    "Usage" comment documents (`echo <rolls> | python3 rolls.py`). This
    satisfies the F3 de-circularization rule directly — the oracle is the
    vendor's own tool, not iancoleman-hex and not either of Alea's own
    Rust/Python implementations.
  - All four `coldcard-dice` mnemonic candidates (12w, 24w, digit-`6`-present,
    and the 40-roll under-advisory-minimum case) reproduced **byte-for-byte
    identical mnemonics** against `rolls.py`/`rolls12.py` — no discrepancy
    found between Rust, Python, and the vendor oracle.
  - The 40-roll case additionally confirms the FreeChoice/advisory semantics
    directly from the vendor script's own behavior: `rolls12.py` printed
    `WARNING: Input is only 103 bits of entropy` to stdout but still emitted
    the 12-word mnemonic — an under-count is a **warning**, never a refusal,
    unlike SeedSigner's `DerivedFromLength` hard refusal at non-canonical
    lengths (SPEC_COMPAT §5.1.1/§6).
  - The remaining hardware-only fact — that a *physical* Coldcard actually
    took the dice-only path rather than the non-reproducible TRNG-mix path —
    is **not** part of this freeze; it is the repurposed
    `requires_hw_confirmation` **runtime-advisory** flag (§6, §10.3): the CLI
    and docs tell the user to confirm dice-only mode on their own device
    before trusting a match, understanding a mix-mode seed will legitimately
    differ.

## NOT frozen (honest limits)

- **iancoleman-hex** — a Method-A DIGEST cross-check oracle only, never a
  SeedSigner oracle and not a user-facing profile (`profile()` hides it,
  SPEC_COMPAT §5.1.4). Its authoritative oracle is the live iancoleman.io JS
  tool, which was not run here (browserless environment). Kept as candidates,
  not frozen.
- **`*_empty_string_no_oracle`** (both `seedsigner_dice_` and
  `coldcard_dice_` variants) — the empty string (`e3b0c442…`) is a
  `math_boundary_no_oracle` fixture (SPEC_COMPAT §10.2): a math boundary with
  no meaningful device oracle. seed-compat's own `Empty` refusal is a
  deliberate Alea-side precaution ("nothing to hash"), not a discovered
  vendor behavior — confirmed by running `rolls.py`/`rolls12.py` on empty
  input: neither refuses; both print `WARNING: Input is empty. This is a
  known wallet` and still emit a (well-known, `e3b0c442…`-keyed) mnemonic.
  Kept as a candidate/regression fixture, never counted as vendor-validated.

## Reproduce

```
python3 reference/python/ref.py compat check tests/vectors/compat/frozen/*.json
source $HOME/.cargo/env; export CARGO_TARGET_DIR=$HOME/.cache/sf-target/wp-c3
cargo test -p seed-compat-vectors     # reads frozen/ once it exists
# seedsigner vendor oracle (needs embit source on sys.path):
python3 /tmp/vendor_oracle.py tests/vectors/compat/frozen
# coldcard vendor oracle (Coinkite's own scripts, no dependencies):
curl -sLo /tmp/rolls.py https://raw.githubusercontent.com/Coldcard/firmware/master/docs/rolls.py
curl -sLo /tmp/rolls12.py https://raw.githubusercontent.com/Coldcard/firmware/master/docs/rolls12.py
sha256sum /tmp/rolls.py /tmp/rolls12.py   # must match the hashes recorded above
echo -n '<events>' | python3 /tmp/rolls12.py   # or rolls.py for the 24w case
```
