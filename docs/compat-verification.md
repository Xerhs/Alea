# Compatibility / verification mode (`seed-compat`) — what a match proves, and what it doesn't

This document explains `tools/compat-verify`, the standalone CLI that
reproduces another vendor's *documented* dice/coin-to-seed math for
throwaway audit purposes. It is governed by `SPEC_COMPAT.md`, and if this
document and `SPEC_COMPAT.md` ever disagree, `SPEC_COMPAT.md` wins and this
file should be corrected. The claim ceiling in this document is
`SPEC_COMPAT.md` §4 and §11 — nothing here may state or imply more than
those sections permit.

## 1. Read this before you use it

> **Entering the same physical dice rolls or coin flips into two devices
> means both devices now hold your seed.** Use compatibility/verification
> mode only with dice or coins you will throw away, for a phrase you will
> never fund. It is an audit tool, not a wallet-creation shortcut.

Compatibility/verification mode is not a second, easier way to make a
Alea wallet, and it does not produce an Alea seed at all
(`SPEC_COMPAT.md` §1, §2). It reproduces a *different* vendor's math, on
purpose, so you can compare two independently-computed outputs against the
same physical rolls. The moment you type those rolls into `compat-verify`
and also into a real Coldcard or SeedSigner, the entropy behind that phrase
is known to *both* systems — it is no longer a private seed for anyone,
including you. There is no "verify now, fund later" version of this: a
seed that compat-verify has ever touched must never be funded.

`compat-verify` is a reference/host tool only. It is not reachable from the
production UEFI ceremony, the UEFI test edition, or any desktop GUI
(`SPEC_COMPAT.md` §3.1, §3.2, §9) — it lives at `tools/compat-verify` and
runs only on your own computer, not on the pre-boot signing environment.
Every screen it prints carries a permanent watermark:

```
COMPATIBILITY / VERIFICATION MODE — reproduces another vendor's method —
NOT Alea generation — public/throwaway seeds only
```

## 2. What a match DOES prove

If `compat-verify`, emulating a profile such as `seedsigner-dice`, derives
mnemonic M from your rolls, and your real device shows the exact same
words M for the same physical rolls, then (`SPEC_COMPAT.md` §4.1):

- **The device's implementation of that vendor's *documented* preimage was
  faithful for this specific input.** It did not silently discard,
  reorder, truncate, or substitute a constant for your entropy; its BIP39
  checksum and word mapping matched the published algorithm for this
  input.

That is arithmetic reproduction: two independent implementations of the
same published formula, run over the same bytes, produced the same output.
Nothing more.

## 3. What a match does NOT prove

A match tells you nothing about (`SPEC_COMPAT.md` §4.2, §11.2):

- **The device's firmware integrity.** `compat-verify` computes the
  vendor's *published* method itself; it does not inspect, disassemble, or
  attest to what code is actually running on your physical device. A
  device could match on the exact inputs you happened to test and diverge
  on any other input — only running the real device yourself, and
  comparing, gives you *any* device evidence, and even then only for the
  inputs you actually tested.
- **The device's secure element, random-number generator, or supply
  chain.** These methods are dice/coin-only; nothing about the device's
  hardware RNG, secure element, or manufacturing provenance is exercised
  by this mode.
- **The quality of your entropy.** A biased die produces a faithfully
  derived *weak* seed on both tools. Match is not a statement about
  randomness quality (see `docs/dice-and-coins.md`).
- **Anything about Alea's own production seeds.** A compat-verify
  seed is a reproduction of a *different* vendor's construction; it is
  never an Alea seed and was never meant to be one (§1, §2 above).

### The only claim this tool is permitted to make

Verbatim, and no stronger (`SPEC_COMPAT.md` §4.3, §11.3):

> Given these exact events, this is the mnemonic that `<device>`'s
> **published algorithm** produces. If your `<device>` shows the same
> words, its dice/coin arithmetic matched for this input. This does not
> prove the device's firmware, secure element, or randomness are
> trustworthy.

Every result screen `compat-verify` prints ends with a version of that
sentence.

## 4. The throwaway-seed rule, stated operationally

- Only ever enter dice rolls or coin flips into `compat-verify` that you
  are willing to discard entirely — never rolls you also intend to seed a
  funded wallet with, on any device, ever.
- If you want to audit your device's math *and* create a real wallet, do
  two **separate** roll sessions: one throwaway session for the
  `compat-verify` comparison, and one private session (on the device
  itself, or via Alea's own production ceremony — which produces a
  domain-separated seed that intentionally differs from every other tool,
  `SPEC_COMPAT.md` §1) for the wallet you will actually fund.
- `compat-verify`'s result screen does not print the entropy hex next to
  the mnemonic by default — you must pass `--show-entropy` to see it
  explicitly. This is deliberate: even though these are declared
  public/test values, the tool preserves the same no-concatenation habit
  Alea's production display uses (`SPEC_COMPAT.md` §7), so the
  muscle memory of "hex and mnemonic never appear together" is never
  broken, even here.
- The mnemonic itself is printed with a `PUBLIC TEST PHRASE — NEVER USE
  WITH FUNDS` header, and the whole screen is bracketed by the
  `[COMPATIBILITY / VERIFICATION — NOT AN ALEA SEED —
  PUBLIC/THROWAWAY]` watermark, so a `compat-verify` result can never be
  mistaken for production output even in a screenshot.

## 5. Using `tools/compat-verify` against a real device

Build it like any other host tool in this repository:

```
source $HOME/.cargo/env
export CARGO_TARGET_DIR="$HOME/.cache/sf-target/<your-tag>"
cargo build -p compat-verify --target x86_64-unknown-linux-musl
```

The binary lands at
`$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/debug/compat-verify`.

### 5.1 List the profiles

```
compat-verify profiles
```

```
Choose the device and method to reproduce:
  [1] COLDCARD — dice (SHA256 of rolls; you pick 12 or 24 words)
  [2] SeedSigner — dice (SHA256 of rolls; 50 rolls = 12 words, 99 = 24 words)
  [3] SeedSigner — coin flips (SHA256 of flips; 128 = 12 words, 256 = 24 words)
```

Only these three profiles are user-selectable. A fourth internal profile,
`iancoleman-hex`, exists only as a digest cross-check oracle used in the
test-vector corpus; it is never offered here and `compat-verify` refuses
it by name if you try to pass `--profile iancoleman-hex` (§6 below
explains why it is not a SeedSigner substitute).

### 5.2 Read the method screen before you enter anything

```
compat-verify method --profile seedsigner-dice
```

prints the exact algorithm, the word-count rule, the vendor source
citation, and any caveats for that profile — so you know precisely what
is about to be computed before you commit any physical rolls to it.

### 5.3 Perform the comparison

1. Physically roll dice (for `*-dice` profiles) or flip coins (for
   `seedsigner-coin`) — a **throwaway** set (§4).
2. Enter the *exact same* sequence of digits into your real device
   (Coldcard or SeedSigner, following its own dice/coin-entry procedure)
   and into `compat-verify`:

   ```
   compat-verify run --profile seedsigner-dice --events <your-99-digit-roll-string>
   ```

3. Compare the mnemonic `compat-verify` prints against what your real
   device displays.
   - **Same words** → the device's implementation of the documented
     preimage matched for this input (§2). Nothing stronger.
   - **Different words** → work through the mismatch checklist in §7
     below before assuming anything is wrong with the device.

#### 5.3.1 `coldcard-dice` only: confirm dice-only mode BEFORE trusting a match

Coldcard's dice-roll math (`rolls.py`/`rolls12.py`) is frozen and verified
(`tests/vectors/compat/frozen/FROZEN.md`), so `compat-verify` reliably
reproduces the *documented algorithm*. But a Coldcard has **more than one**
way to fold dice rolls into a seed, and only one of them is what
`compat-verify` emulates. Before you read anything into a `coldcard-dice`
match or mismatch:

1. **Confirm your physical Coldcard is actually on the dice-only path**:
   `New Seed Words > Advanced > 12 Word Dice Roll` or
   `24 Word Dice Roll` — *not* the default "new seed" flow, and not the
   mix/"Middle Ground" option.
2. If your Coldcard instead used the **mix/"Middle Ground"** path (dice
   rolls folded on top of TRNG-generated bits) or plain TRNG, a mismatch
   against `compat-verify` is **expected, not alarming** — that path
   intentionally combines your rolls with hardware randomness
   `compat-verify` cannot see or reproduce, by design (`SPEC_COMPAT.md`
   §5.1.1).

This on-device check is the one piece of `coldcard-dice` verification that
genuinely requires the physical hardware in hand — `compat-verify` itself,
and the frozen test-vector corpus, can only confirm the *algorithm* is
faithful to Coinkite's own published math (`rolls.py`/`rolls12.py`, run as
the vendor oracle, `SPEC_COMPAT.md` §10.3); only your own device can tell
you which entropy path it actually took. This is the (v0.6.2-repurposed)
`requires_hw_confirmation` flag on the `coldcard-dice` profile: a
**runtime reminder for you to check**, not a gate on whether the test
vectors could be frozen (they already are).

To see the raw entropy hex as well (optional, gated on purpose — §4):

```
compat-verify run --profile seedsigner-dice --events <...> --show-entropy
```

### 5.4 Word-count behavior differs per device — pass `--words` accordingly

- `seedsigner-dice` / `seedsigner-coin` **derive** word count from the
  exact number of rolls/flips you entered, and **refuse** anything else —
  you do not choose it. Entering exactly 50 rolls or 99 rolls (dice), or
  exactly 128 or 256 flips (coin), is required; any other count is
  refused with an explanation, never coerced into a phrase (this refusal
  behavior is the entire point of the `DerivedFromLength` word-count rule
  — see §6.1).
- `coldcard-dice` lets you **choose** 12 or 24 words freely, because that
  is how Coldcard's own two separate scripts (`rolls12.py` / `rolls.py`)
  work — pass `--words 12` or `--words 24` explicitly. 50/99 rolls are
  advisory minimums only for this profile and are not enforced.

Examples:

```
# SeedSigner derives word count — do not pass --words for these profiles
compat-verify run --profile seedsigner-dice --events <50-digit-string>
compat-verify run --profile seedsigner-dice --events <99-digit-string>

# Coldcard requires you to choose
compat-verify run --profile coldcard-dice --events <your-rolls> --words 24
```

### 5.5 Exit codes (so scripted comparisons can branch on them)

- `0` — command completed normally (menu/method printed, or a mnemonic
  was derived and shown).
- `1` — **REFUSED**: the device this profile emulates would refuse this
  input too. This is the *correct*, expected outcome for an out-of-range
  `DerivedFromLength` count, not a tool malfunction.
- `2` — an event character fell outside the profile's alphabet (e.g. a
  `7` for a dice profile).
- `3` — no events were entered.
- `4` — a usage error (bad flags, unknown profile id, I/O failure).

## 6. Method A vs. Method B — why your words might not match

### 6.1 Method A: what `compat-verify` actually implements

Every profile `compat-verify` offers (`coldcard-dice`, `seedsigner-dice`,
`seedsigner-coin`) shares one digest step, "Method A"
(`SPEC_COMPAT.md` §5.1):

```
entropy = SHA256(ASCII of your event digits)[..16 or ..32 bytes]
mnemonic = standard BIP39(entropy)
```

Dice digits `1`–`6` are hashed exactly as typed — **the digit `6` is
*not* remapped to `0`** in this construction. What differs between
vendors is only *how word count gets selected*:

| Profile | Word-count rule | Behavior on a non-canonical count |
| --- | --- | --- |
| `seedsigner-dice` | Derived from the exact roll count (50 → 12w, 99 → 24w) | **Refused** — not coerced, not shown as an approximate phrase |
| `seedsigner-coin` | Derived from the exact flip count (128 → 12w, 256 → 24w) | **Refused**, same as above |
| `coldcard-dice` | Free choice — you pick 12 or 24 words (two separate vendor scripts) | Under-rolling only produces an advisory warning; the vendor's own script would still compute a phrase for that count, so `compat-verify` shows it too |

This distinction (`SPEC_COMPAT.md` §6, review finding F1) is the single
biggest source of "why doesn't `compat-verify` show a phrase for my
count" confusion, and it is deliberate: SeedSigner's own firmware and
`tools/mnemonic.py` refuse the exact same non-canonical counts, so a tool
that fabricated a phrase anyway would be *less* faithful to the device,
not more. If you enter 99 rolls but ask for 12 words, `compat-verify`
refuses — because your real SeedSigner would show you 24 words for 99
rolls, not 12; there is no SeedSigner phrase that answers "99 rolls, 12
words."

### 6.2 Method B — Ian Coleman's *native* dice/base-6 mode (education only)

Ian Coleman's `iancoleman.io/bip39` tool is a useful **Method A digest
oracle** when configured correctly — but it also has a completely
different native mode that is a common source of "why don't my words
match" confusion. `compat-verify` does not implement this mode at all (it
is out of scope for v0.6.1, `SPEC_COMPAT.md` §5.2, §3.2) — it is
documented here purely so you can recognize the discrepancy if you hit
it, not because `compat-verify` can reproduce it:

- **If you want a Method-A digest cross-check** (matching `coldcard-dice`
  or the `seedsigner-*` digest step), set the tool's **Entropy Type to
  `Hex`** and enter your dice/coin digits there, with a numeric
  **Mnemonic Length** (12 or 24 Words). Because `1`–`6` are all valid hex
  characters, the tool takes them literally and computes
  `SHA256(your digit string)` — the same Method-A digest `compat-verify`
  computes.
- **If you instead set Entropy Type to `Dice`** (the tool's own native
  dice mode) **with Mnemonic Length set to `raw`**, you get a *third,
  different* construction ("Method B"): the tool first remaps digit `6`
  to `0` (dice → base-6 digits), expands each base-6 digit into a
  bias-corrected number of bits (not one uniform width per digit), uses
  those bits *directly with no SHA-256 step*, and truncates to a multiple
  of 32 bits. This produces different words than Method A for the *same*
  physical rolls, correctly — it is a genuinely different algorithm, not
  a bug.
- **The `'6'→'0'` trap:** SeedSigner's own documentation calls this out
  explicitly — *"do not use `dice` format because dice `6` will be
  replaced by `0`"* — precisely because Ian Coleman's `Dice` entropy type
  silently remaps `6`, while every profile `compat-verify` implements
  hashes `6` as-is. If you ever see Ian Coleman's tool set to `Dice`
  input, assume it will not match `compat-verify` or a real SeedSigner —
  select **`Hex`** input with a numeric **Words** length instead.

**Bottom line:** if your words don't match, check which of these three
constructions you actually compared before suspecting the device (§7
below has the full checklist, in priority order).

## 7. Why your words might not match (check these first, in this order)

`SPEC_COMPAT.md` §11.1 requires the benign explanations to be listed
*before* any alarming one, led by the mistake this tool is most likely to
introduce:

1. **You entered a roll/flip count the device ties to a specific word
   count, and expected a different one.** For SeedSigner, 50 rolls always
   means 12 words and 99 rolls always means 24 words — there is no
   "99 rolls, 12 words" phrase on the device, so `compat-verify` refuses
   that combination up front (§6.1) rather than let you compare against a
   phrase that can't exist.
2. **Wrong profile selected** — e.g. comparing Coldcard math against a
   SeedSigner, or vice versa.
3. **Coldcard's mix/"Middle Ground" entropy path was used on the device
   instead of dice-only.** Only the dice-only path
   (`New Seed Words > Advanced > 12/24 Word Dice Roll`) is externally
   reproducible; the mix path is not, and a mismatch there is expected,
   not a defect. Confirm which path your device actually used **before**
   trusting a `coldcard-dice` match or mismatch (§5.3.1) — this is the one
   check that genuinely requires the physical device in hand.
4. **Ian Coleman's `Dice`-vs-`Hex` or `raw`-vs-word-count setting**
   (§6.2) — the single most common source of "these don't match" when
   Ian Coleman's tool is used as a third comparison point.
5. **A mistyped event, especially the `'6'→'0'` trap** if you're
   eyeballing a comparison against Ian Coleman's native `Dice` mode
   (§6.2).

Only after ruling out all five of the above should "the device may not
implement its documented method as published" be considered — and even
then, `compat-verify` cannot tell you *which side* is wrong; it can only
tell you that the outputs diverged. Resolving that requires the physical
device, not this tool (`SPEC_COMPAT.md` §11.2).

## 8. Residual limitations (read together with §3)

- `compat-verify` reproduces the vendor's **documented** method. If a
  vendor's real firmware ever disagrees with its own published
  documentation, `compat-verify` follows the documentation, and a
  mismatch is the correct signal — it cannot tell you which side (the
  device or the docs) is wrong.
- Profiles are pinned to a specific source revision (`source_pinned_rev`
  in the profile record). If a vendor changes their method later, a
  stale profile can produce a false mismatch until the profile is
  updated and re-reviewed.
- `coldcard-dice`'s algorithm test vectors **are frozen** (`SPEC_COMPAT.md`
  v0.6.2, §5.1.1, §10.3) against Coinkite's own unmodified `rolls.py` /
  `rolls12.py` verification scripts, fetched from `github.com/Coldcard/
  firmware` and hash-pinned, run exactly as their own "Usage" comment
  documents — the same vendor-tool-oracle discipline `seedsigner-dice` /
  `seedsigner-coin` used against `tools/mnemonic.py`. See
  `tests/vectors/compat/frozen/FROZEN.md` for the exact, current,
  per-profile provenance of every frozen case, including the pinned source
  URLs and content hashes. All three user-facing profiles have now cleared
  both the Rust≡Python check and a real vendor-tool run.
  `requires_hw_confirmation = true` on `coldcard-dice` no longer gates this
  freeze (the v0.6.1 rule requiring physical hardware to freeze was
  dropped) — it is now a **runtime-advisory** flag: only a *physical*
  Coldcard can tell you whether it actually took the reproducible
  dice-only path or the non-reproducible mix/TRNG path, so that
  confirmation remains a step for you to perform on your own device before
  trusting a match (§5.3.1), never a property the frozen vector corpus
  itself needed to carry.
- Reproducing a preimage means the seed is now known to whatever host ran
  `compat-verify`. If that host is later compromised, any funded seed
  that was ever entered into `compat-verify` is compromised too — this is
  the entire reason funds are prohibited (§4) and the watermark is
  permanent (§1).

## 9. See also

- `SPEC_COMPAT.md` — the normative specification this document
  summarizes; §4 and §11 are the exact ceiling on every claim above.
- `docs/prohibited-claims-checklist.md` §8 — the compat-specific
  must-not-claim list for anyone writing release notes or public copy
  about this feature.
- `docs/dice-and-coins.md` — Alea's own (unrelated, differently
  domain-separated) physical-entropy protocol for production seeds.
- `docs/bip39.md` — general BIP39 background (entropy, checksum, mnemonic
  encoding) that applies to every profile here too.
- `tests/vectors/compat/frozen/FROZEN.md` — the frozen test-vector corpus
  and its per-case vendor-oracle provenance, for anyone auditing
  `compat-verify`'s own correctness.
