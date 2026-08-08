# Dice and coins: the physical entropy protocol

SPEC §34.4 requires this explained: transcript hashing and why
information-theoretic exactness is not claimed; roll and flip fairness
and independence; entropy budgets and recommended margins; why human
choice is not entropy; why physical entropy does not defeat malicious
firmware. This document covers each.

## What's accepted, and what isn't

Version 1 accepts two physical methods, and you may use either or both
within one session (`SPEC.md` §17.1):

- **Dice**: repeated rolls of a real, physical six-sided die. You enter
  `1`–`6` for each roll. A fair die yields log₂6 ≈ 2.585 bits of entropy
  per roll.
- **Coins**: repeated flips of a real, physical coin. You enter `H` or
  `T` for each flip. A fair coin yields exactly 1 bit per flip.

The application rejects, as physical input: `0`, `7`–`9`, arbitrary
typed numbers, human-chosen words, mouse movement, timing measurements,
claimed entropy estimates, or imported files. There is no path to feed
Alea anything other than an actual recorded roll or flip result.

## Why human choice is not entropy

It might seem like you could just "pick 24 random-feeling words
yourself" instead of rolling dice. This does not work, and Alea
gives you no interface to try: humans are demonstrably bad at generating
unpredictable sequences on demand — people's "random" choices cluster
around predictable patterns, avoid repeats they perceive as
"non-random" (like `6 6 6`, which is exactly as likely as any other
specific sequence on a fair die), and are influenced by recency and
cultural bias in ways that are measurable and exploitable. A physical
die or coin, by contrast, derives its unpredictability from real-world
mechanical chaos — air resistance, initial velocity, surface texture,
bounce dynamics — that is fundamentally harder to bias intentionally or
unintentionally in the same way human number-picking is. This is why the
protocol only accepts recorded roll/flip *results*, never an
entropy-estimate claim or a typed sequence you composed yourself.

## Transcript hashing: what it claims, and what it deliberately doesn't

Earlier designs for this kind of tool sometimes use *rejection
sampling* — discarding or re-mapping specific rolls to force an exactly
uniform distribution over some smaller range. Alea does not do
this. Instead, every recorded roll and flip goes into a canonical,
domain-separated transcript (source tag, algorithm identifier, and raw
event bytes, in a fixed, defined order — `SPEC.md` §19.1–§19.2), and the
final entropy is:

```
digest = SHA256(canonical_transcript)
final_entropy = digest[0..32]   (24 words → 256 bits)
final_entropy = digest[0..16]   (12 words → 128 bits)
```

The published protocol reasoning (`SPEC.md` §19.3), stated exactly:

> The protocol: condenses variable-length source material; prevents
> ambiguous concatenation; provides source-domain separation; produces
> deterministic public test vectors; does not claim source independence
> or information-theoretic uniformity.

That last clause is the important one, and it is deliberate honesty
rather than an oversight. Alea does **not** claim that
`final_entropy` is exactly, information-theoretically uniform the way a
perfectly executed rejection-sampling scheme over perfectly fair dice
would be. It claims something more modest and more defensible:
**computational** uniformity, resting on SHA-256's properties as a
cryptographic hash function — specifically, that it's infeasible to
predict or bias the output distribution without breaking SHA-256 itself,
even from input that isn't perfectly uniform to begin with. This is
documented rather than buried precisely because a false claim of
information-theoretic exactness would be a strictly worse thing to ship
than an honestly-scoped computational claim.

## Fairness and independence: the disclaimer that's always on screen

Alea counts your rolls and flips against a minimum entropy
budget, but it explicitly does not — cannot — verify that your specific
physical die or coin is actually fair, or that successive rolls/flips
are actually independent of each other (a die with a chip that makes it
land preferentially on one face, or a "lucky" ritual that unconsciously
biases how you flip, would both be invisible to the software). The
entropy-collection screen states this directly, every time:

> The number of rolls or flips does not prove that your dice or coins
> are fair or that the events are independent.

This is why the entropy budget below includes a recommended margin
above the strict minimum — it's a hedge against exactly this kind of
imperfection, not a way to detect it.

## Entropy budget: minimums and the recommended margin

Before you're allowed to derive final entropy, your session must
satisfy, exactly (integer arithmetic — this is not an approximation in
the implementation, `crates/seed-protocol/src/physical/`):

```
2585 × dice_rolls + 1000 × coin_flips ≥ 1000 × target_bits
```

(equivalently, `2.585 × dice_rolls + 1.0 × coin_flips ≥ target_bits`;
the implementation scales everything by 1000 internally specifically so
this comparison never needs floating-point math at all —
`SPEC.md` §17.2).

| Mnemonic | Dice only (required minimum) | Coins only (required minimum) | Recommended (+25% margin) |
| -------- | ----------------------------- | ------------------------------- | --------------------------- |
| 12 words | 50 rolls | 128 flips | 64 rolls / 160 flips |
| 24 words | 100 rolls | 256 flips | 128 rolls / 320 flips |

You can mix dice and coins freely within one session — the same formula
applies with your actual roll and flip counts. The interface *shows*
your live progress toward both the hard minimum and the recommended
margin, and encourages continuing to the recommended margin, but only
*requires* the hard minimum before derivation is enabled.

**Why the margin exists**, stated concretely: the recommended margin is
sized so that even a meaningfully biased die — one as skewed as 20%
toward landing on a single face, well beyond what an ordinary physical
die is likely to exhibit — still delivers at least ≈2.3 bits of
min-entropy per roll rather than the ideal 2.585. The margin absorbs
that kind of imperfection without you needing to somehow assess your own
die's fairness first. If you have the extra minute or two, taking the
recommended count instead of stopping at the bare minimum costs little
and buys real robustness against dice or coins that aren't perfectly
fair.

## History, undo, and what's kept

Every roll or flip you enter is recorded, in order, into a fixed-size
history buffer. `Backspace`/undo removes the most recently entered event
with no recomputation needed; `C`/clear removes everything and requires
a confirmation before it takes effect, so an accidental keypress can't
silently wipe your progress. If you fill the history buffer's fixed
capacity, further entry stops — you can still derive (if your budget is
already met) or clear and restart, but the buffer itself never grows
past its fixed size. Once final entropy is derived, this entire history
buffer is scrubbed — the individual roll and flip values you entered do
not persist anywhere past that point (`SPEC.md` §17.3, §19.4).

## What physical entropy does not defeat

This is worth restating even though it also appears in `SECURITY.md`
and `docs/uefi-trust.md`, because it's specifically relevant to the
moment you're sitting there rolling dice and it's easy to feel like
you're doing "the secure part" of the ceremony:

> Physical dice and coins do not protect against malicious firmware
> that records your keystrokes or changes the program's execution. Use
> a machine whose firmware and physical environment you have reason to
> trust.

Rolling a physically fair die and typing the result in gives you real,
honest entropy going *into* the protocol. It says nothing about whether
the firmware faithfully uses that entropy, whether it's honestly
recording your later hidden re-entry keystrokes, or whether the display
you're looking at is showing you the truth. Physical entropy addresses
one specific risk (weak or backdoored randomness) — it is not a general
defense against a compromised platform. See `SPEC.md` §6 and §8 for the
full threat model, and choose your machine accordingly before you ever
pick up the die.
