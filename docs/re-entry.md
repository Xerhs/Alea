# Re-entry verification: what hidden re-entry proves, and what it doesn't

SPEC §34.5 requires this explained: why multiple-choice verification is
not used; what hidden re-entry proves; what it does not prove; why
restoring on the intended signing device remains necessary. This
document covers each.

## Why not multiple-choice?

An earlier, more "convenient" design for verifying that you wrote your
words down correctly might show you four or five candidate words per
position and ask you to pick the right one. Alea does not do
this, and `SPEC.md` §23 states the reason as a flat prohibition, not a
style preference:

> Multiple-choice verification is prohibited because candidate lists
> leak substantial information and test recognition rather than exact
> transcription.

Both halves of that sentence matter. First, a candidate list is a
leak: even a "safe-looking" list of four plausible words narrows down
what an observer can infer about the real word far more than a blank
input field does — over many positions, that adds up. Second, and more
important for you personally: picking the right word out of a short list
tests whether you can *recognize* it, which is a much weaker test than
whether you can *reproduce* it. You can recognize a word you only
half-remember or misheard; you cannot type its first four letters
correctly from a written slip of paper unless you actually transcribed
it right. Alea's re-entry step is designed to catch the second,
harder failure mode, not just the first.

## The procedure, and what "matched" actually checked

For every position in order, you type the first four letters of the
word (or the complete word, if it's shorter than four letters — no two
BIP39 words share the same first four letters, so this prefix always
resolves unambiguously to exactly one word or is rejected as unresolved)
and press Enter. Nothing you type is echoed to the screen. Your typed
prefix is resolved to a specific word index, and that index is compared
against the word index that was actually generated at that position.
This repeats for all 12 or 24 positions, and every single one must
match (`SPEC.md` §23.1).

If a position doesn't match, you're offered three choices: retry that
position, reveal the full phrase again, or destroy the phrase and shut
down. **Revealing the phrase again discards all prior verification
progress** — re-entry restarts from word 1 after the screen is wiped
once more, and the application deliberately does not tell you which of
your earlier entries were already correct (`SPEC.md` §23.2). This is
intentional: showing "positions 1–14 were fine, only 15 was wrong" would
leak information about the phrase to anyone glancing at the screen at
the wrong moment, and would undermine the point of starting the
verification over cleanly.

Once every position matches, you see:

> **RE-ENTRY MATCHED**
> Every word you entered matched the generated mnemonic.

## What this proves

It proves exactly what it says: the sequence of words you typed, one
character-prefix at a time with no echo and no hints, is identical to
the sequence of words the application generated. That's a real,
meaningful check — it catches the far more common failure mode of
mis-transcribing a word, skipping one, or writing two out of order,
long before you ever try to restore the phrase for real.

## What this does not prove

`SPEC.md` §23.3 is explicit that the completion screen must not claim
more than this, and lists exactly what it must *not* say: **it must not
claim the application inspected or proved the correctness of your
physical backup.** Concretely:

- **A memorized phrase would pass this check too.** If you typed the
  words from memory instead of from what you actually wrote down, "RE-
  ENTRY MATCHED" would look identical. This check verifies your typing
  against the generated phrase — it has no way to look at your paper or
  metal backup and confirm it's legible, complete, or even the same
  words.
- **The durability and secrecy of your physical backup remain entirely
  your responsibility.** A backup that's illegible in five years, stored
  somewhere it'll burn or flood, or accidentally photographed and
  synced to a cloud account, is not something this screen has any way
  to detect. See `docs/backup-security.md`.
- **This does not confirm your wallet software or signing device will
  reconstruct the same wallet.** As `docs/bip39.md` explains, the same
  words can produce entirely different wallets depending on passphrase,
  derivation path and script type. Re-entry matching only confirms the
  *words* are right — it says nothing about what a specific device will
  *do* with them.

## Why you still need to restore on the intended signing device

Because of the point directly above, `SPEC.md` §23.3 requires the
completion screen to also tell you, and this document repeats it because
it's the single most consequential follow-up action after the ceremony:
restore the phrase on the actual signing device you intend to use,
verify the derivation values match (`docs/derivation-verification.md`),
independently confirm any receiving addresses before relying on them,
and send a small test amount before depositing anything substantial.
"RE-ENTRY MATCHED" is a necessary checkpoint on the way to a
usable, verified wallet. It is not the finish line by itself.
