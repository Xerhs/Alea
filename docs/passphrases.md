# BIP39 passphrases: what they are, and how Alea's optional entry works

SPEC §34.8 requires this stated: every passphrase derives a different
wallet; incorrect passphrases usually produce another valid wallet
rather than an error; losing the passphrase loses access; passphrase
backup needs a separate plan; when a passphrase is set, the
derivation-verification values reflect it, and when it is empty (or
skipped), they assume the empty passphrase. It also requires stating
plainly that version 1 implements an optional BIP39 passphrase
(`SPEC.md` §34.8; `SPEC_PASSPHRASE.md`).

## What a BIP39 passphrase is

BIP39 defines an optional extra input — often called the "25th word,"
though it can be any string, not just a word — that feeds into the same
`PBKDF2-HMAC-SHA512` seed-derivation step described in `docs/bip39.md`,
alongside your mnemonic. Change the passphrase, and you get a
completely different 64-byte seed, and therefore a completely different
wallet, from the exact same 12 or 24 words.

## Alea version 1 implements an optional BIP39 passphrase

After the hidden re-entry step, the Alea ceremony offers you an
**OPTIONAL PASSPHRASE** screen with an explicit `[Y]`/`[N]` choice.
Most people should skip it — leave it empty unless you already have a
specific reason to want one. If you choose `[N]`, or the extended
keyboard needed for passphrase entry could not be verified on your
device, generation continues with the **empty** passphrase, and the
result is byte-identical to a run where the passphrase feature did not
exist at all.

If you choose `[Y]`, you type the passphrase twice — masked entry,
showing one neutral placeholder glyph per character typed, never the
actual characters — and the two entries must match before anything is
derived; a mismatch discards both attempts and makes you enter it
again. Entry accepts printable ASCII only (letters, digits, space,
punctuation); any other character is rejected outright with an
on-screen message rather than silently accepted or altered. Once
committed, the passphrase is never displayed again, never logged, and
never written to the entropy transcript — and when it's set, the
derivation-verification screen (`docs/derivation-verification.md`) you
see next is computed *with* it, not with the empty passphrase.

This document explains passphrases in full anyway, because
understanding what a passphrase does is essential to using Alea's own
passphrase step correctly, to correctly interpreting the derivation-
verification screen either way, and to avoiding a specific,
easy-to-make mistake described below.

## Every passphrase derives a different wallet — with no warning

This is the single most important thing to understand, stated as
directly as possible: **a BIP39 passphrase is not like a password that
gates access to an existing wallet. It is an input to *which* wallet you
get in the first place.** The empty passphrase derives one wallet.
Passphrase `"correct horse battery staple"` derives a completely
different, entirely unrelated-looking wallet from the exact same words.
Passphrase `"Correct Horse Battery Staple"` (different capitalization)
derives yet another, different one still. There is no meaningful concept
of "the wrong passphrase" that produces an error message — every
distinct passphrase string, including one you mistyped by a single
character, produces *some* valid-looking wallet. If that wallet happens
to be empty (because you've never actually used it), nothing on
screen will look wrong; it will simply look like a wallet with no funds
in it, indistinguishable from having typed the right passphrase into the
wrong wallet's worth of funds sitting one typo away.

This is exactly why `docs/derivation-verification.md` matters as much as
it does, and exactly why a mismatch there means STOP rather than "try
again casually": if you (or your signing device) apply a passphrase that
Alea's shown fingerprint and addresses don't account for, you
will land on a different wallet with no error telling you so.

## Losing the passphrase loses access — permanently, and separately from the words

If you choose to add a passphrase on your own signing device, losing
that passphrase is functionally equivalent to losing the wallet itself,
**even if your 12 or 24 words are perfectly intact and safely backed
up.** The words alone, without the passphrase, derive a *different*
wallet than the one your funds are actually in — an attacker or a future
you with only the words but not the passphrase gets nowhere useful, and
neither does the words-only backup by itself restore access. There is no
recovery mechanism for a forgotten passphrase; it isn't stored anywhere,
by design, on any implementation that follows the BIP39 standard
correctly.

## Passphrase backup needs its own, separate plan

If you use a passphrase at all, it needs the same durable-backup
thinking `docs/backup-security.md` describes for your words —
independently. Consider, deliberately, whether to store it:

- **Together with the words**, which is simpler to manage but means
  anyone who finds your word backup also gets the passphrase, largely
  defeating the extra protection a passphrase is meant to add; or
- **Separately from the words** (a different location, a different
  medium, memorized rather than written, or held by a different trusted
  person), which preserves the passphrase's protective value but adds
  real risk that the passphrase itself gets lost, forgotten, or becomes
  inaccessible to whoever needs it later (see inheritance, in
  `docs/backup-security.md`).

There is no universally correct choice here — it depends on what threat
you're using the passphrase to defend against in the first place (a
thief who finds your paper backup? A family member you don't want
having access alone? Something else?). Decide deliberately, write down
your reasoning somewhere you'll find it later, and don't leave "figure
out the passphrase backup plan" as a someday task — an unrecorded
passphrase decision is functionally the same risk as no backup at all.

## Why the derivation-verification screen matches whichever passphrase you used

`docs/derivation-verification.md`'s fingerprint and address values are
computed with whatever you actually did at the passphrase step: if you
set a passphrase, the values reflect that passphrase; if you skipped it
or left it empty, the values assume the empty passphrase — the same
values Alea has always shown. Either way, the on-screen caveat text
tells you which case you're in.

If what you did at Alea's passphrase step doesn't match what you plan
to do (or already did) on your actual signing device — for example, you
left it empty in Alea but intend to add a passphrase on the signing
device, or vice versa, or you use a *different* passphrase string on
the two — **the values Alea shows you will not match** what that device
displays, and that's expected, not a sign anything went wrong. In that
case, the values still serve one purpose: they confirm what that
specific words-plus-passphrase combination derives to, which is worth
knowing even if it's not the wallet you ultimately intend to fund — and
they let you confirm your device is at least reading the words (and,
if set, the passphrase) correctly before you rely on it.
