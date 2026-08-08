# BIP39: what your recovery words actually encode

SPEC §34.1 requires this explained: entropy and checksum, mnemonic
encoding, seed derivation, wallet derivation paths and script types, and
why the phrase alone may not fully describe a wallet. This document
covers each in turn, matching what Alea's code actually
implements (`crates/seed-core/src/bip39/`, `SPEC.md` §14).

## Entropy and checksum

An Alea mnemonic starts as either 128 or 256 bits of raw entropy —
random-looking bytes with no inherent meaning yet. Before encoding, a
checksum is appended:

| Words | Entropy | Checksum | Total encoded bits |
| ----- | ------- | -------- | ------------------- |
| 12 | 128 bits | 4 bits | 132 bits |
| 24 | 256 bits | 8 bits | 264 bits |

The checksum is the first *N* bits of `SHA-256(entropy)`, where *N* is 4
bits for 12 words or 8 bits for 24 words. It is not there for security —
it's there so a typo or a single wrong word during manual transcription
or entry is very likely to be caught immediately (a random wrong final
word passes the checksum only 1-in-16 or 1-in-256 of the time,
respectively), rather than silently producing a *different but
still-valid-looking* wallet you don't notice is wrong until it's too
late. This is exactly why Alea's complete hidden re-entry step
(`docs/re-entry.md`) matters: it re-runs this same resolution and
checksum logic against what you actually typed.

## From entropy+checksum to words

The entropy-plus-checksum bit string is split into 11-bit groups (12
groups for a 12-word phrase, 24 groups for a 24-word phrase). Each
11-bit group is a number from 0 to 2047, and indexes directly into the
fixed, 2048-word BIP39 English wordlist — word 0 is `abandon`, word 2047
is `zoo`. **The words are not chosen independently; every word is a
direct, deterministic function of the entropy and checksum bits.** You
cannot swap one word in a validly-generated phrase for a different word
of your choosing and still have a phrase that resolves to the same
wallet, and Alea's own protocol never selects words any other
way (`SPEC.md` §14: "Words MUST NOT be selected independently").

The embedded wordlist is the official published BIP39 English list, and
Alea verifies its own integrity against that list at startup as
one of its cryptographic self-tests (`SPEC.md` §11.6). The first four
letters of every one of the 2048 words are unique — no two words share
the same first four letters — which is exactly what makes the
four-letter-prefix hidden entry described in `docs/re-entry.md` and
`SPEC.md` §12.3 unambiguous.

## From words to a seed

The mnemonic (as its underlying word indexes, not as one concatenated
string — see `docs/uefi-trust.md` and `SPEC.md` §12.2 for why that
distinction is deliberate) is stretched into a 64-byte seed using
`PBKDF2-HMAC-SHA512` with 2048 iterations, a salt of the literal string
`"mnemonic"` optionally followed by a passphrase, per the published
BIP39 standard. **Version 1 always uses the empty passphrase** — see
`docs/passphrases.md` for what that means and why. This seed, not the
words themselves, is what a BIP32-compatible wallet actually uses as
its root key material.

## Derivation paths and script types

The 64-byte seed alone still isn't "a wallet" — a hierarchical
deterministic wallet (BIP32) derives an entire tree of keys from it, and
*which branch of that tree* your addresses come from is a separate
choice, governed by a derivation path and a script type. Alea's
post-re-entry verification screen (`docs/derivation-verification.md`,
`SPEC.md` §24) shows you the first receiving address under each of the
four standard single-signature paths, so you can confirm your signing
device landed on the branch you expect:

| Standard | Path | Script type | Address form |
| -------- | ---- | ------------ | ------------- |
| BIP44 | `m/44'/0'/0'/0/0` | P2PKH (legacy) | `1...` |
| BIP49 | `m/49'/0'/0'/0/0` | P2SH-P2WPKH (nested segwit) | `3...` |
| BIP84 | `m/84'/0'/0'/0/0` | P2WPKH (native segwit) | `bc1q...` |
| BIP86 | `m/86'/0'/0'/0/0` | P2TR (taproot) | `bc1p...` |

## Why the phrase alone may not fully describe a wallet

This is the core point this whole document builds to, and it's the
reason `docs/derivation-verification.md` exists at all: **the same 12
or 24 words can produce an enormous number of different wallets**,
depending on:

- the **passphrase** (empty, or any string — every distinct passphrase
  derives a completely different, unrelated-looking wallet from the
  same words; see `docs/passphrases.md`);
- the **derivation path and script type** your wallet software or
  signing device chooses (legacy vs. nested segwit vs. native segwit vs.
  taproot, or a nonstandard path entirely);
- the **coin/network** (Alea only ever derives Bitcoin mainnet
  addresses; version 1 has no testnet or altcoin derivation at all —
  `SPEC.md` §5).

If you restore the same 24 words into two different pieces of wallet
software with different default settings, you can get two completely
different sets of addresses — neither one "wrong," just different
branches of the same tree. That's precisely why Alea doesn't
consider the ceremony done at "the words matched on re-entry." It shows
you a master fingerprint and specific addresses for the four standard
paths so you have something concrete to compare against what your
actual signing device shows after restoring — see
`docs/derivation-verification.md`.

## Why BIP39 despite its known limitations

Alea uses BIP39 because of broad wallet compatibility — it is by
far the most widely supported mnemonic standard across hardware and
software wallets, which matters enormously for a tool whose entire
purpose is generating a phrase you'll restore somewhere else. This
comes with acknowledged trade-offs (the passphrase-changes-everything
behavior above being the most consequential one for everyday users) that
newer standards like SLIP39 address differently — Alea version 1
does not implement SLIP39 (`SPEC.md` §5). The choice is compatibility
over some of BIP39's rougher edges, made explicitly rather than by
default.

**Whatever wallet or signing device you restore into, verify the
derivation before depositing substantial funds** — see
`docs/derivation-verification.md` and `QUICKSTART.md` step 9.
