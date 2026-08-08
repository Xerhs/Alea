# Derivation verification: the fingerprint/address screen, and why a mismatch means STOP

SPEC §34.6 requires this explained: what the master fingerprint is; what
the four address standards mean; why matching values prove the signing
device derived the same wallet; why a mismatch means STOP (wrong
passphrase, wrong path, or a faulty or malicious device); why these
values affect privacy but are not secret keys. This document, together
with `docs/bip39.md` (which explains *why* the same words can produce
different wallets in the first place), covers all of it.

## When this screen appears, and why it's optional

This screen is offered only **after** your hidden re-entry has fully
matched (`docs/re-entry.md`, `SPEC.md` §24.1) — the words you're about
to see derivation values for are specifically the words you just proved
you correctly wrote down. It's optional and fully skippable: some users
will restore on their signing device and check there instead, and that's
a legitimate choice. What this screen offers is a *reference* you can
compare against, generated independently of whatever device you
eventually restore into.

## What actually gets computed

From the mnemonic (with the empty passphrase — see `docs/passphrases.md`
for why that matters), Alea derives, entirely within its
protected secret arena and scrubbed once this step ends
(`SPEC.md` §24.2):

1. The 64-byte BIP39 seed via `PBKDF2-HMAC-SHA512`, 2048 iterations,
   salt `"mnemonic"`, empty passphrase.
2. The BIP32 master private key and chain code, via
   `HMAC-SHA512("Bitcoin seed", seed)`.
3. The **master fingerprint**: the first 4 bytes of `HASH160` (SHA-256
   then RIPEMD-160) of the master *public* key, shown as 8 hex
   characters.
4. The first external receiving address, at account 0, index 0, under
   each of the four standard single-signature derivation paths.

| Standard | Path | Script type | Address form |
| -------- | ---- | ------------ | ------------- |
| BIP44 | `m/44'/0'/0'/0/0` | P2PKH (legacy) | `1...` |
| BIP49 | `m/49'/0'/0'/0/0` | P2SH-P2WPKH (nested segwit) | `3...` |
| BIP84 | `m/84'/0'/0'/0/0` | P2WPKH (native segwit) | `bc1q...` |
| BIP86 | `m/86'/0'/0'/0/0` | P2TR (taproot) | `bc1p...` |

All private-key arithmetic in this derivation uses the same
constant-time secp256k1 code path used everywhere else in the
cryptographic core (`SPEC.md` §13, §24.2) — there is no separate,
less-reviewed fast path for this "just a verification screen" step.
Every intermediate private key and chain code produced along the way
lives in the secret arena and is scrubbed when this display step ends,
exactly like every other secret in the ceremony.

## What the master fingerprint actually is

The master fingerprint is a short (4-byte / 8-hex-character), *public*
identifier derived from your master public key — not your master
private key, and not usable to derive or spend anything by itself. Its
purpose here is purely as a quick, compact "does this wallet's root key
match" check: if two wallets show the same master fingerprint, they were
derived from the same seed (with, practically, negligible collision
risk at this length for this purpose). It's the fastest single value to
compare between this screen and your signing device.

## What the four address standards mean, briefly

Bitcoin has accumulated several different standard ways to turn a public
key into a spendable address, each with different transaction-size,
fee and compatibility trade-offs. BIP44/49/84/86 are the four dominant
single-signature standards in current use, corresponding to legacy,
nested-segwit, native-segwit and taproot address formats respectively.
Alea doesn't pick one for you — it shows all four, because
different wallets and signing devices default to different ones, and
you need to know *which* address format your specific device will
actually generate and expect funds at. See `docs/bip39.md` for why this
distinction exists at all and isn't just cosmetic.

## Why a match means what it means

If the master fingerprint and the relevant address(es) shown here match
what your signing device shows after you restore the same words on it,
that is strong, concrete evidence that your signing device derived
**exactly the same wallet** this ceremony created — same seed, same
path, same script type, same empty passphrase. This is the whole point
of the screen: it converts "I re-entered my words correctly" (which
`docs/re-entry.md` already established) into "and my actual hardware
wallet will spend from the same place I expect it to."

## Why a mismatch means STOP

If the fingerprint or address does **not** match what your signing
device shows, do not proceed to deposit funds. A mismatch means exactly
one of a small number of things went differently between this ceremony
and your device, and you need to figure out which before trusting the
result:

- **A passphrase is involved somewhere.** These values assume the empty
  passphrase. If your signing device applied a passphrase (or you typed
  one without realizing your device treats an empty field differently
  from truly empty), you'll get a completely different, unrelated-
  looking wallet — not an error, just silently the wrong wallet. See
  `docs/passphrases.md`.
- **Your device used a different derivation path or script type than
  you expected.** Some wallets default to a nonstandard path, or you
  selected the wrong account/address type in its settings.
- **Something is actually wrong with the device** — a bug, a
  misconfiguration, or, in the worst case, a faulty or compromised
  signing device that is not deriving what it claims to.

None of these are things you want to discover *after* sending funds.
Sort out which one applies — usually by carefully checking your signing
device's passphrase and derivation-path settings against what's
documented here — before depositing anything beyond the small test
amount `QUICKSTART.md` recommends regardless.

## Not secret, but not nothing either

None of the values on this screen are secret keys: no private key,
extended private key (`xprv`), the raw BIP39 seed, or a chain code is
ever displayed (`SPEC.md` §24.3 — this is a hard requirement, not a
default that could be turned on). Extended public keys (`xpub`) are also
deliberately never shown or exported in version 1: an `xpub` combined
with even one leaked child private key would expose your entire account,
so withholding it limits what anyone who later sees a record of this
screen can learn, at the cost of the screen showing individual addresses
instead of one compact account-level value.

That said, **these values are not nothing** — the fingerprint and
addresses reveal where your funds will actually sit, which has real
privacy implications if disclosed. It's safe to write them down
alongside your recovery words for your own reference, but treat them
with roughly the care you'd give an account number, not as something to
post publicly or share carelessly.

## If something goes wrong during this step

Any error during derivation follows the same scrub-and-shutdown path as
any other post-secret failure (`SPEC.md` §24.4, §27.2). Because your
mnemonic re-entry already succeeded before this screen was ever offered,
your written backup remains fully usable — the screen (if it can still
display anything at all) will tell you the verification values simply
weren't produced, and that you can repeat the ceremony after a fresh
boot if you want to see them. A failure here never invalidates the words
you already verified.

## Using your Alea seed in any wallet

**The words are the whole wallet.** Alea gives you 12 or 24 words in the
standard **BIP39** format. That is the entire secret. Any wallet that
supports BIP39 — hardware wallets like Trezor, Ledger, Coldcard, or software
wallets like Sparrow, Electrum, BlueWallet — can restore it. There is no
Alea-specific, brand-specific, or type-specific seed. You did not generate
"a Ledger seed" or "a taproot seed" — you generated **a seed**, and every
wallet reads the same words.

**One seed, every address type — the wallet chooses.** From the same words,
your wallet can produce several address types at the same time:

| Type | Also called | First address looks like |
| --- | --- | --- |
| Legacy | BIP44 | `1…` |
| Nested SegWit | BIP49 | `3…` |
| Native SegWit (bech32) | BIP84 | `bc1q…` |
| Taproot | BIP86 | `bc1p…` |

Which one you see is **your wallet's choice** (its "derivation path"), made
when you restore or receive — it is **not** baked into the seed. Most modern
wallets default to Native SegWit or Taproot and let you switch. You never
have to pick a type in Alea, and picking one elsewhere never changes your
words.

**How to restore:** type the words into your wallet's "restore from
recovery phrase" screen. That is all — **no key file, no `xpub`, no export.**
Alea never writes a file and never gives you one to import; the words are
enough.

**Confirm before you fund.** Right after generating, Alea shows you a master
fingerprint and the first receiving address for each of the four types. When
you restore your words in your own wallet, check that it shows the **same**
fingerprint and address for the type it uses. If it matches, you have
restored the same wallet — send a small test amount first, then the rest.
If it does **not** match, stop: it usually means a passphrase is set, a
different derivation path is selected, or the device is faulty — never send
funds until it matches.

**One caveat — the passphrase.** The addresses Alea shows assume **no BIP39
passphrase**. A passphrase (sometimes called a "25th word") creates a
completely different wallet with different addresses. If you use one, your
wallet's addresses will not match Alea's preview — that is expected, and
only you can hold that passphrase.
