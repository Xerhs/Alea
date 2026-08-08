# Alea

**Status: EXPERIMENTAL — not externally audited. Do not use it to protect
substantial funds.** Every production-capable build shows an on-screen
warning to that effect. See [`SECURITY.md`](SECURITY.md).

Alea is a standalone, **pre-operating-system** application for generating
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
recovery words (12 or 24) on a physical x86-64 computer — before Windows,
Linux, or any general-purpose OS loads. It collects entropy from physical
dice/coins and/or an explicitly-approved machine source, derives a
mnemonic, requires you to type every word back with no echo, and only then
shows the wallet fingerprint and first addresses so you can confirm your
signing device restored the exact same wallet before funding it.

Design and threat model: [`docs/DESIGN.md`](docs/DESIGN.md).

## What Alea is *not*

- **Not "memtest for seeds."** It deliberately **refuses** virtualized
  platforms, remote-console paths, managed endpoints, and hardware it
  cannot render secrets into safely — and tells you why. Refusal is a
  feature; a tool that boots everywhere and trusts everything is not the
  goal.
- **Not a hardware wallet, secure element, or proof your computer is
  trustworthy.** It removes the desktop OS from seed *generation* — it does
  not remove the firmware, CPU, memory, display, your environment, the
  compiler, or the release process from what you trust.

**If you are satisfied trusting your hardware wallet's built-in seed
generation, you do not need Alea.**

## Editions

| | Production UEFI | Desktop test |
|---|---|---|
| Purpose | Generate a real mnemonic | Rehearse; cross-check public vectors |
| Runs | Boots from USB, before any OS | Ordinary program on Windows/Linux |
| Entropy | Real dice/coins and/or approved machine source | **Fixed public test vectors only** |
| Marking | None (the real thing) | Permanent watermark; every phrase prefixed `PUBLIC TEST PHRASE — NEVER USE WITH FUNDS` |

**Never treat desktop-test output as a real wallet.** A separate
chain-loaded **verifier** and an **offline web verifier** let anyone
cross-check the implementation against frozen public test vectors. No
watermarked or desktop build is ever a production seed generator.

## Using your seed in any wallet

**The words are the whole wallet.** Alea gives you standard BIP39 words —
the entire secret. Any BIP39 wallet (Trezor, Ledger, Coldcard, Sparrow,
Electrum, …) restores it. There is no Alea-specific seed.

**One seed, every address type — the wallet chooses:**

| Type | Also called | First address |
|---|---|---|
| Legacy | BIP44 | `1…` |
| Nested SegWit | BIP49 | `3…` |
| Native SegWit | BIP84 | `bc1q…` |
| Taproot | BIP86 | `bc1p…` |

The address type is your wallet's derivation-path choice, not baked into
the seed. To restore: type the words into your wallet's "restore from
recovery phrase" screen — **the words alone are enough; no file is written.**

**Optional watch-only / multisig export.** On a separate screen you
deliberately open, behind its own warning, Alea can show the account
extended public key (`xpub`/`zpub`), an output descriptor, and a QR code —
for a **watch-only** wallet or a **multisig cosigner**. This is public data:
it can watch but never spend, is never written to a file, and is never
needed for an ordinary restore. A private key, `xprv`, or the raw seed is
**never** shown or exported.

**Confirm before you fund.** Alea previews a master fingerprint and the
first address for each type. When you restore elsewhere, check it shows the
**same** fingerprint/address. If it matches, send a small test amount first.
If it does **not** match, stop — usually a passphrase or a different
derivation path.

**The passphrase caveat.** After re-entry, Alea offers an *optional* BIP39
passphrase ("25th word"); "none" is the default. A passphrase creates a
completely different wallet and is **unrecoverable if forgotten** — only set
one you are certain you can reproduce exactly.

## Do the ceremony

Read [`QUICKSTART.md`](QUICKSTART.md) — the step-by-step walkthrough: verify
the release, rehearse on the desktop edition, prepare the room, boot, roll
dice, write words down, re-enter, check the derivation against your signing
device, scrub, and power off.

## Build and run

A `rustup`-managed toolchain is required; `rust-toolchain.toml` pins the
version and targets (`x86_64-unknown-uefi`, `x86_64-unknown-linux-musl`).
On Debian/Ubuntu install `musl-tools`; the web-edition gate additionally
needs `node` and binaryen `version_119` (`wasm-opt`). Full provisioning is
in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

```sh
source "$HOME/.cargo/env"                         # if not already on PATH
export CARGO_TARGET_DIR="$HOME/.cache/alea/dev"   # any writable path

./ci.sh                                            # everything CI runs
cargo build -p seed-uefi-production --target x86_64-unknown-uefi --locked
cargo run -p seed-desktop-test                     # desktop rehearsal (test entropy)
cargo run -p seed-desktop-test -- check            # headless vector check
cd reference/python && python3 -m unittest discover -s tests
```

Before writing a USB stick and booting real hardware, read
[`VERIFYING-MEDIA.md`](VERIFYING-MEDIA.md); to reproduce a release build,
[`REPRODUCING.md`](REPRODUCING.md); for Secure Boot,
[`docs/secure-boot.md`](docs/secure-boot.md) (not a "just turn it off").

## Repository map

```
README.md            This file.
docs/DESIGN.md       Architecture and threat model.
SECURITY.md          Experimental status, threat-model summary, reporting.
QUICKSTART.md        Step-by-step ceremony walkthrough.
VERIFYING-MEDIA.md   Release-verification and boot-media ceremony.
REPRODUCING.md       Build-reproducibility instructions.
docs/                User-facing guides + security audits.
crates/              The Rust implementation.
reference/python/    Independent reference implementation (public vectors).
tools/               image-builder, verifiers, binary-policy-scanner.
tests/vectors/       Frozen cross-implementation test vectors.
entropy-policy.toml  Compiled-in, versioned machine-entropy policy.
```

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture and threat model.
- [`SECURITY.md`](SECURITY.md) — status, threat model, vulnerability reporting.
- [`QUICKSTART.md`](QUICKSTART.md) — the ceremony, step by step.
- Security audits: [`docs/ENTROPY-AUDIT.md`](docs/ENTROPY-AUDIT.md), [`docs/MENU-RETURN-AUDIT.md`](docs/MENU-RETURN-AUDIT.md).
- User guides: [`bip39`](docs/bip39.md), [`dice-and-coins`](docs/dice-and-coins.md), [`machine-randomness`](docs/machine-randomness.md), [`re-entry`](docs/re-entry.md), [`derivation-verification`](docs/derivation-verification.md), [`passphrases`](docs/passphrases.md), [`backup-security`](docs/backup-security.md), [`uefi-trust`](docs/uefi-trust.md), [`secure-boot`](docs/secure-boot.md), [`alternatives`](docs/alternatives.md).

## License

Dual-licensed under **MIT** or **Apache-2.0**, at your option — see
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE). Any
contribution submitted for inclusion is dual-licensed as above, without
additional terms.

## Security

See [`SECURITY.md`](SECURITY.md). Changes touching entropy, BIP39,
derivation, the secret lifecycle, or the release system require separate
review — this is not a casual-PR project for those areas.
