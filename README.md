# Alea

Alea is an air-gapped, pre-operating-system application that generates
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
recovery words (12 or 24) on a physical x86-64 computer -- booted from USB,
before Windows, Linux, or any general-purpose OS loads. The core idea:
mix entropy from dice and coins you personally witness with machine
sources you do not have to trust, combined so the result is strong if any
one contributing source was good. It then requires you to write the words
down, type every word back with no echo, and confirm the derived wallet
against your own signing device before you fund it.

> **STATUS: EXPERIMENTAL -- not externally audited. Do not use it to
> protect substantial funds.** Every production-capable build shows an
> on-screen warning to that effect. See [SECURITY.md](SECURITY.md).

If you are satisfied trusting your hardware wallet's built-in seed
generation, you do not need Alea.

## Features

- Boots bare-metal from USB before any OS; opens no network, writes no files, keeps no logs.
- Standard BIP39 output: any BIP39 wallet restores it; there is no Alea-specific seed.
- Witnessable entropy: dice rolls and coin flips counted against an enforced 128/256-bit floor.
- Machine sources (UEFI RNG, RDSEED) run under a compiled-in versioned policy, fail closed, and are credited zero counted bits.
- Optional TPM entropy (2.0 and 1.2): strictly opt-in extras, each shipped policy-disabled until reviewed; credited zero counted bits and not presented as a security upgrade.
- Refusal is a feature: detected virtualization, remote/serial consoles, managed endpoints, and unsafe display paths stop the ceremony with an explanation.
- No-echo re-entry: every word must be typed back and match before the ceremony completes.
- Derivation check: master fingerprint and first BIP44/49/84/86 addresses shown to compare against your signing device.
- Never displays or exports a private key, xprv, or raw seed; watch-only export of public values (xpub, descriptor, QR) is a separate opt-in behind its own warning.
- Optional BIP39 passphrase after re-entry; none is the default, and it is warned as unrecoverable if forgotten.
- Every exit path scrubs secret state and leads to power-off (or an explicit wipe-and-return-to-menu that scrubs at least as much).
- Desktop rehearsal edition (permanently watermarked, fixed public test vectors only), an offline web verifier, and an independent Python reference implementation for cross-checking.

## Get started

1. Download the release and check its signature and hashes through
   independent channels -- [VERIFYING-MEDIA.md](VERIFYING-MEDIA.md) has
   the exact commands.
2. Write the image to a USB stick with a raw block-copy tool, then read
   the stick back and compare its hash.
3. Rehearse on the desktop test edition first
   (`cargo run -p seed-desktop-test`) -- it uses fixed public test
   entropy, is permanently watermarked, and can never produce a real
   wallet.
4. Boot the USB stick on a physical, network-disconnected machine and
   follow the on-screen ceremony.

The full step-by-step walkthrough -- room preparation, entropy modes,
re-entry, derivation check, backup, and shutdown -- is
[QUICKSTART.md](QUICKSTART.md). Read it before doing this for real.

## Verify

Releases are built reproducibly: [REPRODUCING.md](REPRODUCING.md)
describes rebuilding a release bit-for-bit from source, and
[VERIFYING-MEDIA.md](VERIFYING-MEDIA.md) covers checking signatures and
checksums and confirming the USB stick you boot matches what you
verified.

## Learn more

| Document | Contents |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, ceremony, entropy model, threat model |
| [SECURITY.md](SECURITY.md) | Security posture, prohibited claims, vulnerability reporting |
| [docs/machine-randomness.md](docs/machine-randomness.md) | What machine RNGs (including TPMs) can and cannot promise |
| [docs/dice-and-coins.md](docs/dice-and-coins.md) | Physical entropy: how much, and what it does not prove |
| [docs/backup-security.md](docs/backup-security.md) | Storing the written words: paper, metal, theft, fire |

## License

Dual-licensed under MIT or Apache-2.0, at your option -- see
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
Contributions are accepted under the same dual license.
