# Security

## Status

> **EXPERIMENTAL SECURITY SOFTWARE.** This build has not completed the
> stable-release security gates. Do not use it to protect substantial
> funds.

This is the exact banner every production-capable build shows before secret
generation, and it is not boilerplate. Alea has **not** passed its
stable-release gate set (external review, fault-injection and leakage
testing at release scope, hardware-compatibility evidence, a signed
distribution). Treat every mnemonic from any build — including one you
compiled yourself — as experimental. Practice with small amounts first.

The security audits to date are **internal, AI-assisted source reviews**
([`docs/ENTROPY-AUDIT.md`](docs/ENTROPY-AUDIT.md),
[`docs/MENU-RETURN-AUDIT.md`](docs/MENU-RETURN-AUDIT.md)) — documented
inputs, **not** a third-party or professional human audit, and they do not
satisfy the external-review gate.

## What the security claim actually is

Alea provides a small, auditable, pre-operating-system workflow that
removes the ordinary desktop OS from seed generation, supports physical
dice/coin entropy, restricts machine entropy through an explicit compiled-in
policy, avoids intentional persistence, requires complete mnemonic re-entry,
and displays derivation-verification values for the user's signing device.
**The underlying firmware, hardware, release process, and physical
environment remain trusted.** That is the ceiling, not a marketing floor.

## Threat model summary

**Materially reduced** by removing the desktop OS from the seed path:
malicious web seed generators; browser extensions; clipboard monitors; OS
keyloggers; screen recorders; telemetry; swap/hibernation files; shell
history; accidental filesystem storage; cloud sync; OS-dependent malware.

**Only partially reduced** (documentation must never claim otherwise):
secret remnants in RAM, CPU registers, or microarchitectural buffers;
framebuffer remnants; firmware keyboard/console buffers; malicious removable
media; build-system or dependency compromise; transcription errors;
physical observation; faulty machine RNGs; hidden virtualization or
remote-management hardware. Note: on Thunderbolt hardware, pre-boot DMA
protection can be **worse** than a modern OS with IOMMU/kernel DMA
protection — the application inherits the firmware's DMA posture and cannot
configure it. This is a real regression in one dimension, documented rather
than hidden.

**Not solved at all:** malicious UEFI firmware, CPU, microcode, or option
ROMs; hardware implants; active BMC/remote-KVM capture; a camera on the
display; an attacker who replaces both the release and its verification
instructions; a compromised signing key; entering the mnemonic into a
compromised wallet later; theft/loss of the physical backup; coercion; a
malicious compiler; cold-boot / physical memory acquisition; manipulated
dice/coins; a backdoored machine RNG in machine-only mode.

## The one trade-off to understand first

Version 1 does **not** call `ExitBootServices` before the secret workflow
(see [`docs/uefi-trust.md`](docs/uefi-trust.md)). UEFI firmware stays active
and handles every keystroke throughout — including hidden re-entry, which by
construction identifies every word of your mnemonic one keystroke at a time.
**Malicious firmware does not need the screen; the re-entry step alone hands
it the seed if the firmware is dishonest.** Closing this gap with an
application-owned USB HID keyboard driver after `ExitBootServices` is the
headline goal of version 2, not something version 1 claims to have solved.

## What Alea never claims

These descriptions are permanently prohibited, gates satisfied or not:
"unhackable," "trustless seed generation," "equivalent to a hardware
wallet," "guaranteed true randomness," "firmware cannot observe the seed,"
"bare-metal security eliminates malware," "military-grade," "works on any PC
like memtest," "secure because Secure Boot is enabled," "the safest possible
seed generator." See
[`docs/prohibited-claims-checklist.md`](docs/prohibited-claims-checklist.md).

## Reporting a vulnerability

This project is pre-stable-release with no formal bug-bounty program yet.
For anything that could compromise **entropy quality, secret handling,
derivation math, or the release pipeline**:

- Do **not** publish exploit details or working proof-of-concept in a public
  issue before a fix exists.
- Use the most private channel the hosting platform offers (e.g. a private
  security advisory), or contact a maintainer directly.
- Non-sensitive issues (docs, build problems, UI) are fine as public issues.

Changes to entropy, BIP39, derivation, the secret lifecycle, or the release
system require separate dedicated review beyond ordinary code review.

## Independent verification

You are not asked to trust this document or any single party. Cross-check
for yourself: [`VERIFYING-MEDIA.md`](VERIFYING-MEDIA.md) (release + media
read-back), [`REPRODUCING.md`](REPRODUCING.md) (rebuild the unsigned payload
and compare hashes), and `reference/python/` — an independently-written
reference implementation the Rust code and desktop edition must match
bit-for-bit against the frozen vectors in `tests/vectors/`.
