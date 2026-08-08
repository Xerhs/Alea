# Alea — Design Overview

A concise design overview of Alea, an air-gapped UEFI application for generating
and verifying BIP39 recovery words on a physical computer before any operating
system loads. For the full user walkthrough see [`../README.md`](../README.md);
for the security posture and threat model see [`SECURITY.md`](../SECURITY.md).

> **Status: EXPERIMENTAL — not externally audited; do not use it to protect substantial funds.**

---

## What Alea is

Alea is a standalone, single-purpose application that boots from removable media
and runs *before* Windows, Linux, or any general-purpose OS is loaded. Its only
job is to generate a 12- or 24-word BIP39 mnemonic, make the operator write it
down, require them to type every word back, and then let them confirm — against
their own signing device — that the same wallet was restored, before scrubbing
its secret state and powering off. It is not a hardware wallet, a secure element,
or proof that the host is trustworthy.

The value proposition is a **reduced trusted computing base**: by removing the
desktop OS and its applications from seed generation, Alea eliminates a large
class of software threats (malicious web generators, browser extensions,
clipboard monitors, ordinary keyloggers, swap/hibernation leakage, telemetry,
cloud sync). It does **not** remove firmware, CPU/microcode, memory, the firmware
keyboard path, graphics hardware, the physical environment, the compiler, or the
release pipeline from what you trust — and it says so plainly. Refusal is a
feature: on a detected hypervisor, an active remote/serial console, a managed
endpoint, or a graphics adapter it cannot render secrets into safely, Alea stops
and explains why rather than proceeding on a platform it cannot reason about.

**One architectural caveat, stated up front.** Version 1 keeps firmware boot
services active throughout the ceremony. Every keystroke of the hidden re-entry —
which uniquely identifies each word — passes through the firmware keyboard stack.
Malicious firmware need not scrape the screen; the re-entry step hands it the
seed. Closing this with an application-owned USB HID driver after
`ExitBootServices` is the headline goal of a future version, not a version-1
claim.

## The ceremony

The workflow is a linear sequence of seven named stages rendered through Alea's
own graphics path (never firmware text output for anything secret-bearing).
Every mandatory startup gate must pass before any secret entropy is collected;
after a secret exists, no error path ever returns to a menu — it scrubs and
powers off.

| Stage | What happens |
|-------|--------------|
| **Prepare** | Experimental-status banner, opening warning, and three separate environment acknowledgements (release integrity; machine/connectivity; physical environment/aftercare), each a distinct keypress. |
| **Device** | Platform gates: watchdog disabled, obvious virtualization rejected, console topology inspected (serial/network/remote-management paths refuse), linear GOP framebuffer confirmed on the local display. |
| **Setup** | Word count (12/24), entropy mode, and dice/coin instrument chosen together; keyboard self-test and cryptographic known-answer self-tests. |
| **Entropy** | Physical dice/coin entry and/or approved machine-source sampling, with a live counted-bits budget and mode-specific warnings. |
| **Generate** | The final required warning and an explicit, deliberate arm key make entropy final; the BIP39 mnemonic is derived. |
| **Backup** | Each word rendered individually; the operator writes them down, then re-types every word with no echo. A full match is required to proceed; a deliberate destroy path is also offered. |
| **Verify** | After a matched re-entry, the master fingerprint and first receive addresses are shown so the operator can confirm their signing device restored the same wallet, then the ceremony terminates. |

An optional BIP39 passphrase is offered after re-entry; an empty passphrase is
byte-identical to setting none. A passphrase creates a wholly different wallet
and is unrecoverable if forgotten, so it is opt-in and clearly warned.

## Entropy model

Alea supports **physical** entropy (a six-sided die, log₂6 ≈ 2.585 bits/roll; a
coin, exactly 1 bit/flip) and **machine** entropy (the UEFI RNG protocol and
64-bit `RDSEED`, both under a compiled-in versioned policy; `RDRAND` is
supplementary only and can never stand alone). Three modes exist: physical-only,
machine-only, and combined.

- **Counted vs. claimed bits.** Only physical events count toward the security
  floor (2.585 × rolls + 1 × flips ≥ 128 or 256 bits, enforced before generation
  is enabled). Machine sources are credited **zero** counted bits — an honest,
  conservative stance that matches the on-screen composition panel. The number of
  rolls never *proves* the dice were fair; that is stated, not hidden.
- **Domain-separated transcript.** Every source is recorded with a unique,
  versioned tag, explicit lengths, and a canonical order independent of discovery
  order, then bound into one length-prefixed transcript under the fixed domain
  string `Alea/Entropy/v1\0` plus declared header constants (architecture, target
  bits, policy version). The final entropy is a single `SHA-256` of that
  transcript, truncated to 128 or 256 bits. Untrusted firmware strings are never
  mixed in.
- **Mixing property.** The output is strong if *any one* contributing source was
  good: a backdoored RNG cannot weaken a session that also contains sufficient
  fair physical events, and vice versa. Combined mode exists precisely as a
  backstop that does not require trusting the CPU's random silicon.
- **Fail-closed.** Machine sources refuse on every failure branch (unavailable,
  unsupported, denylisted, retry-exhausted, timed out, all-zero, all-0xFF, stuck,
  or `RDRAND`-alone) — there is no weak or PRNG fallback anywhere on the path. An
  empty transcript is rejected at the crypto boundary before any hashing.

The seed is a deterministic function of only the collected transcript and fixed,
declared constants — reproduced bit-for-bit by an independent Python reference
across a frozen vector corpus.

## Key derivation

After a matched re-entry, Alea derives the BIP39 seed (`PBKDF2-HMAC-SHA512`,
2048 iterations, with the committed passphrase) and a BIP32 master key, then
displays a **master fingerprint** and the **first receive address** for each of
the four standard single-sig paths on Bitcoin mainnet, account 0:

| Standard | Path | Address |
|----------|------|---------|
| BIP44 (legacy) | `m/44'/0'/0'/0/0` | `1…` |
| BIP49 (nested SegWit) | `m/49'/0'/0'/0/0` | `3…` |
| BIP84 (native SegWit) | `m/84'/0'/0'/0/0` | `bc1q…` |
| BIP86 (taproot) | `m/86'/0'/0'/0/0` | `bc1p…` |

The seed is a plain BIP39 seed — every BIP39 wallet reads the same words; the
address type is the *wallet's* choice, not baked into the seed. A bounded
more-options grid (account/index/change and a first-N table) and a structured
custom-path builder are available for inspection. All private-key math uses a
constant-time secp256k1 path, and every intermediate key and chain code lives in
the secret arena and is scrubbed when the display ends.

**Alea never displays or exports a private key, an extended private key
(`xprv`), the BIP39 seed, or a raw chain code — anywhere, with no exemption; no
`xprv` serializer even exists in the codebase.** As an explicit opt-in, reached
only by a deliberate keypress behind a full-screen warning, the operator may
display **public, account-level** watch-only export values — the account extended
public key, a BIP-380 output descriptor, a BIP48 multisig cosigner view, and an
on-screen QR of one of those public values — for building a watch-only or
multisig setup. A QR of any secret value is permanently excluded in every
edition.

## Secret handling and shutdown

Secrets live in fixed-size buffers in a single secret arena (`no_std`, no heap
allocation), with explicit scrub methods and no secret-bearing `Debug`,
`Display`, `Clone`, or serialization. Every intermediate is volatile-zeroed
(write + fence + verification read) immediately after use, on success and error
paths, with `Drop` backstops. Alea intentionally performs no persistence and
opens no network: it does not mount or write filesystems, touch the boot device,
create logs, modify UEFI variables, or retrieve remote resources.

Every terminal path runs the same single-sourced ordered scrub — re-entry state,
mnemonic indexes, derived secrets, the whole arena, then the framebuffer. Two
deliberate end points (the destroy confirmation and the finish screen) then offer
the operator a choice:

- **Power off** (the safest exit): scrub, then request shutdown. Power-off is
  recommended because letting DRAM decay also closes the cold-boot / DMA
  remanence window.
- **Wipe and return to the launcher menu**: the *same* scrub, plus additional
  clearing of non-arena staging and verification-display buffers that the
  power-off path would have left to DRAM decay, then a fresh ceremony from the
  top with every startup gate re-run. No secret crosses the boundary.

The menu-return path is reachable only from those two explicit operator choices;
every post-secret *error*, fault, timeout, or watchdog-reassert failure still
routes unconditionally to scrub-and-power-off. The one residual — transient
values that only ever lived in CPU registers, deep stack spills, or
firmware-owned buffers — cannot be reached by zeroing addressable memory and is
erased only by a real power cycle. Alea makes a bounded best-effort stack sweep,
discloses this on screen at the moment it applies, and presents power-off as the
complete-erasure option. Automatic zeroization and shutdown do **not** prove
immediate physical disappearance of all DRAM contents; the operator is told to
confirm a complete power-off, not a warm reboot.

## Editions

| Edition | Purpose | Notes |
|---------|---------|-------|
| **Production UEFI** | The only edition that generates a real, funds-bearing mnemonic | Boots from USB before any OS; real entropy; no test/deterministic hooks; refuses when mandatory checks fail. |
| **Desktop rehearsal / verifier** | Practice the ceremony and cross-check published vectors on Windows/Linux | **Public fixed vectors only — never real entropy**; permanent watermark; distributed separately, never on the production media. |
| **Offline web verifier** | Download-verify-go-offline single-file verification/rehearsal | A `no_std` core compiled to WASM; the highest-risk hot environment, with its own loud warnings; creates **no** fresh secret. |

A separate, independently written Python reference implementation reproduces the
transcript, BIP39, BIP32, and address protocols on public vectors so any party
can cross-check the Rust code bit-for-bit. A test-only UEFI build exists for
QEMU/hardware diagnostics, always watermarked and never accepted by production
signing.

## Security posture

Alea is **EXPERIMENTAL** and has **not** been through an external, professional
security audit. It reduces attack surface; it is not "unhackable", "trustless",
"military-grade", or equivalent to a hardware wallet, and it makes none of those
claims. No single mechanism it provides proves all of: reduced attack surface,
evidence the intended software booted, entropy quality, protection of secret
state, and durability of the physical backup — these are distinct, and the
documentation keeps them distinct.

Two internal, **AI-assisted** source-code audits have been performed and are
published in full, with file-and-line citations and fix-and-re-audit records.
They are documented inputs, **not** certifications, and do not satisfy the
external-review gate required before a stable release:

- [`ENTROPY-AUDIT.md`](ENTROPY-AUDIT.md) — the entropy path and machine-RNG
  robustness. Found one Medium and two Low issues, all fixed and re-audited to
  closure; confirmed the seed derives only from declared inputs and the machine
  source is fail-closed. The irreducible residual is a CPU RNG biased subtly
  enough to pass every catastrophic check — disclosed before generation and
  backstopped by dice/coin entropy.
- [`MENU-RETURN-AUDIT.md`](MENU-RETURN-AUDIT.md) — the wipe-and-return-to-menu
  path. Confirmed its scrub is a strict superset of the power-off scrub, that no
  error path can reach the menu, and that fresh ceremony state is constructed on
  return; the only residual is the register/stack/firmware residue that a power
  cycle erases.

See [`SECURITY.md`](../SECURITY.md) for the full threat model, the list of
permanently prohibited claims, and how to report a vulnerability.
