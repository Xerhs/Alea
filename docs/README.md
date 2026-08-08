# Alea documentation

Start at the repository root: [`../README.md`](../README.md) for
orientation, [`../QUICKSTART.md`](../QUICKSTART.md) for the actual
ceremony walkthrough, [`../SECURITY.md`](../SECURITY.md) for the current
security status and threat model summary.

This directory holds the focused educational documents required by
`SPEC.md` §33–34, plus a checklist for anyone writing release notes or
public copy. `audit-status.md`, when it exists, is owned by the
adversarial-review work package (WP-35), not this documentation set —
everything else here is owned by the documentation work package (WP-36).

| Document | What it covers |
| --- | --- |
| [`secure-boot.md`](secure-boot.md) | The three Secure Boot / signing levels, and the honest Level-1 procedure (verify → disable/enroll → ceremony → re-enable). |
| [`bip39.md`](bip39.md) | Entropy, checksum, mnemonic encoding, seed derivation, and why the words alone don't fully describe a wallet. |
| [`uefi-trust.md`](uefi-trust.md) | What running before the OS loads removes, what it still trusts, and the firmware-input-path trade-off honestly stated. |
| [`machine-randomness.md`](machine-randomness.md) | EFI RNG, RDSEED, supplementary-only RDRAND, policy gating, and why machine-only mode can't be witnessed. |
| [`dice-and-coins.md`](dice-and-coins.md) | The physical entropy protocol, transcript hashing, entropy budgets, and why physical entropy doesn't defeat malicious firmware. |
| [`re-entry.md`](re-entry.md) | Why re-entry is hidden and not multiple-choice, and exactly what "RE-ENTRY MATCHED" does and doesn't prove. |
| [`derivation-verification.md`](derivation-verification.md) | The master fingerprint / address screen, and why a mismatch against your signing device means STOP. |
| [`backup-security.md`](backup-security.md) | Paper vs. metal, fire/water/theft, geographic separation, photography/cloud-sync risk, inheritance. |
| [`passphrases.md`](passphrases.md) | What a BIP39 passphrase is, how Alea's optional passphrase entry works, and what every distinct passphrase silently changing your wallet means for you. |
| [`alternatives.md`](alternatives.md) | An honest comparison against signing-device-native generation and other established approaches. |
| [`usb-trng.md`](usb-trng.md) | USB hardware RNGs (OneRNG/Infinite Noise/BitBabbler), the CLAIMED-not-COUNTED framing, the SPEC §6 attack-surface tension, and why the actual device read is deferred to SPEC §7.4. |
| [`prohibited-claims-checklist.md`](prohibited-claims-checklist.md) | A checklist for anyone drafting release notes or public copy. |

The three documents below are `SPEC.md` §32 fixed release-archive
files, not educational reading — they report the project's actual,
current governance/audit/compatibility status (honestly, including what
is *not* yet true) rather than explaining a concept to a user:

| Document | What it covers |
| --- | --- |
| [`SIGNING-GOVERNANCE.md`](SIGNING-GOVERNANCE.md) | Required signing-key custody, multi-person approval, rotation, revocation and compromise-response procedure (`SPEC.md` §32) — and its current, not-yet-operative status. |
| [`AUDIT-STATUS.md`](AUDIT-STATUS.md) | Gate-by-gate status against `SPEC.md` §36.2's minimum credible gate set. |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | The `SPEC.md` §30 hardware-compatibility reporting methodology, and the (currently empty) results table. |

Two related documents live at the repository root rather than here,
because they're operational runbooks rather than educational reading:
[`../VERIFYING-MEDIA.md`](../VERIFYING-MEDIA.md) (the `SPEC.md` §10
release-verification and boot-media ceremony) and
[`../REPRODUCING.md`](../REPRODUCING.md) (the `SPEC.md` §32
build-reproducibility procedure). Several documents above link into
both; they are not duplicated here.
