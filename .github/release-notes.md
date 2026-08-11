## Alea — air-gapped Bitcoin recovery-phrase generator

**Reproducible build; source tag and checksums signed; binaries NOT
code-signed.** The git tag is SSH-signed and `SHA256SUMS.sig` signs the
checksum file — verify both against the repository's `allowed_signers`
key (`VERIFYING-MEDIA.md`). The `.efi` binaries themselves carry no
Secure Boot signature (Secure Boot must be disabled to boot them — see
the flashing notes below). Verify what you downloaded against
`SHA256SUMS` before flashing:

```
ssh-keygen -Y verify -f allowed_signers \
  -I 312983771+Xerhs@users.noreply.github.com \
  -n file -s SHA256SUMS.sig < SHA256SUMS
```

### What's new in v0.13.0-beta

A **security-hardening** release driven by two independent external audits
(Grok 4.5 Expert and Gemini 3.1 Pro). It changes no generated seed and fixes
no user-facing bug — every item below is defensive.

- **Derivation panic guard** — source assembly is now bounded by
  `MAX_SOURCE_RECORDS` and fails closed (`TooManySources`) rather than risking
  a future out-of-bounds panic mid-ceremony.
- **Verifier memory hygiene** — `alea-verify` scrubs the full string capacity,
  not just the live length (backspaced bytes are now wiped).
- **Offline web verifier** — result HTML is escaped by construction, removing a
  fragile `innerHTML` sink.
- **Release integrity** — publishing now requires an out-of-band signer
  fingerprint pin (fail-closed) and runs an offline RustSec advisory gate.
- **TPM 2.0 / 1.2 entropy ships gated (unapproved)** — the machinery is present
  and hardware-exercised, but awaits its manufacturer-review decision, exactly
  like the EFI-RNG and USB-TRNG sources.

Details: `docs/AFTER-GEMINI-AUDIT-REMEDIATION-2026-08-11.md` and
`docs/GROK-4.5-EXPERT-AUDIT-2026-08-11.md`.

### Files

- `alea-x86_64-usb.img` — the flashable USB image (production launcher at
  `\EFI\BOOT\BOOTX64.EFI` plus the separate verifier at `\EFI\ALEA\VERIFY.EFI`).
  Write it to a whole USB device with Rufus (DD mode), balenaEtcher, or `dd`.
- `alea-x86_64-unsigned.efi` — the production UEFI payload on its own.
- `alea-verify.efi` — the standalone chain-loaded verifier.
- `SHA256SUMS` — checksums for the two payload artifacts above.
- `SHA256SUMS.sig` — SSH signature over `SHA256SUMS`, verifiable against the repository's `allowed_signers` key.

### Booting on real hardware

- **Disable Secure Boot** (the payload is unsigned) and boot the USB in **UEFI
  mode** (not Legacy/CSM).
- Alea deliberately refuses to run under virtualization — it fails the
  local-physical-machine gate — so the full generation ceremony only runs on
  real hardware.

Read `SECURITY.md` for the threat model and the entropy audit, and `README.md`
for the full flashing and verification guide.
