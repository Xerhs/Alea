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
