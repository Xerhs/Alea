# Verifying an Alea release and boot media

Owner: WP-32 (`tools/release-verifier/`). See `IMPLEMENTATION_MAP.md` §5
WP-32 and `SPEC.md` §10 ("Release verification and boot-media ceremony")
and §33 ("Secure Boot and distribution signing").

**Read this before writing Alea to a USB stick or booting it.**
`SPEC.md` §10 is explicit that "verified image" is an operational
*process* you perform, not a label the booted program shows you — a
compromised binary can display any version string or checkmark it likes.
This document is that process, as a runbook.

If you want to rebuild the unsigned executable from source and confirm
you get the same bytes as the published release, see `REPRODUCING.md`
instead — that is a *different*, narrower claim (see its §1) from
everything below.

## 0. Threat model honesty (read this part even if you skip everything else)

- A hash you downloaded from the same (possibly compromised) source as
  the image proves nothing — it would be tampered together with the
  image.
- Secure Boot authenticates a signing *chain*; it says nothing about
  whether the firmware is honest or the entropy is good.
- If the computer you are performing this ceremony on is itself
  compromised, it can falsify **every** step below, including the hash
  comparison your own eyes see printed on screen. This ceremony raises
  the cost of a successful attack; it does not turn an untrusted machine
  into a trusted one. **If your threat model includes "my daily-use
  computer might already be compromised," perform this entire ceremony
  on a separate, dedicated device**, not the machine you normally use.
- Read-back verification (step 6 below) and independent signature
  checking reduce, but do not eliminate, distribution risk.

## 0a. Verifying the signed source tag

Release tags are SSH-signed, and the signing public key is committed at
the repository root as `allowed_signers`. From a clone:

```
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v v0.11.0-beta
```

A good result prints `Good "git" signature for
312983771+Xerhs@users.noreply.github.com` with the key's SHA256
fingerprint. The same honesty rule as everything else in this document:
the keyring ships in the repository it vouches for, so this check proves
the tag matches the key *the repository documents* — trust-on-first-use.
Cross-check the key fingerprint against an independent channel (an
earlier clone, the project site) before treating it as more than that.
This is a single-maintainer key, not the multi-person production signing
governance described in `docs/SIGNING-GOVERNANCE.md`; no release is
production-signed.

The same key signs each release's checksum file. With `SHA256SUMS` and
`SHA256SUMS.sig` downloaded next to a clone:

```
ssh-keygen -Y verify -f allowed_signers \
  -I 312983771+Xerhs@users.noreply.github.com \
  -n file -s SHA256SUMS.sig < SHA256SUMS
```

This proves the checksum list is the one the key holder published — it
does NOT make the `.efi` binaries Secure Boot-signed; that separate
code-signing layer does not exist yet (see section 3 below).

## 1. The complete procedure (SPEC §10)

Do these in order. Skipping steps, especially 1–4 and 8, defeats the
purpose of the later ones.

1. **Obtain the release, detached signature, hashes and release notes.**
   Download `alea-x86_64-signed.efi` (or `-unsigned.efi` if you
   have specifically decided to run an unsigned, Level-1 image — see
   §3), `alea-x86_64-usb.img`, `SHA256SUMS`, `SHA256SUMS.minisig`,
   and the release notes, from the project's published release location.
2. **Verify the project signing-key fingerprint through at least two
   independent channels.** Do not trust a key fingerprint only because
   the same web page that hosts the download also shows it. Cross-check
   it against, e.g., a second site the project publishes to, a
   community-verified copy, or a channel you have prior independent
   trust in. `SIGNING-GOVERNANCE.md` (shipped in every release archive,
   SPEC §32) documents the project's current key(s) and rotation
   history — cross-check the fingerprint you have against what it says,
   through a channel other than the one you downloaded the release from.
3. **Verify the release signature on a second trusted device where
   practical.** Running `release-verifier`/`minisign` only on the same
   machine you'll write the USB stick from is better than nothing, but a
   second, independently-controlled device repeating the same check is
   much stronger evidence — it means an attacker needs to have
   compromised two of your machines identically, not one.
4. **Confirm the release version is not revoked.** Stable releases
   publish a signed revocation list of compromised or withdrawn
   versions (SPEC §10). Check the release you have against the current
   list before proceeding.
5. **Write the complete disk image to removable media.**
   `alea-x86_64-usb.img` is a complete disk image, not a file to
   copy onto an existing filesystem — write it with a raw block-copy
   tool (e.g. `dd`, Rufus in "DD image" mode, balenaEtcher), not by
   drag-and-drop.
6. **Read back the complete written media.** Read every byte back off
   the media you just wrote (e.g. `dd if=/dev/sdX bs=4M | sha256sum`,
   matched against the image's own published hash — truncate the
   read-back to the image's exact byte length first if your media is
   larger than the image, since trailing bytes on the device are not
   part of it).
7. **Compare the read-back image against the published expected hash.**
   This is what `release-verifier` (below) automates for the files it
   can reach directly. The read-back step above produces exactly the
   kind of hash this comparison needs, done by hand or with a hash tool
   of your choice — `release-verifier` operates on files in a directory,
   not on a raw block device, so this specific media-readback comparison
   is a manual step (or use `tools/media-readback-verifier/`, WP-29's
   tool, if invoking this from a release pipeline rather than by hand).
8. **Remove the media from the writing system before booting.** Do not
   boot the USB stick on the same running operating-system session you
   used to write it — that session, if compromised, could have modified
   the media after the hash comparison and before you boot from it.
9. **Confirm the booted build identifier matches the intended release.**
   The production edition displays its release version and immutable
   build identifier before secret generation (SPEC §4.1). Check this
   against the release you obtained. This step only detects *accidental*
   mismatch (e.g. booting last month's USB stick by habit) — it is
   explicitly **not** self-authenticating, because a malicious binary can
   display any identifier it likes. Steps 1–8 are what make the
   identifier meaningful; this step alone proves nothing.

Physical write protection (a hardware read-only switch on the media,
where the media supports one) MAY be enabled during and after writing;
this is a recommendation, not a requirement.

## 2. Running `release-verifier`

`tools/release-verifier` automates steps 2 (the cryptographic half of it
— it does not replace cross-channel fingerprint checking) and 7 for the
files it can reach in an already-downloaded release directory: recomputing
every file's SHA-256 against `SHA256SUMS`, and checking the detached
signature over it — the current `SHA256SUMS.sig` (SSH, `ssh-keygen -Y
verify`) and/or the legacy `SHA256SUMS.minisig` (`minisign`).

Current releases ship `SHA256SUMS.sig` (SSH), so verify against the
committed `allowed_signers` key (obtained/cross-checked per §0a, never
merely trusted because it came in the download):

```sh
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$HOME/.cache/sf-target/<your-tag>"
cargo run --locked -p release-verifier -- /path/to/release-dir \
  --allowed-signers /path/to/allowed_signers \
  --signer-identity 312983771+Xerhs@users.noreply.github.com \
  --require-signature
```

`--require-signature` makes a release that ships **no** detached
signature at all fail (exit 3) instead of passing — use it whenever you
expect an authenticated release. For an older minisign-signed release,
pass `--pubkey @/path/to/alea-signing.pub` instead of the two SSH flags.

- `<release-dir>` must contain `SHA256SUMS` (and everything it lists —
  the release archive contents, per SPEC §32).
- `--pubkey` accepts either a raw minisign public-key string (starting
  `RW...`) or `@/path/to/file` to read one from a file — e.g. the
  project's published `.pub` key, obtained and cross-checked per step 2
  above, never merely trusted because it was bundled in the same
  download.
- `--allowed-signers` is the out-of-band SSH keyring (the repo's
  `allowed_signers`, obtained/cross-checked per §0a) and `--signer-identity`
  the principal in it; the verifier **never** falls back to a keyring
  bundled inside the release directory it is checking. `--pubkey` (raw
  `RW...` minisign key or `@/path/to/file`) covers the legacy minisign
  form.
- If a detached signature (`SHA256SUMS.sig` or `SHA256SUMS.minisig`) is
  present but cannot be checked — no key/keyring given, or the
  `ssh-keygen`/`minisign` binary is missing — `release-verifier` prints a
  **warning** and exits nonzero, never a silent pass; it never reports a
  signature as checked when it wasn't, and prints the exact manual
  command to run once the tool/key is available. See §0a for the manual
  `ssh-keygen -Y verify` command; `release-verifier` deliberately vendors
  no signature cryptography (see `tools/release-verifier/src/lib.rs`).

Exit codes: `0` = every `SHA256SUMS` entry matched and the signature
check either passed or found nothing to check (and `--require-signature`
was not given); `1` = a file's hash did not match, was missing, or
`SHA256SUMS` could not be read; `2` = a signature was positively reported
**invalid** (tampered or wrong-key release — a serious finding, not a
warning); `3` = a detached signature was present but could not be
cryptographically checked (no key/keyring, or the tool is not installed),
**or** `--require-signature` was given and the release ships no signature
at all. Exit code `3` is deliberately never `0`: a hash re-derived from
files sitting in the same release directory you downloaded proves nothing
if that source was compromised
(SPEC §10), so a CI script or wrapper that gates only on "exit code
zero means verified" MUST NOT treat this case as a pass — it must
either fail the build or explicitly special-case exit code `3` as
"unauthenticated, human follow-up required."

`release-verifier` intentionally does not attempt steps 1, 3, 4, 5, 6, 8
or 9 above — those are cross-channel, physical-media and boot-time steps
a program running against a downloaded directory cannot perform on your
behalf. It prints a reminder of this every run so its "PASS" is never
mistaken for "the whole ceremony is done."

## 3. Secure Boot levels (SPEC §33) — what each one actually gives you

Alea may be distributed at up to three trust levels. None of them
replace the ceremony above; they change what your firmware will do with
the result.

- **Level 1 — reproducible unsigned image.** For development and expert
  testing. Requires you to change your Secure Boot configuration.
  **This must never be trusted solely because the USB stick booted.**
  If you use a Level-1 image, the honest procedure is: (1) do the
  verification above *first*; (2) disable Secure Boot, or enroll the
  image hash where your firmware supports that instead of disabling it
  outright; (3) perform the ceremony; (4) **re-enable Secure Boot before
  booting any other operating system on that machine.** Skipping steps
  1 or 4 and going straight to "just disable Secure Boot" is exactly the
  shortcut SPEC §33 prohibits documentation from suggesting.
- **Level 2 — project-key signed image.** Signed by the project's own
  production key. You may enroll that key in your firmware manually,
  which preserves a trust path you control rather than depending on a
  third-party CA — but it requires an advanced firmware operation not
  expected of a general audience.
- **Level 3 — broadly accepted signed image.** Signed through a chain
  common firmware already trusts (e.g. the Microsoft third-party UEFI
  CA, or shim). This is the target distribution state for a stable
  release, because ordinary consumer machines are exactly what this
  project's distribution model presumes booting on. Known obstacles are
  tracked in `docs/secure-boot.md` (WP-36): the third-party CA is
  disabled by default on Secured-core PCs, pre-boot secret-handling
  software attracts more signing-review scrutiny than a typical utility,
  and the CA landscape itself changes over time. A Level-3 signature
  still does not prove the firmware is honest or the entropy is good —
  it only broadens which machines will boot the image without a manual
  trust decision.

Any Secure Boot configuration change must always be paired with the
detached-signature verification and media read-back verification above —
never performed in isolation.

## 4. What this ceremony proves, and what it does not

Per SPEC §2, no single mechanism proves all of: reduction of attack
surface; evidence that the intended software was booted; quality of
entropy; protection of secret state; durability/correctness of the
physical backup. This ceremony addresses the second item (evidence the
intended software was booted) and, transitively, contributes to the
first. It says nothing about entropy quality (see `ENTROPY-POLICY.txt`
and SPEC §15–18), secret handling once the software is running (SPEC
§13, §20), or your physical backup's durability (SPEC §34.7). Treat this
document, `REPRODUCING.md`, `ENTROPY-POLICY.txt` and the educational
material in SPEC §34 as complementary, not redundant.
