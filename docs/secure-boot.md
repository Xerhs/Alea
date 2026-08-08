# Secure Boot and distribution signing

`SPEC.md` §33 marks this section **product-critical, not an appendix**,
for a concrete reason: Alea's entire distribution model is
"boot from a USB stick on ordinary consumer hardware," and that model
collides with Secure Boot on effectively every machine shipped in the
last decade. There is no broadly-bootable path that skips signing
entirely. This document explains the three trust levels Alea can
be distributed at, and — because Level 1 is the one people are tempted
to shortcut — gives the complete, honest procedure for it.

If you only remember one thing from this page: **"the USB stick booted"
is never, by itself, evidence that you should trust it.** Secure Boot
authenticates a signing *chain*; it says nothing about whether the
firmware is honest, whether the entropy is good, or whether the binary
does what it claims. Boot media verification (`VERIFYING-MEDIA.md`,
`SPEC.md` §10) is a separate, required step regardless of which Secure
Boot level applies to your release.

## Level 1: Reproducible unsigned image

Appropriate for development and expert testing. Requires you to change
your firmware's Secure Boot configuration. **Must never be trusted
solely because the USB booted.**

### The honest procedure (not "just disable Secure Boot")

`SPEC.md` §33 is explicit that documentation must not pretend Level-1
users have some other option, and must not instruct disabling Secure
Boot without the steps that bracket it. The complete procedure is:

1. **Verify the release signature and media read-back first.** Do this
   *before* touching any firmware setting — see `VERIFYING-MEDIA.md`
   for the full ceremony (signing-key fingerprint check across
   independent channels, signature verification, revocation check,
   write-then-read-back hash comparison). An unsigned image still ships
   with a detached signature over its hash and a reproducible build
   process; skipping this step because the image is "just unsigned
   anyway" throws away exactly the verification an unsigned image still
   gives you.
2. **Disable Secure Boot — or, where your firmware supports it, enroll
   the image's hash directly instead of disabling Secure Boot
   wholesale.** Hash enrollment (sometimes called a custom Secure Boot
   allowlist or "DB" entry) is preferable when available: it lets this
   one specific image boot without turning Secure Boot off for
   everything else. Not all firmware supports it; where it isn't
   available, disabling Secure Boot in firmware setup is the fallback.
3. **Perform the ceremony.** Boot the verified, read-back-confirmed
   media and complete the Alea workflow as described in
   `QUICKSTART.md`.
4. **Re-enable Secure Boot before booting any other operating system on
   that machine.** This is not optional cleanup — leaving Secure Boot
   disabled after you're done removes a protection for every OS you
   boot on that machine afterward, for no ongoing benefit once the
   Alea ceremony is finished.

Instructing users to disable Secure Boot **without** steps 1 and 4 is
prohibited by `SPEC.md` §33, and this document does not do it. If you
see guidance anywhere — including a future version of this file — that
says "just disable Secure Boot" without a verify-first and re-enable-
after step, that guidance is wrong and should be corrected against
`SPEC.md` §33.

## Level 2: Project-key signed image

Signed by the project's own production key. You may enroll that key in
your firmware's Secure Boot database manually, which preserves a trust
path *you* control (you decided to trust this specific key) rather than
depending on a third-party certificate authority. This requires an
advanced firmware operation (manually adding a certificate to your
platform's Secure Boot key database, via your firmware setup utility or
a tool like `sbctl`/`mokutil` depending on your OS and firmware) and is
not expected of a general audience.

Manual key enrollment does not remove the need for the verification
ceremony in `VERIFYING-MEDIA.md` — it only changes what your firmware
will do with a boot attempt once you've decided to trust the key.

## Level 3: Broadly accepted signed image

Signed through a chain that common firmware already trusts by default —
for example, the Microsoft third-party UEFI certificate authority, or
`shim`. **This is the target distribution state for stable release**,
because Alea's whole distribution model presumes booting on
unmodified consumer machines, and that only works at scale through a
chain firmware already trusts out of the box.

Known obstacles, tracked here per `SPEC.md` §33 so they stay visible
rather than becoming a surprise:

- **The Microsoft third-party UEFI CA is disabled by default on
  Secured-core PCs.** Machines shipped under that Windows hardware
  program will not trust a third-party-CA-signed image without the
  owner explicitly re-enabling third-party UEFI CA trust in firmware
  setup — Level 3 signing does not make Alea boot everywhere
  unconditionally, even on hardware that generally supports the chain.
- **Signing review for a pre-boot secret-handling tool will exceed the
  scrutiny applied to a utility like a memory tester.** A CA reviewing
  a signing request for software that generates and displays wallet
  recovery phrases is reasonably going to ask harder questions than it
  would for `memtest86`. This is expected, not a sign anything is going
  wrong with the process, and it is one reason Level 3 is a target
  rather than a given for a fixed launch date.
- **The certificate-authority landscape itself changes over time.**
  Requirements, accepted CAs and revocation practices are not static;
  a Level-3 chain that's valid today is not a permanent guarantee.

None of the three levels — including Level 3 — proves that the
firmware, the entropy, or the application's runtime behavior is
trustworthy. A Level-3 signature only broadens *which machines will boot
the image without the owner making a manual trust decision first*. It
answers "will this run without extra firmware configuration," not "is
this platform safe to generate a seed on" — that second question is
what the rest of the pre-boot checks (`SPEC.md` §11) and your own
environment (`SPEC.md` §6) are for.

## The rule that applies at every level

Any Secure Boot configuration change — disabling it, enrolling a hash,
enrolling a key — must always be paired with the detached-signature
verification and media read-back verification described in
`VERIFYING-MEDIA.md`. None of the three levels above is a substitute for
that ceremony; they only change what your firmware does automatically
once you've completed it.
