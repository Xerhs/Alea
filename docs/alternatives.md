# Alternatives to Alea

SPEC §34.9 requires this stated honestly: dice-roll seed generation on
dedicated signing devices is a reasonable alternative with different
trade-offs, and documentation must not disparage it. `SPEC.md` §1.1
requires the same honesty about who Alea is *for* in the first
place. This document is that honest comparison.

## The most important alternative: your signing device's own generation

Most hardware signing devices ship with their own built-in mnemonic
generation, typically using an on-device hardware random-number
generator, and increasingly, some devices let you supplement or replace
that with your own physical dice rolls entered directly on the device.
**If you are satisfied trusting your signing device's built-in seed
generation, you do not need Alea.** That is not a hedge or a
caveat — it's stated plainly in `SPEC.md` §1.1 as part of defining who
this project is actually for, and it's the honest answer for a large
share of people who own a hardware wallet.

### Rolling dice directly on a signing device

A number of hardware wallets support entering your own physical
dice-roll (or similar) entropy directly on the device itself, sometimes
combined with the device's own internal RNG, to produce the seed. This
is a genuinely reasonable choice, and `SPEC.md` §34.9 requires this
project to say so without disparagement — which this document does, and
means. The trade-offs are different from Alea's, not simply
worse or better:

- **Fewer moving parts.** One device, one session, no separate boot
  media, no separate computer, no USB stick to verify and write. For
  many people this operational simplicity is a real, legitimate
  advantage, not a corner cut.
- **A narrower, more auditable, purpose-built execution environment.**
  A dedicated signing device's firmware is a much smaller, more
  reviewable surface than a general-purpose PC's UEFI firmware plus CPU
  plus memory subsystem plus GOP graphics stack that Alea
  necessarily depends on (`docs/uefi-trust.md`). If you trust that one
  vendor's firmware, you have fewer other things to also trust.
  Conversely — and this is the flip side that motivates Alea's
  existence — it also means placing complete trust in that one vendor's
  supply chain, firmware and RNG implementation for *generation*, with
  no independent second opinion.
- **No separate re-verification step against a different implementation
  by design**, since generation and eventual use happen on the same
  device. Alea's entire value proposition, by contrast, is
  letting you generate on one execution environment (a booted UEFI
  application whose protocol is public and independently
  re-implementable, `reference/python/`) and then verify the result
  against a *different* device (your actual signing device,
  `docs/derivation-verification.md`) — a cross-check that dice-rolling
  directly on the signing device doesn't naturally produce, because
  there's only ever been the one device involved.

Neither approach is categorically safer. They optimize for different
things: Alea optimizes for cross-implementation verifiability and
not needing to trust any single wallet vendor's generation path; on-
device generation optimizes for simplicity and a smaller number of
components you need to reason about at all.

## Other established approaches, briefly

- **Multiple independent hardware wallets generating and cross-checking
  each other.** Some users generate a seed on one device and confirm it
  restores identically on a second, different vendor's device, as a
  cheaper approximation of the cross-implementation check Alea
  provides more directly. Reasonable, though it depends on both devices'
  RNGs being independently trustworthy in the first place, since neither
  one's generation step gets an outside check the way Alea's
  protocol does via the reference implementation.
- **Multisignature (multisig) setups**, spreading trust across several
  independently generated keys held on different devices, so no single
  seed's compromise is sufficient to move funds. This is a different
  axis of protection entirely (splitting custody, not improving any one
  seed's generation) and is outside Alea's scope in version 1
  (`SPEC.md` §5 excludes multisignature coordination).
- **Paper-and-pencil manual entropy schemes** that predate hardware
  wallets entirely (hand-computing a seed from dice rolls using
  published tables or manual SHA-256, without any device at all). These
  exist and have their own dedicated advocates; they trade convenience
  and speed for removing electronics from the generation step
  altogether, at the cost of being slow and error-prone to execute by
  hand correctly. Alea does not compete with or replace this
  approach — it occupies a different point on the trust-versus-
  convenience spectrum, using a computer but a specifically
  minimized, auditable, offline one.

## Choosing honestly

None of the above, including Alea, is the objectively "most
secure" option in every dimension simultaneously — that framing is
itself one of the prohibited claims this project avoids
(`docs/prohibited-claims-checklist.md`: "the safest possible seed
generator" is explicitly disallowed). The right choice depends on what
you're actually worried about: a single vendor's RNG or supply chain
(Alea helps here), operational simplicity and fewer components
(a signing device's own generation helps here), or protection even if
one seed is fully compromised (multisig helps here, and is orthogonal to
all of the above). It's entirely reasonable to decide Alea isn't
the right tool for you, and this document — and `SPEC.md` §1.1 which
requires it — is written so you can make that call honestly rather than
being talked out of a genuinely reasonable alternative.
