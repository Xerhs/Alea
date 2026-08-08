# USB TRNGs: what they are, what an approved dongle adds, and what it doesn't

This is the fuller version of `SPEC_USB_TRNG.md` §12.5's §34.11 requirement:
what a USB hardware random number generator physically is; the
OneRNG-vs-FTDI device-class distinction and why it matters for a
pre-boot driver; the allow-list's identity matching and its real limits;
the firmware-USB substitution risk (SPEC §6/§7 attack-surface tension);
and why a dongle reinforces, and never replaces, dice and coins. The
transcript/policy/accounting mechanics this page describes are owned by
`SPEC_USB_TRNG.md`; if this page and the spec ever disagree, the spec
wins and this file should be corrected.

**Status:** the transcript tag, policy schema, and accounting rule
described here are specified and frozen (`SPEC_USB_TRNG.md` §6, §8,
§10). The actual USB device *read* — opening the device, sending
commands, pulling bytes off the wire — is **deferred**: it depends on
the application-owned USB host stack in `SPEC.md` §7.4, which has not
landed. Nothing in this document describes a currently shippable
device-read path; see "What's actually deferred" below.

## What a USB TRNG physically is

A USB hardware random number generator is a small external device,
plugged into a USB port, containing a physical noise source — an
avalanche diode, a pair of free-running oscillators, thermal noise in a
resistor, or similar — and (in every open-hardware design examined here)
some amount of on-device or host-side conditioning before the bytes
reach a computer. It is not a certification and not a proof: it is a
peripheral whose designer chose a physical process believed to be hard
to predict, and whose output a host application can read like any other
USB byte stream.

Two design families matter for Alea, because they imply very different
amounts of trusted code a pre-boot driver would need:

- **OneRNG** enumerates as a standard **USB CDC-ACM (serial) device**
  (`1d50:6086`). No proprietary line protocol: open the serial port,
  send a 4-byte ASCII command, read bytes. Its on-board whitening (a
  toggleable CRC16 mixer) runs on the device itself, not in Alea's
  trusted code. This is the only device this feature currently treats
  as a realistic first approved target, precisely because it doesn't
  require porting cryptographic conditioning into firmware.
- **Infinite Noise and BitBabbler** both use an **FTDI vendor-class USB
  chip** (not serial, not HID) whose raw output is explicitly described
  by their own authors as unsafe to use directly — Infinite Noise's
  bits are "correlated" and require host-side Keccak-1600 whitening;
  BitBabbler requires XOR-fold post-processing. Supporting either would
  mean porting real cryptographic conditioning and a bit-bang USB
  protocol into Alea's trusted pre-boot base. Both are **deferred,
  unapproved** targets for that reason, not because the underlying
  noise source is worse.

Device-class facts, not vendor preference, are what drives this: a
device whose safety-critical whitening already happened before the
bytes leave the wire is categorically cheaper and safer to add to a
trusted pre-boot binary than one whose safety depends on code Alea
would have to write and prove correct.

## What an approved USB TRNG adds

Under `SPEC.md` §18.1 ("strong if any one source was good"), an
honest, un-substituted USB TRNG is one more mixed source, physically
distinct from the host silicon, on a supply chain the user chose rather
than one baked into the machine whose firmware Alea is already routing
around. Adding a genuinely independent honest source can only raise the
chance that at least one good source is present in the final mix.

That is the entire, narrow claim. The permitted phrasing
(`SPEC_USB_TRNG.md` §4.3) is:

> An approved USB TRNG adds one more physically distinct source to the
> entropy mix. If it is honest and its data reaches Alea unaltered, it
> can only strengthen the result. Alea cannot prove that it is honest,
> cannot prove its data was unaltered, and does not count its output
> toward the entropy you witnessed by rolling dice or flipping coins.

No stronger phrasing is permitted anywhere — docs, UI, or marketing.

## What it does not add — "claimed," not "counted"

This is the idea that matters most, and it's the same distinction
`docs/machine-randomness.md` draws for EFI RNG, RDSEED, and RDRAND, now
extended to a fourth machine source:

- A USB TRNG's bytes are **CLAIMED / UNPROVEN**, exactly like RDSEED,
  EFI RNG, and RDRAND. They pass a catastrophic-failure health check
  (not a predictability proof) and are mixed into the transcript, but
  Alea never counts them toward the security floor.
- Only **witnessed** entropy — dice (2.585 bits/roll) and coins (1
  bit/flip), events the user physically performed and Alea observed —
  counts toward `SPEC.md` §17.2's floor inequality. Attaching a USB
  TRNG does not change that inequality by one bit. The dice/coin budget
  a user must satisfy in reinforced mode is **identical** whether or
  not a dongle is plugged in.
- There is no policy override for this. `SPEC_USB_TRNG.md` §8.2
  explicitly rejects any `counts_toward_floor` or
  `reviewed_floor_override` key as unknown — a floor a signed file
  could lower would not be a floor. This mirrors the absolute
  RDRAND-never-sole-source rule already enforced in `parser.rs`.
- A USB TRNG does **not** prove the dongle honest, does **not** prove
  the host honest (the bytes still cross a USB stack that could
  substitute them — see below), and does **not** establish that it is
  statistically independent of the machine's other sources. A shared
  USB controller, a shared power rail, or a shared adversary can
  correlate a "distinct" device with the host CPU's own sources; SPEC
  §19.3 makes no independence claim, and neither should any
  description of this feature.

If a malicious or merely defective dongle emits a predictable but
health-check-passing stream, **nothing on screen looks different**
(`SPEC.md` §18.2's machine-only warning applies here in full). That is
by design, not an oversight: Alea cannot inspect the inside of a sealed
USB device any more than it can inspect CPU silicon, and it does not
pretend otherwise.

## The §6/§7 attack-surface tension, and how it's resolved

`SPEC.md` §6 asks for a hardened, "no unknown peripherals" pre-boot
environment. Plugging in an active USB device is visibly in tension
with that posture, and this document does not paper over it. The
resolution `SPEC_USB_TRNG.md` §7.4 specifies has three parts:

1. **Identity allow-list, not trust-on-sight.** A device is read only
   if its exact `idVendor`/`idProduct` *and* interface class match a
   `[[usb_trng_devices]]` entry in the compiled-in policy. Everything else
   is never opened, never commanded, never mixed.
2. **Composite/HID refusal.** Any device also exposing an input
   interface — the BadUSB shape — is refused outright even if its
   VID/PID matches, because Alea will not attach an input-capable
   device during the ceremony.
3. **Explicit, honest user affirmation.** Attaching a TRNG is a
   deliberate act on a dedicated screen, phrased in the SPEC §22.2
   "these are your statements, Alea cannot verify them" style — it
   names the matched device and policy version, states plainly that
   Alea cannot verify the device is genuine, honest, or unaltered, and
   states that its output is not counted toward witnessed entropy.
   Declining leaves the session exactly as if nothing were attached.

What the allow-list actually buys is real but narrow: it mitigates an
**honest-but-unapproved** device (something that isn't on the list at
all) and a **composite BadUSB** device (refused by class). It does
**not** mitigate a **malicious device deliberately built to spoof an
approved identity** — VID/PID/class are declared values a counterfeit
device controls, and Alea has no way to challenge them. The allow-list
narrows which devices are even considered; it is not an authentication
mechanism, and no documentation should describe it as one.

A USB host stack is also, unavoidably, new trusted code and new attack
surface that a physical-only session does not have — DMA exposure of
USB peripherals falls under the existing `SPEC.md` §8.2/§38 residual DMA
risk, not a risk this feature reduces. The honest summary
(`SPEC_USB_TRNG.md` §12.2): a USB TRNG **cannot make a session worse
than physical-only** under the counted/claimed accounting above (its
bytes are claimed, mixed, and floor-neutral), but it **does** enlarge
the attack surface and the trusted base. That is a real trade the user
makes at the affirmation screen, not a free upgrade, and documentation
must present it as a trade.

## What's actually deferred (SPEC §7.4-blocked)

The transcript tag (`0x12`), the policy schema, the accounting rule, and
this document are all specified and frozen now so dependent work (parser
guards, the host-side test double, the educational-UI CLAIMED row) can
proceed without waiting. What is **not** built, and is explicitly out of
scope for this document and this work package, is the actual device
read: opening a USB endpoint, sending OneRNG's `cmdO`/`cmd0` sequence,
and pulling bytes off bulk-in. That depends on the application-owned USB
host stack `SPEC.md` §7.4 describes, which has not landed. Until it
does, "USB TRNG support" means the wire format and policy exist and are
tested against synthetic vectors — not that a real device can be read
by a shipped build. No documentation, release note, or UI text should
imply otherwise.

## Why the dongle is reinforcement, never a dice replacement

Restated plainly, because it is the single most common misreading: a
USB TRNG can only ever add a claimed, unproven, floor-neutral source to
the mix. It never substitutes for, discounts, or shrinks the
dice/coin requirement. "Strong if any one source was good" is a reason
to *also* attach a good dongle if you have one — it is never a reason
to roll fewer dice.

See also: `docs/machine-randomness.md` (the same counted/claimed
distinction for EFI RNG, RDSEED, and RDRAND), `docs/dice-and-coins.md`
(the witnessed floor itself), `SPEC_USB_TRNG.md` (the normative spec,
particularly §4, §6, §10, §12), and `SPEC_EDU_UI.md` (the educational
counted/claimed accounting panel, which renders the CLAIMED row this
feature contributes).
