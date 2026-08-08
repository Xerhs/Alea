# Prohibited-claims checklist for release notes and marketing copy

Use this before publishing any release notes, README changes, blog post,
social media copy, or other public description of Alea. It's
derived directly from `SPEC.md` §2 and §1.1, which are the authority
here — if this checklist and `SPEC.md` ever disagree, `SPEC.md` wins and
this file should be corrected.

## 1. Before stable-release gates are satisfied, this banner is mandatory

Every production-capable build must currently display, and any release
notes describing it should not contradict:

> **EXPERIMENTAL SECURITY SOFTWARE**
> This build has not completed the stable-release security gates. Do
> not use it to protect substantial funds.

Do not write release notes that undercut this — e.g. "now ready for
real funds," "production-grade," or similar language — while this
banner is still active in the shipped build. Check `SPEC.md` §36
(security review gates) before ever claiming the gates are satisfied.

## 2. The approved post-gates description (only once gates are actually satisfied)

Once, and only once, the stable-release gates in `SPEC.md` §36 are
genuinely satisfied, the approved public description is this exact
wording (do not paraphrase it into something stronger):

> Alea is a minimal open-source UEFI application for generating,
> re-entering and derivation-verifying BIP39 recovery words before the
> normal operating system loads. It supports physical dice and coin
> entropy, approved machine-randomness interfaces and reproducible
> release verification while clearly documenting the firmware, hardware
> and physical trust assumptions that remain.

## 3. The hard-prohibited phrase list (permanent — never usable, gates or no gates)

None of the following may ever appear in Alea documentation,
release notes or marketing, at any point, regardless of gate status
(`SPEC.md` §2):

- [ ] "Unhackable."
- [ ] "Trustless seed generation."
- [ ] "Equivalent to a hardware wallet."
- [ ] "Guaranteed true randomness."
- [ ] "Firmware cannot observe the seed."
- [ ] "Bare-metal security eliminates malware."
- [ ] "Military-grade."
- [ ] "Universal on every computer."
- [ ] "Works on any PC, like memtest."
- [ ] "Secure merely because Secure Boot is enabled."
- [ ] "The safest possible seed generator."

Before publishing, search your draft for close paraphrases of each of
these, not just the exact strings — "nothing can observe your seed,"
"runs on virtually any machine," and "the most secure option available"
are the same violations in different words.

## 4. The "not memtest for seeds" positioning (SPEC §1.1)

- [ ] Does the copy avoid implying memtest-like universal bootability or
      "works on everything"? Alea is specified to *refuse*
      virtualized platforms, remote-console paths, managed endpoints and
      unclassifiable hardware, by design — that refusal is a feature and
      should never be framed as a shortcoming to be apologized for.
- [ ] Is any compatibility/breadth claim sourced from the published
      compatibility methodology (`SPEC.md` §30), not an arbitrary
      convenience sample? The only form a stable compatibility claim may
      take is: "Alea completed the production workflow on X of Y
      independently reported systems across Z distinct hardware families
      under compatibility methodology version N." Raw percentages
      without that framing, or the word "universal," are both
      prohibited.
- [ ] Does the copy state plainly, where relevant, that users satisfied
      trusting their signing device's built-in seed generation do not
      need Alea, and that dice-roll generation on a dedicated
      signing device is a reasonable alternative (see
      `docs/alternatives.md`)? Positioning copy should never imply
      Alea is strictly superior to that choice.

## 5. The five things no single mechanism proves (SPEC §2)

`SPEC.md` §2 requires documentation to keep these five claims
*distinct* and never let one stand in for another:

- [ ] Reduction of attack surface.
- [ ] Evidence that the intended software was booted.
- [ ] Quality of entropy.
- [ ] Protection of secret state.
- [ ] Durability and correctness of the physical backup.

Before publishing, check that no sentence implies satisfying one of
these automatically satisfies another — e.g., "it's pre-boot, so your
entropy is safe" conflates attack-surface reduction with entropy
quality; "Secure Boot is enabled" conflates boot evidence with actual
firmware honesty; "re-entry matched" conflates re-entry verification
with physical-backup durability (see `docs/re-entry.md`).

## 6. Common conflation traps, spelled out

These aren't in the SPEC's literal prohibited-phrase list, but they're
the same errors in disguise and should be caught the same way:

- [ ] Confusing **hidden re-entry matching** with **the physical backup
      being verified as durable/legible/safe**. It isn't — see
      `docs/re-entry.md`. A memorized phrase passes re-entry too.
- [ ] Confusing **a machine-checked diagnostic passing** with **proof**.
      Machine-checked items are explicitly labeled as checks a
      deliberate adversary can spoof (`SPEC.md` §22.3) — "Passed"
      language alone, without that context, misrepresents them.
- [ ] Confusing **combining machine and physical entropy** with
      **statistically independent sources**. `SPEC.md` §3 prohibits
      treating source availability as proof of source independence; see
      `docs/machine-randomness.md`.
- [ ] Confusing **the derivation-verification screen matching** with
      **a guarantee of future correct restoration** beyond the displayed
      values (`SPEC.md` §38 residual-risk statement is explicit that this
      is not guaranteed beyond what was actually checked).
- [ ] Describing the desktop test edition's output, in any context, as
      real or usable — even loosely, even in a screenshot caption. See
      `README.md`'s two-editions table and `SPEC.md` §4.3.
- [ ] Implying `ExitBootServices` isolation or a closed firmware input
      path already exists in version 1. It does not — see
      `docs/uefi-trust.md` and `SPEC.md` §7.3. That is a version-2 goal,
      not a shipped property.

## 7. Addendum — compatibility/verification mode (`seed-compat`, `SPEC_COMPAT.md` §11.3)

This section covers `tools/compat-verify` and any documentation, UI text,
or marketing describing it. It is derived directly from
`SPEC_COMPAT.md` §4 and §11.3 — if this addendum and `SPEC_COMPAT.md`
ever disagree, `SPEC_COMPAT.md` wins. See `docs/compat-verification.md`
for the full explanation these checks are drawn from.

### 7.1 The only claim compatibility/verification mode is permitted to make

Copy describing a `compat-verify` match may say, and no more than, this
(`SPEC_COMPAT.md` §4.3):

> Given these exact events, this is the mnemonic that `<device>`'s
> **published algorithm** produces. If your `<device>` shows the same
> words, its dice/coin arithmetic matched for this input. This does not
> prove the device's firmware, secure element, or randomness are
> trustworthy.

A match is documented-preimage **arithmetic equality for the tested
input** — nothing else. Never let a sentence about a match stand in for
a broader trust claim.

### 7.2 The hard-prohibited phrase list for compat-verify (permanent, `SPEC_COMPAT.md` §11.3)

None of the following may ever appear in `compat-verify` documentation,
UI text, or marketing:

- [ ] "Verifies your Coldcard/SeedSigner is secure / not backdoored."
- [ ] "Proves your hardware wallet's firmware is honest."
- [ ] "Audits the device's secure element / random number generator."
- [ ] "Your device is safe because the words matched."
- [ ] "A compatible way to generate a wallet with Alea."
- [ ] "Alea and `<device>` generate the same seed" stated as a
      *feature* — they do not, by design (`SPEC_COMPAT.md` §1); domain
      separation is intentional, not a limitation to apologize for.
- [ ] "Independent verification of your seed's security."
- [ ] Any phrasing that presents a match as **device trust** rather than
      **documented-preimage arithmetic equality** (§7.1 above).

As with §3 above, search drafts for close paraphrases, not just the
exact strings — "confirms your Coldcard can be trusted" and "proves
your SeedSigner's randomness is good" are the same violations in
different words.

### 7.3 Conflation traps specific to compat-verify

- [ ] Confusing **a mnemonic match** with **firmware, secure-element, or
      supply-chain integrity**. A match only says the device's output
      matched the vendor's *published* algorithm for the *tested* input;
      it says nothing about what the device does on other inputs, and
      nothing about its hardware RNG, secure element, or provenance
      (`SPEC_COMPAT.md` §4.2).
- [ ] Confusing **a match** with **entropy quality**. A biased die
      produces a faithfully-derived weak seed on both tools; match is
      not a randomness-quality claim (see `docs/dice-and-coins.md`).
- [ ] Describing compat-verify as an "easier" or "compatible" way to
      make a wallet, or implying it is a shortcut alternative to a real
      device's own seed generation. It is an audit instrument for
      throwaway inputs only — never a generator (`SPEC_COMPAT.md` §2).
- [ ] Omitting the throwaway-seed warning when describing or
      demonstrating the tool. Any description of compat-verify's output
      — including screenshots — must make clear that entering the same
      rolls into two devices means **both** now hold the seed, and that
      compat-verify seeds must never be funded (`SPEC_COMPAT.md` §1,
      §7's watermark requirement).
- [ ] Implying `compat-verify` reproduces or supports Ian Coleman's
      *native* dice/base-6 mode ("Method B"). It does not — that mode is
      education-only in the current spec version, not an implemented
      target (`SPEC_COMPAT.md` §5.2, §3.2).
- [ ] Implying a `DerivedFromLength` profile (SeedSigner dice/coin) ever
      shows a phrase for a non-canonical roll/flip count. It refuses,
      by design — a rendered phrase for a count the real device would
      reject is a defect, not a feature, and must never be described as
      one (`SPEC_COMPAT.md` §6, review finding F1).
- [ ] Presenting `compat-verify` as available from, or safe to use
      alongside, the production UEFI ceremony. It is a separate
      reference/host tool only, structurally excluded from production
      and the UEFI test edition (`SPEC_COMPAT.md` §3, §9).

## 8. Addendum — USB TRNGs (`SPEC_USB_TRNG.md` §12.4)

This section covers any documentation, UI text, or marketing describing
USB hardware random number generator ("USB TRNG") support. It is
derived directly from `SPEC_USB_TRNG.md` §4.3 and §12.4 — if this
addendum and `SPEC_USB_TRNG.md` ever disagree, `SPEC_USB_TRNG.md` wins.
See `docs/usb-trng.md` for the full explanation these checks are drawn
from.

### 8.1 The only claim USB TRNG support is permitted to make

Copy describing an approved, attached USB TRNG may say, and no more
than, this (`SPEC_USB_TRNG.md` §4.3):

> An approved USB TRNG adds one more physically distinct source to the
> entropy mix. If it is honest and its data reaches Alea unaltered, it
> can only strengthen the result. Alea cannot prove that it is honest,
> cannot prove its data was unaltered, and does not count its output
> toward the entropy you witnessed by rolling dice or flipping coins.

### 8.2 The hard-prohibited phrase list for USB TRNGs (permanent, `SPEC_USB_TRNG.md` §12.4)

None of the following may ever appear in USB TRNG documentation, UI
text, or marketing:

- [ ] "Hardware true randomness" / "true random numbers" / "guaranteed
      entropy."
- [ ] "Unhackable entropy" / "unbreakable seed."
- [ ] "The dongle makes it secure" / "secure because you used a
      hardware RNG."
- [ ] "Proves your entropy is unpredictable" / "certified randomness."
- [ ] "The USB device is independent of your CPU/firmware" (source
      independence is never claimed; `SPEC_USB_TRNG.md` §19.3 reference).
- [ ] "A hardware TRNG replaces dice" / "no need to roll dice if a
      dongle is attached."
- [ ] "Alea verified the device is genuine/honest."
- [ ] Any presentation of a USB TRNG's bytes as *counted* entropy, or
      any single figure summing claimed and counted bits.

As with §3 above, search drafts for close paraphrases, not just the
exact strings — "cryptographically guaranteed randomness from the
dongle" and "you can skip rolling dice once you plug it in" are the
same violations in different words.

### 8.3 Conflation traps specific to USB TRNGs

- [ ] Confusing **the allow-list matching a device's declared
      VID/PID/class** with **verifying the device is genuine**. A
      counterfeit device can forge its declared identity; the allow-list
      mitigates honest-but-unapproved and composite/BadUSB devices, not
      a deliberately spoofed one (`SPEC_USB_TRNG.md` §7.4, §12.2).
- [ ] Confusing **a health check passing** with **a predictability
      proof**. Same trap as §6 above for machine sources generally — a
      malicious or defective dongle can pass every health check and
      still emit predictable, health-passing bytes, with nothing
      different on screen (`SPEC_USB_TRNG.md` §4.2, `SPEC.md` §18.2).
- [ ] Describing an attached USB TRNG as reducing, satisfying, or
      standing in for any part of the dice/coin witnessed-entropy
      budget. The budget is identical whether or not a dongle is
      attached, with no policy override (`SPEC_USB_TRNG.md` §10.2).
- [ ] Implying the USB device read path is shipped or usable in the
      current build. It is deferred, blocked on the SPEC §7.4
      application-owned USB host stack; only the transcript tag, policy
      schema, and accounting rule are specified and frozen today
      (`docs/usb-trng.md` "What's actually deferred").
- [ ] Presenting attaching a USB TRNG as consistent with, rather than in
      tension with, `SPEC.md` §6's "no unknown peripherals" hardening
      posture — it is a real, acknowledged trade (new trusted USB-stack
      code and attack surface) made explicit at a user-affirmation
      screen, not a free upgrade (`SPEC_USB_TRNG.md` §12.2, §7.4).

## 9. Final check before publishing

- [ ] Re-read the draft once specifically hunting for confident,
      unhedged security adjectives ("secure," "safe," "guaranteed,"
      "proven," "trusted," "verified") and confirm each one is scoped to
      exactly the claim `SPEC.md` supports, not a broader implication.
- [ ] If in doubt, quote `SPEC.md` §38's residual-risk statement
      verbatim rather than writing new summary language — it is the
      project's actual, reviewed ceiling on what can be claimed, and
      paraphrasing it is where scope creep tends to happen.
