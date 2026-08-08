# Backup security: keeping your words alive longer than a screen ever will

SPEC §34.7 requires this explained: paper versus metal; fire and water;
theft; geographic separation; photography and cloud sync; inheritance;
restoration testing; derivation and wallet metadata. Alea never
prints, exports, photographs, QR-encodes or digitally stores your words
in any form (`SPEC.md` §25) — the physical record you make by hand
during the ceremony is, deliberately, the *only* copy that exists once
the machine shuts down. This document is about keeping that copy safe
for as long as you need it to last, which for most people is decades.

## Paper versus metal

**Paper** is what you'll use during the ceremony itself — it's what's
actually available to write on when your words appear. It is a
completely reasonable *starting point*, but it has real, well-known
weaknesses for anything you intend to rely on for years: it burns
easily, water and humidity degrade it, ink fades, and ordinary paper
physically decays over long timeframes even under good conditions.

**Metal backup plates** (purpose-made steel or titanium plates you
stamp or engrave your words into, or various commercial products built
for this) are substantially more resistant to fire, water and time than
paper, at the cost of being slower to prepare and needing to be
purchased or made in advance. If you're protecting anything beyond a
small, disposable amount long-term, converting your paper backup to a
metal one — carefully, in the same kind of private, unobserved
environment you used for the original ceremony — is worth the effort.
Do this as a deliberate follow-up step, not by trying to improvise
metal engraving during the ceremony itself.

Whichever medium you use, legibility over the full expected storage
lifetime is what actually matters — a beautifully engraved plate that
uses ambiguous handwriting-lookalike characters, or paper written in
fading pencil, both fail the same way eventually: someone (possibly you,
years from now) can no longer read the words correctly.

## Fire and water

Treat both as near-certainties over a long enough time horizon rather
than remote possibilities. A single copy stored in one place, however
well protected that place seems today, is a single point of failure
against a house fire, a flood, or any other localized disaster. This is
one of the reasons geographic separation (below) matters as much as the
medium itself — a fireproof safe in a house that burns down along with
everything inside it doesn't help if the safe itself wasn't rated for
that specific fire's duration and temperature, and even a rated safe is
one bad day away from being the only copy that existed.

## Theft

Anyone who has your words controls the wallet — Alea's own final
confirmation screen says this in exactly those words before you ever see
your mnemonic (`SPEC.md` §22.6). Store your backup somewhere a casual
intruder, a houseguest, a contractor working in your home, or a
determined thief specifically looking for it would not find it
incidentally. "Obviously a safe" is not automatically "actually
inconvenient to steal" — consider both discretion (does it look like
nothing in particular) and physical security (can it actually resist
being taken) as separate properties.

## Geographic separation

A single storage location is a single point of failure against fire,
flood, theft, and simple bad luck all at once. If the amount you're
protecting justifies it, consider splitting your storage across more
than one physical location — while being honest with yourself that this
also means more places something could go wrong or be found. There's a
real tension here between resilience (more copies, more places) and
exposure (more copies, more chances one is compromised); there's no
single right answer, only a trade-off you should make deliberately
rather than by default in either direction.

## Photography and cloud sync: the thing to actively avoid

**Never photograph your recovery words, and never let anything you
photograph or type near them sync to a cloud service.** This deserves
its own heading because it's the single most common way a carefully
executed ceremony gets undone afterward — not by a flaw in Alea,
but by an ordinary phone camera with cloud backup quietly turned on by
default. A photo of your words sitting on a desk, taken "just in case,"
uploaded automatically to cloud photo storage, defeats every protection
this project's pre-boot, no-export, no-clipboard design provides,
instantly and often without the person even realizing it happened. The
same applies to typing your words into a note-taking app, a password
manager, a text message, or any other device or service with any
network connectivity, ever — Alea's final confirmation screen
tells you this explicitly (do not photograph or print the words; do not
enter them into a connected computer), and it applies for the rest of
the backup's life, not just during the ceremony.

## Inheritance

A backup no one but you can find or use is, from an estate-planning
perspective, close to the same outcome as losing it yourself — the
funds become permanently inaccessible the moment you're not available to
retrieve them. If this wallet matters enough to protect carefully, it
matters enough to have a plan for who else needs to know it exists and
how they'll be able to access it when the time comes, balanced against
not giving that access away prematurely. This is a genuinely hard,
personal problem with no universal answer (options range from a sealed
instruction left with an attorney, to multi-location splits with trusted
family members, to formal multi-signature setups outside Alea's
scope entirely) — the only wrong answer is not thinking about it at all.

## Restoration testing

`QUICKSTART.md` step 11 and `docs/re-entry.md`/`docs/derivation-
verification.md` all point at the same underlying practice: **test that
your backup actually works before you rely on it.** Restore the words on
your actual signing device, confirm the derivation values match
(`docs/derivation-verification.md`), and send a small, disposable test
amount before depositing anything substantial. This catches transcription
mistakes, illegible handwriting, and misunderstandings about your
device's settings while the cost of being wrong is small, rather than
discovering a problem only when you actually need the backup years later
and the amount at stake is much larger.

## Derivation and wallet metadata: back up more than just the words

As `docs/bip39.md` explains, the same 24 words can describe wildly
different wallets depending on passphrase, derivation path and script
type. If you use anything other than the plain default (an empty
passphrase, and whichever single derivation standard you settled on
after checking `docs/derivation-verification.md`), **write that down
too, separately, alongside — or deliberately apart from — the words
themselves.** A future restoration attempt that has the correct words
but the wrong passphrase or path will not error out; it will silently
produce a different, empty-looking wallet (`docs/passphrases.md`). The
words alone are not a complete backup if any part of how you derived a
wallet from them isn't a well-known default you're confident you (or
whoever restores this after you) will remember correctly.
