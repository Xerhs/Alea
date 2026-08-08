# Quickstart: performing the Alea ceremony

This is a plain-language walkthrough of generating recovery words with
Alea, start to finish. It assumes no prior familiarity with the
project. It is deliberately slow — this is a ceremony you do rarely and
carefully, not software you rush.

Before you start: Alea is **experimental** (see `SECURITY.md`). If
this is your first time through, treat it as a rehearsal even on real
hardware, and follow step 11 (start small) regardless of how confident
you feel.

Every warning in this document is required by `SPEC.md` and appears
because a specific risk is real, not as legal decoration. None of them
are here to frighten you out of doing the ceremony — they are here so
you go in with accurate expectations.

---

## Before you begin: what you'll need

- A computer you are willing to boot into a pre-OS environment — a
  physical x86-64 PC (not a virtual machine, not a cloud instance),
  ideally one you don't rely on for anything else during this process.
- A blank USB stick, and a second computer to write it from.
- A real six-sided die and/or a real coin, if you plan to use physical
  entropy (recommended — see step 6).
- Something durable to write your words on — Alea never prints,
  photographs, exports or displays a QR code of anything secret, so a
  pen (and ideally a metal backup plate for long-term storage) is
  genuinely part of the toolkit. See `docs/backup-security.md`.
- A private room, free of cameras and onlookers, where you can complete
  the whole ceremony without being interrupted or leaving the machine
  unattended.
- Roughly 20–40 minutes of uninterrupted time, more the first time
  through.

---

## 1. Download and verify the release

Do not skip this. A hash shown on the same web page you downloaded the
image from proves nothing — if that source were compromised, the hash
would be tampered right alongside it.

1. Download the signed release, its detached signature, the published
   hashes, and the release notes from the project's official release
   location.
2. Check the project's signing-key fingerprint through **at least two
   independent channels** — not just the page you downloaded from.
3. Verify the release signature, ideally on a second device.
4. Confirm the release hasn't been revoked.

The full, precise version of this process — including exact commands —
is `VERIFYING-MEDIA.md`. Read it before doing this step for real; this
quickstart intentionally doesn't repeat every command here so there's
only one place that can go stale.

> **If your everyday computer might already be compromised, do this
> verification on a separate, dedicated device.** This ceremony raises
> the cost of an attack; it cannot turn a compromised machine into a
> trusted one.

## 2. Write the USB stick, then read it back

Write the complete disk image to your USB stick with a raw block-copy
tool (`dd`, Rufus in "DD image" mode, balenaEtcher — not drag-and-drop).
Then **read the entire thing back** and compare its hash against the
one you verified in step 1. This catches write errors, a bad stick, or
tampering that happened between verification and writing.

Once the hash matches, remove the USB stick from the computer you wrote
it on before you boot from it. If that computer is compromised, it could
otherwise modify the media in the gap between your hash check and the
boot.

Again: `VERIFYING-MEDIA.md` has the exact commands.

## 3. Rehearse first, on the desktop test edition

**Do this before your first real ceremony**, especially if any part of
steps 5–9 below is unfamiliar. The desktop test edition is a separate
program that runs on an ordinary Windows or Linux computer — it walks
you through the *exact same screens and controls* as the real thing,
but only ever with fixed, public, watermarked test entropy that can
never protect real funds. It's how you learn the keyboard controls, see
what the entropy-collection screen looks like, and practice the hidden
re-entry step, with zero risk.

- It's watermarked permanently, and every phrase it shows is prefixed
  `PUBLIC TEST PHRASE — NEVER USE WITH FUNDS`. That is correct and
  expected behavior, not a bug.
- **The desktop test edition can never generate a real mnemonic. Do not
  use anything it produces for an actual wallet, under any
  circumstances**, even if you can't tell it apart from the real thing
  by eye. See `README.md`'s "two editions" table and
  `SPEC.md` §4.3.
- It's distributed separately from the production USB image and never
  bundled with it — get it as its own download, or build it yourself
  (`cargo run -p seed-desktop-test`; see `README.md`).

Run through the whole flow once here. When you're comfortable with the
controls, move to the real ceremony.

## 4. Prepare the room and the machine

Before you boot the real thing, make sure:

- You're on a **physical computer**, not a VM — Alea will refuse
  to generate on an obvious virtual machine, and that refusal is
  intentional (`README.md`, `SPEC.md` §1.1, §11.2).
- It is **not** a corporate-managed or shared machine.
- The network cable is physically unplugged, and Wi-Fi/Bluetooth are
  disabled in firmware or by a physical switch if your machine has one.
- No known remote-management hardware (BMC, IPMI, Intel AMT, remote
  KVM) is active on it.
- The keyboard and monitor are directly, physically attached — no
  remote desktop, no KVM-over-IP, no serial console.
- No camera, capture device, or other person can see the screen during
  the secret portion of the ceremony.
- You have your dice/coins and your backup material within reach.
- You can complete the whole thing without stepping away from the
  machine, and can fully power the machine off afterward.

Alea can check some of this mechanically (and will refuse to
proceed if a check fails or is inconclusive) but not all of it — you'll
be asked to personally attest to the parts it can't verify, as a
three-item checklist on the opening **"Before we begin"** screen. Each
item takes its own keypress (`[1]`, `[2]`, `[3]`) and `[Enter]` stays
disabled until all three are ticked: these are *your* statements, not
something Alea can confirm. The software genuinely cannot see your room.

The application will also tell you, in its own words, before you go any
further:

> Physical dice and coins do not protect against malicious firmware
> that records your keystrokes or changes the program's execution. Use
> a machine whose firmware and physical environment you have reason to
> trust.

and, separately:

> Alea removes the normal operating system from the seed-
> generation process. It cannot prove that your firmware, processor,
> memory, input devices, display path or physical environment are
> trustworthy.

Both are true regardless of anything else in this document, and are not
specific to your machine — they apply to every Alea ceremony on
any hardware.

## 5. Boot the USB stick

Boot the machine from the USB stick (you may need to change a one-time
boot-device setting in firmware). Alea will:

1. Show its opening **"Before we begin"** screen: its warning and the
   same two statements from step 4, above the three-item checklist you
   tick with `[1]`, `[2]`, `[3]`.
2. Disable the firmware watchdog, check for signs of virtualization and
   remote console paths, and run its own cryptographic self-tests —
   these tick off on a brief checklist screen and need no keypress.
3. Show the display's resolution and device path and ask whether it is
   this machine's own physical display, offering a 34-key keyboard
   self-test on the same screen.

If anything mandatory fails or comes back inconclusive, generation is
disabled and you'll see why. That's the system working as designed, not
a malfunction to route around — see `SPEC.md` §11 for exactly what's
being checked and why an "inconclusive" result can't be waved through.

You'll then reach the setup screen, which carries the machine-checked
diagnostics recap (marked as such, with honest "not proof" wording where
a sophisticated attacker could spoof the check) alongside your choices —
starting with 12 or 24 words. 24 words gives more entropy, but 12 words
is a legitimate, standards-compliant choice: the interface will not tell
you 12 is unsafe, and neither should you assume it is.

## 6. Choose your entropy source, and roll dice or flip coins

You'll pick one of three modes: **machine source + physical entropy**
(recommended, when an approved machine source is available on your
hardware), **physical only**, or **machine only**. Physical-only is
always available if the earlier checks passed. Read
`docs/dice-and-coins.md` and `docs/machine-randomness.md` beforehand if
you want the full reasoning — the short version:

- **Combining sources is safe even if one turns out to be bad.** The
  math is set up so the final result is strong if *at least one*
  contributing source was good — a compromised machine RNG doesn't
  weaken a session that also has enough fair dice/coin entropy in it,
  and vice versa.
- **Machine-only mode cannot be witnessed.** If you choose it, you'll
  see this warning and are expected to take it seriously:

  > You are trusting this machine's random-number hardware completely.
  > You cannot witness or verify the quality of this entropy. If this
  > hardware is faulty or malicious, the resulting wallet is unsafe,
  > and nothing on this screen would look different.

- **Physical-only mode puts the weight entirely on your dice/coins and
  the machine's honesty**, and you'll see:

  > Security now depends entirely on the fairness and independence of
  > your rolls and flips and on the integrity of this computer's
  > firmware and execution.

If you're rolling dice or flipping coins: enter `1`–`6` for each die
roll, `H` or `T` for each coin flip, in whatever mix you like. You need
enough rolls/flips to clear a minimum entropy budget before you can
continue — the screen shows your live progress against both the
required minimum and a recommended margin above it (the margin exists
to absorb dice or coins that aren't perfectly fair). You can undo your
last entry or clear everything and start over. And the screen will
remind you:

> The number of rolls or flips does not prove that your dice or coins
> are fair or that the events are independent.

That's true, and it's why the recommended margin exists — take the
extra rolls if you have the time.

## 7. Final confirmation, then the words appear

Before anything irreversible happens, you'll see one last confirmation
screen listing what comes next: write every word down in exact order;
never photograph or print them; never type them into a connected
computer; anyone who has them controls the wallet; and that the re-entry
check coming up verifies what you *typed*, not the durability of your
paper or metal backup. Confirming here is the point of no return for
this boot — cancelling after this no longer returns you to the boot
menu, only to shutdown.

Your words then appear on screen, numbered, all at once, rendered
directly by the application (never through ordinary firmware text
output, and never as a QR code). **Write every word down by hand, in
order, right now**, before doing anything else. There is no timeout
forcing you to rush, but there's also no reason to linger once you've
transcribed them correctly.

## 8. Hide the words and type them all back in

When you're done writing, hide the display and begin re-entry. For each
word, in order, you'll type the first four letters (or the whole word,
if it's shorter than four letters) and press Enter — nothing you type
is ever echoed back to the screen, and there's no multiple-choice list
to pick from (multiple-choice would leak information and only tests
recognition, not that you actually transcribed the word correctly). If
a word doesn't match, you'll be offered to retry that position, reveal
the phrase again (this discards *all* progress and restarts re-entry
from word 1 after the screen is wiped again — no partial credit is
shown), or destroy the phrase and shut down.

Getting every single word to match is the whole point of this step —
take your time and don't guess.

Once every word matches, you'll see:

> **RE-ENTRY MATCHED**
> Every word you entered matched the generated mnemonic.

Read that sentence for exactly what it says. It means what you *typed*
matches what was generated — it does not, and cannot, mean Alea
inspected your paper or metal backup for legibility or durability.
Someone who had simply memorized the phrase would also pass this check.
The completion screen will also remind you: the durability and secrecy
of your physical backup is still entirely your responsibility, you
should restore this phrase on your actual signing device and check the
derivation values (next step) before trusting it, receiving addresses
should be independently confirmed, and a small test amount should
precede any substantial deposit. See `docs/re-entry.md` for the full
reasoning behind this design.

## 9. Check the derivation values against your signing device

After a full re-entry match, you can optionally view your wallet's
**master fingerprint** and its **first receive address** under each of
the four standard derivation paths (BIP44/49/84/86 — legacy, nested
segwit, native segwit and taproot). None of these values are secret keys
— they're safe to write down — but they do reveal where your funds will
eventually sit, so treat them with the same care you'd give any account
number.

Now restore the same words on your actual hardware signing device, and
compare:

- If the fingerprint and the relevant address(es) **match** what your
  signing device shows, it derived the same wallet this ceremony
  created. Good sign — proceed to step 11 (small test amount) before
  trusting it with anything larger.
- If they **do not match**: **stop.** Do not send funds. A mismatch
  means one of: you (or your device) used a passphrase (these values
  assume the empty passphrase — see `docs/passphrases.md`), your device
  used a different derivation path than you expected, or your device is
  faulty or compromised. Figure out which before proceeding.

`docs/derivation-verification.md` explains exactly what these values do
and don't prove, in more depth than fits here.

## 10. Scrub, shut down, and confirm it's actually off

Once you're done (whether you completed the ceremony or chose to
destroy the phrase early), Alea wipes what it can from memory and
the screen, and asks the firmware to shut the machine down completely —
this is not a reboot, and the application will never return you to a
menu or the boot manager after a mnemonic has existed on that boot.

**Confirm the machine is actually, completely off** — not asleep, not
in a fast-boot hibernation state, fully powered down — before you
consider the ceremony finished. If the automatic shutdown ever fails,
you'll see an on-screen instruction to hold the physical power button
until the machine is off, and not to boot anything else first; follow
it literally. Software zeroization and a shutdown request are best
effort, not proof that every trace has vanished from the machine's
memory the instant power state changes — a real, physical power-off is
part of the actual security model here, not a formality.

## 11. Store the backup, and start small

Put your written words somewhere that matches how much you're trusting
them with — see `docs/backup-security.md` for paper vs. metal, fire and
water exposure, theft, geographic separation, and why photographing or
cloud-syncing them defeats the entire point of this ceremony.

Then, **before moving significant funds**, send a small, disposable
test amount to the address you verified in step 9, confirm you can see
it and, ideally, confirm you can spend it from your signing device.
This is standard practice independent of Alea, and it's the
cheapest insurance available against a mistake anywhere earlier in this
process — including mistakes that have nothing to do with this project
at all.

---

## Using your Alea seed in any wallet

**The words are the whole wallet.** Alea gives you 12 or 24 words in the
standard **BIP39** format. That is the entire secret. Any wallet that
supports BIP39 — hardware wallets like Trezor, Ledger, Coldcard, or software
wallets like Sparrow, Electrum, BlueWallet — can restore it. There is no
Alea-specific, brand-specific, or type-specific seed. You did not generate
"a Ledger seed" or "a taproot seed" — you generated **a seed**, and every
wallet reads the same words.

**One seed, every address type — the wallet chooses.** From the same words,
your wallet can produce several address types at the same time:

| Type | Also called | First address looks like |
| --- | --- | --- |
| Legacy | BIP44 | `1…` |
| Nested SegWit | BIP49 | `3…` |
| Native SegWit (bech32) | BIP84 | `bc1q…` |
| Taproot | BIP86 | `bc1p…` |

Which one you see is **your wallet's choice** (its "derivation path"), made
when you restore or receive — it is **not** baked into the seed. Most modern
wallets default to Native SegWit or Taproot and let you switch. You never
have to pick a type in Alea, and picking one elsewhere never changes your
words.

**How to restore:** type the words into your wallet's "restore from
recovery phrase" screen. That is all — **no key file, no `xpub`, no export.**
Alea never writes a file and never gives you one to import; the words are
enough.

**Confirm before you fund.** Right after generating, Alea shows you a master
fingerprint and the first receiving address for each of the four types. When
you restore your words in your own wallet, check that it shows the **same**
fingerprint and address for the type it uses. If it matches, you have
restored the same wallet — send a small test amount first, then the rest.
If it does **not** match, stop: it usually means a passphrase is set, a
different derivation path is selected, or the device is faulty — never send
funds until it matches.

**One caveat — the passphrase.** The addresses Alea shows assume **no BIP39
passphrase**. A passphrase (sometimes called a "25th word") creates a
completely different wallet with different addresses. If you use one, your
wallet's addresses will not match Alea's preview — that is expected, and
only you can hold that passphrase.

---

## If you get stuck

- Every warning in this document is required and consistent with
  `SPEC.md`; if a screen says something that contradicts this
  quickstart, trust the screen and re-read `SPEC.md` — this document is
  meant to match it exactly, but `SPEC.md` is the source of truth.
- `docs/` has one focused document per topic (BIP39, UEFI trust, machine
  randomness, dice/coins, re-entry, derivation verification, backup
  security, passphrases, alternatives) if you want the reasoning behind
  any single step in more depth.
- If you're not sure your machine or environment is appropriate at all,
  re-read the "Who this is for" section of `README.md` and
  `docs/alternatives.md` — Alea refusing to run on your machine,
  or you deciding a signing device's built-in dice-roll generation suits
  you better, are both completely legitimate outcomes.
