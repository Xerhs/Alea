# UEFI trust: what pre-boot execution buys you, and what it doesn't

SPEC §34.2 requires this explained plainly: the normal OS is absent;
firmware remains active; firmware handles keyboard input, including
hidden re-entry; GOP rendering reduces ordinary console mirroring but
does not defeat malicious firmware or remote-management hardware; the
host is not a secure element; pre-boot DMA posture may be weaker than a
hardened OS. This document walks through each of those, and is the
fuller version of the summary in `SECURITY.md`.

## What "before the OS loads" actually removes

Alea runs as a UEFI application, before Windows, Linux or any
other general-purpose operating system is loaded. Concretely, this
removes an entire category of things that don't exist yet at that point
in the boot process: no installed applications, no browser or browser
extensions, no desktop clipboard service, no screen recorder, no OS swap
or hibernation file, no shell history or terminal scrollback, no crash
reporter, no cloud sync, no OS telemetry, no antivirus hooks, no
application auto-updater. Every one of those is a real, common vector
for secret leakage on a normal desktop, and none of them can touch a
process that hasn't started yet because the OS that would run it hasn't
loaded. This is the genuine, substantial value of the pre-boot approach,
and `SPEC.md` §7.1 and §8.1 list it in full.

## What's still trusted — because it has to be

Removing the OS does not remove everything. The workflow still, fully,
trusts: the UEFI firmware itself; firmware boot services; firmware
keyboard handling; firmware device-path reporting; graphics
initialization; the CPU and its microcode; memory initialization and
system RAM; DMA configuration; the display hardware and cable; the
physical keyboard; the removable-media controller; the compiled
Alea binary itself, the Rust compiler and its build dependencies;
the project's release-signing process; and your own verification and
storage procedures. If any of those is dishonest or compromised, nothing
below saves you. `SPEC.md` §7.2 is the authoritative list.

## The firmware input path: the trade-off you should actually understand

This is the single most important nuance in this document, and it is
easy to miss if you only skim the mnemonic display screen and assume
"application-controlled rendering" means "application-controlled
everything."

**Alea version 1 does not call `ExitBootServices` before running
the secret workflow.** It relies on firmware keyboard input services and
firmware shutdown services the entire time. Stated plainly, as
`SPEC.md` §7.3 requires:

> Firmware remains active through the complete secret workflow, and
> every keystroke of the hidden re-entry — which uniquely identifies
> every word of the mnemonic — passes through the firmware's keyboard
> stack. Malicious firmware does not need to scrape the framebuffer;
> the re-entry step hands it the seed.

Read that again: the *display* protections described below stop a
narrower class of observation than the *input* path exposes. If your
firmware is genuinely malicious, it can simply log every keystroke of
your hidden mnemonic re-entry and reconstruct your entire phrase,
without ever needing to capture a single pixel of the screen. The
application-controlled graphics path is real and valuable against
*passive* observation (ordinary firmware console mirroring, accidental
text leaking through a generic firmware text API), but it is not a
defense against firmware that is actively, deliberately malicious about
your keystrokes.

**Closing this gap is the headline security goal of version 2**: an
application-owned USB HID keyboard driver operating after
`ExitBootServices`, so the firmware's keyboard stack is no longer in the
path during the secret phase at all. Version 1 does not have this yet,
and no documentation should imply otherwise.

## What application-controlled graphics actually buys you

For the *display* side (as opposed to input), Alea renders the
mnemonic and derivation-verification screens directly into the selected
linear GOP framebuffer using an embedded bitmap font and fixed,
application-owned rendering routines — never firmware text output, never
a firmware `Blt()` call carrying secret pixels, never one concatenated
mnemonic string held anywhere in memory (`SPEC.md` §12.2). This reduces
the chance that ordinary firmware console-mirroring or logging paths
ever see your mnemonic text, and it's why Alea refuses to run at
all on a `PixelBltOnly` graphics adapter (one with no linear framebuffer,
where rendering would necessarily pass secret pixels through firmware
`Blt()` code — `SPEC.md` §11.4) rather than silently falling back to a
weaker path.

What it explicitly does **not** do: prevent framebuffer capture by
firmware that's actively malicious, prevent GPU- or BMC-level capture,
prevent an external capture device recording the physical display, or
defeat hardware-level display mirroring. `SPEC.md` §12.2 lists these as
things "the application cannot prevent" in so many words.

## This is not a secure element

A dedicated hardware wallet's secure element is purpose-built silicon
whose entire job is resisting extraction of key material even from
someone with physical possession of the device, typically with
tamper-resistant packaging and a minimal, audited firmware surface.
Alea runs on general-purpose PC firmware, on a general-purpose
CPU, with a general-purpose (if temporarily OS-less) execution
environment. It reduces the *software* attack surface substantially by
removing the desktop OS; it does not, and cannot, provide secure-element
guarantees about the underlying hardware and firmware. Nothing in this
project's documentation should ever describe it as "equivalent to a
hardware wallet" — that phrase is explicitly prohibited
(`SPEC.md` §2, `docs/prohibited-claims-checklist.md`).

## Pre-boot DMA posture: a real, specific regression

Modern operating systems with IOMMU/kernel DMA protection enabled can
defend memory against malicious DMA-capable peripherals — notably over
Thunderbolt — *better* than the pre-boot environment does. Alea
inherits whatever DMA configuration the firmware happens to provide at
boot time and has no way to configure or improve it itself. On
Thunderbolt-equipped hardware, this means the pre-boot environment can
genuinely be a **worse** position than a modern, hardened OS session
would be, in this one specific dimension. `SPEC.md` §8.2 requires this
stated honestly rather than glossed over, precisely because "removed the
OS" is easy to over-read as "improved on the OS in every way," and it
doesn't.

## The bottom line

Pre-boot execution is a genuine, substantial reduction in attack
surface against an enormous category of ordinary desktop-OS threats. It
is not a proof of platform trustworthiness, it does not close the
firmware input-path gap until version 2, and on some hardware it can
even be a step backward for DMA protection specifically. `SPEC.md` §2
requires documentation to distinguish reduction of attack surface,
evidence of what was booted, entropy quality, protection of secret
state, and backup durability as five separate claims — no single
mechanism, including "it's pre-boot," proves all five.
