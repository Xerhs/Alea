# Wipe-and-return-to-menu security audit (Claude/Fable + Opus)

**Date:** 2026-08-08
**Auditor:** Anthropic **Claude Fable** and **Claude Opus** reviewers, two
independent adversarial read-only passes over the final source. This is an
internal, **AI-assisted** source-code audit — see *Provenance* — not a
third-party or human professional audit.
**Scope:** the SPEC §26 amendment (2026-08-08) that lets the operator, after a
seed exists, choose to **wipe every secret and return to the launcher menu**
(`[M]`) as an alternative to the forced scrub-and-power-off (`[P]`/`[Enter]`).
The audit covers the two screens that offer the choice (the §22.7 destroy
confirmation and the Stage-7 Finish screen), the driver terminal that acts on
it, the scrub coverage, and the launcher control flow that resumes.
**Method:** independent source trace of the final state, verifying each asserted
security property against code (not comments), confirming each is pinned by a
non-vacuous test, and reproducing the workspace host suites and all three
`x86_64-unknown-uefi` builds.

> **Provenance — read this first.** This audit was performed by Anthropic Claude
> models (Fable and Opus) reading this repository. It is an **internal,
> AI-assisted** review. It does **not** satisfy `SPEC.md` §36's external-review
> gate and does not substitute for a professional human security audit before
> the software is trusted with material funds. It audits one feature, not the
> whole system.

---

## 1. The feature audited

After a mnemonic exists, the ceremony offers two ways to leave, at each of its
two deliberate end points (immediate destroy from the display screen, and the
Finish screen after re-entry/verification):

- **`[P]` / `[Enter]` — wipe and power off.** The original SPEC §26
  scrub-and-shutdown: run the ordered scrub, then `EfiResetShutdown`. Presented
  as the safest option, because power-off also lets DRAM decay.
- **`[M]` — wipe and return to the menu.** Run the *same* ordered scrub, plus
  additional scrubs of state that lives outside the secret arena, then return to
  the launcher landing menu for a fresh ceremony. A non-secret notice is shown
  first, advising the operator to power off for maximum safety.

The relaxed property is the previous invariant "no path after generation returns
to the menu; a second mnemonic requires a full shutdown and fresh boot"
(SPEC §21/§26 step 8). It is relaxed **only** for a deliberate operator choice,
and **only** after a complete scrub.

## 2. The property at stake

The forced power-off was a hardening measure: powering the machine off lets DRAM
decay, closing the cold-boot / DMA window against any secret residue. It was
never a secrecy requirement of the scrub itself — the scrub already zeroes every
secret on every terminal path. The audit therefore asks one question in several
forms: **does the `[M]` path leave any secret in RAM that the `[P]` path would
have erased, and can `[M]` ever be reached other than by a deliberate,
post-scrub operator choice?**

## 3. Security properties (final state)

### 3.1 Erasure before return is a strict superset of the power-off scrub

Before control returns to the menu, every secret-bearing buffer is
volatile-zeroed:

| Storage | Cleared by | Note |
|---|---|---|
| Whole secret arena — final entropy, BIP39 seed, master key, chain codes, mnemonic indexes, re-entry buffer, derivation scratch, committed passphrase, transcript, machine-source records | `shutdown::scrub_secrets` → `SecretArena::scrub_all` (volatile write + fence + verification read) | The identical §26 steps 1–6 the power-off path runs — single-sourced |
| Framebuffer / rendering buffers | `scrub_secrets` step 5 (`scrub_sequence`) | Direct-scanout linear framebuffer; the scrubbed memory is the displayed memory |
| Driver-local physical-staging (dice/coin) and machine-source acquisition buffers | Explicit `staging.scrub()` / `machine_sources.scrub()` on the menu path | These are stack locals, not arena fields; the power-off path leaves them to DRAM decay, the menu path clears them |
| Verification-display buffers — master fingerprint and up to 400 pre-derived addresses (`ExtendedVerificationValues` and its `base_values` copy) | `ExtendedVerificationValues::scrub` / `VerificationValues::scrub`, called on **every** exit from the verification screen | Wallet-identifying, though not key material; cleared on the power-off path too (defensive) |

The scrub the `[M]` path performs is thus a superset of the `[P]` scrub: nothing
the power-off path zeroes is skipped, and the menu path additionally clears the
non-arena buffers power-off left to decay.

### 3.2 Error and fault paths always power off

The driver terminal is split into two structurally separate arms. The **clean**
arm (the scrub states reached only from `DestroyConfirmed` or
`EducationAcknowledged`) is the *only* place the operator's menu choice is
consulted. The **fatal** arm (the SPEC §21 fault chain and the §26
shutdown-failure halt) unconditionally calls `scrub_and_shutdown` and never reads
the menu flag. Every post-secret fault, illegal event, timeout, or
watchdog-reassert failure routes into the fatal arm and powers off — SPEC §27.2
is preserved. A menu choice cannot divert a fault away from power-off, because
the fatal arm cannot observe the choice.

### 3.3 Menu-return is gated on an explicit operator action only

The `return_to_menu` flag defaults to "power off" and is set to "menu" at exactly
two sites, both an explicit `[M]` keystroke (the destroy confirmation and the
Finish screen). No error, fault, timeout, or default path sets it. A bare
`[Enter]` no longer destroys at the confirmation screen — an explicit `[M]` or
`[P]` is required — so a stray keystroke cannot wipe the phrase.

### 3.4 Single-sourced scrub

The ordered scrub (SPEC §26 steps 1–6) lives in one function, `scrub_secrets`,
called by both `scrub_and_shutdown` (which then requests power-off) and the menu
path. The two exits cannot drift: any change to the scrub applies to both.

### 3.5 Fresh state on return

Returning to the menu re-enters the launcher's session loop, which re-runs every
SPEC §11 mandatory gate from the top and constructs a fresh state machine and a
fresh secret arena for the next ceremony. No secret or ceremony state crosses the
loop boundary; the panic-scrub registration is balanced per ceremony. The
relaxation of SPEC §21 is only "a complete scrub and a fresh ceremony", never
redisplay or reuse of a destroyed secret.

### 3.6 Best-effort erasure of transient derivation stack

Immediately before returning, the menu path runs a bounded, volatile-zeroed
sweep of the recently-freed ceremony stack, sized well within the UEFI-guaranteed
stack (peak use ≈ half the guaranteed floor) so it cannot overflow, and placed so
it overlaps the frames the derivation leaf calls used. This overwrites the bulk
of transient secret residue (e.g. HMAC key-schedule copies) that addressable
buffer scrubs cannot name.

## 4. Residual risk (accepted and disclosed)

Zeroing every *addressable* buffer, plus the best-effort stack sweep, cannot
guarantee erasing values that only ever lived in CPU registers, spills beyond the
swept window, or firmware-owned input/console buffers. Because the `[M]` path
leaves the machine powered, this residue is not erased by DRAM decay. This is the
irreducible cost of not power-cycling, and it is handled honestly rather than
hidden:

- **`[P]` power-off remains the only complete erasure** and is presented as the
  safest exit.
- The post-destroy notice tells the operator secrets were wiped from memory and
  advises powering the machine off before leaving it unattended.
- SPEC §26 records the residual, its mechanism, and this trade-off explicitly.

The risk is therefore operator-controlled and disclosed at the moment it applies
— never silent.

## 5. Verdict

The feature relaxes exactly one property — the forced power-off — and closes it
with an in-memory scrub that is a strict superset of the power-off scrub, gated
by a structural terminal split so that no error path can ever reach the menu
return, and single-sourced so the two exits cannot diverge. Fresh ceremony state
is constructed on return, with no secret crossing the loop boundary. The sole
remaining exposure is transient stack/register/firmware residue that only a power
cycle can erase; it is mitigated best-effort, disclosed in the SPEC and on
screen, and left to the operator's explicit choice. No unresolved leakage or
invariant violation was found in the final state.

## 6. Methodology and coverage

- Two independent adversarial passes (Claude Fable and Claude Opus), each tracing
  secret lifetime, the terminal control flow, and the launcher loop against code.
- Every asserted property above is pinned by a non-vacuous test, including: the
  menu path returns without any shutdown request and with the full scrub sequence
  recorded; the scrub sequence order; the verification-display buffers zero every
  byte (not just length); the confirmation screen ignores a bare `[Enter]`.
- Workspace host suites pass; all three `x86_64-unknown-uefi` targets build; the
  production payload passes the SPEC §28 binary-policy scan.
