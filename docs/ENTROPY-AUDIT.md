# Entropy integrity & RNG-robustness audit (Claude/Fable)

**Date:** 2026-08-08
**Auditor:** Anthropic **Claude Fable** reviewers (two independent passes, plus a
first corroborating pass by Claude Opus). This is an internal, **AI-assisted**
source-code audit — see *Provenance* — not a third-party or human professional
audit.
**Scope:** the entropy path only — collection → conditioning → BIP39 mnemonic →
seed → BIP32 derivation — plus the machine (hardware) entropy source.
**Method:** independent read-only source trace, verifying every claim against
code (not comments), confirming each asserted security property is pinned by a
non-vacuous test, and independently reproducing the frozen vectors with a
from-scratch Python verifier. Findings were **fixed and then re-audited to
closure** by the same process before this document was written.

> **Provenance — read this first.** This audit was performed by Anthropic
> Claude **Fable** models reading this repository (an earlier pass by Claude
> Opus reached the same "core chain is sound" conclusion but did not surface the
> findings below; the deeper Fable pass did). It is an **internal, AI-assisted**
> review. It does **not** satisfy `SPEC.md` §36's external-review gate and does
> not replace an independent professional/human security audit before this
> software protects substantial funds. Its value is a documented, cite-
> everything trace of the entropy path and a fix-and-re-audit record — treat it
> as one input, not a certification.

## Bottom line

The recovery seed is a **deterministic function of only the entropy the user
saw or created** (dice/coin events, plus machine sources in the modes that use
them) and a small set of fixed, declared, non-secret domain-separation
constants — independently reproduced byte-for-byte against a 23-case frozen
corpus — and the machine source is **fail-closed with no weak/PRNG fallback on
any path**. The audit found **one Medium and two Low findings; all were fixed,
and a re-audit confirmed closure with no regression** (one further ripple, N1,
was caught by the re-audit and also fixed). The single residual the audit cannot
remove — a CPU RNG biased so subtly it still passes the catastrophic checks — is
a hardware-trust limit, disclosed to the user before every generation and
backstopped by dice/coin entropy in Combined mode.

## Findings & their closure

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| **M-1** | Medium | A Back-then-recommit navigation path (introduced by the ceremony redesign's state merge) left machine-entropy records resident: choosing Combined, acquiring machine entropy, pressing Esc, then re-committing **Dice-only** folded the machine bytes into a "dice-only" seed. Never *weakened* the seed (all dice entropy present; the extra source shown on-screen) but broke the mode contract and made the seed **irreproducible from the dice transcript alone**. | **FIXED** — `machine_sources.scrub()` on every setup re-commit (`crates/seed-flow/src/flow_secret/driver.rs:462`); regression test drives the exact scenario and asserts mnemonic equality with a fresh dice-only run via the re-entry gate; mutation-verified. This also eliminated a secondary duplicate-tag fatal-abort. **Re-audited closed.** |
| **L2** | Low | MachineOnly at the 256-bit target fed exactly one RDSEED block to the seed; RDSEED already collects a second block for health checks, then discarded it → **zero over-collection margin** if RDSEED runs below full entropy. | **FIXED** — the RDSEED record now carries both blocks (block_a‖block_b, 512 raw bits → SHA-256), with both blocks still fully health-checked before inclusion; seed width unchanged (`crates/seed-platform-x86/src/rng/rdseed.rs`). Frozen vectors unaffected (they inject fixed sources, never live RDSEED). **Re-audited closed.** |
| **L1** | Low (dormant) | The EFI-RNG final production read was checked for degeneracy but not repeat-checked against its diagnostic reads (a replayed diagnostic block would pass). Dormant — EFI RNG ships unapproved. | **FIXED** — repeat-check added, fail-closed (`crates/seed-platform-x86/src/rng/efi_rng.rs`). **Re-audited closed.** |
| **N1** | Low (dormant) | *Caught by the re-audit of L2.* L2's raising of the shared `MAX_MACHINE_SOURCE_BYTES` (32→64) leaked into the EFI request length, growing the EFI record to 64 and silently disabling the just-added L1 check (32-byte diagnostic vs 64-byte read never compare equal). | **FIXED** — EFI request pinned to a dedicated `EFI_RNG_REQUEST_BYTES = 32` const (compile-asserted, regression-tested); USB clamp likewise decoupled to its own 32 ceiling; stale comments corrected. **Re-audited closed, no new ripple.** |

Commits (branch merged into `master`): M-1 scrub + test, L1, L2, N1/N2/N3. Every
fix ships with a non-vacuous test; the M-1 and L1/L2 fixes were mutation-checked
(removing the fix line makes the pinning test fail).

## A. Derivation integrity

The chain: dice/coin staging + machine records → canonical, domain-separated,
length-prefixed transcript (`"Alea/Entropy/v1\0"` + header of arch/bits/policy
version) → **single SHA-256** truncated to the 128/256-bit target → BIP39
(checksum = SHA256(entropy), 11-bit windowing, wordlist digest-pinned) → the
mnemonic; and, on demand for verification/export only, PBKDF2-HMAC-SHA512 (2048
iters) → BIP32.

Confirmed clean after fixes:

- **Every counted event is fed; nothing fed is uncounted** except machine
  sources, which are credited **zero** counted bits toward the security floor —
  honest and conservative, matching the on-screen composition panel.
- **Mode gating** is structural (single derivation path; the state machine only
  enters machine acquisition / physical collection for the modes that use them),
  and — with the M-1 fix — a re-committed mode always starts from a clean source
  set.
- **No hidden inputs.** No RNG, timestamp, environment/UEFI variable, or
  uninitialized read reaches the seed; the header constants are declared
  domain-separation, not entropy. The `ci.sh` §28 scan is a grep-based
  regression guard for the env/UEFI-variable/feature class — adequate given the
  code review and the no-alloc/fixed-buffer discipline, but a class-based guard,
  not a full dataflow proof.
- **Fail-closed floor.** An empty/zero-content source set is refused at the
  crypto boundary itself, before any hashing.
- **Determinism.** Reproduced bit-for-bit by an independent Python reference
  across a 23-case frozen corpus (transcript, entropy, indexes, words, seed,
  fingerprint, and all four first addresses); no floats, no map iteration, fixed
  buffers.
- **Scrub discipline.** Every intermediate is volatile-scrubbed (write + fence +
  verification read) immediately after use, on success and error paths, with
  `Drop` backstops.

## B. Machine (hardware) RNG robustness

Confirmed fail-closed on **every** branch — unavailable, unsupported,
denylisted, retry-exhausted, timed-out, broken-calibration-clock, all-zero,
all-0xFF, stuck-repeating, and RDRAND-alone — each terminating in an explicit
refusal or an `Err` that cannot become a seed. RDSEED (true random) is preferred;
its success/carry flag is honored on every draw and never substituted with zero;
CPUID is gated before any instruction; the denylist beats the allowlist and
unknown vendors default-deny; RDRAND can never stand alone (enforced at four
layers). ≥256 bits (now 512 raw, per L2) are SHA-256-conditioned. **No software
RNG, LCG, or timestamp-seed exists anywhere on the path** (verified by workspace
grep).

## The one residual you should understand

The audit cannot certify the physical correctness of the CPU's random-number
silicon. A hardware RNG that is subtly biased **yet still passes the catastrophic
checks** would yield a seed with less entropy than its bit-count implies, and no
software on that same CPU can detect it. Alea is explicit about this — it is the
substance of the §8.4/§16 warnings shown before generation — and it is why
**Combined mode** exists: your dice/coin entropy is the backstop that does not
depend on trusting the silicon. The L2 fix widens the raw-input margin but does
not remove this boundary. If you do not want to trust the CPU RNG at all, use
**Dice-only** or **Combined**.

## Informational notes (no change warranted)

1. `ci.sh` §28 is a grep-based, class-scoped regression guard, not a semantic
   dataflow proof — the code review and frozen-vector chain carry the
   "no hidden inputs" claim.
2. Independent seed reproduction must fix the declared header constants
   (architecture, target bit-length, entropy-policy version) as well as the
   dice/coin transcript — not "same dice → same seed" alone.
3. `efi_rng::sample` accepts a variable request length by design; the L1
   cross-boundary repeat-check is only non-vacuous at the pinned 32-byte length —
   which is compile-asserted, single-caller, and regression-tested. Dormant
   (EFI RNG unapproved) and guarded, so no change was warranted.
4. The scrub verification read is best-effort (single address space,
   `debug_assert`) — the strongest available in `no_std`; an integrity-neutral,
   display-side concern, already self-documented.
