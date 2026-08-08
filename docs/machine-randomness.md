# Machine randomness: EFI RNG, RDSEED, RDRAND, TPM, and why you can't watch it work

SPEC §34.3 requires this explained: EFI RNG; RDSEED; supplementary-only
RDRAND; CPU and firmware errata; health checks versus proof; lack of
guaranteed source independence; why machine-only mode cannot be
witnessed. This is the fuller version of the reasoning behind the
entropy-mode selection screen in `QUICKSTART.md` step 6.

## Every machine source is governed by one compiled-in policy, not by trust-on-sight

Alea never treats "this hardware feature is present" as "this
hardware feature is approved." Every machine entropy source is gated by
`entropy-policy.toml`, a compiled-in, versioned policy file shipped with each
release (`SPEC.md` §15) that defines: which source classes and specific
algorithm identifiers are approved at all; CPU vendor/family/model/
stepping rules; known-bad platform denylist entries; retry limits and
sample sizes; catastrophic-failure checks; and — critically — whether a
given source is allowed to be a *sole* source or only a *supplementary*
one. The application displays which policy version it used. Availability
never implies approval: the code checks the policy explicitly for every
source before using it (`crates/seed-protocol/src/policy/`,
`crates/seed-platform-x86/src/rng/`).

## The source classes

### `EFI_RNG_PROTOCOL` (the UEFI RNG protocol)

A standard UEFI protocol that firmware may expose, backed by whatever
hardware or algorithm the platform vendor implements behind it — which
varies. Alea may use it only for algorithms explicitly listed in
the current policy's allow-list (`SPEC.md` §15.1); as shipped, that
allow-list starts empty (`entropy-policy.toml`'s `[efi_rng]` section:
`approved = false`), meaning this source is not yet approved for any
algorithm until specific ones are reviewed and added. This is a
deliberate "unapproved by default" posture, not an oversight.

### 64-bit `RDSEED`

An x86-64 CPU instruction, on Intel and AMD parts that support it,
intended to draw directly from an on-die entropy source (as opposed to
`RDRAND`'s pseudorandom-generator-fed-by-that-source design — see
below). Alea's policy approves `RDSEED` and allows it to stand
alone as a sole machine source, subject to CPU vendor/family/model/
stepping rules and a denylist for specific known-bad combinations
(`SPEC.md` §15.2). The implementation checks the CPUID feature bit,
consults the policy's CPU rules, performs bounded retries per the
policy's retry limit, checks the carry flag after *every individual*
instruction execution (not just the batch), requires a minimum number of
successful values, and rejects results that are all-zero, all-`0xFF`, or
otherwise fail a basic sanity check — never silently substituting zeros
for a failed read (`SPEC.md` §15.2: "reject failed values rather than
substituting zero").

### `RDRAND`

A related x86-64 instruction, drawing from a pseudorandom generator
that is itself periodically reseeded from the same underlying hardware
source `RDSEED` exposes more directly. **`RDRAND` is supplementary-only
in version 1 — it is never a sole entropy source, by explicit policy and
by explicit product rule** (`SPEC.md` §3: "Treat `RDRAND` alone as an
approved version-1 machine source" is listed under things Alea
MUST NOT do; `entropy-policy.toml`'s `[rdrand]` section:
`sole_source_allowed = false`, `supplementary_only = true` — the policy
parser itself rejects a policy file that tries to set this any other
way). Its output may still be sampled and tagged into the transcript,
but it can never by itself make an otherwise-unsupported platform
"approved," and it is never described as independent from `RDSEED` or
the EFI RNG, because it draws from a related underlying source.

### TPM `GetRandom` (opt-in, ships policy-disabled)

The platform TPM — a discrete security chip on some boards, firmware
inside the CPU package (Intel PTT / AMD fTPM) on many others — exposes
its own random-number generator, and Alea can mix it in as an
**explicitly opt-in extra**: a "Machine extras" toggle on the setup
screen, default off. Both TPM 2.0 (via the TCG2 protocol) and the older
TPM 1.2 family are implemented, each behind its own policy section, and
the shipped policy disables both until the review process approves them
— availability is never approval, same as every other source here.

The honesty rules are unchanged and worth restating for this source in
particular: a TPM's output is claimed, not witnessed — it contributes
zero counted bits toward the physical-entropy floor. Alea cannot prove
whether the "TPM" answering is a separate chip or firmware pretending to
be one, so it never claims TPM output is independent of the CPU's own
sources. And a TPM 1.2 part is 2005-era silicon with an older RNG
design, which the ceremony's education panel says out loud rather than
hiding.

## Health checks are not proof

Alea's `RDSEED` handling performs real, structured checks — carry
flag per instruction, retry limits, minimum successful-value counts,
rejection of degenerate (all-zero/all-`0xFF`) output, CPU
vendor/family/model/stepping policy matching. These catch a meaningful
category of failures: a CPU that's out of entropy and returning garbage,
an instruction that silently fails, an obviously-broken result. **None
of this proves the underlying hardware entropy source is honest.** A
sophisticated hardware backdoor, or a deliberately weakened
implementation in specific microcode, can produce output that passes
every one of these checks while still being predictable to whoever
built the backdoor. This is why the CPU/microcode denylist exists at
all — it's an acknowledgment that specific known-bad combinations need
to be named and excluded, because a generic health check cannot catch
them.

## No claim of source independence

Even when Alea uses multiple machine sources together (say,
`EFI_RNG_PROTOCOL` plus `RDSEED` plus `RDRAND` as supplementary data),
it never claims these are *independent* sources of randomness in the
statistical sense. They may ultimately share the same underlying silicon
entropy source, the same firmware vendor's implementation choices, or
the same class of vulnerability. `SPEC.md` §3 explicitly prohibits
treating source availability as proof of source independence. What
combining machine and physical sources *does* buy you is covered next.

## Reinforced mode: why combining sources still helps, honestly

When you choose the recommended mode — machine source plus physical dice
and/or coins — Alea samples the machine source *first*, before
you start entering physical events, specifically so an honest
implementation cannot adapt its machine-source output based on what
you're about to roll or flip. Both source records then go into one
canonical, domain-separated SHA-256 transcript (`docs/dice-and-coins.md`,
`SPEC.md` §18.1, §19). The resulting property, stated exactly as the
spec states it:

> The final entropy is strong if *any one* contributing source was
> good. A backdoored RDSEED cannot weaken a session that also contains
> sufficient fair physical events, and vice versa.

This is a real, meaningful security property — it does not require you
to trust *both* sources, only that *at least one* of them was good — but
it is not the same claim as "the sources are statistically independent."
It's a much more modest and much more defensible claim, and it's the one
Alea actually makes.

## Machine-only mode: why it cannot be witnessed

If you choose machine-only entropy (available only when at least one
source is approved by the current policy to be a sole source — in
practice, `RDSEED` on an allowed CPU, as of this writing, since
`EFI_RNG_PROTOCOL` ships unapproved and `RDRAND` can never be sole), you
will see the source class, its algorithm identifier, the CPU/microcode
policy result, the policy version, and this required warning before you
can proceed:

> You are trusting this machine's random-number hardware completely.
> You cannot witness or verify the quality of this entropy. If this
> hardware is faulty or malicious, the resulting wallet is unsafe, and
> nothing on this screen would look different.

That last sentence is the crux of it: unlike a die roll, where you
watched the die land on a specific face and can independently judge
whether it seemed fair, there is no analogous act of witnessing for a
CPU instruction's internal entropy source. You are trusting the
hardware completely, and the screen looks identical whether that trust
is well-placed or not. This is exactly why physical entropy exists as an
option in this project at all, and why reinforced mode — where a bad
machine source alone still can't sink you — is the recommended default
whenever an approved machine source is present.

## No acceptable fallback

If no approved machine source is present on your hardware and you
decline physical entry, Alea stops generation entirely rather
than falling back to something weaker (`SPEC.md` §18.4). There is no
silent degraded mode anywhere in this design.
