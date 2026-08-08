# Pre-release audit triage report

**Date:** 2026-08-04
**Triaged by:** pre-release audit triage lead, consolidating five specialized
auditor passes into one ranked, independently re-verified report.
**Status of this document:** this is a triage/consolidation report, not a
`SPEC.md` §36.2 gate-status document — see `docs/AUDIT-STATUS.md` for that.
Nothing below changes any row of `AUDIT-STATUS.md`'s gate table by itself;
where a finding bears on a §36.2 gate, that relationship is called out
explicitly, but the gate table itself is only updated by the process
`AUDIT-STATUS.md` §"Revision history" describes.

## Scope audited

Five auditors each ran one dimension against the production seed-generation
path and returned confirmed findings:

1. Security audit — production seed path (secret lifecycle, entropy
   handling, fail-closed behavior, unsafe soundness, crypto validity,
   dependencies).
2. Error handling and fail-closed discipline (silent-failure / swallowed-
   error hunt) on the production seed path.
3. Type design — invariant strength, expression and encapsulation of
   secret-bearing and secret-gating types (SPEC §13, §20.2/§20.3, §27.2).
4. Test coverage on the production seed path.
5. Comment/doc SPEC-citation accuracy and prohibited-claims/overclaim
   conformance.

Files touched by the underlying findings: `crates/seed-core/src/pipeline/
mod.rs`, `crates/seed-core/src/arena/mod.rs`, `crates/seed-core/src/
contracts.rs`, `crates/seed-derive/src/curve/mod.rs`, `crates/seed-uefi-
test/flow/src/flow_secret/{machine,reentry,derive,driver}.rs`, `crates/
seed-uefi-production/src/main.rs`, `crates/seed-platform-x86/src/rng/
raw.rs`, `crates/seed-protocol/src/transcript/mod.rs`, `crates/seed-compat/
src/lib.rs`, `docs/machine-randomness.md`, `README.md`.

This triage did **not** re-run the workspace test suite or rebuild the UEFI
binaries; every finding below was re-verified by reading the cited source
directly against the auditor's claim (line numbers, surrounding logic, and
where relevant the exact `SPEC.md` section text). All 15 raw findings held
up under that re-read — **0 were dropped as false positives.** Two findings
(both auditor set #1 and #2 hitting `pipeline/mod.rs:173`) are the same
root cause reported independently and are merged into one row below (noted
in the table).

## Ranked findings

Ranked by real release impact for a Bitcoin seed generator: live
secret-handling defects first, then fail-open/spec-conformance gaps with no
live trigger today, then hardening/test-coverage/documentation items.

| Rank | Severity | File:line | Finding | Owner (crate) | Live today? |
| --- | --- | --- | --- | --- | --- |
| 1 | **High** | `crates/seed-core/src/contracts.rs:53-61` | `PrefixResult::Unique(u16)` carries a live secret BIP39 index and derives `Debug, Clone, Copy, PartialEq, Eq`; the same file's own header (lines 14-17) falsely claims no type in the file is secret-bearing. | seed-core | Yes — the type is live on the production hidden-re-entry path today, gated only by convention (`#[deprecated]` + two `#[allow(deprecated)]` sites), not by the type system. |
| 2 | Medium (catastrophic if triggered) | `crates/seed-core/src/pipeline/mod.rs:173` (+ `crates/seed-uefi-test/flow/src/flow_secret/derive.rs:90-127`) | `derive_final_entropy`/`derive()` has no minimum-entropy-source floor: an empty or too-small `sources` slice still produces a "valid" mnemonic — for zero sources, a fixed, publicly-computable seed. **Merged duplicate:** reported independently by both the security auditor and the fail-closed auditor. | seed-core (+ seed-uefi-test/flow as caller) | Not reachable today — upstream state-machine gates (`PhysicalBudgetMet`, machine-acquire-success) block an empty source set before this function is ever called. The gap is that the crypto boundary itself has no self-check; a future refactor of the gating logic could silently reopen it. |
| 3 | Medium | `crates/seed-uefi-test/flow/src/flow_secret/machine.rs:161-230` | `assemble_acquired_sources` treats any primary-source success (`efi_rng` OR `rdseed`) as sufficient for `MachineOnly` mode, without re-checking that the specific succeeding source is itself sole-source-approved under the compiled-in policy (SPEC §18.2 requires sole-source approval specifically for machine-only). | seed-uefi-test (flow) | Not live under the shipped `entropy-policy.toml` (only `rdseed` is both approved and sole; `efi_rng` is `approved=false`). Becomes live only if a future compiled-in policy approves `efi_rng` as approved-but-not-sole while `rdseed` stays sole. |
| 4 | Medium | `crates/seed-core/src/contracts.rs:127-141` | `AddressBuf` exposes public `bytes: [u8; 92]` / `len: u8` with no validating constructor or accessor; nothing stops constructing `len > 92`, which panics the post-secret wallet-verification-display slice read. | seed-core | Not live — every current constructor (bech32/base58 encoders) guards `total_len > 92` before setting `len`. Enforced by convention only. |
| 5 | Medium | `crates/seed-compat/src/lib.rs:286-303` | `CompatOutput` derives `Debug, Clone, Copy, PartialEq, Eq` while carrying `mnemonic_indexes: [u16; 24]` — a real user mnemonic in the tool's primary (device-reproduction) use case. Same defect class as #1, with no scrub/`Drop`. | **seed-compat — DO NOT EDIT.** Auditor-flagged as owned by another in-flight agent finalizing this crate; listed here for that agent's/the orchestrator's attention only. | Yes, in the tool's primary use case. |
| 6 | Low | `crates/seed-uefi-production/src/main.rs:191-198` (+ `flow_secret/driver.rs:296`) | Production `#[panic_handler]` halts with no secret scrub; `panic=abort` skips `Drop`, and `driver.rs:296`'s `word_count.expect(...)` on the post-secret `DerivationVerificationDisplay` arm is a genuinely reachable-by-invariant-violation post-secret panic site. | seed-uefi-production (handler) / seed-uefi-test flow (expect site) | Only reachable via an invariant violation (a state-machine bug), not by any known input today. Acknowledged residual per SPEC §20.1. |
| 7 | Low | `crates/seed-core/src/pipeline/mod.rs:216-224` | `derive_final_entropy`'s `Bip39` error branch returns via `?` before `scrub_local(&mut entropy_local)`, leaving an unscrubbed stack copy of final entropy on that path; branch has no test. | seed-core | Not reachable in practice — `entropy_to_indexes` only errors on a length outside `{16,32}`, and this function always passes 16 or 32. |
| 8 | Low | `crates/seed-core/src/arena/mod.rs:373-401` (+ `bip39/mod.rs:386`, `pipeline/mod.rs:342-376`) | `scrub_bytes`'s volatile verification read-back only feeds a `debug_assert_eq!`, which is compiled out under the shipped `[profile.release]`; a failed scrub is undetectable in production. | seed-core | Always true in the shipped profile — but the volatile *write* (the real guarantee) is unaffected; this only weakens the self-check. Within SPEC §20.3's documented "best-effort ... where practical" latitude. |
| 9 | Low | `crates/seed-uefi-test/flow/src/flow_secret/reentry.rs:106-110` | `scrub_u16` (secret resolved word index) uses only a volatile write + `compiler_fence`, omitting the architecture memory fence and verification read-back that `arena::scrub_slice` (used two lines earlier in the same function) provides. | seed-uefi-test (flow) | Yes, every hidden re-entry — but low practical exposure (single stack `u16`, immediately followed by return). |
| 10 | Low | `crates/seed-derive/src/curve/mod.rs:51-208, 363` | `ckd_scalar_add`'s `*il_scalar + *k_par_scalar` is a compiler-visible `Copy` of a secret scalar before it's moved into `Zeroizing`; `Zeroizing` cannot reach that codegen-level copy. | seed-derive | Already self-documented as a known, reviewed residual with an assembly-review note in the module header; auditor states no action is strictly required beyond what's already tracked. |
| 11 | Low | `crates/seed-platform-x86/src/rng/raw.rs:150-230` | Every failure-path test uses `RawSample{value:0, success:false}`; none pins that rejection keys off the carry flag rather than `value != 0`, so a regression to a `value`-keyed check would pass all existing tests. | seed-platform-x86 | Test-coverage gap only; production code correctly reads `success` (the carry flag), confirmed by inspection. |
| 12 | Low | `crates/seed-protocol/src/transcript/mod.rs:560-566` | `decode`'s `record_count > MAX_SOURCE_RECORDS` rejection (`TooManyRecords`) has no wire-byte KAT, unlike every other `decode` rejection reason; confirmed unreachable via the *encoder* (only 5 tags exist today, matching `MAX_SOURCE_RECORDS`) but still parses an attacker-controllable header byte on `decode`. | seed-protocol | Test-coverage gap only. |
| 13 | Low | `docs/machine-randomness.md:51` | Cites `SPEC.md §16, §37` as the verbatim source of `"zero-substitution is forbidden"`; neither section contains that phrase (actual source: §15.2, `"reject failed values rather than substituting zero"`) — confirmed by direct grep against `SPEC.md`. | docs | Doc-accuracy only; the underlying technical claim is true and correctly implemented. |
| 14 | Low | `README.md:185` | Repo-map line for `tests/vectors/frozen/` cites `SPEC §16` ("Machine-source health checks"); the correct citation is `SPEC §29.2` ("Cross-implementation tests") — confirmed against both section headers in `SPEC.md`. | docs | Doc-accuracy only; the primary trust document for a soon-to-be-public project. |

**Total unique findings after dedup: 14** (from 15 raw auditor findings; 1
pair merged as the same root cause). **0 dropped as false positives** — all
14 held up on independent re-read of the cited code and, where a SPEC quote
was involved, against `SPEC.md` itself.

## Must fix / should fix / nice-to-have

### MUST fix before public release

These are the two findings where the cost of a fix is trivial relative to
the consequence of the underlying defect ever firing, on a tool whose
entire purpose is generating a real Bitcoin wallet's root secret.

1. **`PrefixResult::Unique(u16)` secret-in-derive (contracts.rs:53-61).**
   Split the secret-carrying `Unique` variant into a dedicated non-Copy,
   non-Debug, non-Eq newtype (or drop those derives from `PrefixResult`
   entirely and route all secret resolution exclusively through the
   already-existing `resolve_prefix_into`/`PrefixOutcome` path, then retire
   `resolve_prefix`). Separately, fix the false claim in the file's own
   header ("None of the types below are themselves secret-bearing") so it
   stops contradicting the type it sits four lines above.
   **Owner:** seed-core (orchestrator-level — `contracts.rs` is a frozen
   contract file, not a leaf work package's to change unilaterally).
   **§36.2 relation:** gate 7 ("at least one external review of the
   entropy, derivation and secret-lifecycle design with published
   findings") — an external secret-lifecycle reviewer would flag this
   immediately; fixing it now removes a finding that gate's eventual
   review would otherwise surface. Also bears on gate 5 in spirit (no
   post-secret path should expose secret material through an
   easily-misused type), though the re-entry index isn't itself a modeled
   fault-injection scenario today.

2. **Missing fail-closed entropy floor at the derivation boundary
   (`pipeline/mod.rs:173`, `flow_secret/derive.rs:90-127`).** Add an
   explicit, independent check inside `derive_final_entropy` (or its
   `derive()` caller) that rejects an empty or entropy-insufficient source
   set before hashing, rather than relying solely on upstream
   state-machine gates. This is defense-in-depth for the single point of
   failure whose silent breakage produces a deterministic, attacker-known
   seed — the worst possible failure mode for this product, currently
   caught only by callers several layers away from the actual crypto step.
   **Owner:** seed-core (`derive_final_entropy`) with a corresponding
   caller-side check or propagated error in seed-uefi-test's
   `flow_secret::derive` and any other integration crate that calls it.
   **§36.2 relation:** gate 7 (entropy/derivation design review) — this is
   exactly the class of defense-in-depth gap a funded external entropy
   review is meant to catch; fixing it preemptively strengthens the case
   for that review when it happens. Not gate 5 today (no post-secret path
   is affected — this fires, if ever, before secret creation).

### Should fix (before the project treats itself as ready for real funds,
even under the experimental label)

3. **MachineOnly sole-source gate (`flow_secret/machine.rs:161-230`).**
   Thread the sole-source requirement into acquisition itself: when the
   selected mode is `MachineOnly`, require that at least one *acquired*
   source is sole-source-approved under the compiled-in policy, not merely that
   "a primary succeeded." Fail closed (pre-secret exit) otherwise. Not
   urgent under the shipped policy (only `rdseed` qualifies as
   approved+sole today), but a future compiled-in policy change could
   silently reopen SPEC §18.2 non-conformance with nothing visibly
   different on screen. **Owner:** seed-uefi-test (flow_secret). **§36.2
   relation:** gate 7 (entropy design review would need to re-derive this
   from the policy file each time absent a code-level guard).

4. **`AddressBuf` encapsulation (`contracts.rs:127-141`).** Make `bytes`/
   `len` private; add a checked constructor and an `as_bytes()`/`as_str()`
   accessor that validates `len <= 92` once, at construction. Removes a
   panic-on-display class entirely rather than relying on every
   constructor getting it right by convention. **Owner:** seed-core
   (orchestrator-level, frozen contract). **§36.2 relation:** gate 5
   (fault-injection: no modeled post-secret failure may crash/expose —
   this is the one post-secret display panic surface not yet made
   type-safe).

5. **Panic-handler scrub gap (`seed-uefi-production/src/main.rs:191-198`)
   and the post-secret `.expect()` sites feeding it
   (`flow_secret/driver.rs:296`, `:177`, `:209`).** Have the panic handler
   perform a best-effort volatile scrub of the secret arena and blank the
   framebuffer before `halt_forever()` (emitting no secret-bearing text,
   per SPEC §20.4/§27.3); and/or replace the reachable post-secret
   `.expect()` invariant checks with explicit `Event::Fault` transitions
   into the existing ordered scrub-and-shutdown chain. **Owner:**
   seed-uefi-production (handler) + seed-uefi-test/flow (driver.rs call
   sites — shared-file coordination needed since the handler lives in one
   crate and the reachable panic sites in another). **§36.2 relation:**
   gate 5 directly — this is precisely "no modeled post-secret failure
   exposes secrets," and a panic is exactly the failure mode
   `AUDIT-STATUS.md` row 5 (currently **Met**) says the fault-injection
   suite already covers for *recoverable* errors; this closes the gap for
   the *unrecoverable* (panic) case that suite doesn't reach.

6. **Scrub-on-error path (`pipeline/mod.rs:216-224`) and weaker
   `scrub_u16` (`flow_secret/reentry.rs:106-110`).** Move
   `scrub_local(&mut entropy_local)` ahead of the `?` in the `Bip39` error
   branch (or scrub then propagate), and route `scrub_u16` through
   `seed_core::arena::scrub_slice` (or add the missing `fence(SeqCst)` +
   verification read) so both match the module's own stated
   scrub-on-every-path invariant. Both are currently unreachable/
   low-exposure, but both are cheap, mechanical fixes that close the gap
   between what the modules' own doc comments promise and what the code
   does. **Owner:** seed-core (pipeline) / seed-uefi-test flow (reentry).
   **§36.2 relation:** gate 5.

### Nice-to-have / documented residual (no action strictly required before
release; track and revisit)

7. **Inert release-build scrub verification (`arena/mod.rs:373-401`,
   `bip39/mod.rs:386`, `pipeline/mod.rs:342-376`).** `debug_assert_eq!`
   read-back is a no-op in the shipped release profile. The write itself
   (the actual guarantee) is unaffected; this only weakens self-detection.
   Within SPEC §20.3's documented "best-effort ... where practical"
   latitude — a documentation/expectation gap, not a scrub-correctness
   bug. If tightened later, promote to a runtime `assert!`/fault branch
   for the arena's own scrub paths specifically (not a blanket change,
   since `debug_assert` elsewhere in the codebase is deliberate).

8. **Residual in-memory scalar copy (`seed-derive/src/curve/mod.rs:363`).**
   Already tracked as a known, reviewed residual in the module's own
   header with an assembly-review note. No action beyond what's already
   tracked is required per the auditor's own assessment; revisit only if
   a from-real-shipped-bytes disassembly review becomes possible (see
   `AUDIT-STATUS.md` row 7's residual on this exact point).

9. **`CompatOutput` secret-in-derive (`seed-compat/src/lib.rs:286-303`).**
   Same defect class as must-fix #1, but `seed-compat` is explicitly
   **out of scope for this triage** (another agent is finalizing it; this
   report does not edit compat files per the operating instructions it
   was run under). Flagged here so the owning agent/orchestrator picks it
   up — recommended treatment mirrors must-fix #1: drop `Copy`/`Debug`,
   add scrub-on-drop.

10. **Test-coverage gaps: no-zero-substitution KAT
    (`seed-platform-x86/src/rng/raw.rs:150-230`) and `TooManyRecords`
    decode KAT (`seed-protocol/src/transcript/mod.rs:560-566`).** Both are
    cheap, mechanical test additions (a `RawSample{value: nonzero,
    success:false}` case; a hand-crafted `record_count=6` wire-byte case)
    that close real gaps in otherwise-thorough rejection-matrix test
    suites. Recommended but not blocking, since the code under test is
    independently confirmed correct by inspection today.

11. **Doc SPEC-citation errors
    (`docs/machine-randomness.md:51`, `README.md:185`).** Both are
    pure citation corrections with no technical-claim impact:
    `machine-randomness.md:51` → cite `SPEC.md §15.2` (drop the invented
    `§16, §37` quotation, or quote §15.2's actual wording); `README.md:185`
    → change `(SPEC §16)` to `(SPEC §29.2)` for the frozen test-vectors
    repo-map line. Cheap, should land before the README/docs are the first
    thing a public audience reads, but carry no security consequence.

## Honesty note

Consistent with `docs/AUDIT-STATUS.md`'s framing: nothing in this report
changes the project's `SPEC.md` §36.2 gate count (still 5 of 8 **Met** as
of this writing) or its EXPERIMENTAL status. Every "not live today" finding
above is reported as such because it is true today, not because it is
unimportant — several are single-point-of-failure gaps whose current
inertness depends entirely on other code (upstream gating, today's signed
policy contents) staying exactly as it is. That is the reason must-fix #2
and should-fix #3 are ranked as high as they are despite "impact today:
nil."

## Revision history

| Date | Change |
| --- | --- |
| 2026-08-04 | Initial publication: consolidated 5 auditor passes (15 raw findings, 14 unique after 1 duplicate merge, 0 dropped) into ranked must-fix/should-fix/nice-to-have triage. |
