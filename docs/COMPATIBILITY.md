# Hardware compatibility methodology and current status

`SPEC.md` §32 lists `COMPATIBILITY.md` as one of the fixed files every
stable release archive contains, and `SPEC.md` §30 ("Compatibility
methodology") governs what this document is and is not allowed to say.

## Current status (read this first)

> **No compatibility data has been collected yet.** Alea has not
> run its production workflow against any tracked hardware population.
> The table in "Results" below is intentionally empty. This document
> exists to fix the *methodology* before any data is collected, per
> `SPEC.md` §30's requirement that the project "MUST NOT claim '95%
> compatibility' from an arbitrary convenience sample" — publishing the
> rules first, then the data, is the only order that avoids the metric
> being defined after the fact to flatter whatever sample happened to be
> available.

## Prohibited claims (permanent, `SPEC.md` §1.1, §30)

This document, and any release notes derived from it, MUST NOT:
- Claim or imply "universal" compatibility, or compare Alea's
  breadth to `memtest86`-style near-universal hardware coverage.
- Report an aggregate percentage without also publishing the sample
  definition and a confidence interval (see "Reporting rules" below).
- Let a single hardware family (e.g. many revisions of one popular
  laptop model) dominate an aggregate figure.

## Reporting rules (`SPEC.md` §30)

Once compatibility testing begins, every report entering this file, or
a future release's `COMPATIBILITY.md`, MUST:

1. **Define the sampled hardware population** — how systems were
   selected, and by whom (self-reported by users running the release,
   a maintainer's own hardware, a funded lab, etc. — named explicitly).
2. **Limit duplicate motherboard/laptop families** dominating the
   metric — a documented cap or weighting scheme, not an unweighted
   count of individual reports.
3. **Include multiple firmware vendors**, not just one OEM's UEFI
   implementation.
4. **Publish failures as well as successes** — a system that failed to
   boot, render, or accept input belongs in this table exactly as much
   as one that worked.
5. **Report deliberate security refusals in their own category**,
   distinct from accidental incompatibility. A system correctly refused
   by the entropy/console/virtualization policy (e.g. `PixelBltOnly`
   graphics-console rejection, a denylisted CPU, a detected
   virtualization environment when physical dice/coins were required)
   is not "incompatible" in the ordinary sense — it is the security
   policy working as designed. Conflating the two would understate real
   compatibility and overstate real refusals, in opposite directions.
6. **Separate boot, graphics, keyboard, console-policy, entropy and
   shutdown results** per system — a single pass/fail bit per machine
   loses exactly the information §30 requires this document to carry.
7. **Identify the exact release tested** (build identifier, signed tag)
   for every reported result.
8. **Publish confidence intervals** wherever an aggregate percentage is
   reported.

## The only claim form this document may ever produce

Per `SPEC.md` §30, a stable compatibility claim may take this exact
shape (fill in the values from real, methodology-conformant data —
never invent placeholder numbers):

> Alea completed the production workflow on X of Y independently
> reported systems across Z distinct hardware families under
> compatibility methodology version N.

No such claim currently has data behind it (see "Results" below).

## Methodology version

**Version 1** (this document, first publication). Any future change to
the sampling, weighting, or category rules above MUST increment this
version number and be reflected in every subsequent compatibility claim
("...under compatibility methodology version N").

## Results

*(No data yet. This table is the required shape a first report would
take once real, methodology-conformant reports exist — it is a schema,
not a claim.)*

| System (family) | Firmware vendor | Release tested | Boot | Graphics | Keyboard | Console policy | Entropy | Shutdown | Category |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| *(none reported)* | | | | | | | | | |

## Revision history

| Date | Change |
| --- | --- |
| 2026-08-04 | Initial publication (gap-fix agent 6, spec-conformance audit response): methodology only, no data. |
