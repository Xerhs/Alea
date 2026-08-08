# Signing governance (key custody, rotation, revocation, compromise response)

`SPEC.md` §32 requires that every stable release document "signed
source tag; ... multi-person approval for production signing;
documented signing-key custody; documented rotation, revocation and
compromise response," and lists `SIGNING-GOVERNANCE.md` as one of the
fixed files every stable release archive contains. This document is
that artifact.

## Current status (read this first)

> **This governance process is not yet operative.** Alea has
> produced **zero** production-signed stable releases. No signing key
> has been generated, custodied, or used under this document. No
> multi-person approval has ever been exercised, because there has
> never been a production signing event to approve. `SECURITY.md` and
> the on-screen `EXPERIMENTAL SECURITY SOFTWARE` banner
> (`docs/prohibited-claims-checklist.md`) reflect this: the project has
> not passed the `SPEC.md` §36 gate set, and this document existing does
> not change that. Publishing the *procedure* below is a precondition
> for a first stable release, not evidence one has happened.
>
> Per `SPEC.md` §36.1: "The project MUST publish who is expected to
> fund and perform each gate before claiming the gates are the release
> plan." As of this writing, no funded external audit, independent
> build-attestor arrangement, or multi-person signing quorum has been
> established or named. Until it is, this document's procedures are the
> *requirement a release must meet*, not a claim that one has.

## Required approvers

A production signing event MUST have **at least two** independent
approvers, neither of whom is the sole author of the change being
released, before the signing key is invoked. "Independent" means: able
to inspect the diff, the build log, and the reproducibility check
(`REPRODUCING.md`) without relying solely on the release engineer's own
say-so, and able to refuse the release. A release performed by one
person alone, from one machine, without a second approver's recorded
sign-off, does not satisfy this document — regardless of how the
signing key was invoked.

Each approver's sign-off MUST record, at minimum:
- The exact commit hash and signed source tag being released.
- The `SHA256SUMS` digest(s) they independently reproduced or
  independently confirmed against `REPRODUCING.md` (SPEC §36.2: "at
  least one party other than the release engineer").
- Their explicit approval or refusal, and if refusal, why.

## No automatic release from a developer laptop

`SPEC.md` §32: "no automatic release from a developer laptop." The
signing key MUST NOT be present, in any form (including an
environment variable, a CI secret usable without a second factor a
single person controls, or a locally mounted hardware token left
attached to a personal machine), on any machine that is also used for
day-to-day development. Concretely, before a first stable release:

- The signing step MUST run from a controlled, auditable build
  environment (e.g. CI triggered only by a signed git tag pushed by an
  approver, or an air-gapped signing machine used for nothing else) —
  never a `cargo build --release && sign-it` run from whatever laptop
  happens to have the key file on it that day.
- `tools/image-builder` and `tools/release-verifier` already produce
  the deterministic, host-runnable pieces this depends on (the
  unsigned `.img`/`.efi` payload and its hash, and the manifest-
  completeness check — see `tools/release-verifier`'s `--check-manifest`
  flag); neither of those tools requires or touches a signing key, by
  design, so the reproducible-build half of the pipeline can run
  identically on a laptop, in CI, or on an air-gapped machine — only
  the final signing step is restricted.

## Key custody

Requirements for any signing key generated under this document (none
exist yet):

- Private key material MUST be generated and stored on hardware the
  day-to-day development environment never touches (a hardware security
  module or a dedicated offline signing device), never as a plaintext
  file on a general-purpose machine or in a CI secret store reachable
  by ordinary commits.
- At least two people MUST be needed to invoke the key for a production
  signing operation (see "Required approvers" above) — a lost or
  coerced single custodian must not be sufficient to produce a
  seemingly-legitimate signed release.
- The corresponding public key(s) MUST be published through a channel
  independent of this repository's own hosting (so a compromise of one
  does not silently compromise verification of the other) —
  `VERIFYING-MEDIA.md` documents the resulting cross-channel
  verification ceremony for end users.

## Rotation

Planned, non-emergency key rotation MUST:
- Be announced before the new key is used for a production signature,
  with both the outgoing and incoming public key fingerprints published
  through the same independent channel required above.
- Overlap: releases signed with the outgoing key remain verifiable
  (the outgoing public key is never deleted from the published record,
  only marked superseded) so historical releases don't silently become
  unverifiable.

## Revocation and compromise response

If a signing key is suspected or confirmed compromised:

1. Immediately publish a revocation notice through the independent
   channel above, naming the exact key fingerprint revoked and the
   date/reason.
2. Treat every release signed with that key from the suspected
   compromise window forward as untrusted until independently
   re-verified against the reproducible unsigned payload
   (`REPRODUCING.md`) by at least one of the required approvers.
3. Generate a replacement key under a fresh custody arrangement (never
   simply re-issuing under the same custody conditions that failed) and
   follow the rotation procedure above.
4. Record the incident, resolution, and any affected release identifiers
   in `AUDIT-STATUS.md` (`docs/AUDIT-STATUS.md`).

No revocation has occurred; no key has ever been issued to revoke.

## What this document does not, and cannot, prove

Publishing this procedure does not itself demonstrate that any of it
has been followed — that is exactly why `SPEC.md` §36.1 requires naming
who funds and performs each gate before claiming it as the release
plan, and why `SECURITY.md` keeps the experimental banner active
regardless of what documentation exists. A future stable release's
`AUDIT-STATUS.md` (`docs/AUDIT-STATUS.md`) is where the *evidence* that
this procedure was actually followed for a specific release belongs —
this file only defines what "followed" means.
