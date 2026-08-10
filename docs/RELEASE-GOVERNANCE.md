# Release governance (solo-maintainer era)

This document records the repository settings and human steps the release
workflow **assumes** but cannot itself enforce (ALEA-2026-001/003/004). It
is distinct from `docs/SIGNING-GOVERNANCE.md`, which covers signing-key
custody/rotation for the future multi-person **stable** era. Everything
here is a solo-maintainer stopgap that raises the bar; none of it is an
independent trust root, and none of it changes Alea's EXPERIMENTAL,
unaudited, not-for-substantial-funds posture.

## Why these controls exist

The 2026-08-09 external GPT 5.6 Sol audit
(`docs/GPT-5.6-SOL-AUDIT-2026-08-09.md`, ALEA-2026-001) found that the release gate verified a `v*` tag against the
`allowed_signers` keyring **shipped in the same checkout it authorizes** —
a circular trust root a single repo-write could redefine. The fixes below
raise the required attacker capability from repo-write/PR-merge to
repository-**settings-admin**, and force every released commit through
`master`'s review history. They do **not** make the trust root
independent; only the multi-person `SIGNING-GOVERNANCE.md` process does.

## Required GitHub settings (maintainer must configure)

The workflow enforces what it can and fails closed on the rest, but these
settings are what make the enforcement meaningful. Configure them once:

1. **Branch protection on `master`:** require pull requests, require the
   `ci` status check to pass, require signed commits, disallow
   force-pushes, and require linear history. The release workflow's
   master-ancestry gate (below) is only as strong as this protection.
2. **Tag protection rule for `v*`:** restrict who may create/push release
   tags to the maintainer (or a dedicated release role). A `v*` tag is the
   release trigger; anyone who can push one can start a release.
3. **A protected `release` Environment** holding a repository/environment
   **variable** `ALEA_TAG_SIGNER_FPR` set to the tag-signing key's SSH
   fingerprint (currently `SHA256:CxtkbKytle8ka7yGbZ4autLODy3sxkg+L7VIV/OIezI`,
   the dedicated `alea-tag-signing` key). The `build-and-gate` job runs in
   this Environment; the fingerprint pin (below) is active only when this
   variable is set. Optionally add a required-reviewer / wait-timer (a
   one-person repo cannot enforce two-person review — that is the stable
   era).

## What the workflow enforces (fail-closed)

Run via `tools/release-verifier/scripts/tag-trust-gate.sh` (host-tested,
`scripts/tests/gate-scripts.test.sh`):

- **Signed tag** verifies against the committed `allowed_signers`.
- **Master-ancestry:** the tagged commit MUST be an ancestor of
  `origin/master` — no releases from unreviewed side branches or off-master
  tags (the single ancestry gate; ALEA-2026-004).
- **Fingerprint pin** (defense in depth, ALEA-2026-001): when
  `ALEA_TAG_SIGNER_FPR` is set, the signer's actual fingerprint must equal
  it AND appear in the committed `allowed_signers`. When the variable is
  unset, the pin is **skipped with a loud warning** — never a silent pass;
  configure the Environment variable to activate it.
- **Full CI on the exact tag** (ALEA-2026-004): `release.yml` reuses
  `ci.yml` via `workflow_call` and `needs:` it, so the complete `ci.sh`
  gate runs on the tagged commit before any build/publish — not a stale or
  assumed status.

## Draft-first publication (ALEA-2026-003)

Publication and signature are one fail-closed transaction:

1. `release.yml` builds + gates and creates the GitHub Release as a
   **draft** (no public surface, no notifications).
2. **Offline (human):** download the exact `SHA256SUMS` from the draft,
   sign it with the SSH tag-signing key
   (`ssh-keygen -Y sign -n file -f <key> SHA256SUMS` → `SHA256SUMS.sig`),
   and upload `SHA256SUMS.sig` to the draft. The private key never enters
   CI.
3. Run the `release-publish` workflow (`workflow_dispatch`, `tag` input):
   it verifies `SHA256SUMS.sig` against `allowed_signers` via
   `scripts/release-verify-signature.sh` and only then un-drafts the
   release. No public release exists until the signature is present and
   verified.

## Honesty

None of the above makes the binaries Secure Boot-signed, the release
audited, or the tool production-ready. The signature authenticates only
the checksum list against a single-maintainer TOFU key; cross-channel
fingerprint verification (`VERIFYING-MEDIA.md` §0a) remains the user's
manual step and is the only thing that makes the keyring itself trustworthy.
