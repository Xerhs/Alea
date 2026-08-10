#!/usr/bin/env bash
#
# tag-trust-gate.sh (WP-32, ALEA-2026-001 + ALEA-2026-004) — the
# release-authorization gate the `release` workflow runs before it builds
# or publishes anything for a `v*` tag.
#
# It enforces, fail-closed, three things that a signature check alone does
# NOT (see SPEC_AUDIT_REMEDIATION_2026-08-09.md §ALEA-2026-001/004):
#
#   1. The tag object carries an SSH signature that verifies against the
#      committed allowed_signers keyring (the existing check, kept here so
#      the whole trust decision is in one host-testable place).
#   2. (ALEA-2026-004) The tagged commit is an ANCESTOR of the protected
#      branch ref (default origin/master) — so a release cannot be cut
#      from an unreviewed side branch or an off-master tag. This is the
#      SINGLE ancestry gate; release.yml must not add a second.
#   3. (ALEA-2026-001, defense in depth) When an EXPECTED fingerprint is
#      supplied out-of-band (a protected GitHub Environment variable,
#      NOT a value read from the source tree), the signer's actual
#      fingerprint must equal it AND that fingerprint must literally
#      appear in the checked-out allowed_signers. This raises the required
#      attacker capability from repo-write/PR-merge to repo-settings-admin.
#      It is NOT an independent trust root (an attacker with full settings
#      access can change both inputs); the real fix is the multi-person
#      SIGNING-GOVERNANCE.md era. When no expected fingerprint is supplied
#      (the Environment variable is unset), the pin is skipped with a loud
#      WARNING — never a silent pass.
#
# Usage:
#   tag-trust-gate.sh --tag <tag> --allowed-signers <path> \
#       --branch-ref <ref> [--expected-fpr <SHA256:...>]
#
# Exits 0 only if every applicable check passes; nonzero (and prints
# FAIL:) otherwise. Requires `git` and `ssh-keygen` on PATH.
set -euo pipefail

TAG="" ALLOWED="" BRANCH_REF="origin/master" EXPECTED_FPR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --allowed-signers) ALLOWED="$2"; shift 2 ;;
    --branch-ref) BRANCH_REF="$2"; shift 2 ;;
    --expected-fpr) EXPECTED_FPR="${2:-}"; shift 2 ;;
    *) echo "FAIL: unknown argument: $1" >&2; exit 64 ;;
  esac
done

[ -n "$TAG" ] || { echo "FAIL: --tag is required" >&2; exit 64; }
[ -n "$ALLOWED" ] || { echo "FAIL: --allowed-signers is required" >&2; exit 64; }
[ -f "$ALLOWED" ] || { echo "FAIL: allowed_signers file not found: $ALLOWED" >&2; exit 1; }

# (1) signed-tag verification against the committed keyring.
verify_out="$(git -c "gpg.ssh.allowedSignersFile=$ALLOWED" tag -v "$TAG" 2>&1)" || {
  echo "FAIL: tag '$TAG' did not verify against $ALLOWED"
  echo "$verify_out"
  exit 1
}
echo "PASS: tag '$TAG' signature verifies against the committed allowed_signers."

# (2) ancestry gate (the single one — ALEA-2026-004 / CC-1).
if ! git merge-base --is-ancestor "${TAG}^{commit}" "$BRANCH_REF"; then
  echo "FAIL: tag '$TAG' commit is not an ancestor of $BRANCH_REF —"
  echo "      releases must build from reviewed $BRANCH_REF history."
  exit 1
fi
echo "PASS: tag '$TAG' commit is an ancestor of $BRANCH_REF."

# (3) out-of-band fingerprint pin (ALEA-2026-001, defense in depth).
if [ -z "$EXPECTED_FPR" ]; then
  echo "WARNING: no --expected-fpr supplied (protected Environment variable"
  echo "         ALEA_TAG_SIGNER_FPR is unset). The defense-in-depth signer"
  echo "         pin is NOT active; a source-only allowed_signers swap would"
  echo "         still pass. Configure it per docs/RELEASE-GOVERNANCE.md."
else
  # ssh-keygen prints e.g.: Good "git" signature ... with ED25519 key SHA256:....
  actual_fpr="$(printf '%s\n' "$verify_out" | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | head -n1)"
  if [ -z "$actual_fpr" ]; then
    echo "FAIL: could not extract the signer fingerprint from the verification output."
    exit 1
  fi
  if [ "$actual_fpr" != "$EXPECTED_FPR" ]; then
    echo "FAIL: signer fingerprint $actual_fpr != expected $EXPECTED_FPR."
    exit 1
  fi
  if ! ssh-keygen -lf "$ALLOWED" 2>/dev/null | grep -qF "$EXPECTED_FPR"; then
    echo "FAIL: expected fingerprint $EXPECTED_FPR is not present in $ALLOWED —"
    echo "      the committed keyring and the out-of-band pin disagree."
    exit 1
  fi
  echo "PASS: signer fingerprint matches the out-of-band pin and the committed keyring."
fi

echo "PASS: tag-trust-gate: all applicable checks passed for '$TAG'."
