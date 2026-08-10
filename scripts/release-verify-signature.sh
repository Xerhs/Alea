#!/usr/bin/env bash
#
# release-verify-signature.sh (WP-32, ALEA-2026-003) — the fail-closed
# check the draft->publish flow runs before a GitHub Release is made
# public. It verifies that the detached SSH signature over the release's
# SHA256SUMS exists and verifies against the committed allowed_signers
# keyring; if it does not, the release MUST stay a draft.
#
# This closes the ALEA-2026-003 window in which v0.11.0-beta was public
# for ~153 s before its SHA256SUMS.sig existed: publication and
# authentication are now one fail-closed transaction (build -> DRAFT ->
# offline human sign -> THIS check -> un-draft), and the private signing
# key never enters CI.
#
# Usage:
#   release-verify-signature.sh <release-dir> <allowed-signers> <signer-identity>
#
# Exits 0 only if SHA256SUMS.sig is present and verifies; nonzero
# otherwise. Requires `ssh-keygen`.
#
# Honesty: this authenticates ONLY that the checksum list was signed by a
# key in the committed (TOFU) allowed_signers — not that that keyring is
# itself trustworthy (cross-channel fingerprint check is still manual,
# VERIFYING-MEDIA.md §0a), and nothing about the binaries (unsigned),
# entropy, or firmware.
set -euo pipefail

DIR="${1:-}"
ALLOWED="${2:-}"
IDENTITY="${3:-}"

if [ -z "$DIR" ] || [ -z "$ALLOWED" ] || [ -z "$IDENTITY" ]; then
  echo "usage: release-verify-signature.sh <release-dir> <allowed-signers> <signer-identity>" >&2
  exit 64
fi

SUMS="$DIR/SHA256SUMS"
SIG="$DIR/SHA256SUMS.sig"

[ -f "$ALLOWED" ] || { echo "FAIL: allowed_signers not found: $ALLOWED"; exit 1; }
[ -f "$SUMS" ]    || { echo "FAIL: $SUMS not found — nothing to authenticate."; exit 1; }
[ -f "$SIG" ]     || { echo "FAIL: $SIG not found — refusing to publish an unsigned release (ALEA-2026-003)."; exit 1; }

if ssh-keygen -Y verify -f "$ALLOWED" -I "$IDENTITY" -n file -s "$SIG" < "$SUMS"; then
  echo "PASS: $SIG verifies against $ALLOWED for identity $IDENTITY — safe to un-draft."
  exit 0
else
  echo "FAIL: $SIG did NOT verify — release must remain a draft."
  exit 1
fi
