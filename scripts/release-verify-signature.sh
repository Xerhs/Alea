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
#   release-verify-signature.sh <release-dir> <allowed-signers> <signer-identity> [expected-fingerprint]
#
# Exits 0 only if SHA256SUMS.sig is present and verifies; nonzero
# otherwise. Requires `ssh-keygen`.
#
# ALEA-AUDIT-001 (Gemini 3.1 Pro): when <expected-fingerprint> is given, the
# key that `allowed_signers` binds to <signer-identity> MUST have exactly that
# SHA256 fingerprint. Because `allowed_signers` here is read from the tag being
# published (TOFU), an attacker who rewrote it could otherwise bind the same
# identity string to their OWN key and provide a matching signature. The
# fingerprint is supplied out-of-band (the protected `release` Environment
# variable ALEA_TAG_SIGNER_FPR, NOT the tag), so a swapped key fails this pin.
# release-publish.yml passes it and fails closed if it is unset.
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
EXPECTED_FPR="${4:-}"

if [ -z "$DIR" ] || [ -z "$ALLOWED" ] || [ -z "$IDENTITY" ]; then
  echo "usage: release-verify-signature.sh <release-dir> <allowed-signers> <signer-identity> [expected-fingerprint]" >&2
  exit 64
fi

SUMS="$DIR/SHA256SUMS"
SIG="$DIR/SHA256SUMS.sig"

[ -f "$ALLOWED" ] || { echo "FAIL: allowed_signers not found: $ALLOWED"; exit 1; }
[ -f "$SUMS" ]    || { echo "FAIL: $SUMS not found — nothing to authenticate."; exit 1; }
[ -f "$SIG" ]     || { echo "FAIL: $SIG not found — refusing to publish an unsigned release (ALEA-2026-003)."; exit 1; }

if ! ssh-keygen -Y verify -f "$ALLOWED" -I "$IDENTITY" -n file -s "$SIG" < "$SUMS"; then
  echo "FAIL: $SIG did NOT verify — release must remain a draft."
  exit 1
fi

# ALEA-AUDIT-001: out-of-band fingerprint pin. The key `allowed_signers` binds
# to $IDENTITY must have exactly $EXPECTED_FPR — so a rewritten tag-local
# keyring that binds the same identity to a different key cannot pass.
if [ -n "$EXPECTED_FPR" ]; then
  # Extract the pubkey allowed_signers binds to this exact principal.
  PUB="$(awk -v id="$IDENTITY" '$1==id {print $2" "$3; exit}' "$ALLOWED")"
  if [ -z "$PUB" ]; then
    echo "FAIL: identity $IDENTITY has no exact-principal key line in $ALLOWED for the fingerprint pin."
    exit 1
  fi
  TMP="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$TMP'" EXIT
  printf '%s\n' "$PUB" > "$TMP"
  ACTUAL_FPR="$(ssh-keygen -lf "$TMP" 2>/dev/null | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | head -n1)"
  if [ -z "$ACTUAL_FPR" ]; then
    echo "FAIL: could not compute the signer key fingerprint from $ALLOWED."
    exit 1
  fi
  if [ "$ACTUAL_FPR" != "$EXPECTED_FPR" ]; then
    echo "FAIL: signer key fingerprint $ACTUAL_FPR != pinned $EXPECTED_FPR —"
    echo "      refusing (a rewritten allowed_signers cannot rebind the identity to another key)."
    exit 1
  fi
  echo "fingerprint pin OK: $ACTUAL_FPR."
fi

echo "PASS: $SIG verifies against $ALLOWED for identity $IDENTITY${EXPECTED_FPR:+ (fpr pinned)} — safe to un-draft."
exit 0
