#!/usr/bin/env bash
#
# Host test for the WP4 release-authorization gate scripts
# (ALEA-2026-001/003/004). Invoked by ci.sh. Self-contained: builds a
# throwaway git repo + ed25519 signing key in a temp dir, so it needs
# `git` and `ssh-keygen` (skips cleanly if ssh-keygen is unavailable).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VS="$REPO_ROOT/scripts/release-verify-signature.sh"
TG="$REPO_ROOT/tools/release-verifier/scripts/tag-trust-gate.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "SKIP: ssh-keygen not available"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Throwaway signing key + allowed_signers.
ssh-keygen -t ed25519 -N "" -q -f "$WORK/id"
IDENTITY="release-test@alea"
PUB="$(cat "$WORK/id.pub")"
KT="$(echo "$PUB" | awk '{print $1}')"
KB="$(echo "$PUB" | awk '{print $2}')"
printf '%s %s %s\n' "$IDENTITY" "$KT" "$KB" > "$WORK/allowed_signers"

# ---- release-verify-signature.sh ----
mkdir -p "$WORK/rel"
printf 'the checksum list\n' > "$WORK/rel/SHA256SUMS"

# (a) missing signature -> fail closed
if bash "$VS" "$WORK/rel" "$WORK/allowed_signers" "$IDENTITY" >/dev/null 2>&1; then
  fail "release-verify-signature: missing .sig must fail closed"
fi
pass "release-verify-signature: missing signature fails closed"

# (b) valid signature -> pass
ssh-keygen -Y sign -n file -f "$WORK/id" "$WORK/rel/SHA256SUMS" >/dev/null 2>&1
bash "$VS" "$WORK/rel" "$WORK/allowed_signers" "$IDENTITY" >/dev/null 2>&1 \
  || fail "release-verify-signature: valid signature must pass"
pass "release-verify-signature: valid signature passes"

# (c) tampered SHA256SUMS -> fail
printf 'the checksum list (tampered)\n' > "$WORK/rel/SHA256SUMS"
if bash "$VS" "$WORK/rel" "$WORK/allowed_signers" "$IDENTITY" >/dev/null 2>&1; then
  fail "release-verify-signature: tampered checksums must fail"
fi
pass "release-verify-signature: tampered checksums fail"

# ---- tag-trust-gate.sh ----
export GIT_CONFIG_GLOBAL="$WORK/gitconfig"
git init -q "$WORK/repo"
cd "$WORK/repo"
git config user.name t; git config user.email t@t
git config gpg.format ssh
git config user.signingkey "$WORK/id.pub"
git commit -q --allow-empty -m base
git branch -M master
BASEFPR="$(ssh-keygen -lf "$WORK/id.pub" | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | head -n1)"

# ancestor + signed tag on master
git tag -s -m good v-good
git update-ref refs/remotes/origin/master master
bash "$TG" --tag v-good --allowed-signers "$WORK/allowed_signers" --branch-ref origin/master --expected-fpr "$BASEFPR" >/dev/null 2>&1 \
  || fail "tag-trust-gate: signed ancestor tag matching fpr must pass"
pass "tag-trust-gate: signed ancestor tag matching fpr passes"

# fpr mismatch -> fail
if bash "$TG" --tag v-good --allowed-signers "$WORK/allowed_signers" --branch-ref origin/master --expected-fpr "SHA256:wrongfprwrongfprwrongfprwrongfprwrongfpr00" >/dev/null 2>&1; then
  fail "tag-trust-gate: fpr mismatch must fail"
fi
pass "tag-trust-gate: fpr mismatch fails"

# non-ancestor tag (on a side branch) -> fail
git checkout -q -b side
git commit -q --allow-empty -m side
git tag -s -m sidetag v-side
if bash "$TG" --tag v-side --allowed-signers "$WORK/allowed_signers" --branch-ref origin/master --expected-fpr "$BASEFPR" >/dev/null 2>&1; then
  fail "tag-trust-gate: non-ancestor tag must fail"
fi
pass "tag-trust-gate: non-ancestor tag fails"

# missing allowed_signers -> fail closed
if bash "$TG" --tag v-good --allowed-signers /nonexistent --branch-ref origin/master >/dev/null 2>&1; then
  fail "tag-trust-gate: missing allowed_signers must fail closed"
fi
pass "tag-trust-gate: missing allowed_signers fails closed"

echo "PASS: WP4 gate scripts (release-verify-signature, tag-trust-gate)."
