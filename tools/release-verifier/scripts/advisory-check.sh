#!/usr/bin/env bash
#
# ALEA-2026-008 remainder / Grok 4.5 Expert audit finding F-06:
# the deterministic RustSec advisory gate.
#
# The freshness half (advisory-db-age) was already wired; this is the part
# that actually RUNS `cargo deny check advisories`. To keep it deterministic
# WITHOUT vendoring the whole advisory-db into the repo, it:
#
#   1. runs the freshness gate (the pinned snapshot must not be stale);
#   2. fetches rustsec/advisory-db into the deny.toml-configured db-path;
#   3. PINS that checkout to the exact commit recorded in
#      supply-chain/advisory-db.lock and verifies the SHA (fail-closed on
#      any mismatch — this is what makes the "CI fetches the pinned commit"
#      model trustworthy);
#   4. runs `cargo deny --offline check advisories` against that pinned
#      snapshot.
#
# Honesty: a green result proves only "no RustSec advisory matches the
# pinned dependency graph as of the snapshot commit." It is not an audit and
# does not change Alea's EXPERIMENTAL / not-for-substantial-funds posture.
# See supply-chain/README.md and deny.toml.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
LOCK="supply-chain/advisory-db.lock"
DB_URL="https://github.com/rustsec/advisory-db"

COMMIT="$(sed -nE 's/^[[:space:]]*commit[[:space:]]*=[[:space:]]*"([0-9a-fA-F]{40})".*/\1/p' "$LOCK" | head -n1)"
if [ -z "$COMMIT" ]; then
    echo "FAIL: no 40-hex commit found in $LOCK"
    exit 1
fi

# 1. Freshness — fail closed if the pin is stale / missing / future-dated.
cargo run --quiet -p release-verifier --bin advisory-db-age -- "$LOCK"

# 2. cargo-deny must be present (mirrors the cargo-vet requirement in ci.sh).
if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "FAIL: cargo-deny not installed — required for the RustSec advisory gate."
    echo "      Install for the gnu target (never build the tool itself for musl):"
    echo "        CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu cargo install cargo-deny --locked"
    exit 1
fi

# 3. Populate the advisory-db at deny.toml's [advisories] db-path, then pin
#    it to the exact snapshot commit and verify.
DBROOT="$ROOT/target/advisory-db"
mkdir -p "$DBROOT"
cargo deny fetch advisories 2>/dev/null || cargo deny fetch
DBDIR="$(find "$DBROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1)"
if [ -z "${DBDIR:-}" ] || [ ! -e "$DBDIR/.git" ]; then
    # Fallback: cargo-deny did not leave a git checkout where expected — clone
    # it ourselves so the pin/verify below is still possible (fail-closed).
    DBDIR="$DBROOT/rustsec-advisory-db"
    rm -rf "$DBDIR"
    git clone --quiet "$DB_URL" "$DBDIR"
fi
# The pinned commit is a past commit on the default branch; make sure it is
# present even if the clone was shallow.
if ! git -C "$DBDIR" cat-file -e "${COMMIT}^{commit}" 2>/dev/null; then
    git -C "$DBDIR" fetch --quiet origin "$COMMIT" 2>/dev/null \
        || git -C "$DBDIR" fetch --quiet --unshallow 2>/dev/null \
        || git -C "$DBDIR" fetch --quiet origin 2>/dev/null || true
fi
git -C "$DBDIR" checkout --quiet "$COMMIT"
ACTUAL="$(git -C "$DBDIR" rev-parse HEAD)"
if [ "$ACTUAL" != "$COMMIT" ]; then
    echo "FAIL: advisory-db pinned-commit mismatch — got $ACTUAL, want $COMMIT"
    exit 1
fi
echo "advisory-db pinned at $COMMIT (verified)."

# 4. Deterministic offline advisory check against the pinned snapshot.
cargo deny --offline check advisories
echo "PASS: cargo deny --offline check advisories (pinned $COMMIT)."
