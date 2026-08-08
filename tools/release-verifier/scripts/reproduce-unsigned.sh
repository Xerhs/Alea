#!/usr/bin/env bash
# WP-32 (SPEC §32): reproducibility harness for the deterministic
# unsigned production payload.
#
# SPEC §32 requires "deterministic unsigned EFI payload" and "at least
# two independent build attestations". This script is the mechanical
# half of that: it builds the given crate for the given target *twice*,
# each time from a completely fresh `CARGO_TARGET_DIR` (so nothing is
# reused between the two builds — this is not merely "incremental build
# didn't change", it is "two independent build invocations produced the
# same bytes"), with a fixed `SOURCE_DATE_EPOCH`, and asserts the
# resulting artifact is byte-for-byte identical.
#
# It builds the REAL production target (`seed-uefi-production` for
# `x86_64-unknown-uefi`) by default — in this environment a from-clean
# build of that crate takes single-digit seconds (measured; see
# REPRODUCING.md), so there is no need to fall back to a toy/minimal
# crate to keep this fast. The `--crate`/`--target`/`--triple` flags
# exist so the *same* harness can also be pointed at a minimal crate
# (e.g. for a quick sanity check of the harness itself, or in an
# environment where the full production build genuinely is too slow) —
# see REPRODUCING.md's note on this.
#
# This script deliberately does NOT touch the signed `.efi`/USB image or
# any signing step (SPEC §32: "reproduction of the unsigned executable
# payload" is a *different* claim from "verification of the signed
# wrapper" — see REPRODUCING.md).
set -euo pipefail

# shellcheck disable=SC1091
source "$HOME/.cargo/env"

CRATE="seed-uefi-production"
TARGET_TRIPLE="x86_64-unknown-uefi"
PROFILE="release"
ARTIFACT_NAME=""   # auto-derived from CRATE if empty (crate-name.efi for the uefi target)
KEEP=0

usage() {
    cat <<'EOF'
usage: reproduce-unsigned.sh [--crate NAME] [--triple TARGET_TRIPLE] [--artifact FILE] [--keep]

Builds the given crate for the given target triple twice, from two
independent clean CARGO_TARGET_DIR trees, and asserts the resulting
artifact is byte-for-byte identical between the two builds.

  --crate NAME       Crate to build (default: seed-uefi-production).
  --triple TRIPLE    cargo --target value (default: x86_64-unknown-uefi).
  --artifact FILE    Artifact file name under target/<triple>/release/
                     (default: <crate-name-with-dashes-as-underscores>.efi
                     for a *-uefi triple, or the crate name otherwise).
  --keep             Do not delete the two temporary CARGO_TARGET_DIR
                      trees on success (they are always kept on failure).

Exit status: 0 if both builds produced byte-identical output, 1 otherwise.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --crate) CRATE="$2"; shift 2 ;;
        --triple) TARGET_TRIPLE="$2"; shift 2 ;;
        --artifact) ARTIFACT_NAME="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
    esac
done

if [ -z "$ARTIFACT_NAME" ]; then
    # Cargo names the primary [[bin]] artifact after the crate name
    # verbatim (dashes kept) for the top-level `target/<triple>/<profile>/`
    # artifact; only the `deps/` directory's copy uses the mangled
    # underscore form. We want the former.
    case "$TARGET_TRIPLE" in
        *-uefi) ARTIFACT_NAME="${CRATE}.efi" ;;
        *) ARTIFACT_NAME="$CRATE" ;;
    esac
fi

# Fixed build-input timestamp (SPEC §32 determinism). If the caller
# already set one (e.g. a release pipeline pinning it to the signed
# source tag's commit time), respect it; otherwise pick a fixed
# constant so *this script's* two builds are always mutually
# consistent even though neither build actually consumes the variable
# today (see the note below).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"

# Build flags are NOT set here. All reproducibility link flags for the
# `*-uefi` target (`/Brepro`, `/DEBUG:NONE`) — and the mandatory
# `sha2_backend="soft"` codegen cfg — live in `.cargo/config.toml` under
# `[target.x86_64-unknown-uefi]`, so this harness and the normal
# `--release` build (scripts/build-release.sh) draw from ONE identical
# flag source. This script must NOT export a RUSTFLAGS env var: a
# RUSTFLAGS env value REPLACES the target rustflags from config.toml
# wholesale (cargo does not merge the two — the env source wins and the
# config source is ignored entirely), which would drop the sha2_backend
# cfg and make the "reproduced" binary diverge from the shipped one. If
# the caller has RUSTFLAGS set in the environment for some reason, that
# is their (clobbering) choice; this harness deliberately leaves it
# untouched rather than adding to the problem.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

WORK=$(mktemp -d /tmp/sf-reproduce-XXXXXX)
DIR_A="$WORK/target-a"
DIR_B="$WORK/target-b"

echo "== reproduce-unsigned: $CRATE for $TARGET_TRIPLE (profile=$PROFILE) =="
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "build A target dir: $DIR_A"
echo "build B target dir: $DIR_B"

build_one() {
    local target_dir="$1"
    CARGO_TARGET_DIR="$target_dir" cargo build \
        -p "$CRATE" \
        --target "$TARGET_TRIPLE" \
        --"$PROFILE" \
        --locked
}

echo "-- build A --"
build_one "$DIR_A"
echo "-- build B --"
build_one "$DIR_B"

ARTIFACT_A="$DIR_A/$TARGET_TRIPLE/$PROFILE/$ARTIFACT_NAME"
ARTIFACT_B="$DIR_B/$TARGET_TRIPLE/$PROFILE/$ARTIFACT_NAME"

if [ ! -f "$ARTIFACT_A" ]; then
    echo "FAIL: expected artifact not found after build A: $ARTIFACT_A" >&2
    exit 1
fi
if [ ! -f "$ARTIFACT_B" ]; then
    echo "FAIL: expected artifact not found after build B: $ARTIFACT_B" >&2
    exit 1
fi

HASH_A=$(sha256sum "$ARTIFACT_A" | cut -d' ' -f1)
HASH_B=$(sha256sum "$ARTIFACT_B" | cut -d' ' -f1)

echo "build A sha256: $HASH_A  ($ARTIFACT_A)"
echo "build B sha256: $HASH_B  ($ARTIFACT_B)"

if [ "$HASH_A" = "$HASH_B" ]; then
    echo "PASS: two independent clean builds produced a byte-identical artifact."
    if [ "$KEEP" -eq 0 ]; then
        rm -rf "$WORK"
    else
        echo "(--keep given: build trees left at $WORK)"
    fi
    exit 0
else
    echo "FAIL: builds diverged. Byte-for-byte reproducibility is broken." >&2
    echo "Build trees left at $WORK for inspection (e.g. cmp -l, or diffoscope)." >&2
    exit 1
fi
