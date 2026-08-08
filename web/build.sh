#!/usr/bin/env bash
# Deterministic build for the Alea Offline Web Edition — Phase 1.
# (SPEC_WEB_OFFLINE §5.2). Builds the seed-web glue crate to wasm32 with the
# normative reproducibility pins, runs the pinned wasm-opt, then inlines the
# single self-contained alea-web-offline.html.
#
# The deliverable name is `alea-web-offline.html` — SPEC_WEB_OFFLINE §5.1 names
# it normatively, and the Integrity tab in src/shell.html tells users to hash
# exactly that filename before opening it.
#
# Uses a SEPARATE wasm target dir (~/.cache/seedmaker-wasm) — never the main
# ~/.cache/seedmaker-target. Does not touch the root workspace.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CRATE="$HERE/seed-web"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/seedmaker-wasm}"

# Normative rustc pins (§5.2): strip symbols, and remap build paths so no
# /home/... absolute path is baked into panic-location strings (reproducible
# across machines). panic=abort + strip + opt-level are also set in the crate
# [profile.release]; the flags here are additive/idempotent.
export RUSTFLAGS="-C strip=symbols --remap-path-prefix=$HOME=~ --remap-path-prefix=$REPO=/alea"

# --locked (§5.2/§11.8): build against the committed Cargo.lock exactly. A build
# that silently resolves a different dependency set is not reproducible, and
# §11.8 makes a non-reproducible build a hard prohibition — so fail rather than
# re-resolve if the lockfile is stale.
echo ">> building seed-web -> wasm32-unknown-unknown (release, --locked)"
( cd "$CRATE" && cargo build --locked --release --target wasm32-unknown-unknown )

RAW_WASM="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/seed_web.wasm"

# wasm-opt (binaryen) — NORMATIVE §5.2 pin, HARD requirement (not optional).
# §5.2 makes the wasm-opt version AND its exact flags part of the reproducible
# build definition, and §11.8 makes a non-reproducible build a hard
# prohibition. The old "warn and ship the raw wasm" fallback silently produced
# bytes that no one else could reproduce (a different size and hash than the
# pinned toolchain yields), so it is removed: if the pinned wasm-opt is not on
# PATH we FAIL the build instead of shipping an off-spec artifact.
#
# Pin: binaryen version_119. The version string MUST contain "version 119"
# (`wasm-opt --version` prints e.g. "wasm-opt version 119 (version_119)").
WASM_OPT_URL="https://github.com/WebAssembly/binaryen/releases/download/version_119/binaryen-version_119-x86_64-linux.tar.gz"
if ! command -v wasm-opt >/dev/null 2>&1; then
  echo "FAIL: wasm-opt (binaryen) is NOT on PATH, but it is a NORMATIVE build pin" >&2
  echo "      (SPEC_WEB_OFFLINE §5.2; §11.8 forbids a non-reproducible build)." >&2
  echo "      Install binaryen version_119 and put its bin/ on PATH:" >&2
  echo "        $WASM_OPT_URL" >&2
  echo "      e.g. extract it and: export PATH=\"\$HOME/.local/binaryen-version_119/bin:\$PATH\"" >&2
  exit 1
fi
WASM_OPT_VERSION="$(wasm-opt --version)"
if [[ "$WASM_OPT_VERSION" != *"version 119"* ]]; then
  echo "FAIL: wrong wasm-opt version: '$WASM_OPT_VERSION'" >&2
  echo "      SPEC_WEB_OFFLINE §5.2 pins binaryen version_119 (the flags and size" >&2
  echo "      are only reproducible against that exact release); §11.8 forbids a" >&2
  echo "      non-reproducible build. Install version_119 and put its bin/ on PATH:" >&2
  echo "        $WASM_OPT_URL" >&2
  exit 1
fi

# Pinned wasm-opt invocation (§5.2). --enable-bulk-memory is REQUIRED: wasm-opt
# 119 rejects the rustc-emitted module without it (rustc emits bulk-memory
# ops — memory.copy/fill — that binaryen 119 will not parse unless the feature
# is explicitly enabled). Verified: this is the ONLY extra feature flag needed.
# -Oz size-optimizes; --strip-producers/--strip-debug remove the non-normative
# toolchain-identifying sections so the bytes are stable across machines.
OPT_WASM="$HERE/seed_web.opt.wasm"
echo ">> wasm-opt $WASM_OPT_VERSION -Oz --enable-bulk-memory"
wasm-opt -Oz --enable-bulk-memory --strip-producers --strip-debug "$RAW_WASM" -o "$OPT_WASM"
WASM="$OPT_WASM"

echo ">> inlining single-file alea-web-offline.html"
python3 "$HERE/build.py" "$WASM" "$HERE/alea-web-offline.html"

echo ">> done: $HERE/alea-web-offline.html"
