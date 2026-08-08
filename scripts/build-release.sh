#!/usr/bin/env bash
#
# build-release.sh — assemble an Alea release bundle (SPEC.md §32).
#
# Produces a `dist/` directory a user can flash to a USB flash drive and boot
# on a physical x86-64 UEFI PC, plus the separate desktop rehearsal edition,
# checksums, and the docs a first-time user needs.
#
# This is EXPERIMENTAL software (SPEC.md §2). Every produced artifact carries
# the experimental banner; this script does NOT and cannot mark it audited or
# stable — that requires the human-only SPEC §36.2 gates (external review, a
# real signing key, third-party build reproduction).
#
# Usage:
#   scripts/build-release.sh [--version <tag>] [--minisign-key <path>]
#
# With --minisign-key, SHA256SUMS is signed (SHA256SUMS.minisig). Without it,
# the release is published UNSIGNED and the script says so loudly — an unsigned
# experimental build, honest about what it is.
#
# Reproducibility (SPEC §32): SOURCE_DATE_EPOCH is pinned so the unsigned
# payload and the USB image are byte-deterministic across clean rebuilds.

set -euo pipefail

# --- config ------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Beta versioning: this is a pre-1.0 EXPERIMENTAL beta (SPEC §2/§36 — the
# stable gates are not met, so no "1.0"/"v1" which would imply stable/audited).
# 1.0 is reserved for when all SPEC §36.2 gates read Met (external audit, signed
# release, third-party build reproduction). Override with --version.
VERSION="0.10.0-beta+$(git rev-parse --short HEAD 2>/dev/null || echo local)"
MINISIGN_KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version)      VERSION="$2"; shift 2 ;;
    --minisign-key) MINISIGN_KEY="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done

DIST="$REPO_ROOT/dist/alea-$VERSION"
RELEASE_TARGET="${CARGO_TARGET_DIR:-$HOME/.cache/sf-target/release}"
export CARGO_TARGET_DIR="$RELEASE_TARGET"
# Deterministic builds (SPEC §32): fixed epoch so unsigned payload + image hash
# reproduce. Overridable, but defaults to the HEAD commit time for traceability.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 1704067200)}"
# Stamp the build identity into the payload. `seed-uefi-production`'s
# `release::BUILD_ID` reads this via `option_env!("ALEA_BUILD_ID")`; without it
# the binary falls back to the `UNSET-LOCAL-BUILD-…` placeholder shown in the
# launcher header and About screen. Deterministic given the commit (VERSION is
# the release tag + short hash), so it does not weaken the reproducible-build
# guarantee above.
export ALEA_BUILD_ID="$VERSION"

EFI="alea-x86_64-unsigned.efi"
IMG="alea-x86_64-usb.img"
# SPEC_MAIN_MENU.md §17.4: the separate cross-device verifier, chain-loaded by
# the production launcher's Verify item. Shipped as its own artifact AND placed
# on the USB image at \EFI\ALEA\VERIFY.EFI (see step 3's dual-file image build).
VERIFY_EFI="alea-verify.efi"

log()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null || fail "cargo not found — run: source \$HOME/.cargo/env"

log "Alea release build  (version: $VERSION, SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH)"
rm -rf "$DIST"; mkdir -p "$DIST"

# --- 0. standalone security suites (SPEC §29.5, §29.6) -----------------------
# tests/fault-injection (WP-33) and tests/leakage (WP-34) are deliberately
# standalone Cargo workspaces (own Cargo.lock + bare [workspace] table; see
# each suite's Cargo.toml doc comment) — no `cargo test --workspace` ever
# runs them, so a release must invoke them explicitly or the bundled
# docs/AUDIT-STATUS.md gate-5 claim ("Fault-injection suite passes: Met")
# ships unproven. Per-suite target subdirs keep their locks/fingerprints
# out of this release build's cache (same pattern as ci.sh).
log "0/8  standalone security suites (fault-injection SPEC §29.5, leakage SPEC §29.6)"
CARGO_TARGET_DIR="$RELEASE_TARGET/standalone-fault-injection" \
  cargo test --locked --manifest-path "$REPO_ROOT/tests/fault-injection/Cargo.toml" \
  || fail "fault-injection suite failed (SPEC §29.5) — release aborted"
CARGO_TARGET_DIR="$RELEASE_TARGET/standalone-leakage" \
  cargo test --locked --manifest-path "$REPO_ROOT/tests/leakage/Cargo.toml" \
  || fail "leakage suite failed (SPEC §29.6) — release aborted"

# --- 1. build the production UEFI payload ------------------------------------
log "1/8  building production UEFI payload (release)"
cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release --locked
BUILT_EFI="$RELEASE_TARGET/x86_64-unknown-uefi/release/seed-uefi-production.efi"
[ -f "$BUILT_EFI" ] || fail "production .efi not produced at $BUILT_EFI"
cp "$BUILT_EFI" "$DIST/$EFI"

# --- 1b. build the separate verifier (SPEC_MAIN_MENU.md §17.4) ---------------
# The isolation-preserving Option-B piece: the cross-device verification
# surface ships as its OWN #![no_std]/#![no_main] UEFI binary (`alea-verify`)
# whose dependency graph carries `seed-compat`, so `seed-uefi-production` never
# links it (SPEC_COMPAT §9). The production launcher chain-loads it for menu
# item 2 rather than linking the compat code in. Built with a `-p`-scoped
# invocation (never `--workspace` for the UEFI target — see alea-verify's
# Cargo.toml feature-unification note).
log "1b/8  building the separate verifier alea-verify.efi (SPEC_MAIN_MENU.md §17.4)"
cargo build -p alea-verify --target x86_64-unknown-uefi --release --locked
BUILT_VERIFY="$RELEASE_TARGET/x86_64-unknown-uefi/release/alea-verify.efi"
[ -f "$BUILT_VERIFY" ] || fail "verifier .efi not produced at $BUILT_VERIFY"
cp "$BUILT_VERIFY" "$DIST/$VERIFY_EFI"

# --- 2. isolation / policy gate (SPEC §28) -----------------------------------
log "2/8  binary-policy scan (must pass: production marker present, no test/compat leakage)"
cargo run --quiet -p binary-policy-scanner -- "$DIST/$EFI" \
  || fail "binary-policy-scanner rejected the production payload — release aborted"

# --- 3. deterministic bootable USB image (SPEC §5, §32) ----------------------
# Dual-file image: the standard boot loader at \EFI\BOOT\BOOTX64.EFI PLUS the
# separate verifier at \EFI\ALEA\VERIFY.EFI (SPEC_MAIN_MENU.md §17.4), passed as
# the optional 3rd image-builder argument.
log "3/8  building deterministic USB image (GPT + EFI System Partition, \\EFI\\BOOT\\BOOTX64.EFI + \\EFI\\ALEA\\VERIFY.EFI)"
cargo run --quiet -p image-builder --bin image-builder -- "$DIST/$EFI" "$DIST/$IMG" "$DIST/$VERIFY_EFI"
[ -f "$DIST/$IMG" ] || fail "USB image not produced"
gzip -nkf "$DIST/$IMG"                 # keep both .img and .img.gz; -n omits name/timestamp (deterministic gz, SPEC §32)

# --- 4. desktop rehearsal edition (SPEC §4.3) — SEPARATE artifact ------------
# SPEC §4.3/§32/§37: the desktop rehearsal (test) edition MUST NOT be placed in
# the production release archive or on shared media with the production edition
# — that isolation is what stops the easier desktop workflow from becoming the
# de facto product. So we build + self-check it, then emit it to its OWN dist
# directory as a separate download, and leave only a pointer in the production
# release.
log "4/8  building desktop rehearsal edition (SEPARATE artifact, SPEC §4.3)"
cargo build -p seed-desktop-test --release --locked
cargo run --quiet -p seed-desktop-test -- check \
  || fail "desktop rehearsal edition failed its frozen-vector self-check"
DIST_DESKTOP="$REPO_ROOT/dist/alea-desktop-rehearsal-$VERSION"
rm -rf "$DIST_DESKTOP"; mkdir -p "$DIST_DESKTOP"
# The host may default-target a specific triple (e.g. x86_64-unknown-linux-musl),
# so the binary can land under <target>/<triple>/release/ rather than release/.
DESKTOP_BIN="$(find "$RELEASE_TARGET" -path '*/release/seed-desktop-test' -type f 2>/dev/null | head -1)"
if [ -n "$DESKTOP_BIN" ] && [ -f "$DESKTOP_BIN" ]; then
  cp "$DESKTOP_BIN" "$DIST_DESKTOP/alea-desktop-rehearsal-linux-x86_64"
  ( cd "$DIST_DESKTOP" && sha256sum -- alea-desktop-rehearsal-* > SHA256SUMS )
  echo "  desktop rehearsal edition -> $DIST_DESKTOP (separate from the production release)"
else
  echo "  (desktop rehearsal binary not found on this host)"
fi
cat > "$DIST_DESKTOP/README.txt" <<'RD'
Alea — Desktop Rehearsal Edition (PRACTICE ONLY, separate download)
This is NOT the production seed generator. Per SPEC §4.3 it is distributed
separately and never bundled with the bootable release. It walks the full
ceremony using PUBLIC, fixed (fake) seeds so you can learn the steps with
zero risk — it is permanently watermarked and can never produce a real seed.
Never treat anything it shows as a real wallet.
Windows/macOS: build on that host with  cargo build -p seed-desktop-test --release
RD
# Production release carries only a POINTER to the separate rehearsal download.
echo "The desktop REHEARSAL edition is a SEPARATE download (not bundled here, by design — SPEC §4.3). Practice the whole ceremony risk-free on public/fake seeds before you boot the real thing." \
  > "$DIST/DESKTOP-REHEARSAL.txt"

# --- 5. offline web edition (SPEC_WEB_OFFLINE §4.3/§5.1) — SEPARATE artifact --
# Same §4.3 isolation logic as the desktop rehearsal edition directly above, one
# step further out: the web edition is the HIGHEST-risk "hot browser" edition,
# so it is a SEPARATE download and is NEVER bundled into the production USB
# archive (bundling the easiest, hottest path would let it become the de facto
# product). It ships as its OWN dist directory with its OWN signed SHA256SUMS —
# the "signed release manifest" web/src/shell.html tells users to verify against
# — plus the standalone .wasm secondary form (§5.1) whose sha256 the in-page
# Integrity self-check records (§5.3). The artifact is NORMATIVELY reproducible
# (§5.2 pins), so the build MUST use the pinned binaryen version_119; without it
# we abort the release rather than ship an off-spec, non-reproducible web
# artifact (§11.8 makes a non-reproducible build a hard prohibition).
log "5/8  building offline web edition (SEPARATE artifact, SPEC_WEB_OFFLINE §4.3)"
WASM_OPT_URL="https://github.com/WebAssembly/binaryen/releases/download/version_119/binaryen-version_119-x86_64-linux.tar.gz"
command -v wasm-opt >/dev/null 2>&1 || export PATH="$HOME/.local/binaryen-version_119/bin:$PATH"
command -v wasm-opt >/dev/null 2>&1 \
  || fail "wasm-opt (binaryen version_119) not on PATH — required for the reproducible web edition. Install: $WASM_OPT_URL"
wasm-opt --version | grep -q "version 119" \
  || fail "wrong wasm-opt version ($(wasm-opt --version)); SPEC_WEB_OFFLINE §5.2 pins binaryen version_119. Install: $WASM_OPT_URL"
# The web edition uses its OWN wasm target dir (~/.cache/seedmaker-wasm), never
# the release CARGO_TARGET_DIR this script exports for the UEFI/host builds.
CARGO_TARGET_DIR="$HOME/.cache/seedmaker-wasm" bash web/build.sh \
  || fail "web/build.sh failed — reproducible web edition not produced"
DIST_WEB="$REPO_ROOT/dist/alea-web-offline-$VERSION"
rm -rf "$DIST_WEB"; mkdir -p "$DIST_WEB"
cp "$REPO_ROOT/web/alea-web-offline.html" "$DIST_WEB/alea-web-offline.html"
# Standalone secondary form (§5.1): the OPTIMIZED wasm actually embedded in the
# .html — its sha256 equals the in-page Integrity self-hash (§5.3), so a user
# can cross-check the embedded bytes against this SHA256SUMS entry. (The .html
# is the default single-file deliverable; the .wasm is the optional secondary
# form for users who prefer to load the module by relative file:// path.)
cp "$REPO_ROOT/web/seed_web.opt.wasm" "$DIST_WEB/seed_web.wasm"
cat > "$DIST_WEB/README.txt" <<'RD'
Alea — Offline Web Edition (HOT BROWSER — highest risk, separate download)

Trust hierarchy:  Air-gapped USB (UEFI)  >  Desktop (hot OS)  >  Web (hot browser).
This web edition is the MOST convenient and the HIGHEST-risk edition. Per
SPEC_WEB_OFFLINE §4.3 it is distributed SEPARATELY and is never bundled into the
production USB release — the same isolation that stops the easiest path from
becoming the de facto product.

Phase 1 is VERIFICATION / REHEARSAL ONLY: it generates no real seed. It
rehearses a fixed public vector, verifies a mnemonic you supply, and reproduces
foreign entropy-encoding material. A browser CANNOT scrub memory: anything you
type or display (mnemonic, passphrase) leaves copies in the JS heap this app
cannot erase. For anything of value, use the air-gapped USB edition.

The only supported use:
  1. Verify the SHA-256 of alea-web-offline.html against the SIGNED SHA256SUMS
     in this download (SHA256SUMS.minisig, if present).
  2. Disconnect the network.
  3. Open alea-web-offline.html from a local file:// path, offline.

seed_web.wasm is the standalone WebAssembly module embedded in the .html; its
sha256 matches the in-page Integrity self-check. The single .html file is the
default deliverable and the .wasm is only an optional secondary form.
RD
# The web edition carries its OWN checksums (and, with a key, its own signature)
# — the signed manifest shell.html points users to. Kept out of the production
# SHA256SUMS by living in a separate directory (§4.3 isolation).
( cd "$DIST_WEB" && sha256sum -- alea-web-offline.html seed_web.wasm > SHA256SUMS )
if [ -n "$MINISIGN_KEY" ] && command -v minisign >/dev/null; then
  ( cd "$DIST_WEB" && minisign -S -s "$MINISIGN_KEY" -m SHA256SUMS ) \
    && echo "  signed: web SHA256SUMS.minisig"
fi
echo "  offline web edition -> $DIST_WEB (separate from the production release)"
# Production release carries only a POINTER to the separate web download.
echo "The offline WEB edition (hot browser — the highest-risk edition) is a SEPARATE download (not bundled here, by design — SPEC_WEB_OFFLINE §4.3, the same isolation as the desktop rehearsal). It has its own signed SHA256SUMS. Trust hierarchy: air-gapped USB > desktop > web. Verification/rehearsal only; open it offline from a local file:// path." \
  > "$DIST/WEB-EDITION.txt"

# --- 6. docs + remaining SPEC §32 manifest artifacts -------------------------
log "6/8  bundling user documentation and SPEC §32 manifest artifacts"
for d in README.md QUICKSTART.md SECURITY.md \
         docs/secure-boot.md docs/backup-security.md docs/re-entry.md \
         docs/dice-and-coins.md docs/derivation-verification.md \
         docs/AUDIT-STATUS.md VERIFYING-MEDIA.md REPRODUCING.md \
         docs/COMPATIBILITY.md docs/SIGNING-GOVERNANCE.md; do
  [ -f "$d" ] && cp "$d" "$DIST/$(basename "$d")" || echo "  (skip missing $d)"
done

# Source tarball (SPEC §32: "alea-source.tar.gz") — the exact HEAD commit
# this build was produced from, for independent reproduction (REPRODUCING.md).
git archive --format=tar.gz --prefix=alea/ -o "$DIST/alea-source.tar.gz" HEAD

# SBOM, entropy policy export, and denylist (SPEC §32/§31/§15) — generated
# from the same pinned Cargo.lock / entropy-policy.toml this build used.
cargo run -q -p image-builder --bin sbom-gen -- Cargo.lock "$DIST/SBOM.spdx.json"
cargo run -q -p image-builder --bin entropy-policy-export -- entropy-policy.toml "$DIST/ENTROPY-POLICY.txt"
cargo run -q -p image-builder --bin denylist-gen -- entropy-policy.toml "$DIST/DENYLIST.txt"

# Dependency-audit report (SPEC §31) — the release MUST include a dependency-
# audit report alongside the SBOM/entropy-policy/denylist. It bundles the two
# machine-checkable halves of SPEC §31 into one text file:
#   (1) the mechanical policy report (no unpinned git deps; exact `=` version
#       pins on workspace.dependencies), from the pinned Cargo.lock/Cargo.toml;
#   (2) the cargo-vet supply-chain verdict over the bundled supply-chain/ store.
# Kept deterministic (SPEC §32): only VERSION + SOURCE_DATE_EPOCH appear (both
# already pinned above) — no timestamps/hostnames — so it reproduces byte-for-
# byte across clean rebuilds, like the other manifest artifacts.
DEP_AUDIT="$DIST/DEPENDENCY-AUDIT.txt"
{
  echo "Alea SPEC §31 dependency-audit report"
  echo "version: $VERSION"
  echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
  echo
} > "$DEP_AUDIT"
# (1) mechanical §31 policy report — captured to the file; a nonzero exit means
# a real §31 policy violation (git dep / non-exact pin), so fail the release.
cargo run --quiet -p release-verifier --bin dependency-audit -- Cargo.lock Cargo.toml >> "$DEP_AUDIT" \
  || fail "dependency-audit checks failed (SPEC §31) — see $DEP_AUDIT"
# (2) cargo-vet verdict. Require the tool on PATH — same posture as the wasm-opt
# gate in the web step: without it the supply-chain half of §31 cannot be
# proven, so a missing tool is a hard failure, not a silent skip. (musl-gcc is
# absent on this host, so cargo-vet is built for the gnu target.)
command -v cargo-vet >/dev/null 2>&1 \
  || fail "cargo-vet not on PATH — required for the SPEC §31 supply-chain audit. Install: CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu cargo install cargo-vet --locked"
{
  echo
  echo "cargo-vet supply-chain verdict (\`cargo vet --locked --frozen\`):"
} >> "$DEP_AUDIT"
# cargo vet uses its own resolution, reading supply-chain/ + Cargo.lock from
# $REPO_ROOT; --locked --frozen forbids it mutating the store (read-only
# verification), so this can never rewrite the committed audit record.
( cd "$REPO_ROOT" && cargo vet --locked --frozen ) >> "$DEP_AUDIT" 2>&1 \
  || fail "cargo vet failed (SPEC §31 supply-chain audit) — see $DEP_AUDIT"
# Point independent re-checkers at the bundled store (shipped in the source
# tarball) so the verdict above is reproducible offline from a clean checkout.
echo "The full machine-checkable cargo-vet store (supply-chain/config.toml, audits.toml, imports.lock) is bundled in alea-source.tar.gz for independent re-checking." >> "$DEP_AUDIT"

# --- 7. checksums + optional signature (SPEC §32) ----------------------------
log "7/8  checksums + signature"
( cd "$DIST" && sha256sum -- $(ls | grep -vE '^SHA256SUMS') > SHA256SUMS )
if [ -n "$MINISIGN_KEY" ] && command -v minisign >/dev/null; then
  ( cd "$DIST" && minisign -S -s "$MINISIGN_KEY" -m SHA256SUMS ) \
    && echo "  signed: SHA256SUMS.minisig"
else
  printf '\033[33m  UNSIGNED release — no signing key provided. This is an experimental,\n  unsigned build; users must verify by an independent channel (see VERIFYING-MEDIA.md).\033[0m\n'
  echo "This release is UNSIGNED (experimental). Verify the SHA256SUMS via an independent, trusted channel before flashing." > "$DIST/UNSIGNED-RELEASE.txt"
fi

# --- 8. verify the assembled bundle ------------------------------------------
log "8/8  verifying the assembled release directory"
if [ -n "$MINISIGN_KEY" ]; then
  cargo run --quiet -p release-verifier --bin release-verifier -- "$DIST" --check-manifest || fail "release-verifier failed"
else
  # Unsigned beta: the two signature files (alea-x86_64-signed.efi,
  # SHA256SUMS.minisig) are legitimately absent — no key to sign with —
  # so verify with --unsigned. The bundle is otherwise expected to be
  # complete now, so a failure here is a real error, not a soft warning.
  cargo run --quiet -p release-verifier --bin release-verifier -- "$DIST" --check-manifest --unsigned || fail "release-verifier failed (unsigned mode)"
fi

# --- summary -----------------------------------------------------------------
log "DONE — release at: $DIST"
cat <<EOF

Flash & boot (the easy path):
  1. Verify:  check the SHA256SUMS value against an independent source you trust.
  2. Flash:   open balenaEtcher (Windows/macOS/Linux), select
              $IMG.gz, select your USB drive, Flash. Etcher verifies the write.
              (Advanced: Rufus on Windows, or  gunzip -c $IMG.gz | sudo dd of=/dev/sdX bs=4M  on Linux/macOS.)
  3. Practice first (recommended): run the desktop rehearsal edition — it walks
     the exact ceremony using public/fake seeds, so nothing is at risk.
  4. Boot:    reboot the target PC, pick the USB drive in the firmware boot menu.
  5. Follow QUICKSTART.md on the screen.

EXPERIMENTAL — not externally audited. Do not use to protect substantial funds.
EOF
