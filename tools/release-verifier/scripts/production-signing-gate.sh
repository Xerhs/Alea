#!/usr/bin/env bash
# WP-32 (SPEC §28, §32): the production-signing refusal gate.
#
# SPEC §28 requires, of the release pipeline itself (not just the
# compiled artifact): "production signing refuses artifacts with test
# markers"; "test and production use different signing identities";
# "test builds cannot be renamed into production by the release
# pipeline". This script is the mechanical enforcement of those three
# clauses, meant to run as the one mandatory gate between "an unsigned
# `.efi` sits on disk" and "an external signer is invoked against it" in
# any real release pipeline (CI or otherwise).
#
# Like `tools/release-verifier` (SPEC §10, §32 — see that crate's own
# doc comment), this script deliberately does NOT vendor or perform any
# signing cryptography itself: real production code-signing requires key
# custody, multi-person approval and (for Level 2/3, SPEC §33) an
# external CA relationship that cannot exist inside this source tree
# (see `SECURITY.md`'s "Reporting a vulnerability" section and
# `docs/secure-boot.md`). What CAN live in this repository, and is
# implemented here, is the structural refusal logic that must run
# before any real signer is invoked, regardless of what that signer is:
#
#   1. Refuse if the artifact fails the `binary-policy-scanner` gate
#      (SPEC §28 "production signing refuses artifacts with test
#      markers") — checked by CONTENT, not by file name, which is what
#      makes step 3 below true for free: an attacker (or a confused CI
#      script) cannot rename `seed-uefi-test.efi` to
#      `alea-x86_64-unsigned.efi` and have it pass, because the
#      scanner parses the PE/COFF bytes themselves.
#   2. Refuse if the declared production and test signing identities are
#      the same string (SPEC §28 "test and production use different
#      signing identities"). This script does not know what a signing
#      identity concretely *is* for any given signer (a key fingerprint,
#      a certificate subject, an HSM slot label...) — it only enforces
#      that whatever two identity strings the caller supplies are
#      textually distinct, which is the one property expressible without
#      assuming a specific signing backend.
#   3. Refuse if the requested output file name does not match one of
#      the two fixed SPEC §32 release-archive names
#      (`alea-x86_64-unsigned.efi` /
#      `alea-x86_64-signed.efi`) — a second, independent guard
#      against a mis-named artifact silently entering the release
#      archive under the wrong identity.
#
# Only once all three checks pass does this script either invoke a
# caller-supplied `--sign-cmd` (for a real pipeline with a real signer
# wired in) or, with no `--sign-cmd`, print the exact next step and exit
# 0 (a "gate passed" dry run — useful for CI legs that only want to
# assert the structural gate, not perform an actual signature).
#
# Usage:
#   production-signing-gate.sh \
#     --artifact <path-to-unsigned.efi> \
#     --out-name <alea-x86_64-unsigned.efi|alea-x86_64-signed.efi> \
#     --prod-identity <string> \
#     --test-identity <string> \
#     [--scanner <path-to-binary-policy-scanner>] \
#     [--sign-cmd <shell command>]
#
# `--sign-cmd` is run via `sh -c`, with the environment variables
# SIGNING_GATE_ARTIFACT and SIGNING_GATE_OUT_NAME set, only after both
# structural checks above have passed.
#
# Exit codes:
#   0  — all gates passed (and --sign-cmd, if given, exited 0).
#   1  — a SPEC §28 policy refusal (test marker found, identities equal,
#        or bad output name).
#   64 — usage error.
#   *  — whatever --sign-cmd itself exited with, if it was run and failed.
set -euo pipefail

usage() {
    cat <<'EOF'
usage: production-signing-gate.sh --artifact FILE --out-name NAME \
           --prod-identity ID --test-identity ID \
           [--scanner PATH] [--sign-cmd CMD]

Refuses (exit 1) to proceed toward signing when:
  - `binary-policy-scanner FILE` reports any violation (SPEC §28: test
    markers, watermark banners, hidden-entropy-toggle markers, etc);
  - --prod-identity and --test-identity are the same string;
  - --out-name is not one of alea-x86_64-unsigned.efi /
    alea-x86_64-signed.efi (SPEC §32 fixed release names).

If every gate passes and --sign-cmd is given, runs it (via `sh -c`) and
exits with its exit code. If every gate passes and --sign-cmd is not
given, prints the pending manual signing step and exits 0.
EOF
}

ARTIFACT=""
OUT_NAME=""
PROD_IDENTITY=""
TEST_IDENTITY=""
SCANNER="binary-policy-scanner"
SIGN_CMD=""

while [ $# -gt 0 ]; do
    case "$1" in
        --artifact) ARTIFACT="$2"; shift 2 ;;
        --out-name) OUT_NAME="$2"; shift 2 ;;
        --prod-identity) PROD_IDENTITY="$2"; shift 2 ;;
        --test-identity) TEST_IDENTITY="$2"; shift 2 ;;
        --scanner) SCANNER="$2"; shift 2 ;;
        --sign-cmd) SIGN_CMD="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
    esac
done

if [ -z "$ARTIFACT" ] || [ -z "$OUT_NAME" ] || [ -z "$PROD_IDENTITY" ] || [ -z "$TEST_IDENTITY" ]; then
    echo "error: --artifact, --out-name, --prod-identity and --test-identity are all required" >&2
    usage >&2
    exit 64
fi

echo "== production-signing-gate: $ARTIFACT -> $OUT_NAME =="

# --- Gate 1: SPEC §28 "production signing refuses artifacts with test
# markers". Content-based (the scanner parses PE/COFF bytes), so this
# gate is unaffected by whatever ARTIFACT or OUT_NAME happen to be named
# — SPEC §28's "test builds cannot be renamed into production by the
# release pipeline" clause falls directly out of that content-based
# check, not out of any separate file-name allowlist. ---
if [ ! -f "$ARTIFACT" ]; then
    echo "FAIL: artifact not found: $ARTIFACT" >&2
    exit 1
fi

echo "-- gate 1/3: binary-policy-scanner content scan --"
if ! "$SCANNER" "$ARTIFACT"; then
    echo "REFUSED: $ARTIFACT failed the binary-policy scan — production signing" >&2
    echo "         MUST refuse artifacts carrying test markers (SPEC §28)." >&2
    exit 1
fi
echo "PASS: gate 1/3 (no test markers; production marker present)."

# --- Gate 2: SPEC §28 "test and production use different signing
# identities". ---
echo "-- gate 2/3: signing-identity separation --"
if [ "$PROD_IDENTITY" = "$TEST_IDENTITY" ]; then
    echo "REFUSED: --prod-identity and --test-identity are identical ('$PROD_IDENTITY')." >&2
    echo "         SPEC §28 requires test and production to use different signing" >&2
    echo "         identities; refusing to sign with a shared identity." >&2
    exit 1
fi
echo "PASS: gate 2/3 (production identity '$PROD_IDENTITY' differs from test identity '$TEST_IDENTITY')."

# --- Gate 3: SPEC §32 fixed release-archive artifact names. A second,
# independent guard on the *output* side against a mis-named artifact
# entering the release archive. ---
echo "-- gate 3/3: output file-name policy --"
case "$OUT_NAME" in
    alea-x86_64-unsigned.efi|alea-x86_64-signed.efi) ;;
    *)
        echo "REFUSED: --out-name '$OUT_NAME' is not a recognized SPEC §32 release" >&2
        echo "         artifact name (alea-x86_64-unsigned.efi or" >&2
        echo "         alea-x86_64-signed.efi)." >&2
        exit 1
        ;;
esac
echo "PASS: gate 3/3 ('$OUT_NAME' is a recognized SPEC §32 release name)."

echo "== all gates passed =="

if [ -n "$SIGN_CMD" ]; then
    echo "-- running --sign-cmd --"
    SIGNING_GATE_ARTIFACT="$ARTIFACT" SIGNING_GATE_OUT_NAME="$OUT_NAME" sh -c "$SIGN_CMD"
    exit $?
fi

echo "(no --sign-cmd given: this was a structural-gate dry run only)"
echo "Next step: sign '$ARTIFACT' as '$PROD_IDENTITY', writing the result to '$OUT_NAME'."
echo "This script does not perform that step itself — see SECURITY.md and"
echo "docs/secure-boot.md for the (external, not-yet-established) signing-key"
echo "custody process this repository does not and cannot vendor."
exit 0
