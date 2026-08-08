#!/usr/bin/env bash
# tests/qemu/boot-smoke.sh — WP-31 (SPEC §29.3).
#
# Headless boot-and-assert smoke test: boots an edition under QEMU/OVMF
# with the serial port wired straight to a log file (no monitor
# multiplexing — see `lib/common.sh` doc comment on why a dedicated
# chardev is used instead of `mon:stdio`), waits up to a timeout, then
# greps the captured serial transcript for the expected pre-secret banner
# text (SPEC §5 for the always-on banner; SPEC §22.1 opening warning for
# the full pre-secret flow entry screen).
#
# This only exercises text-console output (SPEC §12.1 permits firmware
# text pre-secret) — the GOP-rendered secret-phase screens (mnemonic
# display etc., WP-26) are NOT visible over serial; see `screenshot.sh`
# for those.
#
# SAFE TO RUN ANYWHERE: prints "SKIPPED: ..." and exits 0 if QEMU/OVMF are
# not installed.
#
# Usage:
#   tests/qemu/boot-smoke.sh [test|production] [--timeout SECONDS]
#
# Exit status: 0 if every expected string is found (or a clean SKIPPED
# short-circuit); 1 if QEMU ran but the expected text never appeared.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_prereqs_or_skip
OVMF_CODE_PATH="${HAVE_OVMF_CODE}"
OVMF_VARS_TEMPLATE="${HAVE_OVMF_VARS}"

EDITION="${1:-test}"
TIMEOUT_SECS="15"
if [[ "${2:-}" == "--timeout" ]]; then
    TIMEOUT_SECS="${3:?--timeout requires a value in seconds}"
fi

case "${EDITION}" in
    test|production) ;;
    *)
        echo "usage: $0 [test|production] [--timeout SECONDS]" >&2
        exit 2
        ;;
esac

# Text every edition MUST print before anything secret-bearing (SPEC §5
# banner is test-edition-only per its own doc comment; the SPEC §22.1
# opening-warning title comes from the shared `seed-flow` driver and is
# common to both editions since WP-27 reuses the same flow logic).
EXPECTED_STRINGS=("ALEA")
if [[ "${EDITION}" == "test" ]]; then
    EXPECTED_STRINGS+=("PUBLIC TEST PHRASE")
fi

EFI_BIN="$(efi_bin_path "${EDITION}" --build)"
EFI_NAME="$(basename "${EFI_BIN}")"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

OVMF_VARS_COPY="$(scratch_ovmf_vars "${WORKDIR}" "${OVMF_VARS_TEMPLATE}")"
ESP_DIR="$(build_esp "${WORKDIR}" "${EFI_BIN}")"
SERIAL_LOG="${WORKDIR}/serial.log"

QEMU_ARGS=(
    -machine q35
    -m 256M
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE_PATH}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    -drive "format=raw,file=fat:rw:${ESP_DIR}"
    -net none
    -display none
    -chardev "stdio,id=char-serial,signal=off"
    -serial chardev:char-serial
    -no-reboot
)

qlog "boot-smoke: ${EFI_NAME}, timeout=${TIMEOUT_SECS}s"
qlog "  serial log: ${SERIAL_LOG}"

# `timeout` is expected to fire here in the common case (the pre-secret
# flow blocks on a keypress that never arrives over a closed stdin) —
# that is success, not failure; only the captured text matters. `|| true`
# so a SIGTERM-caused non-zero exit from `timeout`/qemu doesn't trip
# `set -e` before we get to check the transcript.
timeout "${TIMEOUT_SECS}" qemu-system-x86_64 "${QEMU_ARGS[@]}" </dev/null >"${SERIAL_LOG}" 2>&1 || true

MISSING=0
for expected in "${EXPECTED_STRINGS[@]}"; do
    if ! grep -qF "${expected}" "${SERIAL_LOG}"; then
        qerr "expected string not found in serial transcript: '${expected}'"
        MISSING=1
    fi
done

if [[ "${MISSING}" -ne 0 ]]; then
    qerr "--- captured serial transcript (${SERIAL_LOG}) ---"
    cat "${SERIAL_LOG}" >&2 || true
    qerr "--- end transcript ---"
    exit 1
fi

qlog "PASS: all expected strings found for ${EDITION} edition"
