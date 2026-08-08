#!/usr/bin/env bash
# tests/qemu/run.sh — WP-31 (SPEC §29.3).
#
# Boots an Alea UEFI edition under QEMU + OVMF interactively (serial
# console attached to this terminal's stdio) for manual exploration. This
# is the "just boot it and look" entry point; see `boot-smoke.sh` for the
# scripted/headless assertion runner and `screenshot.sh` for GOP-screen
# capture.
#
# SAFE TO RUN ANYWHERE: if `qemu-system-x86_64` or an OVMF firmware pair
# is not installed, this prints a SKIPPED line and exits 0 immediately —
# it never hangs and never fails a CI step.
#
# Usage:
#   tests/qemu/run.sh [test|production] [--timeout SECONDS]
#
# Requires (once QEMU/OVMF are installed):
#   - qemu-system-x86_64 on PATH
#   - An OVMF firmware pair (code + vars). Override the search with
#     OVMF_CODE / OVMF_VARS env vars if your distro doesn't ship the
#     defaults probed in lib/common.sh.
#   - The target crate built for x86_64-unknown-uefi (built automatically
#     if missing, via `cargo build -p <crate> --target x86_64-unknown-uefi`).
#
# Exit status: 0 on a clean SKIPPED short-circuit, otherwise forwards
# QEMU's own exit status.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_prereqs_or_skip
OVMF_CODE_PATH="${HAVE_OVMF_CODE}"
OVMF_VARS_TEMPLATE="${HAVE_OVMF_VARS}"

EDITION="${1:-test}"
TIMEOUT_SECS=""
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

EFI_BIN="$(efi_bin_path "${EDITION}" --build)"
EFI_NAME="$(basename "${EFI_BIN}")"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

OVMF_VARS_COPY="$(scratch_ovmf_vars "${WORKDIR}" "${OVMF_VARS_TEMPLATE}")"
ESP_DIR="$(build_esp "${WORKDIR}" "${EFI_BIN}")"

QEMU_ARGS=(
    -machine q35
    -m 256M
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE_PATH}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    -drive "format=raw,file=fat:rw:${ESP_DIR}"
    -net none
    -nographic
    -serial mon:stdio
    -no-reboot
)

qlog "booting ${EFI_NAME} under OVMF (SPEC §29.3) ..."
qlog "  code: ${OVMF_CODE_PATH}"
qlog "  vars: ${OVMF_VARS_TEMPLATE} (scratch copy)"
qlog "  esp:  ${ESP_DIR}"
qlog "  (serial console is multiplexed onto this terminal: Ctrl-A C for the QEMU monitor, Ctrl-A X to quit)"

if [[ -n "${TIMEOUT_SECS}" ]]; then
    exec timeout "${TIMEOUT_SECS}" qemu-system-x86_64 "${QEMU_ARGS[@]}"
else
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
fi
