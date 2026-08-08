#!/usr/bin/env bash
# tests/qemu/screenshot.sh — WP-31 (SPEC §29.3).
#
# Captures GOP framebuffer screenshots from a running QEMU instance and
# hash-compares them against known-good baselines under `golden/`. This
# is the only way to observe the secret-phase screens (WP-26's mnemonic
# display etc.): they render straight to the GOP linear framebuffer
# (`seed-gop-ui`), never through the text console `serial-drive.sh`/
# `boot-smoke.sh` can see.
#
# # How this differs from the other scripts
#
# `-nographic` (used by `run.sh`/`boot-smoke.sh`/`serial-drive.sh`)
# disables QEMU's video card entirely, so there is no GOP to screenshot.
# This script instead attaches a real (but headless) video device
# (`-vga std`, `-display none`) and drives the QEMU *human monitor
# protocol* over a plain TCP socket (via bash's own `/dev/tcp`, no `nc`/
# `socat` dependency — see `lib/common.sh`) to issue `screendump` at
# fixed delays. Serial is still attached (to a log file) so pre-secret
# progress remains visible for sequencing.
#
# # Known limitation: fixed-delay capture, not event-driven
#
# There is no signal from the guest back to this harness saying "the
# mnemonic-display screen is now on screen" — GOP writes are invisible to
# QEMU's monitor/serial introspection. Captures happen at a fixed set of
# delays after boot instead. This is inherently timing-fragile; on a
# real QEMU/OVMF install, tune `--delays` to match observed timing, or
# (better) extend `serial-drive.sh` to walk the pre-secret text menus up
# to the secret-phase handoff first, *then* start this script's captures
# relative to that known point. See README.md.
#
# Usage:
#   tests/qemu/screenshot.sh [test|production] [--out DIR]
#                            [--delays "3 6 10"] [--timeout SECONDS]
#
# Output: one `screen-<delay>s.ppm` file per delay under --out (default:
# a fresh dir under tests/qemu/out/), plus a `.sha256` next to each. If
# `golden/<edition>/screen-<delay>s.sha256` already exists, the freshly
# captured hash is compared against it (mismatch -> non-zero exit); if it
# does not exist yet, this script writes it as a new baseline and prints
# a NOTE (first-run baselining — review the .ppm before trusting it).
#
# SAFE TO RUN ANYWHERE: prints "SKIPPED: ..." and exits 0 if QEMU/OVMF are
# not installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_prereqs_or_skip
OVMF_CODE_PATH="${HAVE_OVMF_CODE}"
OVMF_VARS_TEMPLATE="${HAVE_OVMF_VARS}"

EDITION="test"
OUT_DIR=""
DELAYS="3 6 10"
OVERALL_TIMEOUT="30"

while [[ $# -gt 0 ]]; do
    case "$1" in
        test|production) EDITION="$1"; shift ;;
        --out) OUT_DIR="${2:?}"; shift 2 ;;
        --delays) DELAYS="${2:?}"; shift 2 ;;
        --timeout) OVERALL_TIMEOUT="${2:?}"; shift 2 ;;
        *) qerr "unknown argument: $1"; exit 2 ;;
    esac
done

if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="${QEMU_DIR}/out/$(date -u +%Y%m%dT%H%M%SZ)-${EDITION}"
fi
mkdir -p "${OUT_DIR}"

GOLDEN_DIR="${QEMU_DIR}/golden/${EDITION}"
mkdir -p "${GOLDEN_DIR}"

EFI_BIN="$(efi_bin_path "${EDITION}" --build)"
EFI_NAME="$(basename "${EFI_BIN}")"

WORKDIR="$(mktemp -d)"
SERIAL_LOG="${WORKDIR}/serial.log"
MONITOR_PORT="$(free_tcp_port 4555)"

OVMF_VARS_COPY="$(scratch_ovmf_vars "${WORKDIR}" "${OVMF_VARS_TEMPLATE}")"
ESP_DIR="$(build_esp "${WORKDIR}" "${EFI_BIN}")"

QEMU_ARGS=(
    -machine q35
    -m 256M
    -vga std
    -display none
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE_PATH}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    -drive "format=raw,file=fat:rw:${ESP_DIR}"
    -net none
    -monitor "telnet:127.0.0.1:${MONITOR_PORT},server,nowait"
    -serial "file:${SERIAL_LOG}"
    -no-reboot
)

qlog "screenshot: ${EFI_NAME}, delays=[${DELAYS}]s, out=${OUT_DIR}"
qlog "  monitor port: ${MONITOR_PORT}"

QEMU_PID=""
cleanup() {
    if [[ -n "${QEMU_PID}" ]]; then
        monitor_send "${MONITOR_PORT}" "quit" || true
        sleep 0.3
        kill "${QEMU_PID}" >/dev/null 2>&1 || true
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

timeout "${OVERALL_TIMEOUT}" qemu-system-x86_64 "${QEMU_ARGS[@]}" </dev/null >/dev/null 2>&1 &
QEMU_PID=$!

if ! wait_for_tcp_port "${MONITOR_PORT}" 15; then
    qerr "QEMU monitor never became reachable on port ${MONITOR_PORT}"
    exit 1
fi
# Give the monitor a moment past "port open" to finish its own startup
# banner before the first real command.
sleep 0.5

FAILED=0
for delay in ${DELAYS}; do
    sleep "${delay}"
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        qerr "QEMU exited before the ${delay}s capture"
        FAILED=1
        break
    fi
    shot_name="screen-${delay}s"
    shot_path="${OUT_DIR}/${shot_name}.ppm"
    monitor_send "${MONITOR_PORT}" "screendump ${shot_path}" || true
    # `screendump` writes asynchronously relative to the monitor reply;
    # give it a moment to land before hashing.
    sleep 0.3
    if [[ ! -f "${shot_path}" ]]; then
        qerr "expected screenshot not written: ${shot_path}"
        FAILED=1
        continue
    fi
    hash="$(sha256sum "${shot_path}" | awk '{print $1}')"
    echo "${hash}  ${shot_name}.ppm" > "${OUT_DIR}/${shot_name}.sha256"

    golden_file="${GOLDEN_DIR}/${shot_name}.sha256"
    if [[ -f "${golden_file}" ]]; then
        golden_hash="$(awk '{print $1}' "${golden_file}")"
        if [[ "${hash}" == "${golden_hash}" ]]; then
            qlog "MATCH ${shot_name}: ${hash}"
        else
            qerr "MISMATCH ${shot_name}: got ${hash}, golden ${golden_hash} (${shot_path} vs ${golden_file})"
            FAILED=1
        fi
    else
        cp "${OUT_DIR}/${shot_name}.sha256" "${golden_file}"
        qlog "NOTE: no golden baseline for ${shot_name} yet — wrote one from this run (${golden_file}). Review ${shot_path} by hand before trusting it as a real baseline."
    fi
done

cp "${SERIAL_LOG}" "${OUT_DIR}/serial.log" 2>/dev/null || true

if [[ "${FAILED}" -ne 0 ]]; then
    exit 1
fi

qlog "PASS: screenshots captured for ${EDITION} edition under ${OUT_DIR}"
