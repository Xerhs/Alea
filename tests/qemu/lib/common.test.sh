#!/usr/bin/env bash
# tests/qemu/lib/common.test.sh — WP-31 (SPEC §29.3).
#
# Fast, host-only unit tests for `lib/common.sh`'s pure shell helpers.
# Unlike every other script in `tests/qemu/`, this one does NOT require
# QEMU or OVMF to be installed (it never invokes `qemu-system-x86_64`) and
# always runs — there is nothing here for `require_prereqs_or_skip` to
# gate.
#
# Regression coverage for the finding that `build_esp()` never wrote a
# `startup.nsh`: on a fresh (never-before-booted) OVMF NVRAM, "EFI
# Internal Shell" is registered as Boot0001 *ahead of* the ESP's
# removable-media \EFI\BOOT\BOOTX64.EFI fallback, so without a
# `startup.nsh` at the ESP root the firmware drops to an interactive
# "Shell>" prompt instead of ever auto-executing the Alea binary —
# every other script in this directory (`boot-smoke.sh`, `serial-drive.sh`,
# `screenshot.sh`, `run.sh`) then either times out waiting for text that
# is never printed, or (screenshot.sh) silently baselines a screenshot of
# the Shell prompt instead of the app.
#
# Usage: tests/qemu/lib/common.test.sh
# Exit status: 0 if every assertion passes, 1 otherwise (with a diagnostic
# printed to stderr for the first failure encountered).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

FAILED=0

fail() {
    echo "FAIL: $*" >&2
    FAILED=1
}

# ---------------------------------------------------------------------------
# build_esp(): must produce \EFI\BOOT\BOOTX64.EFI AND a root startup.nsh
# that chainloads it, so a Shell-first fresh-NVRAM boot still reaches the
# app instead of stopping at an interactive prompt.
# ---------------------------------------------------------------------------

test_build_esp_writes_bootx64() {
    local workdir fake_efi esp_dir
    workdir="$(mktemp -d)"
    fake_efi="${workdir}/fake-input.efi"
    printf 'not a real PE binary, just needs to exist and be copyable' > "${fake_efi}"

    esp_dir="$(build_esp "${workdir}" "${fake_efi}")"

    if [[ "${esp_dir}" != "${workdir}/esp" ]]; then
        fail "build_esp printed unexpected esp path: '${esp_dir}' (expected '${workdir}/esp')"
    fi
    if [[ ! -f "${esp_dir}/EFI/BOOT/BOOTX64.EFI" ]]; then
        fail "build_esp did not write \\EFI\\BOOT\\BOOTX64.EFI under ${esp_dir}"
    elif ! cmp -s "${fake_efi}" "${esp_dir}/EFI/BOOT/BOOTX64.EFI"; then
        fail "BOOTX64.EFI content does not match the source binary"
    fi

    rm -rf "${workdir}"
}

test_build_esp_writes_startup_nsh() {
    local workdir fake_efi esp_dir nsh_path nsh_content
    workdir="$(mktemp -d)"
    fake_efi="${workdir}/fake-input.efi"
    printf 'not a real PE binary, just needs to exist and be copyable' > "${fake_efi}"

    esp_dir="$(build_esp "${workdir}" "${fake_efi}")"
    nsh_path="${esp_dir}/startup.nsh"

    if [[ ! -f "${nsh_path}" ]]; then
        fail "build_esp did not write a startup.nsh at the ESP root (${nsh_path}) — a fresh-NVRAM OVMF boot will stop at the Shell prompt instead of auto-running BOOTX64.EFI"
    else
        nsh_content="$(cat "${nsh_path}")"
        # The Shell chainloads via the FS0: mapping + Windows-style
        # backslash path; this is the exact line verified (in the
        # reviewed finding) to make a real OVMF Shell auto-run the app.
        if [[ "${nsh_content}" != 'FS0:\EFI\BOOT\BOOTX64.EFI' ]]; then
            fail "startup.nsh has unexpected content: '${nsh_content}' (expected 'FS0:\\EFI\\BOOT\\BOOTX64.EFI')"
        fi
    fi

    rm -rf "${workdir}"
}

test_build_esp_writes_bootx64
test_build_esp_writes_startup_nsh

if [[ "${FAILED}" -ne 0 ]]; then
    echo "[qemu-harness] common.test.sh: FAILED" >&2
    exit 1
fi

echo "[qemu-harness] common.test.sh: PASS (build_esp writes BOOTX64.EFI + startup.nsh)"
