#!/usr/bin/env bash
# tests/qemu/serial-drive.sh — WP-31 (SPEC §29.3).
#
# Drives the pre-secret text-console flow (SPEC §22.1-§22.5) end to end
# by injecting keystrokes over the emulated serial port and asserting on
# the transcript as it grows. This is the "serial input injection" piece
# of this work package's brief.
#
# # Why serial injection works here
#
# `crates/seed-flow/src/keys.rs` and the SPEC §22 screens read
# input through the firmware's `SIMPLE_TEXT_INPUT_PROTOCOL` (`ConIn`).
# Stock OVMF (`OvmfPkg`, as packaged by `qemu-system-x86` distros) wires
# its serial port into the same console splitter as the graphical
# keyboard console via `TerminalDxe`, so plain ASCII bytes written to the
# serial chardev (Enter = `\r`, Escape = ESC `\x1b`, Backspace = `\x08`,
# printable chars as themselves) arrive at `ConIn` exactly as if typed at
# a local keyboard. This is the same mechanism every "drive the UEFI
# Shell over a serial cable" guide relies on.
#
# This assumption is NOT re-verified by this script (it can't be, without
# QEMU installed) — the first real run on a QEMU-equipped machine is the
# actual verification. If it turns out an OVMF build's console splitter
# does *not* include serial in `ConIn` by default, the fix is a firmware
# variable / build flag, not a change to this script's approach.
#
# # Only pre-secret is covered
#
# The GOP-rendered secret-phase screens (WP-26 mnemonic display etc.) are
# not text-console output and are not observable or drivable this way;
# see `screenshot.sh`. Driving *into* the secret phase over serial may
# still work (the physical-entry screens before mnemonic display are read
# through the same `ConIn`), but this script's bundled example scripts
# stop at the pre-secret/secret-phase boundary deliberately, since the
# exact entropy-mode menu keybindings are owned by WP-25/26, not this WP,
# and asserting on them here would be guessing at another WP's contract.
#
# # Script file format
#
# One directive per line, blank lines and `#`-comments ignored:
#   WAIT <seconds>          sleep before the next directive
#   SEND <literal text>     write the literal bytes (no trailing newline)
#   KEY ENTER|ESC|BACKSPACE send the corresponding single control byte
#   EXPECT <substring>      poll the transcript-so-far for this substring,
#                           up to --expect-timeout seconds (default 10)
#
# Usage:
#   tests/qemu/serial-drive.sh <script-file> [test|production]
#                               [--timeout SECONDS] [--expect-timeout SECONDS]
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

KEY_SCRIPT="${1:?usage: $0 <script-file> [test|production] [--timeout SECONDS] [--expect-timeout SECONDS]}"
shift

EDITION="test"
if [[ $# -gt 0 && "$1" != --* ]]; then
    EDITION="$1"
    shift
fi

OVERALL_TIMEOUT="60"
EXPECT_TIMEOUT="10"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) OVERALL_TIMEOUT="${2:?}"; shift 2 ;;
        --expect-timeout) EXPECT_TIMEOUT="${2:?}"; shift 2 ;;
        *) qerr "unknown argument: $1"; exit 2 ;;
    esac
done

if [[ ! -f "${KEY_SCRIPT}" ]]; then
    qerr "no such key script: ${KEY_SCRIPT}"
    exit 2
fi

case "${EDITION}" in
    test|production) ;;
    *) qerr "unknown edition '${EDITION}' (expected test|production)"; exit 2 ;;
esac

EFI_BIN="$(efi_bin_path "${EDITION}" --build)"
EFI_NAME="$(basename "${EFI_BIN}")"

WORKDIR="$(mktemp -d)"
FIFO="${WORKDIR}/serial-in.fifo"
SERIAL_LOG="${WORKDIR}/serial.log"
mkfifo "${FIFO}"
: >"${SERIAL_LOG}"

OVMF_VARS_COPY="$(scratch_ovmf_vars "${WORKDIR}" "${OVMF_VARS_TEMPLATE}")"
ESP_DIR="$(build_esp "${WORKDIR}" "${EFI_BIN}")"

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

qlog "serial-drive: ${EFI_NAME}, script=${KEY_SCRIPT}"
qlog "  serial log: ${SERIAL_LOG}"

QEMU_PID=""
cleanup() {
    [[ -n "${QEMU_PID}" ]] && kill "${QEMU_PID}" >/dev/null 2>&1 || true
    # `exec` with only redirections and no command applies them for the
    # *rest of the shell*, not just this statement — a bare
    # `exec 9>&- 2>/dev/null` would permanently silence every later qlog/
    # qerr line (including the final PASS/FAIL diagnostics) for the rest
    # of the script. The brace group scopes `2>/dev/null` to just this
    # one `exec 9>&-` (closing our copy of the FIFO write end so a
    # not-yet-opened fd 9 doesn't print "bad file descriptor"), while
    # still running the `exec` itself in the current shell so it actually
    # closes fd 9 rather than a subshell's copy.
    { exec 9>&-; } 2>/dev/null || true
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# Launch QEMU reading its serial input from the FIFO and writing output
# to the log file. The `timeout` wrapper bounds the whole run in case a
# WAIT/EXPECT never resolves.
timeout "${OVERALL_TIMEOUT}" qemu-system-x86_64 "${QEMU_ARGS[@]}" <"${FIFO}" >"${SERIAL_LOG}" 2>&1 &
QEMU_PID=$!

# Open the FIFO's write side and keep it open for the whole run — opening
# a FIFO for read blocks until a writer exists, and closing the last
# writer sends EOF to the reader, which would end qemu's stdin stream
# after the first write otherwise.
exec 9>"${FIFO}"

send_bytes() {
    printf '%s' "$1" >&9
}

wait_for_expect() {
    local needle="$1" waited_ms=0 step_ms=200
    while ! grep -qF "${needle}" "${SERIAL_LOG}" 2>/dev/null; do
        sleep 0.2
        waited_ms=$((waited_ms + step_ms))
        if [[ "${waited_ms}" -ge $((EXPECT_TIMEOUT * 1000)) ]]; then
            return 1
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

FAILED=0
LINE_NO=0
while IFS= read -r line || [[ -n "${line}" ]]; do
    LINE_NO=$((LINE_NO + 1))
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    directive="${line%% *}"
    arg="${line#* }"
    [[ "${arg}" == "${line}" ]] && arg=""
    case "${directive}" in
        WAIT)
            sleep "${arg}"
            ;;
        SEND)
            send_bytes "${arg}"
            ;;
        KEY)
            case "${arg}" in
                ENTER) send_bytes $'\r' ;;
                ESC) send_bytes $'\x1b' ;;
                BACKSPACE) send_bytes $'\x08' ;;
                *) qerr "line ${LINE_NO}: unknown KEY '${arg}'"; FAILED=1 ;;
            esac
            ;;
        EXPECT)
            if ! wait_for_expect "${arg}"; then
                qerr "line ${LINE_NO}: EXPECT '${arg}' not seen within ${EXPECT_TIMEOUT}s"
                FAILED=1
                break
            fi
            ;;
        *)
            qerr "line ${LINE_NO}: unknown directive '${directive}'"
            FAILED=1
            ;;
    esac
    if [[ "${FAILED}" -ne 0 ]]; then
        break
    fi
done < "${KEY_SCRIPT}"

# See the matching brace-group comment in cleanup() above: a bare
# `exec 9>&- 2>/dev/null` (no command) would permanently redirect this
# script's stderr to /dev/null for everything that follows, silently
# swallowing the PASS/FAIL qlog/qerr lines below.
{ exec 9>&-; } 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=""

if [[ "${FAILED}" -ne 0 ]]; then
    qerr "--- captured serial transcript (${SERIAL_LOG}) ---"
    cat "${SERIAL_LOG}" >&2 || true
    qerr "--- end transcript ---"
    exit 1
fi

qlog "PASS: ${KEY_SCRIPT} completed against ${EDITION} edition"
