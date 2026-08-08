#!/usr/bin/env bash
# tests/qemu/lib/common.sh — WP-31 (SPEC §29.3).
#
# Shared shell functions for every script in `tests/qemu/`. This file is
# meant to be `source`d, never executed directly.
#
# Design goal (per this WP's DoD): every script that sources this file
# MUST be safe to run in an environment with no QEMU/OVMF installed at
# all. `require_prereqs_or_skip` is the single gate every entry-point
# script calls first, before doing anything else (in particular, before
# any `cargo build` — that can be slow, and a missing-tool skip must be
# near-instant and must never hang).

# Not `set -e` here: this file only defines functions; the caller (an
# entry-point script) owns its own `set -euo pipefail`.

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Resolve once, relative to this file, so callers can `source` it from any
# cwd. `QEMU_DIR` is `tests/qemu`; `REPO_ROOT` is the repository root.
QEMU_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_DIR="$(cd "${QEMU_LIB_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${QEMU_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

qlog() { echo "[qemu-harness] $*" >&2; }
qerr() { echo "[qemu-harness] error: $*" >&2; }

# ---------------------------------------------------------------------------
# Tool / firmware detection
# ---------------------------------------------------------------------------

# Prints "yes"/"no"; never fails.
have_qemu() {
    if command -v qemu-system-x86_64 >/dev/null 2>&1; then
        echo "yes"
    else
        echo "no"
    fi
}

# Probes common OVMF install locations (edk2-ovmf package names differ by
# distro). Honors OVMF_CODE / OVMF_VARS env overrides. Prints the path on
# stdout and returns 0 on success; returns 1 (prints nothing) if not found.
find_ovmf_code() {
    if [[ -n "${OVMF_CODE:-}" ]]; then
        [[ -f "${OVMF_CODE}" ]] && { echo "${OVMF_CODE}"; return 0; }
        return 1
    fi
    local candidate
    for candidate in \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/qemu/OVMF.fd
    do
        [[ -f "${candidate}" ]] && { echo "${candidate}"; return 0; }
    done
    return 1
}

find_ovmf_vars() {
    if [[ -n "${OVMF_VARS:-}" ]]; then
        [[ -f "${OVMF_VARS}" ]] && { echo "${OVMF_VARS}"; return 0; }
        return 1
    fi
    local candidate
    for candidate in \
        /usr/share/OVMF/OVMF_VARS.fd \
        /usr/share/OVMF/OVMF_VARS_4M.fd \
        /usr/share/edk2/ovmf/OVMF_VARS.fd \
        /usr/share/edk2-ovmf/x64/OVMF_VARS.fd
    do
        [[ -f "${candidate}" ]] && { echo "${candidate}"; return 0; }
    done
    return 1
}

# THE gate. Call this first, before anything else, in every entry-point
# script. On success, sets HAVE_OVMF_CODE / HAVE_OVMF_VARS as globals and
# returns 0. On any missing prerequisite it prints the mandated SKIPPED
# line to stdout (so it shows up in captured CI/test-runner output, not
# just stderr) and calls `exit 0` itself — callers never need their own
# `exit 0` after calling this.
require_prereqs_or_skip() {
    local missing=0
    if [[ "$(have_qemu)" != "yes" ]]; then
        missing=1
    fi
    local ovmf_code ovmf_vars
    if ! ovmf_code="$(find_ovmf_code)"; then
        missing=1
    fi
    if ! ovmf_vars="$(find_ovmf_vars)"; then
        missing=1
    fi

    if [[ "${missing}" -eq 1 ]]; then
        echo "SKIPPED: qemu/ovmf not installed — run: sudo apt-get install -y qemu-system-x86 ovmf"
        exit 0
    fi

    HAVE_OVMF_CODE="${ovmf_code}"
    HAVE_OVMF_VARS="${ovmf_vars}"
}

# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------

cargo_target_dir() {
    echo "${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
}

# Resolves (and, if requested, builds) the UEFI binary for an edition.
# Usage: efi_bin_path <test|production> [--build]
efi_bin_path() {
    local edition="$1"
    local do_build="${2:-}"
    local crate efi_name
    case "${edition}" in
        test) crate="seed-uefi-test" ;;
        production) crate="seed-uefi-production" ;;
        *) qerr "unknown edition '${edition}' (expected test|production)"; return 2 ;;
    esac
    efi_name="${crate//-/_}.efi"

    local target_dir bin alt_bin
    target_dir="$(cargo_target_dir)"
    bin="${target_dir}/x86_64-unknown-uefi/debug/${efi_name}"
    alt_bin="${target_dir}/x86_64-unknown-uefi/debug/${crate}.efi"

    if [[ ! -f "${bin}" && ! -f "${alt_bin}" && "${do_build}" == "--build" ]]; then
        qlog "building ${crate} for x86_64-unknown-uefi ..."
        ( source "$HOME/.cargo/env" 2>/dev/null || true
          cd "${REPO_ROOT}" && \
          CARGO_TARGET_DIR="${target_dir}" cargo build -p "${crate}" --target x86_64-unknown-uefi ) >&2
    fi

    if [[ -f "${bin}" ]]; then
        echo "${bin}"
        return 0
    elif [[ -f "${alt_bin}" ]]; then
        echo "${alt_bin}"
        return 0
    fi

    qerr "built EFI binary not found; expected one of:"
    qerr "  ${bin}"
    qerr "  ${alt_bin}"
    qerr "Build first: cargo build -p ${crate} --target x86_64-unknown-uefi"
    return 1
}

# ---------------------------------------------------------------------------
# ESP / OVMF scratch-state helpers
# ---------------------------------------------------------------------------

# Builds a minimal `\EFI\BOOT\BOOTX64.EFI` ESP tree under $1/esp, copying
# the given EFI binary ($2). QEMU's built-in `fat:` vvfat driver serves it
# straight off the directory — no `mtools`/`mcopy`/loop-mount/root needed,
# which matters because this must work unprivileged in CI containers.
#
# Also drops a one-line `startup.nsh` at the ESP root. A never-before-
# booted OVMF's fresh NVRAM registers "EFI Internal Shell" as Boot0001
# *ahead of* the ESP's removable-media \EFI\BOOT\BOOTX64.EFI fallback, so
# without this the firmware drops to an interactive "Shell>" prompt
# instead of ever running our binary (verified against real
# qemu-system-x86_64 8.2.2 + OVMF 2024.02 — the exact
# `qemu-system-x86 ovmf` combo this harness's README tells users to
# install — every other script in this directory then times out waiting
# for text that is never printed). The UEFI Shell's own startup
# convention is to look for `startup.nsh` at the root of a mapped
# filesystem and, if found, run it non-interactively instead of dropping
# to the prompt, so chainloading our binary from it makes the
# Shell-first boot path reach the same place the removable-media
# fallback would have.
build_esp() {
    local workdir="$1" efi_bin="$2"
    local esp_root="${workdir}/esp"
    local esp_boot_dir="${esp_root}/EFI/BOOT"
    mkdir -p "${esp_boot_dir}"
    cp "${efi_bin}" "${esp_boot_dir}/BOOTX64.EFI"
    printf '%s\n' 'FS0:\EFI\BOOT\BOOTX64.EFI' > "${esp_root}/startup.nsh"
    echo "${esp_root}"
}

# Makes a scratch, writable copy of the OVMF vars template so repeated /
# parallel runs never fight over shared NVRAM state (QEMU mutates the vars
# file in place).
scratch_ovmf_vars() {
    local workdir="$1" template="$2"
    local copy="${workdir}/OVMF_VARS.fd"
    cp "${template}" "${copy}"
    echo "${copy}"
}

# A free-ish local TCP port for the human monitor protocol. Not
# race-proof against a concurrent bind between the check and QEMU's own
# bind, but this harness never runs two instances against the same port
# concurrently in practice (each caller mktemp's its own workdir), and a
# retry loop would add more flakiness than it removes for a test harness.
free_tcp_port() {
    local base="${1:-4444}"
    local port="${base}"
    while (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
        port=$((port + 1))
    done
    echo "${port}"
}

# Sends a single human-monitor-protocol command to a QEMU instance
# listening on `-monitor telnet:127.0.0.1:<port>,server,nowait`, over a
# plain bash `/dev/tcp` socket (no `nc`/`socat` dependency). Best-effort:
# swallows connection errors so a slow-starting monitor doesn't abort the
# whole script.
monitor_send() {
    local port="$1" cmd="$2"
    local fd
    # `exec` with only redirections and no command applies them for the
    # *rest of the calling shell*, not just this statement — a bare
    # `exec {fd}<>... 2>/dev/null` would permanently silence every later
    # qlog/qerr call in the caller (screenshot.sh's MATCH/MISMATCH/NOTE/
    # PASS lines all went missing this way before this fix). Brace groups
    # scope `2>/dev/null` to just the one `exec` inside them, while still
    # running it in the current shell so `fd` and the socket it opens
    # persist for the rest of this function (a subshell `( ... )` would
    # not do that — its fd would vanish when the subshell exits).
    { exec {fd}<>"/dev/tcp/127.0.0.1/${port}"; } 2>/dev/null || return 1
    printf '%s\n' "${cmd}" >&"${fd}"
    # Drain and discard the monitor's reply so it doesn't block the next
    # connection attempt; a short read timeout keeps this bounded.
    timeout 2 cat <&"${fd}" >/dev/null 2>&1 || true
    { exec {fd}<&- {fd}>&-; } 2>/dev/null || true
}

# Polls until a TCP port is accepting connections, or times out.
wait_for_tcp_port() {
    local port="$1" timeout_secs="${2:-15}"
    local waited=0
    while ! (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
        sleep 0.5
        waited=$((waited + 1))
        if [[ "${waited}" -ge $((timeout_secs * 2)) ]]; then
            return 1
        fi
    done
    # Same bare-`exec`-with-no-command hazard as `monitor_send` above: a
    # plain `exec 3>&- 3<&- 2>/dev/null` here would permanently redirect
    # the *caller's* stderr to /dev/null for the rest of its script (this
    # function returns success right after, straight into
    # screenshot.sh's per-delay capture loop, so every later qlog/qerr —
    # MATCH/MISMATCH/NOTE/PASS — would silently vanish). The brace group
    # scopes `2>/dev/null` to just this fd-close.
    { exec 3>&- 3<&-; } 2>/dev/null || true
    return 0
}
