#!/usr/bin/env python3
"""tests/qemu/drive-ceremony.py — drive the whole GOP-rendered ceremony
under QEMU + OVMF, by emulated keyboard, capturing a screenshot per stage.

# Why this exists (and why `serial-drive.sh` no longer suffices)

`serial-drive.sh` injects bytes on the serial chardev and asserts on the
*serial transcript*. Since the 2026-08-06 GOP amendment (commit 9625405)
both UEFI editions render the entire ceremony — banner, warnings, gates,
selections and every secret-phase screen — straight to the GOP linear
framebuffer. Nothing is written to the firmware text console any more, so
`EXPECT <substring>` has nothing to match: the transcript is empty. The
serial path is also only a *side* channel into `ConIn`, which real
hardware does not have.

This driver instead:

  * boots the REAL release image (`-drive format=raw,file=...`), or a
    scratch ESP built from a single `.efi`;
  * injects keys as an emulated PS/2 keyboard through QMP `send-key` —
    the same path a physical keyboard takes into
    `SIMPLE_TEXT_INPUT_PROTOCOL`, so the keystream this harness proves is
    the keystream a user actually types;
  * captures the framebuffer with QMP `screendump` at each named stage.

Only the five `InputEvent` shapes the product can observe exist here
(`crates/seed-platform-x86/src/input/mod.rs`): printable ASCII, Enter,
Escape, Backspace — everything else arrives as `Other` and is dropped, so
arrows/F-keys are deliberately unsupported.

# Keystream script format

One directive per line; `#` starts a comment.

    WAIT <seconds>          sleep (float ok)
    KEY <token> [token...]  send keys, in order
    TYPE <literal text>     send each character of the rest of the line
    SHOT <name>             screendump to <out>/<name>.ppm
    DELAY <ms>              default per-key delay for later KEY/TYPE lines
    ECHO <text>             print a progress marker

`KEY` tokens: a single printable character, or one of `ENTER`, `ESC`,
`BACKSPACE`, `SPACE`. `TYPE` is the bulk form used for the 50/100 dice
rolls and the 24-word re-entry prefixes.

# Usage

    tests/qemu/drive-ceremony.py --image dist/alea-x86_64-usb.img \\
        --script tests/qemu/scripts/production-happy-path.keys \\
        --out tests/qemu/out/run1

    tests/qemu/drive-ceremony.py --efi <path>.efi --script ... --out ...

Exit status is 0 only if every directive ran, QEMU stayed alive to the
end, and no screendump was missing.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

OVMF_CODE_CANDIDATES = [
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
]
OVMF_VARS_CANDIDATES = [
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
]

# Character -> (qcode, needs_shift). Only what the product can observe.
QCODE = {}
for _c in "abcdefghijklmnopqrstuvwxyz":
    QCODE[_c] = (_c, False)
    QCODE[_c.upper()] = (_c, True)
for _c in "0123456789":
    QCODE[_c] = (_c, False)
QCODE.update(
    {
        " ": ("spc", False),
        "-": ("minus", False),
        "_": ("minus", True),
        ".": ("dot", False),
        ",": ("comma", False),
        "/": ("slash", False),
        "'": ("apostrophe", False),
        ";": ("semicolon", False),
        "=": ("equal", False),
        "+": ("equal", True),
        "!": ("1", True),
        "@": ("2", True),
        "#": ("3", True),
        "$": ("4", True),
        "%": ("5", True),
        "^": ("6", True),
        "&": ("7", True),
        "*": ("8", True),
        "(": ("9", True),
        ")": ("0", True),
        ":": ("semicolon", True),
        "?": ("slash", True),
    }
)
NAMED = {
    "ENTER": ("ret", False),
    "RET": ("ret", False),
    "ESC": ("esc", False),
    "BACKSPACE": ("backspace", False),
    "SPACE": ("spc", False),
}


def find_first(paths, override):
    if override:
        return override
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


class Qmp:
    """Minimal QMP client (no external dependency)."""

    def __init__(self, path, timeout=30.0):
        deadline = time.time() + timeout
        self.sock = None
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(path)
                self.sock = s
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.2)
        if self.sock is None:
            raise RuntimeError(f"QMP socket never appeared at {path}")
        self.sock.settimeout(20.0)
        self.buf = b""
        self._read_json()  # greeting
        self.command("qmp_capabilities")

    def _read_json(self):
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1 :]
                if line.strip():
                    return json.loads(line)
                continue
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("QMP connection closed")
            self.buf += chunk

    def command(self, name, **args):
        msg = {"execute": name}
        if args:
            msg["arguments"] = args
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        while True:
            reply = self._read_json()
            if "event" in reply:  # asynchronous; ignore
                continue
            if "error" in reply:
                raise RuntimeError(f"QMP {name} failed: {reply['error']}")
            return reply.get("return")

    def send_key(self, qcode, shift=False, hold_ms=60):
        keys = []
        if shift:
            keys.append({"type": "qcode", "data": "shift"})
        keys.append({"type": "qcode", "data": qcode})
        self.command("send-key", keys=keys, **{"hold-time": hold_ms})

    def screendump(self, path):
        self.command("screendump", filename=path)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def build_esp(workdir, efi_bin, verify_efi=None):
    esp = os.path.join(workdir, "esp")
    boot = os.path.join(esp, "EFI", "BOOT")
    os.makedirs(boot, exist_ok=True)
    shutil.copy(efi_bin, os.path.join(boot, "BOOTX64.EFI"))
    if verify_efi:
        alea = os.path.join(esp, "EFI", "ALEA")
        os.makedirs(alea, exist_ok=True)
        shutil.copy(verify_efi, os.path.join(alea, "VERIFY.EFI"))
    with open(os.path.join(esp, "startup.nsh"), "w", encoding="ascii") as fh:
        fh.write("FS0:\\EFI\\BOOT\\BOOTX64.EFI\n")
    return esp


def parse_script(path):
    directives = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            verb, _, rest = stripped.partition(" ")
            directives.append((lineno, verb.upper(), rest))
    return directives


def tokens_to_keys(tokens, lineno):
    out = []
    for tok in tokens:
        up = tok.upper()
        if up in NAMED:
            out.append(NAMED[up])
        elif len(tok) == 1 and tok in QCODE:
            out.append(QCODE[tok])
        else:
            raise SystemExit(f"script line {lineno}: unknown key token {tok!r}")
    return out


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--image", help="raw bootable image (the real release .img)")
    src.add_argument("--efi", help="a single .efi to stage at \\EFI\\BOOT\\BOOTX64.EFI")
    ap.add_argument("--verify-efi", help="with --efi: also stage \\EFI\\ALEA\\VERIFY.EFI")
    ap.add_argument("--script", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mem", default="512M")
    ap.add_argument("--boot-wait", type=float, default=12.0,
                    help="seconds to wait after power-on before the first directive")
    ap.add_argument("--key-delay", type=int, default=90, help="default ms between keys")
    ap.add_argument("--timeout", type=int, default=900, help="hard QEMU kill timeout")
    ap.add_argument("--ovmf-code")
    ap.add_argument("--ovmf-vars")
    args = ap.parse_args()

    code = find_first(OVMF_CODE_CANDIDATES, args.ovmf_code)
    varsf = find_first(OVMF_VARS_CANDIDATES, args.ovmf_vars)
    if not shutil.which("qemu-system-x86_64") or not code or not varsf:
        print("SKIPPED: qemu/ovmf not installed — run: sudo apt-get install -y qemu-system-x86 ovmf")
        return 0

    os.makedirs(args.out, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="alea-qemu-")
    qmp_path = os.path.join(workdir, "qmp.sock")
    serial_log = os.path.join(args.out, "serial.log")
    vars_copy = os.path.join(workdir, "OVMF_VARS.fd")
    shutil.copy(varsf, vars_copy)

    if args.image:
        disk = ["-drive", f"format=raw,file={args.image}"]
    else:
        esp = build_esp(workdir, args.efi, args.verify_efi)
        disk = ["-drive", f"format=raw,file=fat:rw:{esp}"]

    qemu = [
        "qemu-system-x86_64",
        "-machine", "q35",
        "-m", args.mem,
        "-vga", "std",
        "-display", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_copy}",
        *disk,
        "-net", "none",
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-serial", f"file:{serial_log}",
        "-no-reboot",
    ]

    print("[drive] " + " ".join(qemu), flush=True)
    proc = subprocess.Popen(qemu, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    started = time.time()
    failures = []
    shots = []
    try:
        qmp = Qmp(qmp_path)
        print(f"[drive] QMP up; waiting {args.boot_wait}s for firmware+app", flush=True)
        time.sleep(args.boot_wait)

        key_delay = args.key_delay
        for lineno, verb, rest in parse_script(args.script):
            if time.time() - started > args.timeout:
                failures.append(f"line {lineno}: overall timeout")
                break
            if proc.poll() is not None:
                failures.append(f"line {lineno}: QEMU exited early (rc={proc.returncode})")
                break

            if verb == "WAIT":
                time.sleep(float(rest))
            elif verb == "DELAY":
                key_delay = int(rest)
            elif verb == "ECHO":
                print(f"[drive] {rest}", flush=True)
            elif verb == "KEY":
                for qcode, shift in tokens_to_keys(rest.split(), lineno):
                    qmp.send_key(qcode, shift)
                    time.sleep(key_delay / 1000.0)
            elif verb == "TYPE":
                for ch in rest:
                    if ch not in QCODE:
                        raise SystemExit(f"script line {lineno}: untypeable char {ch!r}")
                    qcode, shift = QCODE[ch]
                    qmp.send_key(qcode, shift)
                    time.sleep(key_delay / 1000.0)
            elif verb == "SHOT":
                name = rest.strip()
                path = os.path.abspath(os.path.join(args.out, f"{name}.ppm"))
                qmp.screendump(path)
                time.sleep(0.5)
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    shots.append((name, os.path.getsize(path)))
                    print(f"[drive] SHOT {name} ({os.path.getsize(path)} bytes)", flush=True)
                else:
                    failures.append(f"line {lineno}: screendump {name} not written")
            else:
                raise SystemExit(f"script line {lineno}: unknown directive {verb!r}")

        # A final capture always, so a run that ends unexpectedly still
        # leaves evidence of where it stopped.
        if proc.poll() is None:
            final = os.path.abspath(os.path.join(args.out, "zz-final.ppm"))
            try:
                qmp.screendump(final)
                time.sleep(0.5)
            except (RuntimeError, OSError):
                pass
        try:
            qmp.command("quit")
        except (RuntimeError, OSError):
            pass
        qmp.close()
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    if stderr.strip():
        with open(os.path.join(args.out, "qemu-stderr.log"), "w", encoding="utf-8") as fh:
            fh.write(stderr)

    print(f"[drive] captured {len(shots)} screenshots into {args.out}")
    for name, size in shots:
        print(f"    {name}.ppm  {size}")
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("PASS: keystream ran to completion")
    return 0


if __name__ == "__main__":
    sys.exit(main())
