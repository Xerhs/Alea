#!/usr/bin/env python3
"""tests/qemu/decode-qr.py — decode the QR symbol out of an export-screen PPM.

Answers "does the Stage 7 export screen's QR actually scan?" against the real
rendered pixels (see `tests/qemu/render-screens/`), rather than against the
module matrix a unit test can inspect directly.

Needs a QR decoder on the host. It tries, in order:
  1. `zxingcpp` (pip: `zxing-cpp` — a self-contained wheel, no system lib),
  2. `cv2.QRCodeDetector` (pip: `opencv-python-headless`),
  3. `zbarimg` on PATH (apt: `zbar-tools`).
If none is present it says so and exits 2 — an honest "not verified", never a
silent pass.

Usage:
    python3 tests/qemu/decode-qr.py IMG.ppm [IMG.ppm ...]
    python3 tests/qemu/decode-qr.py --expect-substr xpub6 IMG.ppm
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ppm2png import read_ppm  # noqa: E402


def to_gray(w, h, rgb):
    import numpy as np

    arr = np.frombuffer(rgb, dtype=np.uint8).reshape(h, w, 3)
    return (
        0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    ).astype("uint8")


def decode(path):
    w, h, rgb = read_ppm(path)
    try:
        import zxingcpp

        gray = to_gray(w, h, rgb)
        results = zxingcpp.read_barcodes(gray)
        if results:
            return "zxingcpp", [(r.format.name if hasattr(r.format, "name") else str(r.format), r.text) for r in results]
        return "zxingcpp", []
    except ImportError:
        pass
    try:
        import cv2
        import numpy as np

        gray = to_gray(w, h, rgb)
        text, pts, _ = cv2.QRCodeDetector().detectAndDecode(gray)
        return "cv2", [("QRCode", text)] if text else []
    except ImportError:
        pass
    if subprocess.run(["which", "zbarimg"], capture_output=True).returncode == 0:
        out = subprocess.run(["zbarimg", "--raw", "-q", path], capture_output=True)
        text = out.stdout.decode(errors="replace").strip()
        return "zbarimg", [("QRCode", text)] if text else []
    return None, []


def main(argv):
    expect = None
    files = []
    i = 0
    while i < len(argv):
        if argv[i] == "--expect-substr":
            expect = argv[i + 1]
            i += 2
        else:
            files.append(argv[i])
            i += 1
    if not files:
        print(__doc__)
        return 2

    failures = 0
    for path in files:
        engine, results = decode(path)
        if engine is None:
            print("SKIPPED: no QR decoder available (install zxing-cpp, "
                  "opencv-python-headless, or zbar-tools)")
            return 2
        if not results:
            print(f"FAIL {os.path.basename(path)}: {engine} found no barcode")
            failures += 1
            continue
        for fmt, text in results:
            ok = expect is None or expect in text
            status = "PASS" if ok else "FAIL"
            if not ok:
                failures += 1
            print(f"{status} {os.path.basename(path)} [{engine}/{fmt}] "
                  f"{len(text)} chars: {text}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
