#!/usr/bin/env python3
"""tests/qemu/ppm2png.py — convert QEMU `screendump` PPM output to PNG.

QEMU's human-monitor / QMP `screendump` writes binary PPM (P6). Nothing on
a minimal Linux host reads that: no ImageMagick, no PIL. This converter is
pure standard library (`zlib` + `struct`), so the harness never depends on
an image toolchain being installed.

Usage:
    python3 tests/qemu/ppm2png.py IN.ppm [OUT.png]
    python3 tests/qemu/ppm2png.py --all DIR      # every *.ppm in DIR

With `--crop X,Y,W,H` a sub-rectangle is written instead of the whole
frame (used to isolate the export screen's QR matrix for decoding).
"""

import os
import struct
import sys
import zlib


def read_ppm(path):
    """Returns (width, height, rgb_bytes) for a binary P6 PPM."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"P6"):
        raise ValueError(f"{path}: not a binary P6 PPM")
    # Header: P6 <w> <h> <maxval>, whitespace-separated, '#' comments allowed.
    fields = []
    i = 2
    while len(fields) < 3:
        while i < len(data) and data[i : i + 1].isspace():
            i += 1
        if data[i : i + 1] == b"#":
            while i < len(data) and data[i] != 0x0A:
                i += 1
            continue
        j = i
        while j < len(data) and not data[j : j + 1].isspace():
            j += 1
        fields.append(int(data[i:j]))
        i = j
    i += 1  # single whitespace byte after maxval
    w, h, maxval = fields
    if maxval != 255:
        raise ValueError(f"{path}: unsupported maxval {maxval}")
    return w, h, data[i : i + w * h * 3]


def crop(w, h, rgb, x0, y0, cw, ch):
    out = bytearray()
    for y in range(y0, min(y0 + ch, h)):
        start = (y * w + x0) * 3
        out += rgb[start : start + cw * 3]
    return cw, min(y0 + ch, h) - y0, bytes(out)


def write_png(path, w, h, rgb):
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter type 0 (None)
        raw += rgb[y * w * 3 : (y + 1) * w * 3]

    def chunk(tag, payload):
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def convert(src, dst=None, box=None):
    w, h, rgb = read_ppm(src)
    if box:
        w, h, rgb = crop(w, h, rgb, *box)
    dst = dst or os.path.splitext(src)[0] + ".png"
    write_png(dst, w, h, rgb)
    return dst, w, h


def main(argv):
    box = None
    args = []
    i = 0
    while i < len(argv):
        if argv[i] == "--crop":
            box = tuple(int(v) for v in argv[i + 1].split(","))
            i += 2
        else:
            args.append(argv[i])
            i += 1
    if args and args[0] == "--all":
        directory = args[1]
        for name in sorted(os.listdir(directory)):
            if name.endswith(".ppm"):
                dst, w, h = convert(os.path.join(directory, name), box=box)
                print(f"{dst} {w}x{h}")
        return 0
    if not args:
        print(__doc__)
        return 2
    dst, w, h = convert(args[0], args[1] if len(args) > 1 else None, box=box)
    print(f"{dst} {w}x{h}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
