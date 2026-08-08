"""Pure-Python RIPEMD-160 (SPEC §24.2: `hash160 = RIPEMD160(SHA256(x))`).

Vendored from the Bitcoin Core project's test framework (MIT-licensed,
public-domain-equivalent reference code), since the stdlib `hashlib`
RIPEMD-160 implementation is only conditionally available depending on
the local OpenSSL build's legacy-provider configuration and this
reference implementation must run identically everywhere (WP-11 brief:
"implement ... yourself -- stdlib only" spirit -- RIPEMD-160 support is
not guaranteed present in `hashlib.algorithms_available`, so it is
vendored here rather than relied upon).

Source: Bitcoin Core, `test/functional/test_framework/ripemd160.py`,
Copyright (c) 2021 Pieter Wuille, MIT License. Verified byte-for-byte
against the ISO/IEC 10118-3 RIPEMD-160 known-answer vectors below (see
`tests/test_ripemd160.py`) before being trusted by this package.
"""

from __future__ import annotations

# Message schedule indexes for the left path.
_ML = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

# Message schedule indexes for the right path.
_MR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]

# Rotation counts for the left path.
_RL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

# Rotation counts for the right path.
_RR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

# K constants for the left path.
_KL = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]

# K constants for the right path.
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]


def _fi(x: int, y: int, z: int, i: int) -> int:
    """The f1, f2, f3, f4, f5 functions from the specification."""
    if i == 0:
        return x ^ y ^ z
    if i == 1:
        return (x & y) | (~x & z)
    if i == 2:
        return (x | ~y) ^ z
    if i == 3:
        return (x & z) | (y & ~z)
    if i == 4:
        return x ^ (y | ~z)
    raise AssertionError("unreachable")


def _rol(x: int, i: int) -> int:
    """Rotate the bottom 32 bits of x left by i bits."""
    return ((x << i) | ((x & 0xFFFFFFFF) >> (32 - i))) & 0xFFFFFFFF


def _compress(h0: int, h1: int, h2: int, h3: int, h4: int, block: bytes):
    """Compress state (h0..h4) with one 64-byte block."""
    al, bl, cl, dl, el = h0, h1, h2, h3, h4
    ar, br, cr, dr, er = h0, h1, h2, h3, h4
    x = [int.from_bytes(block[4 * i : 4 * (i + 1)], "little") for i in range(16)]

    for j in range(80):
        rnd = j >> 4
        al = _rol((al + _fi(bl, cl, dl, rnd) + x[_ML[j]] + _KL[rnd]) & 0xFFFFFFFF, _RL[j])
        al = (al + el) & 0xFFFFFFFF
        al, bl, cl, dl, el = el, al, bl, _rol(cl, 10), dl

        ar = _rol((ar + _fi(br, cr, dr, 4 - rnd) + x[_MR[j]] + _KR[rnd]) & 0xFFFFFFFF, _RR[j])
        ar = (ar + er) & 0xFFFFFFFF
        ar, br, cr, dr, er = er, ar, br, _rol(cr, 10), dr

    return (
        (h1 + cl + dr) & 0xFFFFFFFF,
        (h2 + dl + er) & 0xFFFFFFFF,
        (h3 + el + ar) & 0xFFFFFFFF,
        (h4 + al + br) & 0xFFFFFFFF,
        (h0 + bl + cr) & 0xFFFFFFFF,
    )


def ripemd160(data: bytes) -> bytes:
    """Compute the RIPEMD-160 digest of `data` (20 bytes)."""
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    for b in range(len(data) >> 6):
        state = _compress(*state, data[64 * b : 64 * (b + 1)])
    pad = b"\x80" + b"\x00" * ((119 - len(data)) & 63)
    fin = data[len(data) & ~63 :] + pad + (8 * len(data)).to_bytes(8, "little")
    for b in range(len(fin) >> 6):
        state = _compress(*state, fin[64 * b : 64 * (b + 1)])
    return b"".join((h & 0xFFFFFFFF).to_bytes(4, "little") for h in state)


def hash160(data: bytes) -> bytes:
    """`hash160(x) = RIPEMD160(SHA256(x))` (SPEC §24.2), 20 bytes."""
    from .hashes import sha256

    return ripemd160(sha256(data))
