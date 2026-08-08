"""Bech32 / Bech32m encoding (BIP173, BIP350; SPEC §24.2/§24.3: P2WPKH/P2TR
addresses).

Encode-only, implemented directly from BIP173 and BIP350 reference
pseudocode. The only difference between the two is the checksum
constant: witness version 0 uses classic Bech32 (BIP173), witness
version >= 1 uses Bech32m (BIP350). No third-party dependency.
"""

from __future__ import annotations

from typing import List

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: List[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp: str, data: List[int], const: int) -> List[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> List[int]:
    """General power-of-2 base conversion (BIP173 reference `convertbits`)."""
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid data value for convertbits")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in convertbits")
    return ret


def segwit_addr_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address per BIP173 (witver 0) / BIP350 (witver >= 1).

    `witver` in 0..16, `witprog` length in 2..40 bytes, with the BIP141
    v0 restriction to exactly 20 or 32 bytes.
    """
    if not (0 <= witver <= 16):
        raise ValueError("invalid witness version")
    if not (2 <= len(witprog) <= 40):
        raise ValueError("invalid witness program length")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("invalid witness program length for version 0")

    const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    data = [witver] + convertbits(witprog, 8, 5, True)
    checksum = _create_checksum(hrp, data, const)
    combined = data + checksum
    return hrp + "1" + "".join(_CHARSET[d] for d in combined)
