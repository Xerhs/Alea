"""Base58Check encoding (SPEC §24.2/§24.3: P2PKH/P2SH addresses).

Encode-only, implemented from the public Base58Check description (Bitcoin
address encoding), matching `IMPLEMENTATION_MAP.md` §4's
`base58check_encode` contract shape. No third-party dependency.
"""

from __future__ import annotations

from .hashes import double_sha256

_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    """Plain Base58 encoding (no checksum) of `data`."""
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_ALPHABET[rem])
    out.reverse()
    # Every leading 0x00 byte in the input becomes a leading '1'.
    n_leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * n_leading_zeros + out.decode("ascii")


def base58check_encode(payload: bytes) -> str:
    """Base58Check-encode `payload`: `base58(payload || checksum)`, where
    `checksum = SHA256(SHA256(payload))[0:4]` (SPEC §24.2).

    `payload` is typically `version_byte || hash160(...)` (25 bytes for
    P2PKH/P2SH).
    """
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)
