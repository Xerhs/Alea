"""Pure-Python secp256k1 point arithmetic (SPEC §13, §24.2).

Implemented from the curve parameters and BIP340/BIP341 public
specifications only (affine Weierstrass point add/double/scalar-mul,
x-only public keys, taproot output-key tweaking). No third-party
elliptic-curve library. Not constant-time -- this is a reference/test
tool operating only on public test vectors (SPEC §4.4), never on
production secrets; SPEC §13's constant-time requirement binds the Rust
production implementation, not this independent reference.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .hashes import sha256

Point = Tuple[int, int]

#: Field prime: p = 2**256 - 2**32 - 977.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

#: Curve order.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Generator point.
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G: Point = (_GX, _GY)


def _inv(a: int, m: int) -> int:
    """Modular inverse via Fermat's little theorem (m prime)."""
    return pow(a, m - 2, m)


def point_add(p1: Optional[Point], p2: Optional[Point]) -> Optional[Point]:
    """Affine point addition on secp256k1 (`None` is the point at infinity)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv((2 * y1) % P, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(pt: Optional[Point], scalar: int) -> Optional[Point]:
    """Scalar multiplication via double-and-add. `scalar` must be >= 0."""
    result: Optional[Point] = None
    addend = pt
    s = scalar
    while s:
        if s & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        s >>= 1
    return result


def privkey_int_to_pubkey(d: int) -> Point:
    """secp256k1 public point for private scalar `d` (`1 <= d < N`)."""
    if not (1 <= d < N):
        raise ValueError("private scalar out of range")
    pt = point_mul(G, d)
    assert pt is not None
    return pt


def privkey_to_compressed_pubkey(privkey: bytes) -> bytes:
    """33-byte SEC1-compressed public key for a 32-byte private key."""
    d = int.from_bytes(privkey, "big")
    x, y = privkey_int_to_pubkey(d)
    prefix = 2 if (y % 2 == 0) else 3
    return bytes([prefix]) + x.to_bytes(32, "big")


def privkey_to_xonly_pubkey(privkey: bytes) -> bytes:
    """32-byte x-only public key for a 32-byte private key (BIP340 §Public
    Key Generation): the x-coordinate of `d*G`, independent of y-parity.
    """
    d = int.from_bytes(privkey, "big")
    x, _y = privkey_int_to_pubkey(d)
    return x.to_bytes(32, "big")


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP340 tagged hash:
    `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
    """
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + msg)


def lift_x(x: int) -> Optional[Point]:
    """BIP340 `lift_x`: the point on the curve with x-coordinate `x` and an
    even y-coordinate, or `None` if `x` is not a valid x-coordinate.
    """
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    if y % 2 != 0:
        y = P - y
    return (x, y)


def taproot_tweak_pubkey(internal_xonly: bytes) -> bytes:
    """BIP341 key-path-only taproot output key (no script tree):

    `Q = P + tagged_hash("TapTweak", P_x) * G`

    where `P = lift_x(internal_xonly)` (even-y normalization) and the
    result is the 32-byte x-only serialization of `Q` (SPEC §24.2 BIP86
    row). Raises `ValueError` if the internal key or tweak is invalid.
    """
    p_point = lift_x(int.from_bytes(internal_xonly, "big"))
    if p_point is None:
        raise ValueError("invalid internal taproot key")
    t = int.from_bytes(tagged_hash("TapTweak", internal_xonly), "big")
    if t >= N:
        raise ValueError("invalid taproot tweak")
    tweak_point = point_mul(G, t)
    q_point = point_add(p_point, tweak_point)
    if q_point is None:
        raise ValueError("taproot tweak produced point at infinity")
    qx, _qy = q_point
    return qx.to_bytes(32, "big")
