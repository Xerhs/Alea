"""Hash primitives (SPEC §11.6, §14, §24.2).

Wraps Python stdlib `hashlib`/`hmac` only, per the WP-11 brief
("Pure Python (hashlib, hmac; implement secp256k1 point math, bech32,
base58 yourself -- stdlib only)"). No third-party dependency.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac


def sha256(data: bytes) -> bytes:
    """SHA-256(data), 32 bytes."""
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """SHA-256(SHA-256(data)) -- Base58Check checksum input (SPEC §24.2)."""
    return sha256(sha256(data))


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA512(key, msg), 64 bytes.

    Used for BIP32 master-key generation (`"Bitcoin seed"` key, SPEC
    §24.2) and BIP32 child-key derivation.
    """
    return _hmac.new(key, msg, hashlib.sha512).digest()


def pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA512(password, salt, iterations), 64 bytes.

    SPEC §14 / §24.2: BIP39 seed derivation, always used with 2048
    iterations, salt `b"mnemonic"` (+ optional passphrase, always empty
    in this project -- SPEC §5 excludes BIP39 passphrase entry).
    """
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=64)
