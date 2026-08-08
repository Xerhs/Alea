"""BIP32 hierarchical deterministic key derivation (SPEC §24.2).

Implements master-key generation, hardened + normal child-key derivation
(CKD-priv), master fingerprint, and a fixed-path runner, following the
public BIP32 specification text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .hashes import hmac_sha512
from .ripemd160 import hash160
from .secp256k1 import N, privkey_to_compressed_pubkey

HARDENED_OFFSET = 0x8000_0000


@dataclass
class ExtendedKey:
    """A BIP32 extended private key: 32-byte key + 32-byte chain code."""

    key: bytes
    chain_code: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32 or len(self.chain_code) != 32:
            raise ValueError("key and chain_code must each be 32 bytes")


def master_from_seed(seed: bytes) -> ExtendedKey:
    """BIP32 master key: `I = HMAC-SHA512(key=b"Bitcoin seed", data=seed)`;
    `I_L` is the master private key, `I_R` the master chain code
    (SPEC §24.2).
    """
    i = hmac_sha512(b"Bitcoin seed", seed)
    il, ir = i[:32], i[32:]
    il_int = int.from_bytes(il, "big")
    if il_int == 0 or il_int >= N:
        raise ValueError("invalid master key (IL out of range) -- vanishingly unlikely, retry with different seed")
    return ExtendedKey(il, ir)


def ckd_priv(parent: ExtendedKey, index: int) -> ExtendedKey:
    """BIP32 CKD-priv: derive child extended key `index` from `parent`.

    Hardened iff `index >= 0x8000_0000`.
    """
    if not (0 <= index <= 0xFFFFFFFF):
        raise ValueError("index out of range")

    if index >= HARDENED_OFFSET:
        data = b"\x00" + parent.key + index.to_bytes(4, "big")
    else:
        pub = privkey_to_compressed_pubkey(parent.key)
        data = pub + index.to_bytes(4, "big")

    i = hmac_sha512(parent.chain_code, data)
    il, ir = i[:32], i[32:]
    il_int = int.from_bytes(il, "big")
    k_par_int = int.from_bytes(parent.key, "big")
    if il_int >= N:
        raise ValueError("invalid child key (IL >= n) -- caller must retry with index+1 per BIP32")
    child_int = (il_int + k_par_int) % N
    if child_int == 0:
        raise ValueError("invalid child key (result is zero) -- caller must retry with index+1 per BIP32")
    child_key = child_int.to_bytes(32, "big")
    return ExtendedKey(child_key, ir)


def derive_path(master: ExtendedKey, path: List[int]) -> ExtendedKey:
    """Apply `ckd_priv` for each index in `path`, starting from `master`."""
    node = master
    for index in path:
        node = ckd_priv(node, index)
    return node


def master_fingerprint(master: ExtendedKey) -> bytes:
    """First 4 bytes of `HASH160(compressed master pubkey)` (SPEC §24.2)."""
    pub = privkey_to_compressed_pubkey(master.key)
    return hash160(pub)[:4]


def h(index: int) -> int:
    """Hardened-index helper: `h(44) == 0x8000002C`."""
    return index + HARDENED_OFFSET
