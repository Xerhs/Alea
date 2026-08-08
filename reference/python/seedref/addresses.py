"""Address construction for the four fixed derivation standards
(SPEC §24.2 table, §24.3 display rules).

| Standard | Path                | Script type           | Address form |
|----------|---------------------|------------------------|--------------|
| BIP44    | m/44'/0'/0'/0/0     | P2PKH (legacy)         | 1...         |
| BIP49    | m/49'/0'/0'/0/0     | P2SH-P2WPKH (nested)   | 3...         |
| BIP84    | m/84'/0'/0'/0/0     | P2WPKH (native segwit) | bc1q...      |
| BIP86    | m/86'/0'/0'/0/0     | P2TR (taproot)         | bc1p...      |
"""

from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from .base58 import base58check_encode
from .bech32 import segwit_addr_encode
from .bip32 import derive_path, h, master_from_seed, master_fingerprint
from .ripemd160 import hash160
from .secp256k1 import privkey_to_compressed_pubkey, privkey_to_xonly_pubkey, taproot_tweak_pubkey

_MAINNET_P2PKH_VERSION = 0x00
_MAINNET_P2SH_VERSION = 0x05
_MAINNET_HRP = "bc"

#: Account/change/index levels shared by all four standards: account 0,
#: external chain, index 0 (SPEC §24.2/§5: "external chain, index 0").
_ACCOUNT0_EXTERNAL_0 = [h(0), 0, 0]


class PathStandard(Enum):
    """Mirrors `contracts.rs`' `PathStandard` (SPEC §24.2)."""

    BIP44 = "bip44"
    BIP49 = "bip49"
    BIP84 = "bip84"
    BIP86 = "bip86"


_PURPOSE = {
    PathStandard.BIP44: 44,
    PathStandard.BIP49: 49,
    PathStandard.BIP84: 84,
    PathStandard.BIP86: 86,
}


def path_for(standard: PathStandard) -> list:
    """The full derivation path `m/purpose'/0'/0'/0/0` for `standard`."""
    return [h(_PURPOSE[standard]), h(0)] + _ACCOUNT0_EXTERNAL_0


def p2pkh_address(compressed_pubkey: bytes) -> str:
    """BIP44 legacy address: `base58check(0x00 || hash160(pubkey))`."""
    return base58check_encode(bytes([_MAINNET_P2PKH_VERSION]) + hash160(compressed_pubkey))


def p2sh_p2wpkh_address(compressed_pubkey: bytes) -> str:
    """BIP49 nested-segwit address: the witness program script is
    `OP_0 <20-byte-hash160(pubkey)>` (i.e. `0x0014` || hash160(pubkey));
    the P2SH address hashes *that script*, not the pubkey hash directly
    (SPEC §24.2 pitfall)."""
    witness_script = b"\x00\x14" + hash160(compressed_pubkey)
    return base58check_encode(bytes([_MAINNET_P2SH_VERSION]) + hash160(witness_script))


def p2wpkh_address(compressed_pubkey: bytes) -> str:
    """BIP84 native-segwit address: bech32(witver=0, hash160(pubkey))."""
    return segwit_addr_encode(_MAINNET_HRP, 0, hash160(compressed_pubkey))


def p2tr_address(xonly_internal_pubkey: bytes) -> str:
    """BIP86 taproot address: bech32m(witver=1, tweaked x-only pubkey).

    Uses the *tweaked* output key, not the raw internal key (SPEC §24.2
    pitfall)."""
    tweaked = taproot_tweak_pubkey(xonly_internal_pubkey)
    return segwit_addr_encode(_MAINNET_HRP, 1, tweaked)


class DerivationResult(NamedTuple):
    master_fingerprint_hex: str
    addresses: dict  # PathStandard -> address string


def first_address(seed: bytes, standard: PathStandard) -> str:
    """First external receive address (account 0, index 0) for `standard`,
    derived directly from a 64-byte BIP39 seed (SPEC §24.2)."""
    master = master_from_seed(seed)
    node = derive_path(master, path_for(standard))

    if standard == PathStandard.BIP44:
        pub = privkey_to_compressed_pubkey(node.key)
        return p2pkh_address(pub)
    if standard == PathStandard.BIP49:
        pub = privkey_to_compressed_pubkey(node.key)
        return p2sh_p2wpkh_address(pub)
    if standard == PathStandard.BIP84:
        pub = privkey_to_compressed_pubkey(node.key)
        return p2wpkh_address(pub)
    if standard == PathStandard.BIP86:
        xonly = privkey_to_xonly_pubkey(node.key)
        return p2tr_address(xonly)
    raise ValueError(f"unknown standard: {standard}")


def derive_verification_values(seed: bytes) -> DerivationResult:
    """SPEC §24.3 screen contents: master fingerprint + all four first
    receive addresses, derived from one BIP39 seed."""
    master = master_from_seed(seed)
    fp = master_fingerprint(master).hex()
    addrs = {std: first_address(seed, std) for std in PathStandard}
    return DerivationResult(master_fingerprint_hex=fp, addresses=addrs)
