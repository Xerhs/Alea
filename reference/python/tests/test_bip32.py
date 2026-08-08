import unittest

from seedref.base58 import base58_encode
from seedref.bip32 import HARDENED_OFFSET, ckd_priv, master_fingerprint, master_from_seed
from seedref.hashes import double_sha256
from seedref.secp256k1 import privkey_to_compressed_pubkey

_XPRV_VERSION = bytes.fromhex("0488ADE4")
_XPUB_VERSION = bytes.fromhex("0488B21E")


def _serialize_xprv(depth: int, parent_fp: bytes, child_number: int, chain_code: bytes, key: bytes) -> str:
    payload = (
        _XPRV_VERSION
        + bytes([depth])
        + parent_fp
        + child_number.to_bytes(4, "big")
        + chain_code
        + b"\x00"
        + key
    )
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def _serialize_xpub(depth: int, parent_fp: bytes, child_number: int, chain_code: bytes, key: bytes) -> str:
    pub = privkey_to_compressed_pubkey(key)
    payload = (
        _XPUB_VERSION
        + bytes([depth])
        + parent_fp
        + child_number.to_bytes(4, "big")
        + chain_code
        + pub
    )
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


class Bip32VectorWalker:
    """Walks a BIP32 test-vector chain, serializing xprv/xpub at each
    step exactly like the reference `bip32.mediawiki` test vectors, so
    this project's `master_from_seed`/`ckd_priv` can be checked against
    the officially published base58 strings without needing a base58
    *decoder* (SPEC/this package is encode-focused; re-deriving and
    re-encoding is an equally strong cross-check)."""

    def __init__(self, seed: bytes) -> None:
        self.node = master_from_seed(seed)
        self.depth = 0
        self.parent_fp = b"\x00\x00\x00\x00"
        self.child_number = 0

    def xprv(self) -> str:
        return _serialize_xprv(self.depth, self.parent_fp, self.child_number, self.node.chain_code, self.node.key)

    def xpub(self) -> str:
        return _serialize_xpub(self.depth, self.parent_fp, self.child_number, self.node.chain_code, self.node.key)

    def descend(self, index: int) -> None:
        fp = master_fingerprint(self.node)
        child = ckd_priv(self.node, index)
        self.node = child
        self.depth += 1
        self.parent_fp = fp
        self.child_number = index


class TestBip32Vector1(unittest.TestCase):
    SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_chain(self) -> None:
        w = Bip32VectorWalker(self.SEED)
        self.assertEqual(
            w.xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        )
        self.assertEqual(
            w.xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )

        w.descend(HARDENED_OFFSET + 0)
        self.assertEqual(
            w.xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        )
        self.assertEqual(
            w.xpub(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        )

        w.descend(1)
        self.assertEqual(
            w.xprv(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        )
        self.assertEqual(
            w.xpub(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        )

        w.descend(HARDENED_OFFSET + 2)
        self.assertEqual(
            w.xprv(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        )
        self.assertEqual(
            w.xpub(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        )

        w.descend(2)
        self.assertEqual(
            w.xprv(),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        )
        self.assertEqual(
            w.xpub(),
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        )

        w.descend(1000000000)
        self.assertEqual(
            w.xprv(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        )
        self.assertEqual(
            w.xpub(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        )


class TestBip32Vector2(unittest.TestCase):
    SEED = bytes.fromhex(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
        "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    )

    def test_chain_including_large_non_hardened_index(self) -> None:
        w = Bip32VectorWalker(self.SEED)
        self.assertEqual(
            w.xprv(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        )

        w.descend(0)
        self.assertEqual(
            w.xprv(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        )

        w.descend(HARDENED_OFFSET + 2147483647)
        self.assertEqual(
            w.xprv(),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        )

        w.descend(1)
        self.assertEqual(
            w.xprv(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        )

        w.descend(HARDENED_OFFSET + 2147483646)
        self.assertEqual(
            w.xprv(),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        )

        w.descend(2)
        self.assertEqual(
            w.xprv(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        )


class TestBip32Vector3LeadingZeros(unittest.TestCase):
    """Retention of leading zeros in derived private keys."""

    SEED = bytes.fromhex(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4"
        "acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    )

    def test_chain(self) -> None:
        w = Bip32VectorWalker(self.SEED)
        self.assertEqual(
            w.xprv(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        )
        w.descend(HARDENED_OFFSET + 0)
        self.assertEqual(
            w.xprv(),
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        )


class TestBip32Vector4LeadingZeros(unittest.TestCase):
    SEED = bytes.fromhex("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")

    def test_chain(self) -> None:
        w = Bip32VectorWalker(self.SEED)
        self.assertEqual(
            w.xprv(),
            "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        )
        w.descend(HARDENED_OFFSET + 0)
        self.assertEqual(
            w.xprv(),
            "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        )
        w.descend(HARDENED_OFFSET + 1)
        self.assertEqual(
            w.xprv(),
            "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        )


if __name__ == "__main__":
    unittest.main()
