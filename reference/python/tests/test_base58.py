import unittest

from seedref.base58 import base58check_encode


class TestBase58Check(unittest.TestCase):
    def test_bip49_testnet_p2sh_address_vector(self) -> None:
        # BIP49 published test vector: addressBytes = HASH160(scriptSig),
        # base58check-encoded with the testnet P2SH version byte (0xc4).
        address_bytes = bytes.fromhex("336caa13e08b96080a32b5d818d59b4ab3b36742")
        self.assertEqual(len(address_bytes), 20)
        encoded = base58check_encode(bytes([0xC4]) + address_bytes)
        self.assertEqual(encoded, "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")

    def test_leading_zero_byte_becomes_leading_one(self) -> None:
        encoded = base58check_encode(b"\x00" * 21)
        self.assertTrue(encoded.startswith("1"))

    def test_pubkey_hash_zero_version_known_address(self) -> None:
        # version 0x00 + hash160 of the SEC1-compressed pubkey for
        # privkey=1 -> the famous "private key = 1" Bitcoin address,
        # independently confirmed on-chain (real, funded, widely-known
        # test/donation address -- e.g. blockstream.info/api/address/
        # 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH shows real transaction
        # history), used here purely as a public, reproducible KAT.
        from seedref.ripemd160 import hash160

        pub = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        addr = base58check_encode(bytes([0x00]) + hash160(pub))
        self.assertEqual(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")


if __name__ == "__main__":
    unittest.main()
