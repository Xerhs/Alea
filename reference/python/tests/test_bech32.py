import unittest

from seedref.bech32 import segwit_addr_encode


class TestBech32Encode(unittest.TestCase):
    """BIP173 / BIP350 "valid segwit addresses" test vectors (encode
    direction -- scriptPubKey hex -> address string). Program bytes below
    are the scriptPubKey with its leading `<version-opcode><push-len>`
    stripped."""

    def test_bip173_v0_20byte_program(self) -> None:
        prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        addr = segwit_addr_encode("bc", 0, prog)
        self.assertEqual(addr.upper(), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")

    def test_bip173_v0_32byte_program(self) -> None:
        prog = bytes.fromhex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
        addr = segwit_addr_encode("tb", 0, prog)
        self.assertEqual(addr, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")

    def test_bip350_v16_2byte_program(self) -> None:
        # BIP350 (current spec: witness version >= 1 uses Bech32m, not
        # the BIP173-era Bech32 -- BC1SW50QGDZ25J supersedes BIP173's now
        # invalid BC1SW50QA3JX3S for this same scriptPubKey 6002751e,
        # 0x60 = OP_16).
        prog = bytes.fromhex("751e")
        addr = segwit_addr_encode("bc", 16, prog)
        self.assertEqual(addr.upper(), "BC1SW50QGDZ25J")

    def test_bip350_v2_16byte_program(self) -> None:
        # bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs (Bech32m, BIP350) <-
        # scriptPubKey 5210751e76e8199196d454941c45d1b3a323 (0x52 = OP_2).
        prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323")
        addr = segwit_addr_encode("bc", 2, prog)
        self.assertEqual(addr, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")

    def test_bip350_v1_taproot_program(self) -> None:
        # bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
        # <- scriptPubKey 512079be...81798 (0x51 = OP_1).
        prog = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        addr = segwit_addr_encode("bc", 1, prog)
        self.assertEqual(addr, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")

    def test_bip350_v1_second_taproot_program(self) -> None:
        # bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y
        # <- scriptPubKey 5128<64-byte program> (0x51 = OP_1, push 0x28=40 bytes).
        prog = bytes.fromhex(
            "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
        )
        addr = segwit_addr_encode("bc", 1, prog)
        self.assertEqual(
            addr,
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        )

    def test_invalid_v0_program_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            segwit_addr_encode("bc", 0, bytes(21))

    def test_invalid_witness_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            segwit_addr_encode("bc", 17, bytes(20))

    def test_invalid_program_too_short_rejected(self) -> None:
        with self.assertRaises(ValueError):
            segwit_addr_encode("bc", 1, bytes(1))

    def test_invalid_program_too_long_rejected(self) -> None:
        with self.assertRaises(ValueError):
            segwit_addr_encode("bc", 1, bytes(41))


if __name__ == "__main__":
    unittest.main()
