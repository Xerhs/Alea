import unittest

from seedref.addresses import PathStandard, first_address
from seedref.bip39 import mnemonic_to_seed

_TEST_MNEMONIC_WORDS = ["abandon"] * 11 + ["about"]


def _seed_for_test_mnemonic() -> bytes:
    from seedref.bip39 import WORDLIST

    indexes = [WORDLIST.index(w) for w in _TEST_MNEMONIC_WORDS]
    return mnemonic_to_seed(indexes)


class TestPublishedAddressVectors(unittest.TestCase):
    """BIP49/BIP84/BIP86 published test vectors, mnemonic
    "abandon abandon abandon abandon abandon abandon abandon abandon
    abandon abandon abandon about" (empty passphrase, mainnet, account 0,
    external chain, index 0 -- SPEC §24.2)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.seed = _seed_for_test_mnemonic()

    def test_bip84_native_segwit_address(self) -> None:
        addr = first_address(self.seed, PathStandard.BIP84)
        self.assertEqual(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    def test_bip86_taproot_address(self) -> None:
        addr = first_address(self.seed, PathStandard.BIP86)
        self.assertEqual(
            addr, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        )

    def test_bip44_legacy_address_matches_known_public_value(self) -> None:
        # Widely published derivation of the standard test mnemonic
        # (m/44'/0'/0'/0/0, mainnet P2PKH) -- cross-checked against the
        # BIP32 xprv chain for the same seed via seedref's own base58
        # encode + hash160 pipeline, both independently KAT-tested
        # (test_base58.py, test_ripemd160.py, test_bip32.py).
        addr = first_address(self.seed, PathStandard.BIP44)
        self.assertEqual(addr, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")

    def test_bip49_nested_segwit_address_matches_known_public_value(self) -> None:
        addr = first_address(self.seed, PathStandard.BIP49)
        self.assertEqual(addr, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")

    def test_all_four_addresses_distinct(self) -> None:
        addrs = {first_address(self.seed, std) for std in PathStandard}
        self.assertEqual(len(addrs), 4)


class TestBip84SecondAddressesFromXprv(unittest.TestCase):
    """BIP84 published test vector also gives m/84'/0'/0'/0/1 and
    m/84'/0'/0'/1/0; verify our path derivation against those too."""

    def test_second_receiving_and_first_change(self) -> None:
        from seedref.bip32 import ckd_priv, h, master_from_seed
        from seedref.secp256k1 import privkey_to_compressed_pubkey

        seed = _seed_for_test_mnemonic()
        master = master_from_seed(seed)
        account = master
        for idx in (h(84), h(0), h(0)):
            account = ckd_priv(account, idx)

        external = ckd_priv(account, 0)
        second_recv = ckd_priv(external, 1)
        pub = privkey_to_compressed_pubkey(second_recv.key)
        from seedref.addresses import p2wpkh_address

        self.assertEqual(p2wpkh_address(pub), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")

        change = ckd_priv(account, 1)
        first_change = ckd_priv(change, 0)
        pub2 = privkey_to_compressed_pubkey(first_change.key)
        self.assertEqual(p2wpkh_address(pub2), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")


if __name__ == "__main__":
    unittest.main()
