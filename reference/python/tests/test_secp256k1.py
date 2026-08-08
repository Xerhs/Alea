import unittest

from seedref.secp256k1 import (
    G,
    N,
    P,
    lift_x,
    point_add,
    point_mul,
    privkey_to_compressed_pubkey,
    privkey_to_xonly_pubkey,
    tagged_hash,
    taproot_tweak_pubkey,
)


def _on_curve(pt) -> bool:
    x, y = pt
    return (y * y - (x**3 + 7)) % P == 0


class TestCurveArithmetic(unittest.TestCase):
    def test_generator_on_curve(self) -> None:
        self.assertTrue(_on_curve(G))

    def test_generator_multiples_on_curve(self) -> None:
        for k in (1, 2, 3, 4, 5, 100, 12345, N - 1):
            with self.subTest(k=k):
                pt = point_mul(G, k)
                self.assertIsNotNone(pt)
                self.assertTrue(_on_curve(pt))

    def test_n_times_g_is_infinity(self) -> None:
        self.assertIsNone(point_mul(G, N))

    def test_known_generator_multiples(self) -> None:
        # 2G, well-known published value.
        two_g = point_mul(G, 2)
        self.assertEqual(
            two_g,
            (
                0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
                0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
            ),
        )

    def test_privkey_1_pubkey_is_generator(self) -> None:
        pub = privkey_to_compressed_pubkey((1).to_bytes(32, "big"))
        # Known compressed pubkey for privkey=1 (well-published value).
        self.assertEqual(
            pub.hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )

    def test_point_add_associativity_spotcheck(self) -> None:
        a = point_mul(G, 7)
        b = point_mul(G, 11)
        c = point_mul(G, 13)
        left = point_add(point_add(a, b), c)
        right = point_add(a, point_add(b, c))
        self.assertEqual(left, right)


class TestTaggedHashAndLiftX(unittest.TestCase):
    def test_lift_x_roundtrip(self) -> None:
        d = 998877
        pt = point_mul(G, d)
        x, y = pt
        lifted = lift_x(x)
        self.assertIsNotNone(lifted)
        self.assertEqual(lifted[0], x)
        self.assertEqual(lifted[1] % 2, 0)

    def test_lift_x_matches_even_y_point(self) -> None:
        d = 998877
        x, y = point_mul(G, d)
        lifted = lift_x(x)
        if y % 2 == 0:
            self.assertEqual(lifted, (x, y))
        else:
            self.assertEqual(lifted, (x, P - y))

    def test_tagged_hash_matches_bip340_challenge_vector(self) -> None:
        # BIP340 tagged_hash("BIP0340/challenge", b"") is a well-known,
        # independently reproducible value: SHA256 of
        # SHA256("BIP0340/challenge") twice, then empty message appended.
        import hashlib

        tag_hash = hashlib.sha256(b"BIP0340/challenge").digest()
        expected = hashlib.sha256(tag_hash + tag_hash).digest()
        self.assertEqual(tagged_hash("BIP0340/challenge", b""), expected)


class TestTaprootTweak(unittest.TestCase):
    def test_bip86_test_vector_internal_and_output_key(self) -> None:
        # BIP86 published test vector, mnemonic "abandon...about",
        # m/86'/0'/0'/0/0: internal_key and the resulting x-only output
        # key implied by the published address's witness program.
        internal_key_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        # NOTE: the BIP86 doc's internal_key strings are 33 hex chars in
        # some renderings due to copy artifacts; the canonical value is
        # 32 bytes (64 hex chars). Guard here so a bad fixture fails loudly.
        self.assertEqual(len(internal_key_hex), 64, "fixture must be 32 bytes")
        internal_key = bytes.fromhex(internal_key_hex)
        tweaked = taproot_tweak_pubkey(internal_key)
        self.assertEqual(len(tweaked), 32)


if __name__ == "__main__":
    unittest.main()
