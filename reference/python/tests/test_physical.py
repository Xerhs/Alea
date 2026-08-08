import unittest

from seedref.physical import PhysicalSession


class TestPhysicalSession(unittest.TestCase):
    def test_push_and_counts(self) -> None:
        s = PhysicalSession()
        s.push_roll(4)
        s.push_roll(6)
        s.push_flip(True)
        self.assertEqual(s.rolls, 2)
        self.assertEqual(s.flips, 1)
        self.assertEqual(s.dice_bytes(), bytes([4, 6]))
        self.assertEqual(s.coin_bytes(), bytes([1]))

    def test_invalid_roll_rejected(self) -> None:
        s = PhysicalSession()
        for bad in (0, 7, 9, -1, 100):
            with self.assertRaises(ValueError):
                s.push_roll(bad)

    def test_undo_inverts_push(self) -> None:
        s = PhysicalSession()
        s.push_roll(3)
        before = (s.rolls, s.flips, s.dice_bytes(), s.coin_bytes())
        s.push_flip(False)
        s.undo()
        after = (s.rolls, s.flips, s.dice_bytes(), s.coin_bytes())
        self.assertEqual(before, after)

    def test_undo_on_empty_is_noop(self) -> None:
        s = PhysicalSession()
        s.undo()
        self.assertEqual(s.rolls, 0)
        self.assertEqual(s.flips, 0)

    def test_clear(self) -> None:
        s = PhysicalSession()
        s.push_roll(1)
        s.push_flip(True)
        s.clear()
        self.assertEqual(s.rolls, 0)
        self.assertEqual(s.flips, 0)
        self.assertEqual(s.budget_bits_x1000(), 0)

    def test_budget_formula_dice_only(self) -> None:
        s = PhysicalSession()
        for _ in range(50):
            s.push_roll(1)
        self.assertEqual(s.budget_bits_x1000(), 2585 * 50)
        self.assertTrue(s.budget_met(128))  # 129250 >= 128000
        self.assertFalse(s.budget_met(256))

    def test_budget_formula_coins_only(self) -> None:
        s = PhysicalSession()
        for _ in range(128):
            s.push_flip(True)
        self.assertEqual(s.budget_bits_x1000(), 1000 * 128)
        self.assertTrue(s.budget_met(128))  # exact boundary
        s.push_flip(False)
        self.assertFalse(s.budget_met(256))

    def test_budget_monotonic_under_push(self) -> None:
        s = PhysicalSession()
        prev = s.budget_bits_x1000()
        for i in range(40):
            if i % 2 == 0:
                s.push_roll((i % 6) + 1)
            else:
                s.push_flip(i % 3 == 0)
            cur = s.budget_bits_x1000()
            self.assertGreaterEqual(cur, prev)
            prev = cur

    def test_budget_mixed_exact(self) -> None:
        s = PhysicalSession()
        for _ in range(30):
            s.push_roll(2)
        for _ in range(50):
            s.push_flip(True)
        expected = 2585 * 30 + 1000 * 50
        self.assertEqual(s.budget_bits_x1000(), expected)
        self.assertEqual(s.budget_met(128), expected >= 128000)


if __name__ == "__main__":
    unittest.main()
