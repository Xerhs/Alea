"""Physical dice/coin entry session and entropy budget (SPEC §17).

Mirrors the `IMPLEMENTATION_MAP.md` §4 `PhysicalSession` contract shape:
fixed-order event history, push/undo/clear, integer-only budget
(`2585*rolls + 1000*flips >= 1000*target_bits`, SPEC §17.2 -- scaled by
1000 so the "2.585 bits/roll" constant is exact integer math, no
floats).
"""

from __future__ import annotations

from enum import Enum
from typing import List


class EventKind(Enum):
    ROLL = "roll"
    FLIP = "flip"


class PhysicalSession:
    """One physical dice/coin entry session (SPEC §17.1, §17.3)."""

    def __init__(self) -> None:
        # Ordered list of (kind, value) -- value is 1..6 for rolls,
        # 0/1 for flips (0=tails, 1=heads) matching SourceTag encoding
        # (SPEC §19.1: DICE_ROLLS 0x01..0x06, COIN_FLIPS 0x00=T/0x01=H).
        self._events: List[tuple] = []

    def push_roll(self, value: int) -> None:
        """Record one die roll. `value` MUST be 1..=6 (SPEC §17.1: `0`,
        `7`-`9` and any other value are rejected as physical input)."""
        if not (1 <= value <= 6):
            raise ValueError("die roll must be 1..=6")
        self._events.append((EventKind.ROLL, value))

    def push_flip(self, heads: bool) -> None:
        """Record one coin flip."""
        self._events.append((EventKind.FLIP, 1 if heads else 0))

    def undo(self) -> None:
        """Remove the most recently recorded event, if any (SPEC §17.3:
        "no recomputation is required")."""
        if self._events:
            self._events.pop()

    def clear(self) -> None:
        """Remove all recorded events (SPEC §17.3: requires confirmation
        at the UI layer; this is the underlying primitive)."""
        self._events.clear()

    @property
    def rolls(self) -> int:
        return sum(1 for kind, _ in self._events if kind is EventKind.ROLL)

    @property
    def flips(self) -> int:
        return sum(1 for kind, _ in self._events if kind is EventKind.FLIP)

    def dice_bytes(self) -> bytes:
        """`source_bytes` for a `DICE_ROLLS` transcript record: one byte
        per roll, in entry order, `0x01..=0x06` (SPEC §19.1)."""
        return bytes(v for kind, v in self._events if kind is EventKind.ROLL)

    def coin_bytes(self) -> bytes:
        """`source_bytes` for a `COIN_FLIPS` transcript record: one byte
        per flip, in entry order, `0x00`=tails / `0x01`=heads."""
        return bytes(v for kind, v in self._events if kind is EventKind.FLIP)

    def budget_bits_x1000(self) -> int:
        """`2585*rolls + 1000*flips` (SPEC §17.2, integer, scaled by 1000
        so 2.585 bits/roll is exact)."""
        return 2585 * self.rolls + 1000 * self.flips

    def budget_met(self, target_bits: int) -> bool:
        """`True` iff `budget_bits_x1000() >= 1000 * target_bits`
        (SPEC §17.2)."""
        return self.budget_bits_x1000() >= 1000 * target_bits
