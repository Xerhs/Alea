//! Owned by WP-07 (SPEC §17). Dice/coin physical-entropy session.
//!
//! Holds [`PhysicalSession`]: a fixed-size tagged roll/flip event history,
//! `push_roll`/`push_flip`/`undo`/`clear`, the integer-only entropy budget
//! (SPEC §17.2: `2.585 * rolls + 1.0 * flips >= target_bits`, computed here
//! as `2585 * rolls + 1000 * flips >= 1000 * target_bits` so no floating
//! point is ever used) and capacity-stop behavior (SPEC §17.3).

use core::sync::atomic::{compiler_fence, Ordering};

use seed_core::contracts::{TargetBits, MAX_PHYSICAL_EVENTS};

/// One recorded physical event (SPEC §17.1). The application rejects any
/// input outside these two shapes (`0`, `7`-`9`, arbitrary numbers, etc.)
/// before it ever reaches [`PhysicalSession::push_roll`]/`push_flip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalEvent {
    /// A die roll, value constrained to `1..=6`.
    Roll(u8),
    /// A coin flip.
    Flip(CoinFace),
}

/// The two faces of a fair coin (SPEC §17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinFace {
    /// `H`.
    Heads,
    /// `T`.
    Tails,
}

/// Error returned by a rejected push (SPEC §17.1, §17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalError {
    /// The die-roll value is outside `1..=6`.
    InvalidRoll,
    /// The fixed-size history buffer (`MAX_PHYSICAL_EVENTS`) is full; the
    /// user must derive (if the budget is met) or clear and restart
    /// (SPEC §17.3).
    CapacityReached,
}

/// Tag byte distinguishing a stored roll from a stored flip inside the
/// packed event history. Not part of any external wire format (that is
/// WP-08's transcript); purely an internal encoding for this fixed buffer.
const TAG_ROLL: u8 = 0;
const TAG_FLIP: u8 = 1;

/// A packed physical event: one tag byte + one value byte, matching the
/// "fixed-size secret history buffer" of SPEC §17.3. Kept as a two-byte
/// struct (rather than an enum) so the whole history is a flat
/// `[PackedEvent; MAX_PHYSICAL_EVENTS]` with no padding surprises.
#[derive(Clone, Copy)]
struct PackedEvent {
    tag: u8,
    value: u8,
}

impl PackedEvent {
    const fn zero() -> Self {
        PackedEvent { tag: 0, value: 0 }
    }
}

/// Dice + coin physical-entropy session (SPEC §17).
///
/// Fixed-size event history (`MAX_PHYSICAL_EVENTS` = 512, SPEC §17.3), no
/// `alloc`. This type holds only public event values (`1..=6`, `H`/`T`),
/// not raw seed bytes, but it IS the physical entropy source, so it is
/// scrubbed explicitly on `clear`/`scrub` (SPEC §13, §20): no `Copy`, no
/// `Clone`, no `Debug`/`Display` on this struct itself, only on the small
/// plain-data event types above. In addition — mirroring the
/// `PhysicalStaging`/`StripRing` Drop-scrub discipline — a [`Drop`] impl
/// guarantees the ~1KB history buffer is wiped on *every* drop path
/// (including early returns and unwinding), not only the explicit
/// `clear`/`scrub` calls.
pub struct PhysicalSession {
    events: [PackedEvent; MAX_PHYSICAL_EVENTS],
    len: usize,
    rolls: u32,
    flips: u32,
}

impl PhysicalSession {
    /// Creates an empty session (SPEC §17.3).
    pub const fn new() -> Self {
        PhysicalSession {
            events: [PackedEvent::zero(); MAX_PHYSICAL_EVENTS],
            len: 0,
            rolls: 0,
            flips: 0,
        }
    }

    /// Number of events currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no events are stored.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total dice rolls recorded so far.
    pub fn roll_count(&self) -> u32 {
        self.rolls
    }

    /// Total coin flips recorded so far.
    pub fn flip_count(&self) -> u32 {
        self.flips
    }

    /// Appends a die roll (SPEC §17.1: `1..=6`; `0` and `7`-`9` are
    /// rejected). Fails with [`PhysicalError::CapacityReached`] once the
    /// fixed history buffer is full (SPEC §17.3).
    pub fn push_roll(&mut self, value: u8) -> Result<(), PhysicalError> {
        if !(1..=6).contains(&value) {
            return Err(PhysicalError::InvalidRoll);
        }
        self.push_raw(TAG_ROLL, value)?;
        self.rolls += 1;
        Ok(())
    }

    /// Appends a coin flip (SPEC §17.1). Fails with
    /// [`PhysicalError::CapacityReached`] once the fixed history buffer is
    /// full (SPEC §17.3).
    ///
    /// The stored `value` byte uses the *same* `0`/`1` convention as
    /// `contracts::SourceTag::CoinFlips` (SPEC §19.1: "one byte per flip,
    /// `0x00` = tails, `0x01` = heads") so that any future glue code
    /// converting recorded history into `CoinFlips` `source_bytes` can copy
    /// this value directly without an inversion step.
    pub fn push_flip(&mut self, face: CoinFace) -> Result<(), PhysicalError> {
        let value = match face {
            CoinFace::Tails => 0,
            CoinFace::Heads => 1,
        };
        self.push_raw(TAG_FLIP, value)?;
        self.flips += 1;
        Ok(())
    }

    fn push_raw(&mut self, tag: u8, value: u8) -> Result<(), PhysicalError> {
        if self.len >= MAX_PHYSICAL_EVENTS {
            return Err(PhysicalError::CapacityReached);
        }
        self.events[self.len] = PackedEvent { tag, value };
        self.len += 1;
        Ok(())
    }

    /// Removes the most recently stored event, if any (SPEC §17.3: "Undo
    /// removes the final stored event. No recomputation is required.").
    /// Returns the removed event, or `None` if the history was empty.
    pub fn undo(&mut self) -> Option<PhysicalEvent> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let packed = self.events[self.len];
        // Scrub the vacated slot immediately; it no longer represents
        // live history state.
        self.scrub_slot(self.len);
        match packed.tag {
            TAG_ROLL => {
                self.rolls -= 1;
                Some(PhysicalEvent::Roll(packed.value))
            }
            _ => {
                self.flips -= 1;
                // Inverse of the `push_flip` mapping above: `0` = tails,
                // `1` = heads (SPEC §19.1 `CoinFlips` convention).
                let face = if packed.value == 0 {
                    CoinFace::Tails
                } else {
                    CoinFace::Heads
                };
                Some(PhysicalEvent::Flip(face))
            }
        }
    }

    /// Clears the entire session, scrubbing the history buffer (SPEC
    /// §17.3, §17.4: "Clearing all events requires confirmation" — that
    /// confirmation is a UI-layer concern; this method performs the clear
    /// itself once confirmed).
    pub fn clear(&mut self) {
        self.scrub();
        self.len = 0;
        self.rolls = 0;
        self.flips = 0;
    }

    /// Explicitly scrubs the history buffer using volatile writes plus a
    /// compiler fence so the wipe cannot be optimized away (SPEC §13,
    /// §17.3: "The history buffer is scrubbed after final entropy
    /// derivation."). Does not reset counters; call [`Self::clear`] for a
    /// full reset.
    pub fn scrub(&mut self) {
        for i in 0..MAX_PHYSICAL_EVENTS {
            self.scrub_slot(i);
        }
        compiler_fence(Ordering::SeqCst);
    }

    fn scrub_slot(&mut self, i: usize) {
        // `i < MAX_PHYSICAL_EVENTS` is upheld by every caller (`scrub`
        // iterates in-bounds; `undo` passes `self.len` which is always
        // `< MAX_PHYSICAL_EVENTS` after the decrement above).
        let slot = &mut self.events[i];
        unsafe {
            core::ptr::write_volatile(&mut slot.tag, 0);
            core::ptr::write_volatile(&mut slot.value, 0);
        }
    }

    /// Integer-only entropy budget in milli-bits (SPEC §17.2):
    /// `2585 * rolls + 1000 * flips`, i.e. `1000 *` the fractional-bit
    /// formula `2.585 * dice_rolls + 1.0 * coin_flips`. Never uses
    /// floating point (SPEC §13). The `2585` is `log2(6) = 2.58496...`
    /// milli-bits ROUNDED UP and matches SPEC §17.2 exactly (intentional,
    /// not a bug); see `accounting::counted_milli_bits` for the rounding
    /// rationale and the negligible (<~0.02 bit/session) over-credit.
    pub fn budget_bits_x1000(&self) -> u64 {
        2585u64 * u64::from(self.rolls) + 1000u64 * u64::from(self.flips)
    }

    /// True once the SPEC §17.2 budget is met for `target`:
    /// `budget_bits_x1000() >= 1000 * target_bits`.
    pub fn budget_met(&self, target: TargetBits) -> bool {
        let target_bits = target as u64;
        self.budget_bits_x1000() >= 1000u64 * target_bits
    }

    /// True once the fixed history buffer is full (SPEC §17.3: "Reaching
    /// buffer capacity stops further entry").
    pub fn at_capacity(&self) -> bool {
        self.len >= MAX_PHYSICAL_EVENTS
    }
}

impl Default for PhysicalSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PhysicalSession {
    /// Defense-in-depth scrub (SPEC §13, §17.3, §20): the production flow
    /// already scrubs explicitly via `clear`/`scrub` after final entropy
    /// derivation, but this guarantees the fixed history buffer is wiped on
    /// every drop path — including early returns and stack unwinding — the
    /// same discipline `PhysicalStaging`/`StripRing` already carry. `scrub`
    /// performs volatile writes plus a compiler fence so the wipe cannot be
    /// elided; the counters are zeroed too so no residual event volume
    /// survives.
    fn drop(&mut self) {
        self.scrub();
        self.len = 0;
        self.rolls = 0;
        self.flips = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_roll_rejects_out_of_range() {
        let mut s = PhysicalSession::new();
        assert_eq!(s.push_roll(0), Err(PhysicalError::InvalidRoll));
        assert_eq!(s.push_roll(7), Err(PhysicalError::InvalidRoll));
        assert_eq!(s.push_roll(9), Err(PhysicalError::InvalidRoll));
        assert!(s.push_roll(1).is_ok());
        assert!(s.push_roll(6).is_ok());
        assert_eq!(s.len(), 2);
        assert_eq!(s.roll_count(), 2);
    }

    #[test]
    fn push_flip_counts() {
        let mut s = PhysicalSession::new();
        s.push_flip(CoinFace::Heads).unwrap();
        s.push_flip(CoinFace::Tails).unwrap();
        assert_eq!(s.flip_count(), 2);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn budget_known_answer_dice_only_12w() {
        // SPEC §17.2 reference table: 50 rolls MUST meet 128-bit target.
        let mut s = PhysicalSession::new();
        for _ in 0..50 {
            s.push_roll(1).unwrap();
        }
        assert_eq!(s.budget_bits_x1000(), 2585 * 50);
        assert!(s.budget_met(TargetBits::Bits128));
    }

    #[test]
    fn budget_known_answer_49_rolls_fails_12w() {
        let mut s = PhysicalSession::new();
        for _ in 0..49 {
            s.push_roll(1).unwrap();
        }
        // 2585*49 = 126665 < 128000
        assert_eq!(s.budget_bits_x1000(), 126_665);
        assert!(!s.budget_met(TargetBits::Bits128));
    }

    #[test]
    fn budget_known_answer_coins_only_12w() {
        let mut s = PhysicalSession::new();
        for _ in 0..128 {
            s.push_flip(CoinFace::Heads).unwrap();
        }
        assert_eq!(s.budget_bits_x1000(), 128_000);
        assert!(s.budget_met(TargetBits::Bits128));
    }

    #[test]
    fn budget_known_answer_24w() {
        let mut s = PhysicalSession::new();
        for _ in 0..100 {
            s.push_roll(6).unwrap();
        }
        assert_eq!(s.budget_bits_x1000(), 2585 * 100);
        assert!(s.budget_met(TargetBits::Bits256));

        let mut s2 = PhysicalSession::new();
        for _ in 0..256 {
            s2.push_flip(CoinFace::Tails).unwrap();
        }
        assert_eq!(s2.budget_bits_x1000(), 256_000);
        assert!(s2.budget_met(TargetBits::Bits256));
    }

    #[test]
    fn undo_inverts_push_roll() {
        let mut s = PhysicalSession::new();
        s.push_roll(4).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.budget_bits_x1000(), 2585);
        let ev = s.undo();
        assert_eq!(ev, Some(PhysicalEvent::Roll(4)));
        assert_eq!(s.len(), 0);
        assert_eq!(s.roll_count(), 0);
        assert_eq!(s.budget_bits_x1000(), 0);
    }

    #[test]
    fn undo_inverts_push_flip() {
        let mut s = PhysicalSession::new();
        s.push_flip(CoinFace::Tails).unwrap();
        let ev = s.undo();
        assert_eq!(ev, Some(PhysicalEvent::Flip(CoinFace::Tails)));
        assert_eq!(s.len(), 0);
        assert_eq!(s.flip_count(), 0);
    }

    /// Regression: the packed `value` byte stored for a flip MUST use the
    /// same `0`=tails/`1`=heads convention as `contracts::SourceTag::
    /// CoinFlips` (SPEC §19.1), not its inverse. A naive glue
    /// implementation that copies this internal value byte straight into
    /// `CoinFlips` `source_bytes` must not silently invert every recorded
    /// toss.
    #[test]
    fn push_flip_value_byte_matches_coinflips_wire_convention() {
        let mut s = PhysicalSession::new();
        s.push_flip(CoinFace::Tails).unwrap();
        s.push_flip(CoinFace::Heads).unwrap();
        assert_eq!(s.events[0].tag, TAG_FLIP);
        assert_eq!(s.events[0].value, 0, "tails must pack as 0x00");
        assert_eq!(s.events[1].tag, TAG_FLIP);
        assert_eq!(s.events[1].value, 1, "heads must pack as 0x01");
    }

    #[test]
    fn undo_on_empty_returns_none() {
        let mut s = PhysicalSession::new();
        assert_eq!(s.undo(), None);
    }

    #[test]
    fn undo_sequence_restores_exact_prior_state() {
        let mut s = PhysicalSession::new();
        s.push_roll(3).unwrap();
        s.push_flip(CoinFace::Heads).unwrap();
        s.push_roll(5).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.undo(), Some(PhysicalEvent::Roll(5)));
        assert_eq!(s.len(), 2);
        assert_eq!(s.roll_count(), 1);
        assert_eq!(s.flip_count(), 1);
        assert_eq!(s.undo(), Some(PhysicalEvent::Flip(CoinFace::Heads)));
        assert_eq!(s.undo(), Some(PhysicalEvent::Roll(3)));
        assert_eq!(s.undo(), None);
        assert!(s.is_empty());
    }

    #[test]
    fn clear_resets_everything() {
        let mut s = PhysicalSession::new();
        for _ in 0..10 {
            s.push_roll(2).unwrap();
        }
        s.clear();
        assert_eq!(s.len(), 0);
        assert_eq!(s.roll_count(), 0);
        assert_eq!(s.flip_count(), 0);
        assert_eq!(s.budget_bits_x1000(), 0);
        // scrubbed: underlying slots are zero
        for ev in s.events.iter() {
            assert_eq!(ev.tag, 0);
            assert_eq!(ev.value, 0);
        }
    }

    #[test]
    fn capacity_stop() {
        let mut s = PhysicalSession::new();
        for _ in 0..MAX_PHYSICAL_EVENTS {
            s.push_roll(1).unwrap();
        }
        assert!(s.at_capacity());
        assert_eq!(s.push_roll(1), Err(PhysicalError::CapacityReached));
        assert_eq!(
            s.push_flip(CoinFace::Heads),
            Err(PhysicalError::CapacityReached)
        );
        assert_eq!(s.len(), MAX_PHYSICAL_EVENTS);
    }

    #[test]
    fn capacity_stop_mixed() {
        let mut s = PhysicalSession::new();
        for i in 0..MAX_PHYSICAL_EVENTS {
            if i % 2 == 0 {
                s.push_roll(1).unwrap();
            } else {
                s.push_flip(CoinFace::Heads).unwrap();
            }
        }
        assert!(s.at_capacity());
        assert_eq!(s.push_roll(1), Err(PhysicalError::CapacityReached));
    }

    // Property test: budget stays exactly a pure integer function of
    // (rolls, flips) under any push/undo sequence, i.e. it never drifts
    // from the recomputed value.
    #[test]
    fn property_budget_matches_counts_under_random_sequence() {
        // Deterministic xorshift, host-only test, no external RNG dep.
        let mut state: u32 = 0x1234_5678;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };

        let mut s = PhysicalSession::new();
        for _ in 0..2000 {
            let choice = next() % 3;
            match choice {
                0 => {
                    let v = (next() % 6 + 1) as u8;
                    let _ = s.push_roll(v);
                }
                1 => {
                    let face = if next() % 2 == 0 {
                        CoinFace::Heads
                    } else {
                        CoinFace::Tails
                    };
                    let _ = s.push_flip(face);
                }
                _ => {
                    s.undo();
                }
            }
            let cur = s.budget_bits_x1000();
            let recomputed =
                2585u64 * u64::from(s.roll_count()) + 1000u64 * u64::from(s.flip_count());
            assert_eq!(cur, recomputed);
        }
    }

    /// Property test: budget is monotonically non-decreasing over any
    /// sequence of pushes alone (no undos), regardless of roll/flip mix.
    #[test]
    fn property_budget_monotonic_under_pushes_only() {
        let mut state: u32 = 0x0badc0de;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };

        let mut s = PhysicalSession::new();
        let mut prev = 0u64;
        for _ in 0..300 {
            if next() % 2 == 0 {
                let v = (next() % 6 + 1) as u8;
                let _ = s.push_roll(v);
            } else {
                let face = if next() % 2 == 0 {
                    CoinFace::Heads
                } else {
                    CoinFace::Tails
                };
                let _ = s.push_flip(face);
            }
            let cur = s.budget_bits_x1000();
            assert!(cur >= prev);
            prev = cur;
        }
    }

    #[test]
    fn property_undo_inverts_push_exhaustive_rolls() {
        for v in 1..=6u8 {
            let mut s = PhysicalSession::new();
            s.push_roll(v).unwrap();
            let before_len = s.len();
            let before_rolls = s.roll_count();
            let ev = s.undo().unwrap();
            assert_eq!(ev, PhysicalEvent::Roll(v));
            assert_eq!(s.len(), before_len - 1);
            assert_eq!(s.roll_count(), before_rolls - 1);
        }
    }

    #[test]
    fn property_undo_inverts_push_flips() {
        for face in [CoinFace::Heads, CoinFace::Tails] {
            let mut s = PhysicalSession::new();
            s.push_flip(face).unwrap();
            let ev = s.undo().unwrap();
            assert_eq!(ev, PhysicalEvent::Flip(face));
            assert_eq!(s.len(), 0);
            assert_eq!(s.flip_count(), 0);
        }
    }
}
