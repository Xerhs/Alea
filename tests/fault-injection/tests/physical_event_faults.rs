//! Category C (SPEC §29.5 "during physical-event processing"): faults in
//! dice/coin handling (SPEC §17) -- the shared-budget over-capacity
//! rejection (SPEC §17.3) across several roll/flip split ratios, the
//! exact-capacity boundary for each event type individually, and the
//! empty-session undo edge case.

use seed_fault_injection::{coverage, MAX_PHYSICAL_EVENTS};
use seed_protocol::physical::{PhysicalError, CoinFace, PhysicalSession};

/// SPEC §17.3: "one shared physical-event history buffer" -- fills the
/// session to exactly `MAX_PHYSICAL_EVENTS` with a roll/flip split, then
/// attempts one more push (whichever type), across 8 different split
/// ratios (dice-heavy through coin-heavy), confirming the overflowing
/// push is always rejected with `CapacityReached` -- never silently
/// truncated, never counted, never a panic -- and every event pushed
/// before the boundary is preserved exactly.
#[test]
fn physical_session_shared_capacity_rejects_overflow_across_every_split_ratio() {
    let splits: [usize; 8] = [
        MAX_PHYSICAL_EVENTS,     // all rolls
        MAX_PHYSICAL_EVENTS - 1, // all rolls but one flip
        MAX_PHYSICAL_EVENTS * 3 / 4,
        MAX_PHYSICAL_EVENTS / 2, // exactly half rolls, half flips
        MAX_PHYSICAL_EVENTS / 4,
        100,
        10,
        0, // all flips
    ];

    let mut checked = 0usize;
    for roll_count in splits {
        let mut session = PhysicalSession::new();
        for _ in 0..roll_count {
            session.push_roll(3).unwrap();
        }
        let flip_count = MAX_PHYSICAL_EVENTS - roll_count;
        for _ in 0..flip_count {
            session.push_flip(CoinFace::Heads).unwrap();
        }
        assert!(session.at_capacity(), "roll_count={roll_count}: must be at capacity after filling to MAX_PHYSICAL_EVENTS");
        assert_eq!(session.len(), MAX_PHYSICAL_EVENTS);

        let roll_err = session.push_roll(1).unwrap_err();
        assert_eq!(roll_err, PhysicalError::CapacityReached, "roll_count={roll_count}: overflowing roll must be rejected");
        let flip_err = session.push_flip(CoinFace::Tails).unwrap_err();
        assert_eq!(flip_err, PhysicalError::CapacityReached, "roll_count={roll_count}: overflowing flip must also be rejected");
        assert_eq!(session.len(), MAX_PHYSICAL_EVENTS, "roll_count={roll_count}: rejected pushes must never be counted");
        assert_eq!(session.roll_count(), roll_count as u32, "roll_count={roll_count}: pre-boundary rolls must be preserved exactly");
        assert_eq!(session.flip_count(), flip_count as u32, "roll_count={roll_count}: pre-boundary flips must be preserved exactly");

        checked += 1;
    }
    assert_eq!(checked, coverage::C_PHYSICAL_OVER_BUDGET_COMBOS);
    assert_eq!(splits.len(), coverage::C_PHYSICAL_OVER_BUDGET_COMBOS);
}

/// The exact-capacity boundary for each event type individually (a
/// dice-only session and a coin-only session), distinct from the mixed
/// splits above.
#[test]
fn physical_session_single_type_capacity_boundary_roll_and_flip() {
    let mut checked = 0usize;

    let mut dice_only = PhysicalSession::new();
    for _ in 0..MAX_PHYSICAL_EVENTS {
        dice_only.push_roll(6).unwrap();
    }
    assert_eq!(dice_only.push_roll(6).unwrap_err(), PhysicalError::CapacityReached);
    checked += 1;

    let mut coin_only = PhysicalSession::new();
    for _ in 0..MAX_PHYSICAL_EVENTS {
        coin_only.push_flip(CoinFace::Tails).unwrap();
    }
    assert_eq!(coin_only.push_flip(CoinFace::Heads).unwrap_err(), PhysicalError::CapacityReached);
    checked += 1;

    assert_eq!(checked, coverage::C_PHYSICAL_SESSION_CAPACITY);
}

#[test]
fn physical_session_undo_on_empty_session_returns_none_not_a_panic() {
    let mut session = PhysicalSession::new();
    assert_eq!(session.undo(), None);
    assert_eq!(session.len(), 0);
    assert_eq!(1, coverage::C_PHYSICAL_UNDO_UNDERFLOW);
}

/// Defensive companion check: an invalid die-roll value (outside `1..=6`)
/// must be rejected the same way, never panicking and never being staged
/// -- exercised here (rather than counted separately in the coverage
/// ledger) because it shares this file's `PhysicalSession` fixture setup.
#[test]
fn invalid_roll_value_is_rejected_not_a_panic() {
    let mut session = PhysicalSession::new();
    assert_eq!(session.push_roll(0).unwrap_err(), PhysicalError::InvalidRoll);
    assert_eq!(session.push_roll(7).unwrap_err(), PhysicalError::InvalidRoll);
    assert_eq!(session.len(), 0, "rejected rolls must not be staged");
}
