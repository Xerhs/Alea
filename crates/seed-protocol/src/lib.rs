//! `seed-protocol` — physical entropy session, transcript, entropy policy
//! and the application state machine (SPEC §17, §19, §15, §21).
#![no_std]

/// SPEC_EDU_UI §3: pure counted-vs-claimed entropy accounting helper
/// (category map, milli-bit total, floor check, 1-dp formatter).
pub mod accounting;

/// Dice/coin physical-entropy session with fixed-size event history,
/// undo/clear and integer-only budget enforcement (WP-07).
pub mod physical;

/// Canonical domain-separated entropy transcript builder (WP-08).
pub mod transcript;

/// Compiled-in entropy-policy parser (WP-12).
pub mod policy;

/// Application state machine (WP-23).
pub mod state;
