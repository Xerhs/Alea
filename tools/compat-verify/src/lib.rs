//! `compat-verify` -- the CLI over `seed-compat` + `seed-derive`
//! (SPEC_COMPAT §3, §7, §9, §12; IMPLEMENTATION_MAP_COMPAT.md §4 WP-C4).
//!
//! In v0.6.1 this is the **only** user-facing surface for `seed-compat`
//! (review F6/Q1 cut the desktop-GUI and UEFI-test surfaces): a host `std`
//! binary + library, never part of `seed-uefi-production`'s dependency
//! graph. It:
//!
//! - offers a profile menu with ONLY the three user-facing profiles
//!   (`coldcard-dice`, `seedsigner-dice`, `seedsigner-coin` --
//!   `iancoleman-hex` is never offered, SPEC_COMPAT §5.1.4/§7);
//! - shows a method screen (algorithm, word-count rule, citation, caveats)
//!   before any event entry (SPEC_COMPAT §7);
//! - for `DerivedFromLength` profiles given a non-canonical event count,
//!   prints the REFUSAL message -- never a phrase (SPEC_COMPAT §7, review
//!   F1, the whole point of this feature);
//! - on success, prints the result screen: the permanent watermark line,
//!   the mnemonic, the master fingerprint, and all four first-receive
//!   addresses (SPEC §24.2), with entropy hex gated behind an explicit
//!   `--show-entropy` flag and never concatenated with the mnemonic by
//!   default (SPEC_COMPAT §7, review F7);
//! - can write a `tests/vectors/compat/`-schema vector file for a given
//!   profile/events combination (SPEC_COMPAT §10.1, vector-generation
//!   mode).
//!
//! This library crate holds all the logic; `main.rs` is a thin argument
//! parser over it, matching the pattern the sibling host tools in
//! `tools/` already use (`media-readback-verifier`, `release-verifier`):
//! `lib.rs` for logic + tests, `main.rs` for `std::env::args()` plumbing.

/// Full derivation pipeline: `seed_compat::compat_derive` +
/// `seed-derive` (SPEC_COMPAT §12, §7).
pub mod derive;

/// Screen text builders (SPEC_COMPAT §7, §8).
pub mod screens;

/// Vector-generation mode (SPEC_COMPAT §10.1).
pub mod vectors;

pub use seed_compat::entropy_encoding::{Encoding, EntropyEncodingError};
pub use seed_compat::{profile, CompatProfile, WordCount};
