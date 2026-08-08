//! Owned by WP-27 (SPEC §4.1-4.2, §28). Production-edition wiring for
//! [`seed_flow::run_pre_secret_flow`].
//!
//! # STEP B dedup
//!
//! Every real-firmware provider type (`ProdPlatformGate`,
//! `ProdConsoleGate`, `HeldGopGraphicsGate`, `open_session_gop`,
//! `ProdCryptoSelfTestGate`, `ProdPolicyGates`, `production_watchdog`)
//! now lives in [`seed_flow::firmware_wiring`], shared verbatim with
//! `crates/seed-uefi-test/src/flow_pre/` (see that module's own doc
//! comment for the full rationale and the isolation guarantee it
//! preserves — no test-identity text lives there, only here). This file
//! is now nothing more than a re-export of those shared types plus the
//! two constructors that need this edition's own `production_marker`.
//!
//! SPEC.md amendment (2026-08-06): `HeldGopGraphicsGate` +
//! `open_session_gop` replace the old `ProdGraphicsGate` /
//! `FirmwareTextOutput` re-exports here (both still defined in
//! `seed_flow::firmware_wiring` but no longer constructed by either
//! edition's `main.rs` on the normal boot path — see that module's own
//! doc comments).
//!
//! Menu-key reads (STEP D dedup) go directly through
//! `seed_platform_x86::input::uefi_backend::FirmwareKeySource` —
//! `crate::flow_secret`'s `AliasedInput` already reuses it, and
//! `seed_flow::keys::MenuKeySource`'s blanket impl over any real
//! `seed_platform_x86::input::KeySource` (see that module's own doc
//! comment) means no second, hand-written adapter is needed here either;
//! `main.rs` constructs it directly rather than through a re-export.
//!
//! [`PRODUCTION_MARKER`] is the one and only edition-specific fact this
//! file contributes: `Some(`[`crate::markers::self_check`]`)`, because
//! this genuinely is the verified production build (SPEC §28) — contrast
//! `crates/seed-uefi-test/src/flow_pre/mod.rs`'s `None`.

pub use seed_flow::firmware_wiring::{
    open_session_gop, production_watchdog, HeldGopGraphicsGate, ProdConsoleGate, ProdPlatformGate,
};

/// This edition's production-marker check (SPEC §28), threaded into the
/// shared gate wiring below. Unlike every other edition, this binary
/// genuinely claims to be the verified production build, so the startup
/// gate itself verifies that claim before generation is enabled, not
/// only the SPEC §22.3 diagnostics screen.
pub(crate) const PRODUCTION_MARKER: Option<fn() -> bool> = Some(crate::markers::self_check);

/// Thin call into the shared [`seed_flow::firmware_wiring::ProdCryptoSelfTestGate`],
/// passing this edition's [`PRODUCTION_MARKER`].
#[must_use]
pub fn crypto_self_test_gate() -> seed_flow::firmware_wiring::ProdCryptoSelfTestGate {
    seed_flow::firmware_wiring::ProdCryptoSelfTestGate::new(PRODUCTION_MARKER)
}

/// Thin call into the shared [`seed_flow::firmware_wiring::ProdPolicyGates`],
/// passing this edition's [`PRODUCTION_MARKER`].
#[must_use]
pub fn policy_gates() -> seed_flow::firmware_wiring::ProdPolicyGates {
    seed_flow::firmware_wiring::ProdPolicyGates::new(PRODUCTION_MARKER)
}
