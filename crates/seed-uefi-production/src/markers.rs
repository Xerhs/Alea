//! Production policy markers (SPEC §28) — well-known constants a future
//! WP-30 binary-policy scanner can search for in the compiled
//! `x86_64-unknown-uefi` artifact to confirm it is genuinely this
//! crate's production build, and that no test-only marker string is
//! present.
//!
//! # Marker scheme
//!
//! [`ALEA_PRODUCTION_EDITION_MARKER_V1`] is a fixed-size,
//! `#[no_mangle]`, `#[used]` static byte array. `#[no_mangle]` keeps its
//! exact symbol name in the linked binary's symbol table instead of
//! being mangled or optimized away under a compiler-chosen name;
//! `#[used]` stops the linker from dropping it as dead code even though
//! nothing but [`self_check`] (below) ever reads it back at runtime.
//!
//! A conforming binary-policy scanner (WP-30, `tools/binary-policy-scanner/`)
//! MUST find, in the linked production artifact:
//! - the symbol name `ALEA_PRODUCTION_EDITION_MARKER_V1`;
//! - the exact byte sequence [`PRODUCTION_MARKER_BYTES`].
//!
//! And MUST NOT find, anywhere in that same artifact:
//! - the literal string `"PUBLIC TEST PHRASE"` (SPEC §4.2's required
//!   test-edition mnemonic-screen prefix);
//! - the literal string `"UEFI TEST EDITION"` (`seed-uefi-test`'s own
//!   startup banner, `crates/seed-uefi-test/src/main.rs`);
//! - the crate names `seed-test-vectors` or `seed-desktop-test` in any
//!   embedded metadata or panic/debug string;
//! - a symbol literally named `ALEA_TEST_EDITION_MARKER_V1`
//!   (reserved for a hypothetical future test-edition counterpart to
//!   this module; never defined by any crate `seed-uefi-production`
//!   depends on).
//!
//! This module intentionally defines only the *positive* production
//! marker. The forbidden test-only markers above are documented here for
//! WP-30's benefit but are deliberately never defined as constants
//! anywhere in this crate — embedding e.g. `"PUBLIC TEST PHRASE"` as a
//! `const` here, even unused, would itself put the string in the linked
//! binary's `.rodata` and make this crate fail its own scanner rule.

/// The production-edition marker string (SPEC §28: "production signing
/// refuses artifacts with test markers" needs a positive marker to check
/// for, not only an absence check). Exactly 33 ASCII bytes, no trailing
/// NUL — the array length below is the exact byte length of this
/// literal, so a future accidental edit that changes the string's length
/// without updating both copies is a compile error, not a silent drift.
const PRODUCTION_MARKER_BYTES: &[u8; 33] = b"ALEA-PRODUCTION-EDITION-MARKER-V1";

/// `#[no_mangle]`/`#[used]` copy of [`PRODUCTION_MARKER_BYTES`] at a
/// fixed, scanner-findable symbol name. See the module doc comment.
#[used]
#[no_mangle]
pub static ALEA_PRODUCTION_EDITION_MARKER_V1: [u8; 33] = *PRODUCTION_MARKER_BYTES;

/// Read the marker back and confirm it matches the expected bytes,
/// mirroring `flow_pre::ProdCryptoSelfTestGate`'s fixed-expected-value
/// self-test pattern. The two copies can only drift apart if this source
/// file itself is edited inconsistently (a build-time invariant, not a
/// runtime attacker surface), but performing a real comparison — rather
/// than hardcoding `true` — means `PlatformInfo::production_markers_verified`
/// (SPEC §22.3) reflects an actual check, not an unconditional claim.
#[must_use]
pub fn self_check() -> bool {
    ALEA_PRODUCTION_EDITION_MARKER_V1 == *PRODUCTION_MARKER_BYTES
}
