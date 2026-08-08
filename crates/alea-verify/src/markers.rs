//! Positive edition marker for the standalone `alea-verify.efi` (SPEC §28
//! marker scheme, adapted).
//!
//! Unlike `seed-uefi-production`'s `markers` module, this binary is
//! deliberately NOT scanned by `tools/binary-policy-scanner` (that scanner
//! runs only against `seed-uefi-production.efi`), and it is EXPECTED to
//! contain `seed-compat`'s verification code and its SPEC_COMPAT §7/§8
//! "PUBLIC TEST PHRASE" / "NOT AN ALEA SEED" watermark strings — that is
//! the whole point of the isolation split (those strings live here, never
//! in the production artifact).
//!
//! The marker below is a fixed, `#[used]`, `#[no_mangle]` static so a
//! future verify-aware release tool can positively identify this artifact
//! (e.g. to place it at `\EFI\ALEA\VERIFY.EFI` and record its hash in the
//! release manifest) without confusing it for the production edition.

/// The verify-edition marker bytes. Exactly 29 ASCII bytes, no trailing
/// NUL — the array length is the exact literal length, so a length-changing
/// edit is a compile error rather than silent drift.
const VERIFY_MARKER_BYTES: &[u8; 29] = b"ALEA-VERIFY-EDITION-MARKER-V1";

/// `#[no_mangle]`/`#[used]` copy of [`VERIFY_MARKER_BYTES`] at a fixed,
/// scanner-findable symbol name.
#[used]
#[no_mangle]
pub static ALEA_VERIFY_EDITION_MARKER_V1: [u8; 29] = *VERIFY_MARKER_BYTES;
