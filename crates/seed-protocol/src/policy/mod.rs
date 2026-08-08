//! Compiled-in entropy-policy parser (WP-12, SPEC §15).
//!
//! `entropy-policy.toml` (shipped at the repository root, `SPEC.md` §15)
//! defines which machine entropy sources may be used and how: approved
//! source classes, approved algorithm identifiers, CPU
//! vendor/family/model/stepping rules, a known-bad-platform denylist,
//! sole-source-vs-supplementary-only flags, and the policy version shown
//! by the UI. It also defines the `[usb_trng]` + `[[usb_trng_devices]]`
//! USB hardware-TRNG allow-list (SPEC_USB_TRNG §8). A USB TRNG never
//! counts toward the SPEC §17.2 witnessed floor — there is no policy key
//! that can change that (SPEC_USB_TRNG §8.2, §10.2).
//!
//! This module never allocates and never pulls in a general-purpose TOML
//! crate (`IMPLEMENTATION_MAP.md` §3: project-owned, cross-tested code is
//! preferred to keep the dependency graph minimal, and a full TOML parser
//! would require `alloc`). Instead it implements a small, fixed grammar
//! that is a strict *subset* of TOML — documented in full in
//! [`parser`]'s module header — sufficient to express this one schema.
//! Anything outside that subset, or outside the fixed schema, is rejected;
//! there is no best-effort/partial parse (SPEC §15, §27.3).
//!
//! Signature verification of the policy file is out of scope for this
//! module (owned by the release-signing tooling, `IMPLEMENTATION_MAP.md`
//! §5 WP-29/30); this module only parses and structurally/semantically
//! validates bytes that have already been accepted as authentic.

/// The parser and its error/grammar documentation.
mod parser;

/// The parsed policy data model.
mod types;

pub use parser::{parse, ParseError, ParseErrorKind, MAX_LINE_LEN};
pub use types::{
    AlgoId, CpuRange, CpuRule, DenylistEntry, EfiRngPolicy, FixedStr, Policy, RdrandPolicy,
    RdseedPolicy, Reason, Tpm12Policy, Tpm2Policy, UsbClass, UsbTrngDevice, UsbTrngPolicy, Vendor,
    KNOWN_USB_TRNG_PROFILES, MAX_ALGORITHMS, MAX_ALGO_ID_LEN, MAX_CPU_RULES,
    MAX_DENYLIST_ENTRIES, MAX_INIT_COMMAND_LEN, MAX_MIN_FIRMWARE_LEN, MAX_PROFILE_LEN,
    MAX_REASON_LEN, MAX_TPM_MANUFACTURERS, MAX_USB_TRNG_DEVICES, MAX_USB_TRNG_READ_BYTES,
    MAX_VENDOR_LEN, MIN_USB_TRNG_READ_BYTES,
};
