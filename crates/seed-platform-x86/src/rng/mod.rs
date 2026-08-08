//! Machine entropy: `EFI_RNG_PROTOCOL`, `RDSEED64`, `RDRAND`, USB-TRNG
//! (WP-24, WP-U3, SPEC §15–16, §18, SPEC_USB_TRNG.md §7, §9).
//!
//! Four independent drivers, one per machine-entropy mechanism SPEC §15 /
//! SPEC_USB_TRNG.md recognize:
//!
//! - [`efi_rng`] — `EFI_RNG_PROTOCOL` (SPEC §15.1): locate, enumerate
//!   algorithms into a fixed buffer, policy-filter, exact-length reads,
//!   SPEC §16 catastrophic checks.
//! - [`rdseed`] — `RDSEED` 64-bit form (SPEC §15.2): CPUID gate,
//!   vendor/family/model/stepping vs the compiled-in policy, per-instruction
//!   carry-flag check, bounded retries, ≥4 values per 256-bit record,
//!   catastrophic checks.
//! - [`rdrand`] — `RDRAND` 64-bit form (SPEC §15.3): supplementary-only —
//!   this driver produces a tagged [`record::SourceRecord`] and nothing
//!   more; it never decides whether any entropy mode is enabled. That
//!   decision belongs to the state machine (WP-23) applying policy
//!   (WP-12), never to a driver having merely produced output.
//! - [`usb_trng`] — USB hardware TRNG (SPEC_USB_TRNG.md §7, §9): allow-list
//!   match via [`usb_trng::UsbTrngTransport`], two-block diagnostic read,
//!   SPEC §16 catastrophic checks plus the USB-specific failure modes
//!   (short read, device-gone/timeout/stall, descriptor mismatch, echo
//!   handshake failure). Tagged `0x12`, claimed not counted (SPEC_USB_TRNG
//!   §10) — that accounting rule is enforced by the transcript/policy
//!   layers this driver feeds, not here. The real transport
//!   (`EFI_USB_IO_PROTOCOL`-driven) is WP-U4 and is **not implemented in
//!   this repository** (§7.4-BLOCKED; see `IMPLEMENTATION_MAP_USB_TRNG.md`
//!   §4/§7) — only the trait contract and a host-test double exist here.
//!
//! Every driver's real-hardware/firmware dependency sits behind a small
//! injectable trait ([`efi_rng::EfiRngProvider`],
//! [`raw::RawInstructionSource`], [`usb_trng::UsbTrngTransport`], and the
//! reused [`crate::virt::CpuidSource`]), so the policy-filtering and
//! health-check logic — the actual SPEC-mandated behavior — is exercised
//! by host `cargo test` with canned doubles, never by executing
//! privileged instructions or linking firmware protocols off-target.
//!
//! [`health`] holds the SPEC §16 catastrophic-check primitives shared by
//! every driver, including [`usb_trng`]'s length/degenerate/repeated-block
//! checks (SPEC_USB_TRNG §9). [`record::SourceRecord`] is this module's
//! common output shape: a `(tag, algo_id, bytes)` triple ready for
//! `seed_protocol::transcript::TranscriptBuilder::add_source` (SPEC
//! §19.1) — secret-bearing, so it carries no `Copy`/`Clone`/`Debug`
//! (SPEC §13, §20.2) and scrubs itself on `Drop`.
//!
//! This module never decides *which* sources to sample or what mode they
//! enable (SPEC §18's reinforced/machine-only/physical-only choice) —
//! that orchestration, and the exact UI wording SPEC §15.1/§16/§18
//! mandate, belongs to the workflow crates (WP-25/26) that call these
//! drivers and stage their output into the transcript.

/// SPEC §16 catastrophic-check primitives shared by every driver.
pub mod health;

/// Common secret-bearing output shape ([`record::SourceRecord`]) every
/// driver in this module produces.
pub mod record;

/// EFI GUID → canonical text rendering, used to compare an enumerated
/// `EFI_RNG_PROTOCOL` algorithm against the compiled-in policy's
/// `allowed_algorithms` text identifiers.
pub mod guid;

/// CPUID identification (vendor/family/model/stepping, RDSEED/RDRAND
/// support bits) shared by the `rdseed` and `rdrand` drivers.
pub mod cpu;

/// Raw `RDSEED`/`RDRAND` instruction execution, abstracted for host
/// testing.
pub mod raw;

/// Counts-only progress observation for machine-source acquisition (SPEC
/// §21's acquiring screen), so a slow-but-working source can show visible
/// progress without leaking secret bytes.
pub mod progress;

/// `EFI_RNG_PROTOCOL` driver (SPEC §15.1).
pub mod efi_rng;

/// `RDSEED` (64-bit) driver (SPEC §15.2).
pub mod rdseed;

/// `RDRAND` (64-bit) supplementary-only driver (SPEC §15.3).
pub mod rdrand;

/// USB-TRNG driver (WP-U3, SPEC_USB_TRNG.md §7, §9). The
/// [`usb_trng::UsbTrngTransport`] trait contract plus a host-test double are
/// implemented here; the real `EFI_USB_IO_PROTOCOL` transport (WP-U4) is
/// **not** — see the module doc comment for the §7.4-BLOCKED boundary.
pub mod usb_trng;

mod util;

pub use health::HealthError;
pub use record::SourceRecord;
