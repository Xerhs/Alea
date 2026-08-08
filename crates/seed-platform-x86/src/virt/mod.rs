//! Owned by WP-19 (SPEC §11.2). Virtualization detection.
//!
//! SPEC §11.2 states the purpose honestly: this is "a guard against
//! honest mistakes (booting in a VM or test harness by accident). A
//! malicious hypervisor hides these indicators trivially. This is not a
//! security control against a deliberate adversary and MUST NOT be
//! presented as one."
//!
//! This module checks, per SPEC §11.2:
//! - the CPUID hypervisor-present bit ([`cpuid`]);
//! - known hypervisor CPUID vendor identifiers ([`vendor`]);
//! - firmware vendor/product string heuristics for common virtual
//!   platforms ([`firmware`]);
//! - known virtual graphics and input device PCI identifiers
//!   ([`devpath`]).
//!
//! [`report::evaluate`] combines the first three into a single
//! [`report::VirtReport`]; [`report::evaluate_with_devices`] additionally
//! folds in [`devpath`]'s PCI-identifier check. Either way the result is
//! a structured finding, never a bare `bool` — carrying the exact
//! "not proof" wording the §22.3 diagnostics screen displays.
//!
//! Every backend that touches real hardware/firmware (`RealCpuid`, the
//! UEFI firmware-string source, the UEFI PCI-scan source) is behind an
//! injectable trait ([`cpuid::CpuidSource`], [`firmware::FirmwareStringSource`],
//! [`devpath::PciIdSource`]), so this module's detection/classification
//! logic is exercised by host `cargo test` with canned doubles, matching
//! IMPLEMENTATION_MAP WP-19's "host tests with injected CPUID/string
//! providers via trait" requirement.

pub mod cpuid;
pub mod devpath;
pub mod firmware;
pub mod report;
pub mod vendor;

pub use cpuid::{CpuidLeaf, CpuidSource};
pub use devpath::{PciId, PciIdSource, VirtualDeviceMarker, MAX_PCI_IDS};
pub use firmware::{FirmwareMarker, FirmwareStringSource, FwString};
pub use report::{
    evaluate, evaluate_with_devices, Indicator, VirtReport, MAX_FINDINGS, NOT_PROOF_CLEAN,
    NOT_PROOF_DETECTED,
};
pub use vendor::VendorId;

#[cfg(target_arch = "x86_64")]
pub use cpuid::RealCpuid;

#[cfg(target_os = "uefi")]
pub use firmware::uefi_backend::SystemTableFirmwareStrings;

#[cfg(target_os = "uefi")]
pub use devpath::uefi_backend::scan_bus_zero;
