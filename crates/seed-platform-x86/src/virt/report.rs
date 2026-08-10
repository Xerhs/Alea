//! SPEC §11.2 — the combined, structured virtualization finding.
//!
//! SPEC §11.2 is explicit that this check "is not a security control
//! against a deliberate adversary and MUST NOT be presented as one," and
//! that any diagnostics screen built on it "MUST state that absence of
//! these indicators does not prove that no hidden hypervisor exists."
//! [`VirtReport`] therefore never collapses to a bare `bool`: it carries
//! the individual indicators that fired (if any) plus the exact
//! not-proof wording the §22.3 diagnostics screen displays either way.

use super::cpuid::{hypervisor_bit_set, hypervisor_vendor_string, CpuidSource};
use super::devpath::{classify_pci_id, PciIdSource, VirtualDeviceMarker, MAX_PCI_IDS};
use super::firmware::{classify_firmware_string, FirmwareMarker, FirmwareStringSource, MAX_FW_STRINGS};
use super::vendor::{classify_vendor, VendorId};

/// Upper bound on distinct indicators [`VirtReport`] can hold: one for the
/// CPUID hypervisor bit, one for the CPUID vendor classification, one per
/// inspected firmware string, and one per inspected PCI vendor:device ID.
pub const MAX_FINDINGS: usize = 2 + MAX_FW_STRINGS + MAX_PCI_IDS;

/// SPEC §11.2 — the §22.3 diagnostics-screen wording for a clean result.
/// "Clean" is not proof of absence — the wording says so explicitly, per
/// spec: "The warning MUST state that absence of these indicators does
/// not prove that no hidden hypervisor exists."
pub const NOT_PROOF_CLEAN: &str = "No virtualization indicators detected — not proof";

/// SPEC §11.2 — the §22.3 diagnostics-screen wording when one or more
/// indicators fired. Spec: "If obvious virtualization is detected,
/// production generation MUST be disabled." Disabling generation is the
/// caller's (state machine, WP-23) responsibility; this module only
/// supplies the finding and its wording.
pub const NOT_PROOF_DETECTED: &str =
    "Virtualization indicators detected — production generation disabled; \
     this is not a security guarantee, and its absence would not have been \
     proof that no hidden hypervisor exists";

/// SPEC §11.2 — a single reviewed virtualization indicator. Not
/// secret-bearing; ordinary derives are in scope (SPEC §20.2 governs
/// secret types, not diagnostic/CPU-identifying data).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    /// CPUID leaf 1 ECX bit 31 was set.
    CpuidHypervisorBit,
    /// The CPUID hypervisor vendor-ID leaf classified to `vendor`
    /// (possibly [`VendorId::Unrecognized`] — the bit being set is itself
    /// the indicator; naming the vendor is a bonus, not a requirement).
    CpuidVendor(VendorId),
    /// A firmware-reported string matched a known virtual-platform
    /// marker.
    FirmwareString(FirmwareMarker),
    /// A PCI vendor:device ID matched a known virtual graphics/input
    /// device marker (SPEC §11.2 "known virtual graphics and input
    /// device paths").
    VirtualDevice(VirtualDeviceMarker),
}

#[cfg(test)]
impl core::fmt::Debug for Indicator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Indicator::CpuidHypervisorBit => f.write_str("CpuidHypervisorBit"),
            Indicator::CpuidVendor(v) => write!(f, "CpuidVendor({v:?})"),
            Indicator::FirmwareString(m) => write!(f, "FirmwareString({m:?})"),
            Indicator::VirtualDevice(m) => write!(f, "VirtualDevice({m:?})"),
        }
    }
}

/// SPEC §11.2 — the structured result of a virtualization check: zero or
/// more [`Indicator`]s plus the not-proof wording appropriate to the
/// result, in a fixed-capacity container (`no_alloc`, SPEC §13).
pub struct VirtReport {
    findings: [Option<Indicator>; MAX_FINDINGS],
    count: usize,
}

impl VirtReport {
    fn empty() -> Self {
        Self {
            findings: [None; MAX_FINDINGS],
            count: 0,
        }
    }

    /// Record `indicator`. Silently drops the finding if
    /// [`MAX_FINDINGS`] is already full — that bound is sized to fit
    /// every indicator this module can ever produce in one `evaluate()`
    /// call, so this is unreachable in practice, not a lossy fallback
    /// relied upon by callers.
    fn push(&mut self, indicator: Indicator) {
        if self.count < MAX_FINDINGS {
            self.findings[self.count] = Some(indicator);
            self.count += 1;
        }
    }

    /// The indicators that fired, in detection order.
    #[must_use]
    pub fn findings(&self) -> &[Option<Indicator>] {
        &self.findings[..self.count]
    }

    /// How many indicators fired.
    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.count
    }

    /// SPEC §11.2: "If obvious virtualization is detected, production
    /// generation MUST be disabled." `true` here is the trigger for that
    /// policy; the caller (state machine) enforces the disablement.
    #[must_use]
    pub const fn suspected(&self) -> bool {
        self.count > 0
    }

    /// The exact §22.3 diagnostics-screen wording for this result —
    /// always carries the "not proof" qualifier, whichever branch fires.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        if self.suspected() {
            NOT_PROOF_DETECTED
        } else {
            NOT_PROOF_CLEAN
        }
    }
}

/// SPEC §11.2 — run every reviewed check (CPUID hypervisor bit, CPUID
/// vendor leaf, firmware string heuristics) and combine the results into
/// one [`VirtReport`].
///
/// `cpuid` and `firmware` are trait objects so production code can pass
/// [`super::cpuid::RealCpuid`] / a real firmware-string source while host
/// tests pass canned doubles — none of this function's logic depends on
/// which.
#[must_use]
pub fn evaluate(cpuid: &dyn CpuidSource, firmware: &dyn FirmwareStringSource) -> VirtReport {
    let mut report = VirtReport::empty();

    if hypervisor_bit_set(cpuid) {
        report.push(Indicator::CpuidHypervisorBit);
        let raw_vendor = hypervisor_vendor_string(cpuid);
        let vendor = classify_vendor(&raw_vendor);
        report.push(Indicator::CpuidVendor(vendor));
    }

    let fw_count = firmware.count().min(MAX_FW_STRINGS);
    for i in 0..fw_count {
        let s = firmware.get(i);
        if let Some(marker) = classify_firmware_string(s.as_str()) {
            report.push(Indicator::FirmwareString(marker));
        }
    }

    report
}

/// SPEC §11.2 — [`evaluate`], plus the "known virtual graphics and input
/// device paths" indicator: every reviewed check the SPEC enumerates for
/// §11.2, combined into one [`VirtReport`].
///
/// Kept as a separate, additive entry point (rather than changing
/// [`evaluate`]'s signature) so existing call sites are unaffected; a
/// caller wiring in a real [`super::devpath::uefi_backend::scan_bus_zero`]
/// result opts in by calling this function instead.
#[must_use]
pub fn evaluate_with_devices(
    cpuid: &dyn CpuidSource,
    firmware: &dyn FirmwareStringSource,
    devices: &dyn PciIdSource,
) -> VirtReport {
    let mut report = evaluate(cpuid, firmware);

    let dev_count = devices.count().min(MAX_PCI_IDS);
    for i in 0..dev_count {
        let id = devices.get(i);
        if let Some(marker) = classify_pci_id(id.vendor, id.device) {
            report.push(Indicator::VirtualDevice(marker));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virt::cpuid::{CpuidLeaf, HYPERVISOR_PRESENT_BIT, HYPERVISOR_VENDOR_LEAF};
    use crate::virt::firmware::FwString;

    struct FakeCpuid {
        leaf1_ecx: u32,
        vendor: [u8; 12],
    }

    impl CpuidSource for FakeCpuid {
        fn leaf(&self, eax: u32) -> CpuidLeaf {
            match eax {
                1 => CpuidLeaf {
                    eax: 0,
                    ebx: 0,
                    ecx: self.leaf1_ecx,
                    edx: 0,
                },
                HYPERVISOR_VENDOR_LEAF => CpuidLeaf {
                    eax: 0,
                    ebx: u32::from_le_bytes(self.vendor[0..4].try_into().unwrap()),
                    ecx: u32::from_le_bytes(self.vendor[4..8].try_into().unwrap()),
                    edx: u32::from_le_bytes(self.vendor[8..12].try_into().unwrap()),
                },
                _ => CpuidLeaf {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            }
        }
    }

    fn bare_metal_cpuid() -> FakeCpuid {
        FakeCpuid {
            leaf1_ecx: 0,
            vendor: [0; 12],
        }
    }

    struct FakeFirmware {
        strings: [&'static str; MAX_FW_STRINGS],
        count: usize,
    }

    impl FirmwareStringSource for FakeFirmware {
        fn count(&self) -> usize {
            self.count
        }
        fn get(&self, index: usize) -> FwString {
            if index >= self.count {
                return FwString::empty();
            }
            FwString::from_str_truncating(self.strings[index])
        }
    }

    fn no_firmware_strings() -> FakeFirmware {
        FakeFirmware {
            strings: [""; MAX_FW_STRINGS],
            count: 0,
        }
    }

    #[test]
    fn bare_metal_yields_clean_not_proof_summary() {
        let report = evaluate(&bare_metal_cpuid(), &no_firmware_strings());
        assert!(!report.suspected());
        assert_eq!(report.finding_count(), 0);
        assert_eq!(report.summary(), NOT_PROOF_CLEAN);
        assert!(report.summary().contains("not proof"));
    }

    #[test]
    fn kvm_hypervisor_bit_and_vendor_are_both_reported() {
        let cpuid = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"KVMKVMKVM\0\0\0",
        };
        let report = evaluate(&cpuid, &no_firmware_strings());
        assert!(report.suspected());
        let findings = report.findings();
        assert_eq!(findings[0], Some(Indicator::CpuidHypervisorBit));
        assert_eq!(
            findings[1],
            Some(Indicator::CpuidVendor(VendorId::Kvm))
        );
        assert_eq!(report.summary(), NOT_PROOF_DETECTED);
    }

    #[test]
    fn firmware_string_alone_triggers_suspected_even_without_cpuid_bit() {
        let firmware = FakeFirmware {
            strings: ["QEMU Standard PC", "", "", ""],
            count: 1,
        };
        let report = evaluate(&bare_metal_cpuid(), &firmware);
        assert!(report.suspected());
        assert_eq!(
            report.findings()[0],
            Some(Indicator::FirmwareString(FirmwareMarker::Qemu))
        );
    }

    #[test]
    fn hypervisor_bit_with_unrecognized_vendor_still_flags_suspected() {
        let cpuid = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"totallyfake!",
        };
        let report = evaluate(&cpuid, &no_firmware_strings());
        assert!(report.suspected());
        assert_eq!(
            report.findings()[1],
            Some(Indicator::CpuidVendor(VendorId::Unrecognized))
        );
    }

    #[test]
    fn multiple_indicators_all_fit_within_max_findings() {
        let cpuid = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"VBoxVBoxVBox",
        };
        let firmware = FakeFirmware {
            strings: ["innotek GmbH", "VirtualBox", "", ""],
            count: 2,
        };
        let report = evaluate(&cpuid, &firmware);
        // hypervisor bit + vendor + 2 firmware markers = 4, well within
        // MAX_FINDINGS.
        assert_eq!(report.finding_count(), 4);
        assert!(report.suspected());
    }

    #[test]
    fn ordinary_firmware_strings_do_not_cause_false_positive() {
        let firmware = FakeFirmware {
            strings: [
                "American Megatrends International, LLC",
                "Lenovo Group Limited",
                "",
                "",
            ],
            count: 2,
        };
        let report = evaluate(&bare_metal_cpuid(), &firmware);
        assert!(!report.suspected());
        assert_eq!(report.summary(), NOT_PROOF_CLEAN);
    }

    // ---- SPEC §11.2 "known virtual graphics and input device paths" ----

    use crate::virt::devpath::{PciId, PciIdSource, VirtualDeviceMarker, MAX_PCI_IDS};

    struct FakeDevices {
        ids: [PciId; MAX_PCI_IDS],
        count: usize,
    }

    impl PciIdSource for FakeDevices {
        fn count(&self) -> usize {
            self.count
        }
        fn get(&self, index: usize) -> PciId {
            if index >= self.count {
                return PciId { vendor: 0, device: 0 };
            }
            self.ids[index]
        }
    }

    fn no_devices() -> FakeDevices {
        FakeDevices {
            ids: [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS],
            count: 0,
        }
    }

    #[test]
    fn evaluate_with_devices_matches_plain_evaluate_when_no_devices_reported() {
        let a = evaluate(&bare_metal_cpuid(), &no_firmware_strings());
        let b = evaluate_with_devices(&bare_metal_cpuid(), &no_firmware_strings(), &no_devices());
        assert_eq!(a.suspected(), b.suspected());
        assert_eq!(a.finding_count(), b.finding_count());
        assert_eq!(a.summary(), b.summary());
    }

    #[test]
    fn virtio_gpu_pci_id_alone_triggers_suspected() {
        let mut ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        ids[0] = PciId {
            vendor: 0x1AF4,
            device: 0x1050,
        };
        let devices = FakeDevices { ids, count: 1 };
        let report = evaluate_with_devices(&bare_metal_cpuid(), &no_firmware_strings(), &devices);
        assert!(report.suspected());
        assert_eq!(report.summary(), NOT_PROOF_DETECTED);
        assert_eq!(
            report.findings()[0],
            Some(Indicator::VirtualDevice(VirtualDeviceMarker::VirtioGpu))
        );
    }

    /// ALEA-2026-005: a virtual marker at the LAST populated slot (not the
    /// first) is still detected — `evaluate_with_devices` scans the whole
    /// source, it does not stop at the first entry. (In production
    /// `scan_bus_zero` pre-filters to matches, so a marker can never be
    /// crowded out of the buffer by benign devices in the first place; this
    /// pins the report layer's no-early-stop half of that guarantee.)
    #[test]
    fn virtual_marker_at_last_slot_is_still_detected() {
        let mut ids = [PciId { vendor: 0x8086, device: 0x1912 }; MAX_PCI_IDS]; // benign fill
        let last = MAX_PCI_IDS - 1;
        ids[last] = PciId { vendor: 0x1AF4, device: 0x1050 }; // virtio-gpu marker
        let devices = FakeDevices {
            ids,
            count: MAX_PCI_IDS,
        };
        let report = evaluate_with_devices(&bare_metal_cpuid(), &no_firmware_strings(), &devices);
        assert!(report.suspected(), "marker at the last slot must be detected");
        assert_eq!(report.summary(), NOT_PROOF_DETECTED);
    }

    #[test]
    fn ordinary_pci_id_does_not_cause_false_positive() {
        let mut ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        ids[0] = PciId {
            vendor: 0x8086,
            device: 0x1912,
        }; // real Intel integrated graphics
        let devices = FakeDevices { ids, count: 1 };
        let report = evaluate_with_devices(&bare_metal_cpuid(), &no_firmware_strings(), &devices);
        assert!(!report.suspected());
        assert_eq!(report.summary(), NOT_PROOF_CLEAN);
    }

    #[test]
    fn all_four_indicator_classes_combine_within_max_findings() {
        let cpuid = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"KVMKVMKVM\0\0\0",
        };
        let firmware = FakeFirmware {
            strings: ["QEMU Standard PC", "", "", ""],
            count: 1,
        };
        let mut ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        ids[0] = PciId {
            vendor: 0x1AF4,
            device: 0x1050,
        };
        let devices = FakeDevices { ids, count: 1 };
        let report = evaluate_with_devices(&cpuid, &firmware, &devices);
        // hypervisor bit + vendor + 1 firmware marker + 1 device marker.
        assert_eq!(report.finding_count(), 4);
        assert!(report.suspected());
    }
}
