//! SPEC §11.2 — known hypervisor CPUID vendor-ID strings.
//!
//! Reviewed set: KVM, VMware, VirtualBox, Hyper-V, QEMU (plain TCG, i.e.
//! not running under KVM), Xen, Parallels — the vendors IMPLEMENTATION_MAP
//! §5 names for WP-19.

/// SPEC §11.2 — a recognized (or not) CPUID hypervisor vendor identity.
/// Not secret-bearing; ordinary derives are in scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VendorId {
    Kvm,
    Vmware,
    VirtualBox,
    HyperV,
    QemuTcg,
    Xen,
    Parallels,
    /// The hypervisor-present bit was set but the 12-byte vendor string
    /// did not match any reviewed entry. Still reported as an indicator —
    /// SPEC §11.2 does not require naming the hypervisor, only detecting
    /// it.
    Unrecognized,
}

#[cfg(test)]
impl core::fmt::Debug for VendorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            VendorId::Kvm => "Kvm",
            VendorId::Vmware => "Vmware",
            VendorId::VirtualBox => "VirtualBox",
            VendorId::HyperV => "HyperV",
            VendorId::QemuTcg => "QemuTcg",
            VendorId::Xen => "Xen",
            VendorId::Parallels => "Parallels",
            VendorId::Unrecognized => "Unrecognized",
        };
        f.write_str(s)
    }
}

/// SPEC §11.2 — reviewed 12-byte ASCII CPUID hypervisor vendor-ID strings,
/// as published by each hypervisor project.
const KNOWN_VENDORS: &[(VendorId, [u8; 12])] = &[
    (VendorId::Kvm, *b"KVMKVMKVM\0\0\0"),
    (VendorId::Vmware, *b"VMwareVMware"),
    (VendorId::VirtualBox, *b"VBoxVBoxVBox"),
    (VendorId::HyperV, *b"Microsoft Hv"),
    (VendorId::QemuTcg, *b"TCGTCGTCGTCG"),
    (VendorId::Xen, *b"XenVMMXenVMM"),
    (VendorId::Parallels, *b" prl hyperv "),
];

/// SPEC §11.2 — classify a 12-byte CPUID hypervisor vendor-ID string
/// against the reviewed set.
pub fn classify_vendor(id: &[u8; 12]) -> VendorId {
    for (vendor, pattern) in KNOWN_VENDORS {
        if id == pattern {
            return *vendor;
        }
    }
    VendorId::Unrecognized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_known_vendor_string_classifies_correctly() {
        assert_eq!(classify_vendor(b"KVMKVMKVM\0\0\0"), VendorId::Kvm);
        assert_eq!(classify_vendor(b"VMwareVMware"), VendorId::Vmware);
        assert_eq!(classify_vendor(b"VBoxVBoxVBox"), VendorId::VirtualBox);
        assert_eq!(classify_vendor(b"Microsoft Hv"), VendorId::HyperV);
        assert_eq!(classify_vendor(b"TCGTCGTCGTCG"), VendorId::QemuTcg);
        assert_eq!(classify_vendor(b"XenVMMXenVMM"), VendorId::Xen);
        assert_eq!(classify_vendor(b" prl hyperv "), VendorId::Parallels);
    }

    #[test]
    fn unknown_string_is_unrecognized_not_a_panic() {
        assert_eq!(classify_vendor(b"totallyfake!"), VendorId::Unrecognized);
        assert_eq!(classify_vendor(&[0u8; 12]), VendorId::Unrecognized);
    }

    #[test]
    fn near_miss_does_not_alias_to_a_known_vendor() {
        // One byte off from the KVM string must not classify as KVM.
        assert_eq!(classify_vendor(b"KVMKVMKVN\0\0\0"), VendorId::Unrecognized);
    }
}
