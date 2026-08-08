//! SPEC §11.2 — CPUID hypervisor-present bit and hypervisor vendor-ID leaf.
//!
//! The `cpuid` instruction is abstracted behind [`CpuidSource`] so the
//! decode/classification logic below is host-testable (`cargo test`) with
//! injected leaf values, without ever executing `cpuid` off-target. The
//! real instruction is only reachable through [`RealCpuid`], which is
//! `x86_64`-gated (both the host `x86_64-unknown-linux-musl` test target
//! and the `x86_64-unknown-uefi` production target satisfy that gate).

/// SPEC §11.2 — the four general-purpose registers `cpuid` writes for a
/// given leaf (`eax` input, `eax`/`ebx`/`ecx`/`edx` output).
///
/// Not secret-bearing (CPU-identifying data only), so ordinary derives are
/// fine here per SPEC §20.2's scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CpuidLeaf {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[cfg(test)]
impl core::fmt::Debug for CpuidLeaf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuidLeaf")
            .field("eax", &self.eax)
            .field("ebx", &self.ebx)
            .field("ecx", &self.ecx)
            .field("edx", &self.edx)
            .finish()
    }
}

/// SPEC §11.2 — source of raw CPUID leaves. Injectable so host tests can
/// supply canned hypervisor/bare-metal responses without executing the
/// `cpuid` instruction, and so the real backend stays swappable.
pub trait CpuidSource {
    /// Execute (or simulate) `cpuid` with `eax` as the leaf selector and
    /// `ecx = 0` as the sub-leaf. Every leaf this module reads is a
    /// sub-leaf-0 leaf, so no sub-leaf parameter is exposed.
    fn leaf(&self, eax: u32) -> CpuidLeaf;
}

/// SPEC §11.2 — CPUID leaf 1, ECX bit 31: the hypervisor-present bit that
/// well-behaved hypervisors set to announce themselves to guest software.
pub const HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;

/// SPEC §11.2 — the standard leaf carrying the 12-byte ASCII hypervisor
/// vendor-ID string, valid only when [`HYPERVISOR_PRESENT_BIT`] is set.
pub const HYPERVISOR_VENDOR_LEAF: u32 = 0x4000_0000;

/// SPEC §11.2 — real `cpuid`-backed [`CpuidSource`]. Only compiled for
/// `x86_64` targets (this crate has no other target).
#[cfg(target_arch = "x86_64")]
pub struct RealCpuid;

#[cfg(target_arch = "x86_64")]
impl CpuidSource for RealCpuid {
    fn leaf(&self, eax: u32) -> CpuidLeaf {
        // `__cpuid` executes the `cpuid` instruction, which is
        // unconditionally available on every x86_64 CPU (this crate never
        // targets anything else) and has no memory-safety preconditions —
        // it only reads processor-identification registers. (Safe fn in
        // this toolchain's `core::arch::x86_64`.)
        let r = core::arch::x86_64::__cpuid(eax);
        CpuidLeaf {
            eax: r.eax,
            ebx: r.ebx,
            ecx: r.ecx,
            edx: r.edx,
        }
    }
}

/// SPEC §11.2 — true when CPUID leaf 1 ECX bit 31 (the hypervisor-present
/// bit) is set. This is one indicator among several; see
/// [`crate::virt::report`] for the combined, honestly-worded finding.
pub fn hypervisor_bit_set(src: &dyn CpuidSource) -> bool {
    (src.leaf(1).ecx & HYPERVISOR_PRESENT_BIT) != 0
}

/// SPEC §11.2 — decode the 12-byte ASCII hypervisor vendor-ID string from
/// [`HYPERVISOR_VENDOR_LEAF`] (`ebx:ecx:edx`, each little-endian, per the
/// CPUID hypervisor-vendor-string convention shared by KVM/VMware/
/// VirtualBox/Hyper-V/QEMU-TCG/Xen/Parallels). Only meaningful when
/// [`hypervisor_bit_set`] returned `true`.
pub fn hypervisor_vendor_string(src: &dyn CpuidSource) -> [u8; 12] {
    let l = src.leaf(HYPERVISOR_VENDOR_LEAF);
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&l.ebx.to_le_bytes());
    out[4..8].copy_from_slice(&l.ecx.to_le_bytes());
    out[8..12].copy_from_slice(&l.edx.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
                HYPERVISOR_VENDOR_LEAF => {
                    let ebx = u32::from_le_bytes(self.vendor[0..4].try_into().unwrap());
                    let ecx = u32::from_le_bytes(self.vendor[4..8].try_into().unwrap());
                    let edx = u32::from_le_bytes(self.vendor[8..12].try_into().unwrap());
                    CpuidLeaf {
                        eax: 0,
                        ebx,
                        ecx,
                        edx,
                    }
                }
                _ => CpuidLeaf {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            }
        }
    }

    #[test]
    fn hypervisor_bit_detected_when_set() {
        let src = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"KVMKVMKVM\0\0\0",
        };
        assert!(hypervisor_bit_set(&src));
    }

    #[test]
    fn hypervisor_bit_absent_on_bare_metal() {
        let src = FakeCpuid {
            leaf1_ecx: 0x7FFF_FFFF, // every other bit set, bit 31 clear
            vendor: [0; 12],
        };
        assert!(!hypervisor_bit_set(&src));
    }

    #[test]
    fn hypervisor_bit_other_bits_do_not_trigger_false_positive() {
        // Only bit 31 means "hypervisor present"; a single low bit must
        // not be mistaken for it.
        let src = FakeCpuid {
            leaf1_ecx: 0x0000_0001,
            vendor: [0; 12],
        };
        assert!(!hypervisor_bit_set(&src));
    }

    #[test]
    fn vendor_string_round_trips_through_registers() {
        let src = FakeCpuid {
            leaf1_ecx: HYPERVISOR_PRESENT_BIT,
            vendor: *b"VMwareVMware",
        };
        assert_eq!(&hypervisor_vendor_string(&src), b"VMwareVMware");
    }
}
