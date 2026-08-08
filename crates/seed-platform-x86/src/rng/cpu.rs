//! CPUID identification for RDSEED/RDRAND gating (WP-24, SPEC §15.2,
//! §15.3).
//!
//! Reuses [`crate::virt::CpuidSource`] (owned by WP-19) rather than
//! defining a second CPUID abstraction — that trait's `leaf(eax)` is
//! exactly "execute `cpuid` with `ecx = 0`", which is all every leaf this
//! module reads needs (leaf 0 vendor string, leaf 1 feature/signature
//! bits, leaf 7 sub-leaf 0 extended features). This module only *reads*
//! `crate::virt`; it does not modify anything under that WP's ownership.
//!
//! Family/model/stepping extraction follows the standard CPUID leaf 1
//! `EAX` ("processor signature") decode documented in the Intel SDM,
//! Volume 2A, §"CPUID—CPU Identification": if the base family field is
//! `0xF`, the displayed family is `base_family + extended_family`;
//! displayed model additionally folds in `extended_model` when the base
//! family is `0x6` or `0xF`. AMD's CPUID leaf 1 uses the identical
//! encoding (AMD64 Architecture Programmer's Manual, Volume 3).

use crate::virt::CpuidSource;

/// CPUID leaf carrying the 12-byte ASCII vendor-ID string in `ebx:edx:ecx`
/// order (SPEC §15.2: "identify CPU vendor"). Not to be confused with
/// `crate::virt::cpuid::HYPERVISOR_VENDOR_LEAF` (`0x4000_0000`, `ebx:
/// ecx:edx` order) — this is the standard leaf-0 CPU vendor string, a
/// different leaf with a different register order.
const VENDOR_LEAF: u32 = 0;

/// CPUID leaf carrying the processor signature (family/model/stepping)
/// in `EAX`, and the RDRAND-support bit (bit 30) in `ECX`.
const FEATURE_LEAF: u32 = 1;

/// CPUID leaf 7, sub-leaf 0's `EBX` bit 18: RDSEED support.
const EXTENDED_FEATURE_LEAF: u32 = 7;

/// `ECX` bit 30 of [`FEATURE_LEAF`]: RDRAND support (SPEC §15.3).
const RDRAND_ECX_BIT: u32 = 1 << 30;

/// `EBX` bit 18 of [`EXTENDED_FEATURE_LEAF`] sub-leaf 0: RDSEED support
/// (SPEC §15.2: "verify CPUID support").
const RDSEED_EBX_BIT: u32 = 1 << 18;

/// True when CPUID reports RDSEED support (SPEC §15.2: "verify CPUID
/// support" — MUST be checked before ever executing `rdseed`, since the
/// instruction raises `#UD` on unsupported processors).
pub fn rdseed_supported(src: &dyn CpuidSource) -> bool {
    (src.leaf(EXTENDED_FEATURE_LEAF).ebx & RDSEED_EBX_BIT) != 0
}

/// True when CPUID reports RDRAND support (SPEC §15.3: "CPUID support...
/// required").
pub fn rdrand_supported(src: &dyn CpuidSource) -> bool {
    (src.leaf(FEATURE_LEAF).ecx & RDRAND_ECX_BIT) != 0
}

/// Decodes the standard 12-byte ASCII CPU vendor-ID string (e.g.
/// `"GenuineIntel"`, `"AuthenticAMD"`) from CPUID leaf 0's `ebx:edx:ecx`
/// registers (SPEC §15.2).
pub fn vendor_string(src: &dyn CpuidSource) -> [u8; 12] {
    let leaf = src.leaf(VENDOR_LEAF);
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    out[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
    out[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
    out
}

/// Decodes `(family, model, stepping)` from CPUID leaf 1's `EAX`
/// processor-signature register (SPEC §15.2; see module doc for the
/// extended-family/extended-model folding rule).
pub fn family_model_stepping(src: &dyn CpuidSource) -> (u16, u8, u8) {
    let eax = src.leaf(FEATURE_LEAF).eax;

    let stepping = (eax & 0xF) as u8;
    let base_model = ((eax >> 4) & 0xF) as u8;
    let base_family = ((eax >> 8) & 0xF) as u16;
    let ext_model = ((eax >> 16) & 0xF) as u8;
    let ext_family = ((eax >> 20) & 0xFF) as u16;

    let family = if base_family == 0xF { base_family + ext_family } else { base_family };
    let model =
        if base_family == 0x6 || base_family == 0xF { (ext_model << 4) | base_model } else { base_model };

    (family, model, stepping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virt::CpuidLeaf;

    struct FakeCpuid {
        leaf0: CpuidLeaf,
        leaf1: CpuidLeaf,
        leaf7: CpuidLeaf,
    }

    impl Default for FakeCpuid {
        fn default() -> Self {
            let zero = CpuidLeaf { eax: 0, ebx: 0, ecx: 0, edx: 0 };
            FakeCpuid { leaf0: zero, leaf1: zero, leaf7: zero }
        }
    }

    impl CpuidSource for FakeCpuid {
        fn leaf(&self, eax: u32) -> CpuidLeaf {
            match eax {
                0 => self.leaf0,
                1 => self.leaf1,
                7 => self.leaf7,
                _ => CpuidLeaf { eax: 0, ebx: 0, ecx: 0, edx: 0 },
            }
        }
    }

    #[test]
    fn decodes_genuine_intel_vendor_string() {
        // "GenuineIntel" split ebx="Genu" edx="ineI" ecx="ntel" (standard
        // CPUID leaf-0 vendor-string register order).
        let mut src = FakeCpuid::default();
        src.leaf0 = CpuidLeaf {
            eax: 0,
            ebx: u32::from_le_bytes(*b"Genu"),
            ecx: u32::from_le_bytes(*b"ntel"),
            edx: u32::from_le_bytes(*b"ineI"),
        };
        assert_eq!(&vendor_string(&src), b"GenuineIntel");
    }

    #[test]
    fn decodes_authentic_amd_vendor_string() {
        let mut src = FakeCpuid::default();
        src.leaf0 = CpuidLeaf {
            eax: 0,
            ebx: u32::from_le_bytes(*b"Auth"),
            ecx: u32::from_le_bytes(*b"cAMD"),
            edx: u32::from_le_bytes(*b"enti"),
        };
        assert_eq!(&vendor_string(&src), b"AuthenticAMD");
    }

    #[test]
    fn decodes_skylake_family_model_stepping() {
        // Known-answer: Intel Skylake-family parts report CPUID.1:EAX =
        // 0x000506E3 (publicly documented processor signature), which
        // decodes to family 6, model 0x5E, stepping 3:
        //   stepping    = eax & 0xF                = 0x3
        //   base_model  = (eax >> 4) & 0xF          = 0xE
        //   base_family = (eax >> 8) & 0xF          = 0x6
        //   ext_model   = (eax >> 16) & 0xF         = 0x5
        //   ext_family  = (eax >> 20) & 0xFF        = 0x0
        //   family = base_family (!= 0xF)           = 6
        //   model  = base_family==6 => (ext_model<<4)|base_model = 0x5E
        let mut src = FakeCpuid::default();
        src.leaf1 = CpuidLeaf { eax: 0x000506E3, ebx: 0, ecx: 0, edx: 0 };
        assert_eq!(family_model_stepping(&src), (6, 0x5E, 3));
    }

    #[test]
    fn decodes_extended_family_and_model() {
        // Synthetic EAX built by hand from chosen field values so the
        // extended-family/extended-model folding path (base_family ==
        // 0xF) is exercised, independent of the base-family-6 case above:
        //   stepping=2, base_model=0xA, base_family=0xF, ext_model=0x3,
        //   ext_family=0x06
        //   eax = (0x06<<20) | (0x3<<16) | (0xF<<8) | (0xA<<4) | 0x2
        //       = 0x00630FA2
        // expected family = 0xF + 0x06 = 0x15 (21)
        // expected model  = (0x3<<4)|0xA = 0x3A (58)
        let mut src = FakeCpuid::default();
        src.leaf1 = CpuidLeaf { eax: 0x0063_0FA2, ebx: 0, ecx: 0, edx: 0 };
        assert_eq!(family_model_stepping(&src), (0x15, 0x3A, 2));
    }

    #[test]
    fn rdseed_support_reads_leaf7_ebx_bit18() {
        let mut src = FakeCpuid::default();
        assert!(!rdseed_supported(&src));
        src.leaf7 = CpuidLeaf { eax: 0, ebx: RDSEED_EBX_BIT, ecx: 0, edx: 0 };
        assert!(rdseed_supported(&src));
    }

    #[test]
    fn rdseed_support_ignores_unrelated_bits() {
        let mut src = FakeCpuid::default();
        src.leaf7 = CpuidLeaf { eax: 0, ebx: !RDSEED_EBX_BIT, ecx: 0, edx: 0 };
        assert!(!rdseed_supported(&src));
    }

    #[test]
    fn rdrand_support_reads_leaf1_ecx_bit30() {
        let mut src = FakeCpuid::default();
        assert!(!rdrand_supported(&src));
        src.leaf1 = CpuidLeaf { eax: 0, ebx: 0, ecx: RDRAND_ECX_BIT, edx: 0 };
        assert!(rdrand_supported(&src));
    }

    #[test]
    fn rdrand_support_ignores_unrelated_bits() {
        let mut src = FakeCpuid::default();
        src.leaf1 = CpuidLeaf { eax: 0, ebx: 0, ecx: !RDRAND_ECX_BIT, edx: 0 };
        assert!(!rdrand_supported(&src));
    }
}
