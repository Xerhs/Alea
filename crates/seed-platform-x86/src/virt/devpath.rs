//! SPEC §11.2 — known virtual graphics and input device paths.
//!
//! SPEC §11.2 lists five reviewed indicator classes; this module supplies
//! the fifth that [`super::cpuid`]/[`super::vendor`] (CPUID) and
//! [`super::firmware`] (firmware vendor/product strings) do not cover:
//! "known virtual graphics and input device paths." A UEFI device path
//! for a PCI function never carries the function's PCI vendor/device ID
//! (only its topological bus/device/function position), so identifying a
//! *known* virtual GPU/input device means reading PCI configuration-space
//! offsets 0x00 (vendor ID) and 0x02 (device ID) for the function behind
//! the path — exactly what [`classify_pci_id`] matches against a reviewed
//! table of publicly documented virtual-platform IDs (VirtIO/Red Hat,
//! VirtualBox, VMware, QXL, Hyper-V's synthetic VGA, Bochs/QEMU std VGA).
//!
//! Like [`super::firmware`], this is a **heuristic, not a security
//! control** (SPEC §11.2: "A malicious hypervisor hides these indicators
//! trivially"): matching contributes a positive indicator only, never
//! proof of absence. The classifier ([`classify_pci_id`]) is exercised by
//! host `cargo test` against literal vendor:device pairs; the real
//! firmware-side scan ([`uefi_backend`]) is `#[cfg(target_os = "uefi")]`
//! only and, per IMPLEMENTATION_MAP.md §6 ownership boundaries, is not
//! wired into the flow-level call sites (`seed-uefi-production`/
//! `seed-uefi-test`, owned by WP-25/26/27) by this module — that
//! integration is called out in `shared_file_needs`.
//!
//! No `alloc` (SPEC §13): identifiers are held in a fixed-capacity array.

/// Maximum number of PCI (vendor, device) identifiers a [`PciIdSource`]
/// may report in one scan.
pub const MAX_PCI_IDS: usize = 8;

/// A single PCI vendor:device identifier pair, as read from PCI
/// configuration-space offsets 0x00 (vendor ID) and 0x02 (device ID).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PciId {
    pub vendor: u16,
    pub device: u16,
}

/// SPEC §11.2 — source of PCI vendor:device identifiers to inspect.
/// Injectable so host tests can supply canned IDs without a UEFI
/// environment; the real backend (PCI configuration-space reads via
/// `PciRootBridgeIo`) lives behind `#[cfg(target_os = "uefi")]` in
/// [`uefi_backend`].
pub trait PciIdSource {
    /// How many identifiers are available (at most [`MAX_PCI_IDS`]).
    fn count(&self) -> usize;
    /// Fetch the identifier at `index` (`< count()`). Implementations may
    /// return a zeroed [`PciId`] for an out-of-range index rather than
    /// panicking, keeping this trait infallible.
    fn get(&self, index: usize) -> PciId;
}

/// SPEC §11.2 — a PCI vendor:device identifier associated with a common
/// virtual platform's graphics or input device. Not secret-bearing;
/// ordinary derives are in scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VirtualDeviceMarker {
    /// VirtIO GPU (Red Hat/Qumranet vendor ID 0x1AF4, device 0x1050).
    VirtioGpu,
    /// VirtIO input (Red Hat/Qumranet vendor ID 0x1AF4, device 0x1052).
    VirtioInput,
    /// VirtualBox VBoxVGA/VBoxSVGA graphics adapter (vendor 0x80EE).
    VBoxGraphics,
    /// VMware SVGA II graphics adapter (vendor 0x15AD).
    VmwareSvga,
    /// Red Hat QXL/SPICE virtual graphics adapter (vendor 0x1B36).
    Qxl,
    /// Hyper-V Generation-1 synthetic VGA adapter (vendor 0x1414, device
    /// 0x5353).
    HyperVSynthVideo,
    /// Bochs/QEMU standard VGA (vendor 0x1234, device 0x1111).
    BochsVga,
}

#[cfg(test)]
impl core::fmt::Debug for VirtualDeviceMarker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            VirtualDeviceMarker::VirtioGpu => "VirtioGpu",
            VirtualDeviceMarker::VirtioInput => "VirtioInput",
            VirtualDeviceMarker::VBoxGraphics => "VBoxGraphics",
            VirtualDeviceMarker::VmwareSvga => "VmwareSvga",
            VirtualDeviceMarker::Qxl => "Qxl",
            VirtualDeviceMarker::HyperVSynthVideo => "HyperVSynthVideo",
            VirtualDeviceMarker::BochsVga => "BochsVga",
        };
        f.write_str(s)
    }
}

/// SPEC §11.2 — reviewed (vendor, device, marker) triples. These are
/// publicly documented PCI IDs (see the PCI ID Repository, pci-ids.ucw.cz)
/// used exclusively by virtual/emulated platforms; no real-hardware vendor
/// is known to ship these vendor:device pairs.
const MARKERS: &[(u16, u16, VirtualDeviceMarker)] = &[
    (0x1AF4, 0x1050, VirtualDeviceMarker::VirtioGpu),
    (0x1AF4, 0x1052, VirtualDeviceMarker::VirtioInput),
    (0x80EE, 0xBEEF, VirtualDeviceMarker::VBoxGraphics),
    (0x15AD, 0x0405, VirtualDeviceMarker::VmwareSvga),
    (0x15AD, 0x0710, VirtualDeviceMarker::VmwareSvga),
    (0x1B36, 0x0100, VirtualDeviceMarker::Qxl),
    (0x1414, 0x5353, VirtualDeviceMarker::HyperVSynthVideo),
    (0x1234, 0x1111, VirtualDeviceMarker::BochsVga),
];

/// SPEC §11.2 — classify a single PCI vendor:device pair against the
/// reviewed marker set. Returns `None` when nothing matches (not evidence
/// of absence of virtualization, just of this heuristic).
#[must_use]
pub fn classify_pci_id(vendor: u16, device: u16) -> Option<VirtualDeviceMarker> {
    for (v, d, marker) in MARKERS {
        if *v == vendor && *d == device {
            return Some(*marker);
        }
    }
    None
}

/// Real UEFI adapter: reads PCI configuration-space vendor/device IDs
/// directly, without `alloc`. Only compiled when targeting the `uefi` OS
/// (`x86_64-unknown-uefi`), never pulled into host `cargo test` runs —
/// mirrors the pattern in `crate::virt::firmware::uefi_backend`.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{PciId, PciIdSource, MAX_PCI_IDS};
    use core::mem::MaybeUninit;
    use uefi::boot::{self, SearchType};
    use uefi::proto::pci::root_bridge::PciRootBridgeIo;
    use uefi::proto::pci::PciIoAddress;
    use uefi::{Handle, Identify};

    /// A fixed-capacity, already-scanned set of PCI identifiers.
    /// Implements [`PciIdSource`] so [`super::classify_pci_id`] can run
    /// over it identically to a host-test double.
    pub struct FixedPciIds {
        ids: [PciId; MAX_PCI_IDS],
        count: usize,
    }

    impl PciIdSource for FixedPciIds {
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

    /// Maximum number of `PciRootBridgeIo` handles this scan will
    /// consider. Real systems (and every reviewed virtual platform)
    /// expose one; a handful of headroom is cheap and avoids a hard
    /// failure on unusual segmented-bridge topologies.
    const MAX_ROOT_BRIDGES: usize = 8;

    /// SPEC §11.2 — scan PCI bus 0 (function 0 of every device 0-31, plus
    /// every function of any multi-function device) on each reachable PCI
    /// root bridge, and return the virtual-platform marker IDs found.
    ///
    /// ALEA-2026-005: this classifies each `(vendor, device)` **inline**
    /// (via [`super::classify_pci_id`]) and retains ONLY the matches,
    /// always completing the full `dev 0..32 / fun 0..8` enumeration.
    /// The earlier version stored the first [`MAX_PCI_IDS`] raw IDs and
    /// `break`-ed out once that buffer filled — on a real machine, whose
    /// bus 0 routinely exposes far more than 8 functions (host bridge,
    /// root ports, iGPU, xHCI, SATA, LPC, SMBus, audio…), that could fill
    /// the buffer with benign devices and never reach a virtual GPU/input
    /// marker at a higher device number, silently defeating the detector.
    /// Retaining only matches makes that impossible: matches are 0-1 in
    /// practice, so the buffer never fills for an ordinary machine and the
    /// scan always runs to completion.
    ///
    /// Scope is deliberately bounded to bus 0: every reviewed virtual
    /// platform (QEMU/OVMF, VirtualBox, VMware, Hyper-V Gen1) enumerates
    /// its graphics and input functions on the root PCI bus. A read
    /// failure (protocol unavailable, exclusive-open conflict, PCI read
    /// error) is treated as "no device found at this address" — this
    /// check is an honest-mistake guard, not a security control (SPEC
    /// §11.2), so failing open here is the documented, correct behavior.
    #[must_use]
    pub fn scan_bus_zero() -> FixedPciIds {
        let mut ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        let mut count = 0usize;

        let mut handle_buf = [MaybeUninit::<Handle>::uninit(); MAX_ROOT_BRIDGES];
        let Ok(handles) =
            boot::locate_handle(SearchType::ByProtocol(&PciRootBridgeIo::GUID), &mut handle_buf)
        else {
            return FixedPciIds { ids, count };
        };

        for &handle in handles {
            // NON-EXCLUSIVE open only (ALEA-2026-005 follow-up). Opening the
            // PCI root bridge EXCLUSIVE makes the firmware disconnect its own
            // PCI bus driver and, recursively, the GPU driver producing the
            // GOP framebuffer the app is rendering into — black-screening the
            // display on real (Phoenix-class) hardware with no error. This is
            // the SAME exclusive-open hazard already documented for GOP
            // (seed-flow `ProdGraphicsGate`) and TPM (`firmware_wiring.rs`); a
            // read-only config-space scan must never take the bridge
            // exclusively. `GetProtocol` borrows the protocol without
            // disturbing the firmware's ownership.
            let params = boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            };
            // SAFETY: GetProtocol does not disconnect other agents' drivers;
            // we only read config space and drop the handle at end of scope.
            let opened = unsafe {
                boot::open_protocol::<PciRootBridgeIo>(
                    params,
                    boot::OpenProtocolAttributes::GetProtocol,
                )
            };
            let Ok(mut bridge) = opened else {
                continue;
            };
            for dev in 0..32u8 {
                for fun in 0..8u8 {
                    let addr = PciIoAddress::new(0, dev, fun);
                    let Ok(vendor) = bridge.pci().read_one::<u16>(addr) else {
                        continue;
                    };
                    // 0xFFFF is the standard "no device present" readback.
                    if vendor == 0xFFFF {
                        continue;
                    }
                    let device = bridge
                        .pci()
                        .read_one::<u16>(addr.with_register(2))
                        .unwrap_or(0xFFFF);
                    // Retain only classified virtual-marker matches (the
                    // full scan still runs to completion). Matches are
                    // rare; the buffer only fills on an absurdly virtual
                    // machine, in which case detection has already
                    // succeeded and dropping further matches is harmless.
                    if super::classify_pci_id(vendor, device).is_some() && count < MAX_PCI_IDS {
                        ids[count] = PciId { vendor, device };
                        count += 1;
                    }
                }
            }
        }

        FixedPciIds { ids, count }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePciIds {
        ids: [PciId; MAX_PCI_IDS],
        count: usize,
    }

    impl PciIdSource for FakePciIds {
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

    #[test]
    fn virtio_gpu_is_classified() {
        assert_eq!(
            classify_pci_id(0x1AF4, 0x1050),
            Some(VirtualDeviceMarker::VirtioGpu)
        );
    }

    #[test]
    fn virtio_input_is_classified() {
        assert_eq!(
            classify_pci_id(0x1AF4, 0x1052),
            Some(VirtualDeviceMarker::VirtioInput)
        );
    }

    #[test]
    fn vbox_graphics_is_classified() {
        assert_eq!(
            classify_pci_id(0x80EE, 0xBEEF),
            Some(VirtualDeviceMarker::VBoxGraphics)
        );
    }

    #[test]
    fn vmware_svga_is_classified() {
        assert_eq!(
            classify_pci_id(0x15AD, 0x0405),
            Some(VirtualDeviceMarker::VmwareSvga)
        );
        assert_eq!(
            classify_pci_id(0x15AD, 0x0710),
            Some(VirtualDeviceMarker::VmwareSvga)
        );
    }

    #[test]
    fn qxl_is_classified() {
        assert_eq!(classify_pci_id(0x1B36, 0x0100), Some(VirtualDeviceMarker::Qxl));
    }

    #[test]
    fn hyperv_synthetic_vga_is_classified() {
        assert_eq!(
            classify_pci_id(0x1414, 0x5353),
            Some(VirtualDeviceMarker::HyperVSynthVideo)
        );
    }

    #[test]
    fn bochs_qemu_std_vga_is_classified() {
        assert_eq!(
            classify_pci_id(0x1234, 0x1111),
            Some(VirtualDeviceMarker::BochsVga)
        );
    }

    #[test]
    fn ordinary_pci_id_does_not_match() {
        // Intel (0x8086) integrated graphics — a real-hardware vendor,
        // must never be flagged.
        assert_eq!(classify_pci_id(0x8086, 0x1912), None);
    }

    #[test]
    fn fake_source_round_trips_through_classification() {
        let mut ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        ids[0] = PciId { vendor: 0x1AF4, device: 0x1050 };
        let src = FakePciIds { ids, count: 1 };
        assert_eq!(src.count(), 1);
        let id = src.get(0);
        assert_eq!(classify_pci_id(id.vendor, id.device), Some(VirtualDeviceMarker::VirtioGpu));
    }

    #[test]
    fn out_of_range_get_is_zeroed_not_panicking() {
        let ids = [PciId { vendor: 0, device: 0 }; MAX_PCI_IDS];
        let src = FakePciIds { ids, count: 0 };
        let id = src.get(0);
        assert_eq!(id.vendor, 0);
        assert_eq!(id.device, 0);
        assert_eq!(classify_pci_id(id.vendor, id.device), None);
    }
}
