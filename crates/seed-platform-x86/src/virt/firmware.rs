//! SPEC §11.2 — firmware vendor/product string heuristics.
//!
//! Firmware-reported strings (SMBIOS BIOS-vendor field, the UEFI system
//! table's `FirmwareVendor`, and similar) are compared, case-insensitively,
//! against substrings known to be emitted by common virtual platforms.
//! This is explicitly a *heuristic*: SPEC §11.2 states plainly that a
//! malicious hypervisor can spoof these strings trivially, so this module
//! only ever contributes a positive indicator, never a proof of absence.
//!
//! No `alloc`: matching is done directly against `&str`/`&[u8]` slices,
//! and the injectable [`FirmwareStringSource`] hands back fixed-size
//! buffers rather than owned/allocated strings.

/// Maximum bytes this module will hold for a single firmware string.
/// Firmware vendor/product strings in practice are short ASCII tokens
/// ("QEMU", "American Megatrends International, LLC", ...); anything past
/// this bound is simply not needed for substring matching and is dropped,
/// not overflowed into.
pub const MAX_FW_STRING_LEN: usize = 64;

/// Maximum number of distinct firmware strings a [`FirmwareStringSource`]
/// may report (e.g. vendor, product/model).
pub const MAX_FW_STRINGS: usize = 4;

/// A single fixed-capacity firmware string, UTF-8, possibly truncated.
#[derive(Clone, Copy)]
pub struct FwString {
    buf: [u8; MAX_FW_STRING_LEN],
    len: usize,
}

impl FwString {
    /// The empty string.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; MAX_FW_STRING_LEN],
            len: 0,
        }
    }

    /// Build from a `&str`, truncating (at a `char` boundary) if it does
    /// not fit in [`MAX_FW_STRING_LEN`] bytes.
    #[must_use]
    pub fn from_str_truncating(s: &str) -> Self {
        let mut n = s.len().min(MAX_FW_STRING_LEN);
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut buf = [0u8; MAX_FW_STRING_LEN];
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        Self { buf, len: n }
    }

    /// Borrow the contents as `&str`. Always valid UTF-8: constructed only
    /// from `&str` sources, truncated on a `char` boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// SPEC §11.2 — source of firmware-reported strings to inspect. Injectable
/// so host tests can supply canned firmware text without a UEFI
/// environment; the real backend (SystemTable/SMBIOS) lives behind
/// `#[cfg(target_os = "uefi")]` in [`uefi_backend`].
pub trait FirmwareStringSource {
    /// How many strings are available (at most [`MAX_FW_STRINGS`]).
    fn count(&self) -> usize;
    /// Fetch the string at `index` (`< count()`). Implementations may
    /// return [`FwString::empty`] for an out-of-range index rather than
    /// panicking, keeping this trait infallible.
    fn get(&self, index: usize) -> FwString;
}

/// SPEC §11.2 — a firmware string substring associated with a common
/// virtual platform. Not secret-bearing; ordinary derives are in scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirmwareMarker {
    Qemu,
    SeaBios,
    Ovmf,
    VirtualBox,
    Vmware,
    HyperV,
    Xen,
    Parallels,
    Bochs,
}

#[cfg(test)]
impl core::fmt::Debug for FirmwareMarker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            FirmwareMarker::Qemu => "Qemu",
            FirmwareMarker::SeaBios => "SeaBios",
            FirmwareMarker::Ovmf => "Ovmf",
            FirmwareMarker::VirtualBox => "VirtualBox",
            FirmwareMarker::Vmware => "Vmware",
            FirmwareMarker::HyperV => "HyperV",
            FirmwareMarker::Xen => "Xen",
            FirmwareMarker::Parallels => "Parallels",
            FirmwareMarker::Bochs => "Bochs",
        };
        f.write_str(s)
    }
}

/// SPEC §11.2 — reviewed (marker, needle) pairs. Order matters only in
/// that the first match wins when a string happens to contain more than
/// one needle; that is not expected to occur for real firmware strings.
const MARKERS: &[(FirmwareMarker, &str)] = &[
    (FirmwareMarker::Qemu, "QEMU"),
    (FirmwareMarker::SeaBios, "SeaBIOS"),
    (FirmwareMarker::Ovmf, "OVMF"),
    (FirmwareMarker::VirtualBox, "VirtualBox"),
    (FirmwareMarker::VirtualBox, "innotek"),
    (FirmwareMarker::Vmware, "VMware"),
    (FirmwareMarker::HyperV, "Hyper-V"),
    (FirmwareMarker::HyperV, "Virtual Machine"),
    (FirmwareMarker::Xen, "Xen"),
    (FirmwareMarker::Parallels, "Parallels"),
    (FirmwareMarker::Bochs, "Bochs"),
];

/// ASCII case-insensitive substring search, `no_std`/no-`alloc`.
/// Firmware strings here are ASCII by construction (vendor names); any
/// non-ASCII bytes simply fail to match, which is safe (never a false
/// positive).
fn contains_ignore_case_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    'outer: for start in 0..=(haystack.len() - needle.len()) {
        for i in 0..needle.len() {
            if haystack[start + i].to_ascii_lowercase() != needle[i].to_ascii_lowercase() {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// SPEC §11.2 — classify a single firmware-reported string against the
/// reviewed marker set. Returns `None` when nothing matches (not evidence
/// of absence of virtualization, just of this heuristic).
#[must_use]
pub fn classify_firmware_string(s: &str) -> Option<FirmwareMarker> {
    for (marker, needle) in MARKERS {
        if contains_ignore_case_ascii(s.as_bytes(), needle.as_bytes()) {
            return Some(*marker);
        }
    }
    None
}

/// A `core::fmt::Write` sink over a fixed byte buffer, used to pull
/// firmware-owned UTF-16 strings (via `CStr16::as_str_in_buf`) into a
/// fixed local buffer without allocating.
#[cfg_attr(not(target_os = "uefi"), allow(dead_code))]
pub(crate) struct FixedWriter<'a> {
    pub(crate) buf: &'a mut [u8],
    pub(crate) len: usize,
}

#[cfg_attr(not(target_os = "uefi"), allow(dead_code))]
impl core::fmt::Write for FixedWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.len;
        let n = bytes.len().min(remaining);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        if n < bytes.len() {
            // Truncated: signal so the caller knows, but the bytes
            // written so far are still valid UTF-8 (we never split a
            // multi-byte push mid-way since `s` here is always the whole
            // decoded string in one `write_str` call from `CStr16`).
            Err(core::fmt::Error)
        } else {
            Ok(())
        }
    }
}

/// Real UEFI adapter: reads the system table's `FirmwareVendor` string.
/// Only compiled when targeting the `uefi` OS (`x86_64-unknown-uefi`),
/// never pulled into host `cargo test` runs — mirrors the pattern in
/// `crate::boot::uefi_backend`.
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{FirmwareStringSource, FixedWriter, FwString, MAX_FW_STRING_LEN};
    use core::fmt::Write as _;

    /// [`FirmwareStringSource`] backed by `uefi::system::firmware_vendor`.
    /// Reports exactly one string (the firmware vendor); SPEC §11.2 also
    /// mentions "product strings", which on this platform generally live
    /// in SMBIOS tables outside this module's scope (owned separately if
    /// added later) rather than the UEFI system table.
    pub struct SystemTableFirmwareStrings;

    impl FirmwareStringSource for SystemTableFirmwareStrings {
        fn count(&self) -> usize {
            1
        }

        fn get(&self, index: usize) -> FwString {
            if index != 0 {
                return FwString::empty();
            }
            let vendor = uefi::system::firmware_vendor();
            let mut buf = [0u8; MAX_FW_STRING_LEN];
            let mut writer = FixedWriter {
                buf: &mut buf,
                len: 0,
            };
            // Best-effort: a truncated vendor string still yields a
            // usable (if partial) heuristic match; ignore the `Err` from
            // truncation.
            let _ = write!(writer, "{vendor}");
            let len = writer.len;
            FwString { buf, len }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_string_is_classified() {
        assert_eq!(
            classify_firmware_string("QEMU Standard PC (i440FX + PIIX, 1996)"),
            Some(FirmwareMarker::Qemu)
        );
    }

    #[test]
    fn virtualbox_vendor_string_is_classified() {
        assert_eq!(
            classify_firmware_string("innotek GmbH"),
            Some(FirmwareMarker::VirtualBox)
        );
        assert_eq!(
            classify_firmware_string("VirtualBox"),
            Some(FirmwareMarker::VirtualBox)
        );
    }

    #[test]
    fn vmware_product_string_is_classified() {
        assert_eq!(
            classify_firmware_string("VMware, Inc."),
            Some(FirmwareMarker::Vmware)
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            classify_firmware_string("qEmU"),
            Some(FirmwareMarker::Qemu)
        );
    }

    #[test]
    fn ordinary_firmware_string_does_not_match() {
        assert_eq!(
            classify_firmware_string("American Megatrends International, LLC"),
            None
        );
        assert_eq!(classify_firmware_string(""), None);
    }

    #[test]
    fn fw_string_truncates_at_char_boundary_without_panicking() {
        let long = "a".repeat(MAX_FW_STRING_LEN + 10);
        let fw = FwString::from_str_truncating(&long);
        assert_eq!(fw.as_str().len(), MAX_FW_STRING_LEN);
    }

    #[test]
    fn fw_string_round_trips_short_input() {
        let fw = FwString::from_str_truncating("QEMU");
        assert_eq!(fw.as_str(), "QEMU");
    }
}
