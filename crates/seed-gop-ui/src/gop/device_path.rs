//! Device-path display string (SPEC §11.4: "Display its resolution and
//! device path before generation"). Owned by WP-21.
//!
//! Pure, host-testable fixed-buffer ASCII conversion here;
//! `crate::gop::backend` (feature `uefi-backend`) is the only place that
//! talks to the real `DevicePathToText` protocol and feeds its UTF-16
//! output through [`ascii_from_utf16`].

/// Fixed capacity of a rendered device-path string (SPEC §13: fixed
/// buffers only, no `alloc`). UEFI device-path text strings for the
/// display adapters this project targets (PCI-rooted GOP handles) are
/// well under this; longer paths are truncated rather than causing an
/// allocation or a panic.
pub const MAX_DEVICE_PATH_TEXT: usize = 160;

/// A device-path string rendered into a fixed-size ASCII buffer.
/// Contains no secret data (SPEC §11.4: this is pre-secret diagnostic UI,
/// SPEC §12.1), so ordinary derives are fine.
#[derive(Debug, Clone, Copy)]
pub struct DevicePathText {
    /// Raw ASCII bytes; only `bytes[..len]` is meaningful.
    pub bytes: [u8; MAX_DEVICE_PATH_TEXT],
    /// Number of valid bytes in `bytes`.
    pub len: u16,
}

impl DevicePathText {
    /// Borrow the valid prefix as `&str`. Always valid UTF-8 (in fact
    /// always ASCII) by construction of [`ascii_from_utf16`].
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }

    /// A fixed placeholder used when no device-path text is available
    /// (protocol missing, conversion failed) — never an empty/blank
    /// display, so the confirmation screen (SPEC §11.4: "Require user
    /// confirmation") always shows *something* explicit.
    pub fn unavailable() -> Self {
        let src = NO_DEVICE_PATH_TEXT.as_bytes();
        let mut bytes = [0u8; MAX_DEVICE_PATH_TEXT];
        bytes[..src.len()].copy_from_slice(src);
        Self {
            bytes,
            len: src.len() as u16,
        }
    }
}

/// Placeholder text for [`DevicePathText::unavailable`].
pub const NO_DEVICE_PATH_TEXT: &str = "(device path unavailable)";

/// Convert a NUL-terminated (or not) UTF-16 code-unit sequence into a
/// fixed-size ASCII [`DevicePathText`], stopping at the first NUL, the
/// end of the iterator, or [`MAX_DEVICE_PATH_TEXT`] bytes — whichever
/// comes first. Code units outside printable ASCII (`0x20..=0x7E`) become
/// `'?'` rather than being dropped, so the displayed length still reflects
/// the source string's length (no silent truncation that could hide part
/// of the real path).
pub fn ascii_from_utf16<I: IntoIterator<Item = u16>>(units: I) -> DevicePathText {
    let mut bytes = [0u8; MAX_DEVICE_PATH_TEXT];
    let mut len = 0usize;
    for u in units {
        if u == 0 {
            break;
        }
        if len >= MAX_DEVICE_PATH_TEXT {
            break;
        }
        let b = if (0x20..=0x7E).contains(&u) { u as u8 } else { b'?' };
        bytes[len] = b;
        len += 1;
    }
    DevicePathText {
        bytes,
        len: len as u16,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn utf16(s: &str) -> std::vec::Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn ascii_roundtrips_plain_ascii() {
        let text = ascii_from_utf16(utf16("PciRoot(0x0)/Pci(0x2,0x0)"));
        assert_eq!(text.as_str(), "PciRoot(0x0)/Pci(0x2,0x0)");
    }

    #[test]
    fn ascii_stops_at_nul() {
        let mut units = utf16("Ata(Primary)");
        units.push(0);
        units.extend(utf16("garbage-after-nul"));
        let text = ascii_from_utf16(units);
        assert_eq!(text.as_str(), "Ata(Primary)");
    }

    #[test]
    fn ascii_replaces_non_ascii_with_question_mark() {
        let text = ascii_from_utf16([0x00E9u16, 0x0041]); // 'é', 'A'
        assert_eq!(text.as_str(), "?A");
    }

    #[test]
    fn ascii_truncates_at_capacity_without_panic() {
        let long: std::vec::Vec<u16> = core::iter::repeat(b'X' as u16).take(MAX_DEVICE_PATH_TEXT * 4).collect();
        let text = ascii_from_utf16(long);
        assert_eq!(text.len as usize, MAX_DEVICE_PATH_TEXT);
        assert_eq!(text.as_str().len(), MAX_DEVICE_PATH_TEXT);
    }

    #[test]
    fn empty_input_is_empty_string() {
        let text = ascii_from_utf16([]);
        assert_eq!(text.as_str(), "");
    }

    #[test]
    fn unavailable_placeholder_is_nonempty() {
        let text = DevicePathText::unavailable();
        assert_eq!(text.as_str(), NO_DEVICE_PATH_TEXT);
        assert!(!text.as_str().is_empty());
    }
}
