//! GOP mode enumeration, `PixelBltOnly` refusal and the resolution floor
//! (SPEC §11.4). Owned by WP-21.
//!
//! Pure logic: [`ModeInfo`] is a project-owned descriptor (not the `uefi`
//! crate's `Mode`/`ModeInfo`), so [`select_mode`] is host-testable against
//! a fake mode list with no UEFI dependency. [`crate::gop::backend`]
//! (feature `uefi-backend`) is the only place that builds a `[ModeInfo]`
//! from the real `GraphicsOutput` protocol and calls [`select_mode`].

use crate::gop::pixel::PixelLayout;

/// Upper bound on the number of modes a real GOP implementation reports,
/// used to size the fixed on-stack buffer `backend` enumerates into
/// (`no_alloc`, SPEC §13). Real firmware/QEMU/OVMF implementations report
/// well under 32 modes; this is generous headroom, not a guess at a
/// specific device.
pub const MAX_GOP_MODES: usize = 32;

/// Whether a reported GOP mode has a linear framebuffer the application
/// can draw into directly, or is `PixelBltOnly` (SPEC §11.4: "Refuse
/// production generation when the GOP reports `PixelBltOnly`").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeFormat {
    /// A linear framebuffer in the given pixel layout is available.
    Linear(PixelLayout),
    /// No linear framebuffer; only firmware `Blt()` is available. SPEC
    /// §11.4 requires refusing this mode outright rather than falling
    /// back to `Blt()`, because that would pass secret pixels through
    /// firmware code.
    BltOnly,
}

/// One project-owned description of a GOP-reported mode (SPEC §11.4).
/// Deliberately independent of the `uefi` crate's own `Mode`/`ModeInfo`
/// types so mode-selection logic is host-testable without a UEFI target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeInfo {
    /// The GOP mode index (`GraphicsOutput::set_mode` argument).
    pub index: u32,
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Pixels per scanline (may exceed `width`; SPEC/UEFI allow stride
    /// padding for alignment).
    pub stride_px: u32,
    /// Pixel format/layout this mode reports.
    pub format: ModeFormat,
}

/// Minimum supported horizontal resolution (SPEC §11.4: "Refuse
/// generation below the minimum supported resolution"; SPEC §12.2: "the
/// minimum supported resolution MUST permit a complete display" with "no
/// scrolling").
///
/// Derivation: the fixed 24-word mnemonic display grid
/// (`crate::font::WORD_SLOT_COLUMNS` x `WORD_SLOT_CELL_W`, currently 6
/// columns x 96px) needs 576px of width at minimum. 800x600 is chosen as
/// the floor because it is the lowest resolution universally reported by
/// GOP implementations (firmware, OVMF/QEMU `stdvga`, real hardware) —
/// well above the raw word-grid minimum, leaving headroom for labels,
/// prompts and the device-path/resolution confirmation screen (SPEC
/// §11.4) without any scrolling.
pub const MIN_WIDTH: u32 = 800;

/// Minimum supported vertical resolution. See [`MIN_WIDTH`] for the
/// derivation; the word-grid minimum is 128px (4 rows x 32px), so 600px
/// leaves generous headroom for the same reason.
pub const MIN_HEIGHT: u32 = 600;

/// Human-readable, spec-referenced reason shown when production
/// generation is refused because the GOP has no linear framebuffer (SPEC
/// §11.4: "The refusal screen MUST name this as the reason"). Kept under
/// `seed_gop_ui::font::MAX_TEXT_LEN` (128 bytes) so a flow crate can pass
/// it straight to `draw_text`/firmware text output without wrapping.
pub const PIXEL_BLT_ONLY_REFUSAL_REASON: &str =
    "No linear framebuffer (GOP reports PixelBltOnly). Rendering secrets \
     would require firmware Blt() code (SPEC 11.4). Refused.";

/// Reason shown when every linear-framebuffer mode is below the
/// resolution floor (SPEC §11.4: "Refuse generation below the minimum
/// supported resolution").
pub const BELOW_RESOLUTION_FLOOR_REASON: &str =
    "No graphics mode meets the minimum supported resolution. Refused.";

/// Why [`select_mode`] could not choose a mode to use (SPEC §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSelectError {
    /// The GOP reported zero modes at all.
    NoModesReported,
    /// Every reported mode is `PixelBltOnly` (SPEC §11.4: named refusal
    /// reason, see [`PIXEL_BLT_ONLY_REFUSAL_REASON`]).
    OnlyPixelBltOnly,
    /// At least one linear mode exists, but none meets [`MIN_WIDTH`] x
    /// [`MIN_HEIGHT`] (see [`BELOW_RESOLUTION_FLOOR_REASON`]).
    BelowResolutionFloor,
}

impl ModeSelectError {
    /// The SPEC §11.4-mandated human-readable refusal reason for this
    /// error (`NoModesReported` reuses the BltOnly wording: from the
    /// user's perspective there is still no usable linear framebuffer).
    pub const fn reason(self) -> &'static str {
        match self {
            ModeSelectError::NoModesReported | ModeSelectError::OnlyPixelBltOnly => {
                PIXEL_BLT_ONLY_REFUSAL_REASON
            }
            ModeSelectError::BelowResolutionFloor => BELOW_RESOLUTION_FLOOR_REASON,
        }
    }
}

/// Select one GOP mode to use (SPEC §11.4: "Select one framebuffer").
///
/// Refuses (`Err`) when no mode has a linear framebuffer at or above the
/// resolution floor. Among the eligible modes, picks the largest pixel
/// area (`width * height`); ties break toward the lowest mode index for
/// determinism.
pub fn select_mode(modes: &[ModeInfo]) -> Result<ModeInfo, ModeSelectError> {
    if modes.is_empty() {
        return Err(ModeSelectError::NoModesReported);
    }

    let mut any_linear = false;
    let mut best: Option<ModeInfo> = None;

    for &m in modes {
        let ModeFormat::Linear(_) = m.format else {
            continue;
        };
        any_linear = true;
        if m.width < MIN_WIDTH || m.height < MIN_HEIGHT {
            continue;
        }
        let area = u64::from(m.width) * u64::from(m.height);
        let replace = match best {
            None => true,
            Some(b) => {
                let best_area = u64::from(b.width) * u64::from(b.height);
                area > best_area || (area == best_area && m.index < b.index)
            }
        };
        if replace {
            best = Some(m);
        }
    }

    match best {
        Some(m) => Ok(m),
        None if any_linear => Err(ModeSelectError::BelowResolutionFloor),
        None => Err(ModeSelectError::OnlyPixelBltOnly),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear(index: u32, width: u32, height: u32) -> ModeInfo {
        ModeInfo {
            index,
            width,
            height,
            stride_px: width,
            format: ModeFormat::Linear(PixelLayout::Rgb),
        }
    }

    fn blt_only(index: u32, width: u32, height: u32) -> ModeInfo {
        ModeInfo {
            index,
            width,
            height,
            stride_px: width,
            format: ModeFormat::BltOnly,
        }
    }

    #[test]
    fn empty_mode_list_is_refused() {
        assert_eq!(select_mode(&[]), Err(ModeSelectError::NoModesReported));
    }

    #[test]
    fn all_blt_only_is_refused_with_named_reason() {
        let modes = [blt_only(0, 1920, 1080), blt_only(1, 1024, 768)];
        assert_eq!(select_mode(&modes), Err(ModeSelectError::OnlyPixelBltOnly));
        assert_eq!(
            ModeSelectError::OnlyPixelBltOnly.reason(),
            PIXEL_BLT_ONLY_REFUSAL_REASON
        );
    }

    #[test]
    fn linear_but_all_below_floor_is_refused() {
        let modes = [linear(0, 640, 480), linear(1, 320, 200)];
        assert_eq!(select_mode(&modes), Err(ModeSelectError::BelowResolutionFloor));
    }

    #[test]
    fn mixed_blt_only_and_undersized_linear_is_below_floor_not_blt_only() {
        // A real firmware often reports one BltOnly mode alongside small
        // linear modes; the refusal reason must reflect that a linear
        // framebuffer *did* exist, just too small, not "no linear FB at
        // all".
        let modes = [blt_only(0, 1920, 1080), linear(1, 640, 480)];
        assert_eq!(select_mode(&modes), Err(ModeSelectError::BelowResolutionFloor));
    }

    #[test]
    fn picks_largest_eligible_linear_mode() {
        let modes = [
            linear(0, 800, 600),
            linear(1, 1920, 1080),
            blt_only(2, 3840, 2160),
            linear(3, 1024, 768),
        ];
        let chosen = select_mode(&modes).unwrap();
        assert_eq!(chosen.index, 1);
        assert_eq!((chosen.width, chosen.height), (1920, 1080));
    }

    #[test]
    fn exact_floor_resolution_is_accepted() {
        let modes = [linear(0, MIN_WIDTH, MIN_HEIGHT)];
        assert_eq!(select_mode(&modes).unwrap().index, 0);
    }

    #[test]
    fn one_pixel_below_floor_is_refused() {
        let modes = [linear(0, MIN_WIDTH - 1, MIN_HEIGHT)];
        assert_eq!(select_mode(&modes), Err(ModeSelectError::BelowResolutionFloor));
        let modes = [linear(0, MIN_WIDTH, MIN_HEIGHT - 1)];
        assert_eq!(select_mode(&modes), Err(ModeSelectError::BelowResolutionFloor));
    }

    #[test]
    fn ties_break_toward_lowest_index() {
        let modes = [linear(5, 1024, 768), linear(2, 1024, 768)];
        assert_eq!(select_mode(&modes).unwrap().index, 2);
    }
}
