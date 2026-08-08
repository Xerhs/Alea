//! Pixel-format-aware packing (SPEC §12.2, §11.4). Owned by WP-21.
//!
//! Pure logic, no UEFI dependency: the three linear-framebuffer pixel
//! formats a GOP mode can report (SPEC §11.4: "RGB/BGR/BitMask") are
//! modeled here so the packing arithmetic is host-testable independent of
//! any real graphics hardware. [`crate::gop::backend`] (feature
//! `uefi-backend`) is the only place that converts a real
//! `uefi::proto::console::gop::PixelFormat`/`PixelBitmask` into a
//! [`PixelLayout`].

/// How the three 8-bit color channels are packed into one 32-bit pixel
/// (SPEC §11.4: "pixel-format aware"). Every GOP linear-framebuffer mode is
/// 4 bytes per pixel (the UEFI reference implementations and every mode
/// that is not `PixelBltOnly` use a 32-bit pixel; this matches the `uefi`
/// crate's own `BltPixel`, which is also 4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelLayout {
    /// Byte order in memory is `[R, G, B, reserved]` (low address first).
    Rgb,
    /// Byte order in memory is `[B, G, R, reserved]` (low address first).
    Bgr,
    /// Custom channel bit positions within the 32-bit pixel, given as
    /// contiguous bitmasks (SPEC §11.4 "BitMask"; UEFI
    /// `EFI_PIXEL_BITMASK`).
    Bitmask {
        /// Bits of the 32-bit pixel occupied by the red channel.
        red_mask: u32,
        /// Bits of the 32-bit pixel occupied by the green channel.
        green_mask: u32,
        /// Bits of the 32-bit pixel occupied by the blue channel.
        blue_mask: u32,
    },
}

/// Place an 8-bit channel value into a (assumed contiguous) bitmask,
/// scaling to the mask's bit width. A zero mask contributes nothing.
fn place_channel(channel: u32, mask: u32) -> u32 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let width = mask.count_ones();
    let max_mask_val = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };
    let scaled = if width >= 8 {
        (channel << (width - 8)) & max_mask_val
    } else {
        (channel >> (8 - width)) & max_mask_val
    };
    (scaled << shift) & mask
}

/// Pack an application-side `0x00RRGGBB` pixel value (the convention used
/// by [`seed_core::contracts::Framebuffer::put_row`] callers, e.g.
/// `crate::font::scrub_fill`'s `pattern` argument and `Style::fg`/`bg`)
/// into the native 32-bit value for `layout` (SPEC §11.4/§12.2).
pub fn pack_pixel(layout: PixelLayout, rgb: u32) -> u32 {
    let r = (rgb >> 16) & 0xFF;
    let g = (rgb >> 8) & 0xFF;
    let b = rgb & 0xFF;
    match layout {
        PixelLayout::Rgb => r | (g << 8) | (b << 16),
        PixelLayout::Bgr => b | (g << 8) | (r << 16),
        PixelLayout::Bitmask {
            red_mask,
            green_mask,
            blue_mask,
        } => place_channel(r, red_mask) | place_channel(g, green_mask) | place_channel(b, blue_mask),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb_layout_orders_low_byte_red() {
        // 0x00RRGGBB = white; both layouts pack to the same value since
        // R=G=B=0xFF.
        assert_eq!(pack_pixel(PixelLayout::Rgb, 0x00FFFFFF), 0x00FFFFFF);
        assert_eq!(pack_pixel(PixelLayout::Bgr, 0x00FFFFFF), 0x00FFFFFF);
    }

    #[test]
    fn rgb_vs_bgr_swap_red_and_blue_bytes() {
        // Pure red: R=0xFF, G=0, B=0.
        let red = 0x00FF_0000u32;
        // Rgb layout: byte0(LSB)=R=0xFF -> value has 0xFF in bits 0..8.
        assert_eq!(pack_pixel(PixelLayout::Rgb, red), 0x0000_00FF);
        // Bgr layout: byte0(LSB)=B=0x00, byte2=R=0xFF -> bits 16..24.
        assert_eq!(pack_pixel(PixelLayout::Bgr, red), 0x00FF_0000);
    }

    #[test]
    fn bitmask_8bit_masks_matches_rgb_layout() {
        // An 8-8-8 bitmask laid out exactly like PixelLayout::Rgb must
        // pack identically.
        let layout = PixelLayout::Bitmask {
            red_mask: 0x0000_00FF,
            green_mask: 0x0000_FF00,
            blue_mask: 0x00FF_0000,
        };
        for v in [0x00_00_00_00u32, 0x00FF_FFFF, 0x0012_3456, 0x00AB_CDEF] {
            assert_eq!(pack_pixel(layout, v), pack_pixel(PixelLayout::Rgb, v));
        }
    }

    #[test]
    fn bitmask_narrow_channel_scales_down() {
        // RGB565-style: red=bits11..16(5), green=bits5..11(6), blue=bits0..5(5).
        let layout = PixelLayout::Bitmask {
            red_mask: 0xF800,
            green_mask: 0x07E0,
            blue_mask: 0x001F,
        };
        // Full white must fill every bit of every mask.
        let packed = pack_pixel(layout, 0x00FF_FFFF);
        assert_eq!(packed & 0xFFFF, 0xFFFF);
        // Pure black is all zero.
        assert_eq!(pack_pixel(layout, 0x0000_0000), 0);
    }

    #[test]
    fn bitmask_zero_mask_contributes_nothing() {
        let layout = PixelLayout::Bitmask {
            red_mask: 0,
            green_mask: 0x0000_FF00,
            blue_mask: 0x00FF_0000,
        };
        // Red channel is fully saturated but has no mask bits: it must not
        // leak into green/blue bits.
        let packed = pack_pixel(layout, 0x00FF_0000);
        assert_eq!(packed & 0x0000_FF00, 0);
        assert_eq!(packed & 0x00FF_0000, 0);
    }

    #[test]
    fn place_channel_wide_mask_uses_high_bits() {
        // A >8-bit-wide mask (e.g. 10-bit channel) must be left-shifted so
        // the 8-bit input occupies the *high* bits of the field, not the
        // low bits (matches standard color-scaling behavior: 0xFF -> max).
        let mask = 0x3FF; // 10 bits, shift 0
        assert_eq!(place_channel(0xFF, mask), 0x3FC); // 0xFF << 2
        assert_eq!(place_channel(0x00, mask), 0x000);
    }
}
