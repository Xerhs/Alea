//! Linear-framebuffer `Framebuffer` implementation (SPEC §11.4, §12.2).
//! Owned by WP-21.
//!
//! [`LinearFramebuffer`] wraps a raw base pointer + geometry, exactly like
//! `uefi::proto::console::gop::FrameBuffer::as_mut_ptr()` exposes: it is
//! backend-agnostic on purpose so the *same* code path backs both the real
//! memory-mapped GOP framebuffer (via `crate::gop::backend`, feature
//! `uefi-backend`) and a plain heap buffer in host unit tests (SPEC §11.4
//! Definition of Done: "Host tests on a fake mode list + memory
//! framebuffer"). All pixel writes go through `write_volatile` regardless
//! of backend, matching SPEC §20's "explicit scrub with volatile writes"
//! posture for anything that touches secret-bearing pixel data.

use seed_core::contracts::Framebuffer;

use crate::gop::pixel::{pack_pixel, PixelLayout};

/// A caller-owned linear framebuffer surface (SPEC §11.4: "pixel-format
/// aware: RGB/BGR/BitMask"). Does not own the backing memory: the caller
/// (UEFI backend or a test) guarantees `base` is valid for the lifetime of
/// this value (see [`LinearFramebuffer::new`] safety contract).
pub struct LinearFramebuffer {
    base: *mut u8,
    width: u32,
    height: u32,
    stride_px: u32,
    layout: PixelLayout,
}

impl LinearFramebuffer {
    /// Wrap a raw linear-framebuffer base pointer.
    ///
    /// # Safety
    ///
    /// - `base` must be valid for reads and writes covering at least
    ///   `stride_px as usize * height as usize * 4` bytes (4 bytes per
    ///   pixel — see [`PixelLayout`] doc comment for why every non-`BltOnly`
    ///   GOP mode is 32-bit).
    /// - That memory must remain valid and exclusively owned by this
    ///   `LinearFramebuffer` (no aliasing writers) for as long as the
    ///   value is used.
    /// - `width <= stride_px` (a wider visible width than the scanline
    ///   stride is nonsensical and would read/write out of the intended
    ///   row).
    pub unsafe fn new(base: *mut u8, width: u32, height: u32, stride_px: u32, layout: PixelLayout) -> Self {
        Self {
            base,
            width,
            height,
            stride_px,
            layout,
        }
    }
}

impl Framebuffer for LinearFramebuffer {
    fn dims(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
        // Fail closed on out-of-bounds rather than panicking: firmware
        // code must never panic on a rendering call, and callers
        // (`crate::font`) already clip at the framebuffer edge, but this
        // is the last line of defense against writing outside the mapped
        // region.
        if y >= self.height || x >= self.width {
            return;
        }
        let max_n = (self.width - x) as usize;
        let n = core::cmp::min(px.len(), max_n);
        let row_base = (y as usize) * (self.stride_px as usize) + (x as usize);
        for (i, &value) in px.iter().take(n).enumerate() {
            let native = pack_pixel(self.layout, value);
            let byte_offset = (row_base + i) * 4;
            // SAFETY: `new`'s safety contract guarantees `base` covers
            // `stride_px * height * 4` bytes; `row_base + i < stride_px *
            // height` follows from `y < height`, `x < width <= stride_px`
            // and `i < n <= width - x`, so `byte_offset + 4 <= stride_px *
            // height * 4`.
            unsafe {
                let ptr = self.base.add(byte_offset).cast::<u32>();
                ptr.write_volatile(native);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Build a `LinearFramebuffer` backed by a heap `Vec<u8>` "memory
    /// framebuffer" (WP-21 Definition of Done), returning the buffer too
    /// so tests can inspect raw bytes.
    fn memory_fb(width: u32, height: u32, stride_px: u32, layout: PixelLayout) -> (LinearFramebuffer, Vec<u8>) {
        let mut backing = vec![0u8; (stride_px as usize) * (height as usize) * 4];
        // SAFETY: `backing` outlives `fb` within this function's stack
        // frame and is sized exactly per the safety contract.
        let fb = unsafe { LinearFramebuffer::new(backing.as_mut_ptr(), width, height, stride_px, layout) };
        (fb, backing)
    }

    #[test]
    fn dims_reports_visible_width_height_not_stride() {
        let (fb, _backing) = memory_fb(100, 50, 128, PixelLayout::Rgb);
        assert_eq!(fb.dims(), (100, 50));
    }

    #[test]
    fn put_row_writes_expected_native_bytes_rgb() {
        let (mut fb, backing) = memory_fb(4, 2, 4, PixelLayout::Rgb);
        fb.put_row(0, 0, &[0x00FF_0000]); // pure red
        // Rgb layout: memory bytes [R, G, B, reserved] = [0xFF, 0, 0, 0].
        assert_eq!(&backing[0..4], &[0xFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn put_row_writes_expected_native_bytes_bgr() {
        let (mut fb, backing) = memory_fb(4, 2, 4, PixelLayout::Bgr);
        fb.put_row(0, 0, &[0x00FF_0000]); // pure red
        // Bgr layout: memory bytes [B, G, R, reserved] = [0, 0, 0xFF, 0].
        assert_eq!(&backing[0..4], &[0x00, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn put_row_respects_stride_padding() {
        // stride_px (6) > width (4): row 1 must start at byte offset
        // 6*4=24, not 4*4=16.
        let (mut fb, backing) = memory_fb(4, 2, 6, PixelLayout::Rgb);
        fb.put_row(0, 1, &[0x00FF_FFFF]);
        assert_eq!(&backing[16..24], &[0u8; 8]); // row 0's stride padding untouched
        assert_eq!(&backing[24..28], &[0xFF, 0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn put_row_clips_run_at_right_edge_without_panic() {
        let (mut fb, backing) = memory_fb(4, 1, 4, PixelLayout::Rgb);
        let row = [0x00FF_FFFFu32; 10];
        fb.put_row(2, 0, &row); // only 2 pixels of room (x=2,3)
        assert_eq!(&backing[8..16], &[0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn put_row_out_of_bounds_x_or_y_is_a_no_op_not_a_panic() {
        let (mut fb, backing) = memory_fb(4, 4, 4, PixelLayout::Rgb);
        fb.put_row(4, 0, &[0x00FF_FFFF]); // x == width
        fb.put_row(0, 4, &[0x00FF_FFFF]); // y == height
        fb.put_row(100, 100, &[0x00FF_FFFF]);
        assert!(backing.iter().all(|&b| b == 0));
    }

    #[test]
    fn put_row_bitmask_layout_matches_pack_pixel() {
        let layout = PixelLayout::Bitmask {
            red_mask: 0x0000_00FF,
            green_mask: 0x0000_FF00,
            blue_mask: 0x00FF_0000,
        };
        let (mut fb, backing) = memory_fb(1, 1, 1, layout);
        fb.put_row(0, 0, &[0x0012_3456]);
        let expected = pack_pixel(layout, 0x0012_3456).to_le_bytes();
        assert_eq!(&backing[0..4], &expected);
    }
}
