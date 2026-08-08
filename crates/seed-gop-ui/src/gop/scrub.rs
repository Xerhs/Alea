//! Screen-clearing scrub sequence (SPEC §12.4). Owned by WP-21.
//!
//! SPEC §12.4 ("Screen clearing") requires, both before mnemonic
//! re-entry and after the whole workflow: "the full framebuffer is
//! overwritten with a neutral pattern, then a blank screen; a memory
//! fence is executed". [`scrub_sequence`] is exactly that three-step
//! sequence, built on top of `crate::font::scrub_fill` (WP-10) so the
//! pixel-fill logic itself is written once.

use seed_core::contracts::Framebuffer;

use crate::font::scrub_fill;

/// Neutral scrub pattern (SPEC §12.4 "neutral pattern"): mid-gray, chosen
/// because it is visibly distinct from both an all-black "blank" screen
/// (the second scrub step) and from plausible secret-display foreground
/// colors, so a screen stuck mid-scrub is visually obvious rather than
/// looking like a normal blank/black screen.
pub const NEUTRAL_SCRUB_PATTERN: u32 = 0x00AA_AAAA;

/// Run the full SPEC §12.4 scrub sequence against `fb`: fill with
/// `pattern`, then fill with black (blank), then execute a memory fence.
///
/// Callers needing the SPEC-default neutral pattern should pass
/// [`NEUTRAL_SCRUB_PATTERN`]; the parameter exists so callers can also
/// scrub with a distinct pattern per screen if that helps diagnose a
/// stuck scrub.
///
/// The fence (`core::sync::atomic::fence(SeqCst)`) is a compiler/CPU
/// ordering barrier ensuring the blank-fill writes are not reordered past
/// this point by the compiler or (on x86_64, whose stores are otherwise
/// program-ordered) treated as still-pending by any reasoning that
/// assumes sequential consistency. It does NOT, and cannot, prove that
/// the GPU has flushed the writes to a physical display, nor that no
/// firmware/hardware copy of the pixels survives (SPEC §12.2, §12.4: "the
/// application acknowledges that hardware or firmware copies may
/// remain").
pub fn scrub_sequence(fb: &mut dyn Framebuffer, pattern: u32) {
    scrub_fill(fb, pattern);
    scrub_fill(fb, 0x0000_0000);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct VecFb {
        w: u32,
        h: u32,
        buf: Vec<u32>,
        /// Records every pattern value seen by `put_row`, in call order,
        /// to verify the pattern-then-blank ordering.
        history: Vec<u32>,
    }

    impl VecFb {
        fn new(w: u32, h: u32) -> Self {
            Self {
                w,
                h,
                buf: std::vec![0u32; (w as usize) * (h as usize)],
                history: Vec::new(),
            }
        }
    }

    impl Framebuffer for VecFb {
        fn dims(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        fn put_row(&mut self, x: u32, y: u32, px: &[u32]) {
            let start = (y as usize) * (self.w as usize) + (x as usize);
            self.buf[start..start + px.len()].copy_from_slice(px);
            if let Some(&v) = px.first() {
                self.history.push(v);
            }
        }
    }

    #[test]
    fn scrub_sequence_ends_with_every_pixel_blank() {
        let mut fb = VecFb::new(10, 10);
        scrub_sequence(&mut fb, 0xdead_beef);
        assert!(fb.buf.iter().all(|&p| p == 0x0000_0000));
    }

    #[test]
    fn scrub_sequence_visits_pattern_before_blank() {
        let mut fb = VecFb::new(4, 4);
        scrub_sequence(&mut fb, 0x1234_5678);
        // The pattern value must appear in history before the run of
        // trailing zero (blank) writes.
        let first_pattern_idx = fb.history.iter().position(|&v| v == 0x1234_5678);
        let first_blank_idx = fb.history.iter().position(|&v| v == 0);
        assert!(first_pattern_idx.is_some());
        assert!(first_blank_idx.is_some());
        assert!(first_pattern_idx.unwrap() < first_blank_idx.unwrap());
    }

    #[test]
    fn scrub_sequence_zero_dims_no_panic() {
        let mut fb = VecFb::new(0, 0);
        scrub_sequence(&mut fb, 0xffff_ffff);
    }
}
