//! Shared, non-public helpers for the `rng` module (WP-24, SPEC §13, §20.3).
//!
//! Nothing here is part of the crate's public API; it exists so
//! [`super::record`], [`super::efi_rng`], [`super::rdseed`] and
//! [`super::rdrand`] share one scrub implementation instead of
//! reimplementing volatile-write-plus-fence four times.

use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrite `buf` with zero using volatile writes plus a compiler fence,
/// so the wipe cannot be optimized away (SPEC §13, §20.3). Mirrors
/// `seed_protocol::transcript`'s private `scrub_slice` — this module
/// cannot reach that one (it is private to a different crate/module), so
/// the same small routine is duplicated here rather than exposing it
/// cross-crate for a two-line helper.
pub(crate) fn scrub(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8` for the duration of the write.
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_zeroes_every_byte() {
        let mut buf = [0xAAu8; 32];
        scrub(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }
}
