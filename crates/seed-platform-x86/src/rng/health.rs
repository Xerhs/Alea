//! Machine-source health checks (WP-24, WP-U3, SPEC §16, SPEC_USB_TRNG.md
//! §9).
//!
//! SPEC §16: "Health checks detect only obvious failures." Every machine
//! source driver in this module ([`super::efi_rng`], [`super::rdseed`],
//! [`super::rdrand`], [`super::usb_trng`]) routes its raw samples through
//! these checks before a [`super::record::SourceRecord`] is ever produced.
//! This module carries no state and no secret bytes of its own — it only
//! classifies byte slices a caller still owns — so [`HealthError`] may use
//! ordinary derives (SPEC §20.2 only restricts types that themselves *hold*
//! secret material).
//!
//! [`super::usb_trng`] reuses exactly these three functions unmodified
//! (SPEC_USB_TRNG §9: "extend `crates/seed-platform-x86/src/rng/health.rs`,
//! reusing its existing `check_length`, `check_not_degenerate`, and
//! `check_not_repeated`") — no USB-specific byte-pattern check was needed
//! here. The USB-specific failure modes SPEC_USB_TRNG §9 also lists (device
//! disappearance/timeout, stall, descriptor/class re-verification, and
//! command/echo-handshake sanity) are transport-layer failures, not
//! byte-block classifications, so they are modelled as
//! `usb_trng::UsbReadError`/`UsbTrngError` variants in that module instead
//! of as functions here.
//!
//! The UI-facing "these checks are not proof" wording (SPEC §16) belongs
//! to the presentation layer, not here; this module only implements the
//! pass/fail logic those screens describe honestly. That wording is
//! `seed_flow::text::MACHINE_HEALTH_CHECK_DISCLAIMER_16`
//! (`crates/seed-flow/src/text.rs`), rendered on
//! `seed_flow::flow_secret::machine::render_acquiring` — the one screen
//! shown while these checks execute.

/// Why a sampled block failed a catastrophic health check (SPEC §16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthError {
    /// The source returned a different byte count than was requested
    /// (SPEC §15.1: "the exact requested length is returned successfully";
    /// SPEC §16: "short output").
    LengthMismatch,
    /// Every byte in the block was `0x00` (SPEC §16: "all-zero output").
    AllZero,
    /// Every byte in the block was `0xFF` (SPEC §16: "all-`0xFF` output").
    AllFf,
    /// Two supposedly-independent consecutive blocks were byte-for-byte
    /// identical (SPEC §16: "identical consecutive 256-bit diagnostic
    /// blocks").
    IdenticalConsecutiveBlocks,
}

/// Confirms `actual.len() == expected` (SPEC §15.1/§16: exact-length
/// reads only, never a short or padded result treated as success).
pub fn check_length(actual: usize, expected: usize) -> Result<(), HealthError> {
    if actual == expected {
        Ok(())
    } else {
        Err(HealthError::LengthMismatch)
    }
}

/// Rejects an all-zero or all-`0xFF` block (SPEC §16). An empty block is
/// neither (there is nothing to be uniformly zero or `0xFF`), so this
/// intentionally does not reject `block.is_empty()` — callers that care
/// about non-empty output enforce that via [`check_length`] first.
pub fn check_not_degenerate(block: &[u8]) -> Result<(), HealthError> {
    if !block.is_empty() && block.iter().all(|&b| b == 0x00) {
        return Err(HealthError::AllZero);
    }
    if !block.is_empty() && block.iter().all(|&b| b == 0xFF) {
        return Err(HealthError::AllFf);
    }
    Ok(())
}

/// Rejects two consecutive diagnostic blocks that are byte-for-byte
/// identical (SPEC §15.2, §16). Blocks of different lengths are never
/// considered identical.
pub fn check_not_repeated(previous: &[u8], current: &[u8]) -> Result<(), HealthError> {
    if previous.len() == current.len() && previous == current {
        return Err(HealthError::IdenticalConsecutiveBlocks);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_mismatch_detected() {
        assert_eq!(check_length(31, 32), Err(HealthError::LengthMismatch));
        assert_eq!(check_length(32, 32), Ok(()));
    }

    #[test]
    fn all_zero_block_rejected() {
        let block = [0u8; 32];
        assert_eq!(check_not_degenerate(&block), Err(HealthError::AllZero));
    }

    #[test]
    fn all_ff_block_rejected() {
        let block = [0xFFu8; 32];
        assert_eq!(check_not_degenerate(&block), Err(HealthError::AllFf));
    }

    #[test]
    fn mixed_block_accepted() {
        let mut block = [0u8; 32];
        block[0] = 1;
        assert_eq!(check_not_degenerate(&block), Ok(()));
    }

    #[test]
    fn single_nonzero_nonff_byte_is_not_degenerate() {
        // Regression guard: a block that is all-zero except one byte, or
        // all-0xFF except one byte, must still pass -- only *uniform*
        // blocks are catastrophic per SPEC §16.
        let mut all_zero_but_one = [0u8; 32];
        all_zero_but_one[31] = 0xFF;
        assert_eq!(check_not_degenerate(&all_zero_but_one), Ok(()));

        let mut all_ff_but_one = [0xFFu8; 32];
        all_ff_but_one[0] = 0x00;
        assert_eq!(check_not_degenerate(&all_ff_but_one), Ok(()));
    }

    #[test]
    fn identical_consecutive_blocks_rejected() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert_eq!(check_not_repeated(&a, &b), Err(HealthError::IdenticalConsecutiveBlocks));
    }

    #[test]
    fn distinct_consecutive_blocks_accepted() {
        let mut a = [0x42u8; 32];
        let b = a;
        a[0] = 0x43;
        assert_eq!(check_not_repeated(&a, &b), Ok(()));
    }

    #[test]
    fn different_length_blocks_are_never_identical() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 16];
        assert_eq!(check_not_repeated(&a, &b), Ok(()));
    }
}
