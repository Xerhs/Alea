//! SPEC_EDU_UI §3. Pure, host-testable, `no_std`, no-alloc, no float.
//!
//! Frozen at WP-E2 (`IMPLEMENTATION_MAP_EDU.md` §3.1). Owned by WP-E1,
//! ratified by WP-E2, consumed by the WP-E3 education panel. Recomputes
//! the counted-witnessed milli-bit total from plain counts so the panel
//! needs no live `PhysicalSession`; matches the SPEC §17.2 arithmetic in
//! `physical::PhysicalSession::budget_bits_x1000` exactly.

use seed_core::contracts::{SourceTag, TargetBits};

/// SPEC_EDU_UI §3.1: the two epistemic categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyCategory {
    /// Dice / coins: provable by arithmetic over witnessed events.
    CountedWitnessed,
    /// EFI RNG / RDSEED / RDRAND: health-checked, not proven, 0 counted.
    ClaimedUnproven,
}

/// SPEC_EDU_UI §3.3 contrast table, as code. Exhaustive over `SourceTag`
/// (no wildcard) so a future tag forces a review here rather than silently
/// defaulting. `ApprovedUsbTrng` (`0x12`, SPEC_USB_TRNG.md §6.1) is a
/// machine source like EFI RNG/RDSEED/RDRAND: health-checked, not proven,
/// contributes 0 counted bits — SPEC_USB_TRNG.md §10 the floor is absolute,
/// so this arm is the WP-U1 mechanical ripple that keeps this exhaustive
/// match compiling, never a `CountedWitnessed` arm.
#[must_use]
pub const fn category_of(tag: SourceTag) -> EntropyCategory {
    match tag {
        SourceTag::DiceRolls | SourceTag::CoinFlips => EntropyCategory::CountedWitnessed,
        SourceTag::ApprovedEfiRng
        | SourceTag::X86Rdseed64
        | SourceTag::X86RdrandSupplementary
        | SourceTag::ApprovedUsbTrng => EntropyCategory::ClaimedUnproven,
    }
}

/// SPEC_EDU_UI §4.4: counted (witnessed) total in milli-bits — the SAME
/// arithmetic as `physical::PhysicalSession::budget_bits_x1000`, recomputed
/// from counts so the panel needs no live `PhysicalSession`.
/// `2585 * dice_rolls + 1000 * coin_flips`. Machine sources add nothing.
///
/// On the `2585` per-roll constant: a fair die carries `log2(6) =
/// 2.5849625...` bits/roll. `2585` is that value in milli-bits ROUNDED UP
/// (2584.96 -> 2585), and it matches SPEC §17.2 exactly — this is
/// intentional, not an off-by-one bug. Rounding up credits at most
/// `0.0375 / 1000` bit per roll, so even a maximal single session
/// over-credits by well under ~0.02 bit versus the exact value; that
/// never lowers the number of rolls the SPEC §17.2 floor (`>= 1000 *
/// target_bits`) requires. A future SPEC revision could instead round
/// DOWN to `2584` for a hair more conservatism, but that would move the
/// frozen accounting vectors, so the constant is held at `2585` here.
#[must_use]
pub const fn counted_milli_bits(dice_rolls: u32, coin_flips: u32) -> u64 {
    2585u64 * dice_rolls as u64 + 1000u64 * coin_flips as u64
}

/// SPEC §17.2: `counted_milli_bits >= 1000 * target_bits`.
#[must_use]
pub const fn meets_floor(milli_bits: u64, target: TargetBits) -> bool {
    milli_bits >= 1000u64 * (target as u64)
}

/// SPEC_EDU_UI §4.4/§4.5: format milli-bits to one decimal, ROUNDED
/// half-up to nearest tenth (so 370_880 -> "370.9", matching the §4.5
/// mock), into a caller-owned fixed buffer — no alloc, no float. Returns
/// the written slice.
#[must_use]
pub fn fmt_milli_bits_1dp(milli_bits: u64, out: &mut [u8; 24]) -> &str {
    // milli_bits is thousandths of a bit; we want tenths of a bit,
    // rounded half-up: tenths = round(milli_bits / 100).
    let tenths = (milli_bits + 50) / 100;
    let whole = tenths / 10;
    let frac = tenths % 10;

    let mut buf = [0u8; 24];
    let mut pos = buf.len();

    // Write fractional digit + '.' first (build from the back).
    pos -= 1;
    buf[pos] = b'0' + (frac as u8);
    pos -= 1;
    buf[pos] = b'.';

    if whole == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        let mut w = whole;
        while w > 0 {
            pos -= 1;
            buf[pos] = b'0' + (w % 10) as u8;
            w /= 10;
        }
    }

    let len = buf.len() - pos;
    out[..len].copy_from_slice(&buf[pos..]);
    // SAFETY/correctness: every byte written above is ASCII digit or '.'.
    core::str::from_utf8(&out[..len]).unwrap_or("0.0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::{CoinFace, PhysicalSession};

    // ------------------------------------------------------------------
    // category_of: SPEC_EDU_UI §3.3 contrast table, exhaustively over
    // every `SourceTag` variant that exists today.
    // ------------------------------------------------------------------

    #[test]
    fn category_of_dice_is_counted_witnessed() {
        assert_eq!(
            category_of(SourceTag::DiceRolls),
            EntropyCategory::CountedWitnessed
        );
    }

    #[test]
    fn category_of_coins_is_counted_witnessed() {
        assert_eq!(
            category_of(SourceTag::CoinFlips),
            EntropyCategory::CountedWitnessed
        );
    }

    #[test]
    fn category_of_efi_rng_is_claimed_unproven() {
        assert_eq!(
            category_of(SourceTag::ApprovedEfiRng),
            EntropyCategory::ClaimedUnproven
        );
    }

    #[test]
    fn category_of_rdseed_is_claimed_unproven() {
        assert_eq!(
            category_of(SourceTag::X86Rdseed64),
            EntropyCategory::ClaimedUnproven
        );
    }

    #[test]
    fn category_of_rdrand_is_claimed_unproven() {
        assert_eq!(
            category_of(SourceTag::X86RdrandSupplementary),
            EntropyCategory::ClaimedUnproven
        );
    }

    /// WP-U1 ripple (SPEC_USB_TRNG.md §10): a USB TRNG is health-checked,
    /// not proven — same category as EFI RNG/RDSEED/RDRAND, 0 counted bits,
    /// never `CountedWitnessed`. The floor is absolute; there is no field
    /// or path that moves a machine source into the counted category.
    #[test]
    fn category_of_usb_trng_is_claimed_unproven() {
        assert_eq!(
            category_of(SourceTag::ApprovedUsbTrng),
            EntropyCategory::ClaimedUnproven
        );
    }

    /// Belt-and-braces over the exhaustive match itself: walk every
    /// `SourceTag` variant through `category_of` and assert the SPEC_EDU_UI
    /// §3.3 table (extended by SPEC_USB_TRNG.md §10) holds for all six, in
    /// one place, so a future variant added to `SourceTag` without a
    /// matching arm here fails loudly (the `match` in `category_of` is
    /// itself non-wildcard, so the crate wouldn't even compile — this test
    /// additionally pins the *mapping*).
    #[test]
    fn category_of_covers_all_six_tags_per_contrast_table() {
        let cases = [
            (SourceTag::DiceRolls, EntropyCategory::CountedWitnessed),
            (SourceTag::CoinFlips, EntropyCategory::CountedWitnessed),
            (SourceTag::ApprovedEfiRng, EntropyCategory::ClaimedUnproven),
            (SourceTag::X86Rdseed64, EntropyCategory::ClaimedUnproven),
            (
                SourceTag::X86RdrandSupplementary,
                EntropyCategory::ClaimedUnproven,
            ),
            (SourceTag::ApprovedUsbTrng, EntropyCategory::ClaimedUnproven),
        ];
        assert_eq!(cases.len(), 6, "SPEC_EDU_UI §3.3 + SPEC_USB_TRNG.md §10 list exactly 6 tags");
        for (tag, expected) in cases {
            assert_eq!(category_of(tag), expected);
        }
    }

    // ------------------------------------------------------------------
    // counted_milli_bits: known answers + cross-check against
    // `physical::PhysicalSession::budget_bits_x1000` (SPEC_EDU_UI §4.4).
    // ------------------------------------------------------------------

    #[test]
    fn counted_milli_bits_known_answer_128_rolls_40_flips() {
        // SPEC_EDU_UI §4.5 sample screen: 128 rolls + 40 flips -> 370.9.
        assert_eq!(counted_milli_bits(128, 40), 370_880);
    }

    #[test]
    fn counted_milli_bits_zero_is_zero() {
        assert_eq!(counted_milli_bits(0, 0), 0);
    }

    #[test]
    fn counted_milli_bits_dice_only() {
        assert_eq!(counted_milli_bits(1, 0), 2585);
        assert_eq!(counted_milli_bits(100, 0), 258_500);
    }

    #[test]
    fn counted_milli_bits_coins_only() {
        assert_eq!(counted_milli_bits(0, 1), 1000);
        assert_eq!(counted_milli_bits(0, 256), 256_000);
    }

    /// Cross-check against `physical::PhysicalSession::budget_bits_x1000`
    /// for a spread of sample counts: the panel's recomputation from plain
    /// counts MUST agree with the live session's own arithmetic bit for
    /// bit, for every sample, since §4.4 requires it to be "the SAME
    /// arithmetic".
    #[test]
    fn counted_milli_bits_matches_physical_session_budget_for_samples() {
        let samples: &[(u32, u32)] = &[
            (0, 0),
            (1, 0),
            (0, 1),
            (50, 0),
            (0, 128),
            (128, 40),
            (100, 100),
            (1, 1),
            (7, 13),
        ];
        for &(rolls, flips) in samples {
            let mut s = PhysicalSession::new();
            for _ in 0..rolls {
                s.push_roll(1).unwrap();
            }
            for _ in 0..flips {
                s.push_flip(CoinFace::Heads).unwrap();
            }
            assert_eq!(
                counted_milli_bits(s.roll_count(), s.flip_count()),
                s.budget_bits_x1000(),
                "mismatch for rolls={rolls} flips={flips}"
            );
        }
    }

    // ------------------------------------------------------------------
    // meets_floor: SPEC §17.2 boundary behavior.
    // ------------------------------------------------------------------

    #[test]
    fn meets_floor_exactly_at_boundary_128() {
        // 1000 * 128 = 128_000 exactly meets the 12-word floor.
        assert!(meets_floor(128_000, TargetBits::Bits128));
    }

    #[test]
    fn meets_floor_one_milli_bit_below_boundary_128_fails() {
        assert!(!meets_floor(127_999, TargetBits::Bits128));
    }

    #[test]
    fn meets_floor_one_milli_bit_above_boundary_128_passes() {
        assert!(meets_floor(128_001, TargetBits::Bits128));
    }

    #[test]
    fn meets_floor_exactly_at_boundary_256() {
        assert!(meets_floor(256_000, TargetBits::Bits256));
    }

    #[test]
    fn meets_floor_one_milli_bit_below_boundary_256_fails() {
        assert!(!meets_floor(255_999, TargetBits::Bits256));
    }

    #[test]
    fn meets_floor_zero_never_meets_either_floor() {
        assert!(!meets_floor(0, TargetBits::Bits128));
        assert!(!meets_floor(0, TargetBits::Bits256));
    }

    #[test]
    fn meets_floor_sample_screen_370_880_meets_256_floor() {
        // SPEC_EDU_UI §4.5 sample screen: 370.9 bits >= 256 target.
        assert!(meets_floor(370_880, TargetBits::Bits256));
    }

    // ------------------------------------------------------------------
    // fmt_milli_bits_1dp: no-float, half-up-to-nearest-tenth rounding.
    // ------------------------------------------------------------------

    #[test]
    fn fmt_sample_screen_370_880_renders_370_9() {
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(370_880, &mut buf), "370.9");
    }

    #[test]
    fn fmt_sample_screen_330_880_renders_330_9() {
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(330_880, &mut buf), "330.9");
    }

    #[test]
    fn fmt_exact_tenth_256_000_renders_256_0() {
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(256_000, &mut buf), "256.0");
    }

    #[test]
    fn fmt_zero_renders_0_0() {
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(0, &mut buf), "0.0");
    }

    #[test]
    fn fmt_single_roll_2585_renders_2_6() {
        // One die roll's 2.585 bits rounds half-up to 2.6.
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(2585, &mut buf), "2.6");
    }

    #[test]
    fn fmt_exact_tenth_no_rounding_needed() {
        let mut buf = [0u8; 24];
        // 1234 milli-bits = 1.234 bits -> nearest tenth 1.2 (round down).
        assert_eq!(fmt_milli_bits_1dp(1234, &mut buf), "1.2");
        // 100 milli-bits = 0.100 bits, an exact tenth already.
        assert_eq!(fmt_milli_bits_1dp(100, &mut buf), "0.1");
    }

    #[test]
    fn fmt_exact_half_hundredth_rounds_half_up() {
        // 250 milli-bits = 0.250 bits sits exactly midway between 0.2 and
        // 0.3; half-up rounding must land on 0.3.
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(250, &mut buf), "0.3");
        // 350 milli-bits: midway between 0.3 and 0.4 -> rounds up to 0.4.
        assert_eq!(fmt_milli_bits_1dp(350, &mut buf), "0.4");
        // 450 milli-bits: midway between 0.4 and 0.5 -> rounds up to 0.5.
        assert_eq!(fmt_milli_bits_1dp(450, &mut buf), "0.5");
    }

    #[test]
    fn fmt_rounds_down_when_below_midpoint() {
        // 344 milli-bits = 0.344 bits is closer to 0.3 than 0.4.
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(344, &mut buf), "0.3");
    }

    #[test]
    fn fmt_rounds_up_when_above_midpoint() {
        // 356 milli-bits = 0.356 bits is closer to 0.4 than 0.3.
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(356, &mut buf), "0.4");
    }

    #[test]
    fn fmt_tenth_rollover_carries_into_whole() {
        // 995 milli-bits rounds up to the next whole bit: 1.0, not 9.10.
        let mut buf = [0u8; 24];
        assert_eq!(fmt_milli_bits_1dp(995, &mut buf), "1.0");
    }

    #[test]
    fn fmt_large_value_no_panic_no_truncation() {
        // Worst case for buffer sizing: the maximum possible dice-only
        // total (`u32::MAX` rolls), well beyond any real session but a
        // useful bound check for the fixed 24-byte buffer, no alloc.
        let milli_bits = counted_milli_bits(u32::MAX, 0);
        // 2585 * 4_294_967_295 = 11_102_490_457_575 milli-bits ->
        // tenths = (11_102_490_457_575 + 50) / 100 = 111_024_904_576 ->
        // whole 11_102_490_457, frac 6 -> "11102490457.6".
        assert_eq!(milli_bits, 11_102_490_457_575);
        let mut buf = [0u8; 24];
        let s = fmt_milli_bits_1dp(milli_bits, &mut buf);
        assert_eq!(s, "11102490457.6");
        assert!(s.len() < 24);
    }

    #[test]
    fn fmt_moderately_large_value() {
        let mut buf = [0u8; 24];
        // 1_000_000 milli-bits = 1000.0 bits exactly.
        assert_eq!(fmt_milli_bits_1dp(1_000_000, &mut buf), "1000.0");
    }
}
