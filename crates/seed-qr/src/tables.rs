//! Version/format tables and derived quantities for the QR subset this
//! crate supports: **byte mode, error-correction level M, versions 1..=13**.
//!
//! Everything here is either a short table transcribed from ISO/IEC 18004
//! or a closed-form derivation from it. Every function is `const fn`, total
//! (defined for every `u8` input) and free of arithmetic that can underflow
//! for in-range versions; out-of-range versions are clamped rather than
//! panicking, so no caller can reach a panic through this module.

/// Lowest QR version this crate emits.
pub const MIN_VERSION: u8 = 1;

/// Highest QR version this crate emits (69x69 modules).
pub const MAX_VERSION: u8 = 13;

/// Side length in modules of the largest supported version.
pub const MAX_SIDE: usize = 69;

/// Largest `ecc_per_block` over versions 1..=13 (version 11).
pub const MAX_ECC_PER_BLOCK: usize = 30;

/// Largest `num_blocks` over versions 1..=13 (version 13).
pub const MAX_BLOCKS: usize = 9;

/// Total codewords (data + ECC) of version 13.
pub const MAX_TOTAL_CODEWORDS: usize = 532;

/// Data codewords of version 13.
pub const MAX_DATA_CODEWORDS: usize = 334;

/// Largest number of alignment-pattern coordinates over versions 1..=13.
pub const MAX_ALIGN_POSITIONS: usize = 3;

/// Four-bit mode indicator for byte (8-bit) mode.
pub const MODE_BYTE: u32 = 0b0100;

/// Two-bit format value of error-correction level M (ISO/IEC 18004 §8.9).
pub const ECC_FORMAT_BITS_M: u32 = 0b00;

/// Clamp an arbitrary `u8` into the supported version range.
///
/// Every table below is an exhaustive `match` over the clamped value, so
/// no lookup can be out of bounds *and* none emits a bounds check — the
/// crate stays panic-free in the debug profile as well as in release.
const fn clamp(version: u8) -> u8 {
    if version < MIN_VERSION {
        MIN_VERSION
    } else if version > MAX_VERSION {
        MAX_VERSION
    } else {
        version
    }
}

/// Side length in modules: `17 + 4 * version`.
pub const fn side_for(version: u8) -> usize {
    17 + 4 * clamp(version) as usize
}

/// ECC codewords per block for level M (ISO/IEC 18004 table 13/14, level
/// M column). Pinned element-wise by
/// `tests::ecc_per_block_matches_published_column`.
pub const fn ecc_per_block(version: u8) -> usize {
    match clamp(version) {
        1 => 10,
        2 => 16,
        3 => 26,
        4 => 18,
        5 => 24,
        6 => 16,
        7 => 18,
        8 => 22,
        9 => 22,
        10 => 26,
        11 => 30,
        12 => 22,
        _ => 22,
    }
}

/// Number of ECC blocks for level M (ISO/IEC 18004 table 13/14, level M
/// column). Pinned element-wise by
/// `tests::num_blocks_matches_published_column`.
pub const fn num_blocks(version: u8) -> usize {
    match clamp(version) {
        1 => 1,
        2 => 1,
        3 => 1,
        4 => 2,
        5 => 2,
        6 => 4,
        7 => 4,
        8 => 4,
        9 => 5,
        10 => 5,
        11 => 5,
        12 => 8,
        _ => 9,
    }
}

/// Data-codeword count of each error-correction block, shorter blocks
/// first, written to `out[0..n]`; returns `n`, the block count.
///
/// ISO/IEC 18004 §8.6: the data codewords are divided as evenly as
/// possible, and where the division is uneven the *longer* blocks come
/// last. This is the single shared derivation — the encoder's interleaver
/// and the test decoder's de-interleaver both call it, and it is pinned
/// against the published group-1/group-2 table by
/// `tests::block_lengths_match_published_table`.
pub fn block_lengths(version: u8, out: &mut [usize; MAX_BLOCKS]) -> usize {
    *out = [0; MAX_BLOCKS];
    let blocks = num_blocks(version);
    if blocks == 0 || blocks > MAX_BLOCKS {
        return 0;
    }
    let ndata = num_data_codewords(version);
    let short_len = ndata / blocks;
    // `ndata % blocks < blocks`, so this cannot underflow.
    let num_short = blocks - ndata % blocks;
    let mut b = 0usize;
    while b < blocks {
        if let Some(slot) = out.get_mut(b) {
            *slot = if b < num_short { short_len } else { short_len + 1 };
        }
        b += 1;
    }
    blocks
}

/// Number of modules available to data + ECC codewords, i.e. the symbol
/// area minus every function pattern (finders, separators, timing,
/// alignment, format information, version information and the dark
/// module). Closed form from ISO/IEC 18004 §6.4.10 / annex.
pub const fn num_raw_data_modules(version: u8) -> usize {
    let ver = clamp(version) as usize;
    let mut result = (16 * ver + 128) * ver + 64;
    if ver >= 2 {
        let numalign = ver / 7 + 2;
        result -= (25 * numalign - 10) * numalign - 55;
        if ver >= 7 {
            result -= 36;
        }
    }
    result
}

/// Total 8-bit codewords in the symbol. Remainder bits (`raw % 8`) are
/// left unset by the encoder, per ISO/IEC 18004 §8.7.1.
pub const fn num_total_codewords(version: u8) -> usize {
    num_raw_data_modules(version) / 8
}

/// Data codewords (payload + padding) for level M.
pub const fn num_data_codewords(version: u8) -> usize {
    num_total_codewords(version) - num_blocks(version) * ecc_per_block(version)
}

/// Width of the byte-mode character-count field (ISO/IEC 18004 table 3).
pub const fn char_count_bits(version: u8) -> usize {
    if clamp(version) <= 9 {
        8
    } else {
        16
    }
}

/// Largest byte-mode payload that fits: the data-codeword budget less the
/// 4-bit mode indicator and the character-count field.
pub const fn max_payload_bytes(version: u8) -> usize {
    (num_data_codewords(version) * 8 - 4 - char_count_bits(version)) / 8
}

/// Number of remainder bits after the last codeword (0 or 7 here).
pub const fn num_remainder_bits(version: u8) -> usize {
    num_raw_data_modules(version) % 8
}

/// Write the alignment-pattern centre coordinates for `version` into
/// `out`, returning how many were written (0 for version 1).
///
/// ISO/IEC 18004 annex E: the first centre is always at 6, the last at
/// `side - 7`, and the remaining centres are evenly spaced by an even
/// step. Reproduces the published table exactly for versions 1..=13.
pub fn alignment_positions(version: u8, out: &mut [usize; MAX_ALIGN_POSITIONS]) -> usize {
    let ver = clamp(version) as usize;
    *out = [0; MAX_ALIGN_POSITIONS];
    if ver == 1 {
        return 0;
    }
    let num_align = ver / 7 + 2;
    let step = (ver * 4 + num_align * 2 + 1) / (num_align * 2 - 2) * 2;
    let mut pos = side_for(version) - 7;
    let mut i = num_align;
    while i > 1 {
        i -= 1;
        if let Some(slot) = out.get_mut(i) {
            *slot = pos;
        }
        // `pos` only descends by `step` while `i > 1`, and for every
        // supported version the final value is 6 + step > step, so this
        // subtraction cannot underflow.
        pos = pos.saturating_sub(step);
    }
    if let Some(slot) = out.get_mut(0) {
        *slot = 6;
    }
    num_align
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Total codewords per version, ISO/IEC 18004 table 9 (all EC levels
    /// share these). Cross-checks the closed-form module count.
    #[test]
    fn total_codewords_match_published_table() {
        const EXPECTED: [usize; 13] = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532];
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(num_total_codewords(i as u8 + 1), want, "version {}", i + 1);
        }
    }

    /// Byte-mode character capacity, EC level M, ISO/IEC 18004 table 7.
    #[test]
    fn byte_capacity_matches_published_table() {
        const EXPECTED: [usize; 13] = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331];
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(max_payload_bytes(i as u8 + 1), want, "version {}", i + 1);
        }
    }

    /// Alignment-pattern centres, ISO/IEC 18004 annex E table E.1.
    #[test]
    fn alignment_positions_match_published_table() {
        const EXPECTED: [&[usize]; 13] = [
            &[],
            &[6, 18],
            &[6, 22],
            &[6, 26],
            &[6, 30],
            &[6, 34],
            &[6, 22, 38],
            &[6, 24, 42],
            &[6, 26, 46],
            &[6, 28, 50],
            &[6, 30, 54],
            &[6, 32, 58],
            &[6, 34, 62],
        ];
        let mut buf = [0usize; MAX_ALIGN_POSITIONS];
        for (i, want) in EXPECTED.iter().enumerate() {
            let n = alignment_positions(i as u8 + 1, &mut buf);
            assert_eq!(n, want.len(), "version {}", i + 1);
            assert_eq!(&buf[..n], *want, "version {}", i + 1);
        }
    }

    /// ISO/IEC 18004 table 13/14, "number of error correction codewords
    /// per block", level M column, versions 1..=13. Transcribed literally.
    ///
    /// Without this, `ecc_per_block` and `num_blocks` are pinned only as a
    /// *product* (via the capacity table), so a compensating transposition
    /// between the two would go undetected.
    #[test]
    fn ecc_per_block_matches_published_column() {
        const EXPECTED: [usize; 13] = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22];
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(ecc_per_block(i as u8 + 1), want, "version {}", i + 1);
        }
    }

    /// ISO/IEC 18004 table 13/14, "number of error correction blocks",
    /// level M column, versions 1..=13. Transcribed literally.
    #[test]
    fn num_blocks_matches_published_column() {
        const EXPECTED: [usize; 13] = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9];
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(num_blocks(i as u8 + 1), want, "version {}", i + 1);
        }
    }

    /// The published EC-M block structure, transcribed as
    /// `(group-1 count, group-1 data codewords, group-2 count, group-2
    /// data codewords)` — ISO/IEC 18004 table 13/14. Pins the
    /// short_len / num_short / shorter-blocks-first derivation, which is
    /// otherwise shared between the encoder and the test decoder and so
    /// would cancel out if it were wrong.
    #[test]
    fn block_lengths_match_published_table() {
        const EXPECTED: [(usize, usize, usize, usize); 13] = [
            (1, 16, 0, 0),  // v1
            (1, 28, 0, 0),  // v2
            (1, 44, 0, 0),  // v3
            (2, 32, 0, 0),  // v4
            (2, 43, 0, 0),  // v5
            (4, 27, 0, 0),  // v6
            (4, 31, 0, 0),  // v7
            (2, 38, 2, 39), // v8
            (3, 36, 2, 37), // v9
            (4, 43, 1, 44), // v10
            (1, 50, 4, 51), // v11
            (6, 36, 2, 37), // v12
            (8, 37, 1, 38), // v13
        ];
        let mut lens = [0usize; MAX_BLOCKS];
        for (i, &(n1, l1, n2, l2)) in EXPECTED.iter().enumerate() {
            let version = i as u8 + 1;
            let n = block_lengths(version, &mut lens);
            assert_eq!(n, n1 + n2, "block count, version {version}");

            let mut want = [0usize; MAX_BLOCKS];
            for (b, slot) in want.iter_mut().enumerate().take(n) {
                *slot = if b < n1 { l1 } else { l2 };
            }
            assert_eq!(&lens[..n], &want[..n], "block lengths, version {version}");

            // The split must also account for every data codeword.
            let total: usize = lens[..n].iter().sum();
            assert_eq!(total, num_data_codewords(version), "sum, version {version}");
            assert_eq!(n1 * l1 + n2 * l2, total, "published sum, version {version}");

            // Shorter blocks first, and at most one distinct length step.
            for b in 1..n {
                assert!(lens[b] >= lens[b - 1], "not sorted, version {version}");
                assert!(lens[b] - lens[b - 1] <= 1, "step > 1, version {version}");
            }
        }
    }

    #[test]
    fn payload_capacity_is_monotonic() {
        for v in MIN_VERSION..MAX_VERSION {
            assert!(max_payload_bytes(v) < max_payload_bytes(v + 1));
        }
    }

    #[test]
    fn derived_constants_bound_every_version() {
        for v in MIN_VERSION..=MAX_VERSION {
            assert!(ecc_per_block(v) <= MAX_ECC_PER_BLOCK);
            assert!(num_blocks(v) <= MAX_BLOCKS);
            assert!(num_total_codewords(v) <= MAX_TOTAL_CODEWORDS);
            assert!(num_data_codewords(v) <= MAX_DATA_CODEWORDS);
            assert!(side_for(v) <= MAX_SIDE);
        }
        assert_eq!(side_for(MAX_VERSION), MAX_SIDE);
        assert_eq!(num_total_codewords(MAX_VERSION), MAX_TOTAL_CODEWORDS);
        assert_eq!(num_data_codewords(MAX_VERSION), MAX_DATA_CODEWORDS);
    }
}
