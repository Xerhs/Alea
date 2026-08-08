//! Acceptance vectors for `seed-qr`.
//!
//! Host tests, `std` allowed. The strategy is deliberately *not* "embed a
//! bitmap the implementation produced and freeze it" — that only proves the
//! encoder is self-consistent. Instead this file:
//!
//! 1. Asserts **externally checkable known answers**: the published
//!    ISO/IEC 18004 format-information bit strings, the published
//!    byte-mode capacity table, the hand-derived codeword sequence for
//!    `"HELLO WORLD"`, and the hand-derived first-codeword module
//!    positions.
//! 2. Asserts **structural invariants** provable from the spec: finder
//!    patterns, separators, timing patterns, dark module, function-module
//!    count against the closed-form data-module count.
//! 3. Cross-checks the crate's shift-register GF(256) Reed-Solomon against
//!    an **independent table-driven long-division** implementation written
//!    from scratch in this file.
//! 4. Round-trips every symbol through an **independent decoder** written
//!    here: it rebuilds the function map from the *published* alignment
//!    table (not the crate's closed form), BCH-decodes the format info,
//!    unmasks, re-reads the zigzag, de-interleaves the blocks, checks that
//!    all Reed-Solomon syndromes vanish, and parses the payload back out.

use seed_qr::tables;
use seed_qr::{encode, Matrix, QrError, MAX_SIDE, MAX_VERSION};

// ---------------------------------------------------------------------------
// Independent GF(256) / Reed-Solomon (log-table long division)
// ---------------------------------------------------------------------------

/// Log/antilog tables for GF(256) mod 0x11D. Deliberately a different
/// construction from the crate's branch-free bitwise multiply.
struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    fn pow(&self, i: usize) -> u8 {
        self.exp[i % 255]
    }

    /// Generator polynomial of the given degree, highest-degree coefficient
    /// first, built by explicit convolution of `(x + a^i)` factors.
    fn generator(&self, degree: usize) -> Vec<u8> {
        let mut g = vec![1u8];
        for i in 0..degree {
            let root = self.pow(i);
            let mut ng = vec![0u8; g.len() + 1];
            for (j, &c) in g.iter().enumerate() {
                ng[j] ^= c;
                ng[j + 1] ^= self.mul(c, root);
            }
            g = ng;
        }
        g
    }

    /// Reed-Solomon parity by straight-line polynomial long division of
    /// `msg * x^degree` by the generator polynomial.
    fn parity(&self, msg: &[u8], degree: usize) -> Vec<u8> {
        let g = self.generator(degree);
        assert_eq!(g.len(), degree + 1);
        let mut rem = msg.to_vec();
        rem.extend(std::iter::repeat(0u8).take(degree));
        for i in 0..msg.len() {
            let coef = rem[i];
            if coef != 0 {
                for (j, &gj) in g.iter().enumerate() {
                    rem[i + j] ^= self.mul(gj, coef);
                }
            }
        }
        rem[msg.len()..].to_vec()
    }

    /// Every syndrome of a data+parity codeword must be zero.
    fn syndromes_vanish(&self, codeword: &[u8], degree: usize) -> bool {
        (0..degree).all(|i| {
            let root = self.pow(i);
            let mut acc = 0u8;
            for &b in codeword {
                acc = self.mul(acc, root) ^ b;
            }
            acc == 0
        })
    }
}

// ---------------------------------------------------------------------------
// Independent reference data
// ---------------------------------------------------------------------------

/// Alignment-pattern centres, ISO/IEC 18004 annex E table E.1, versions
/// 1..=13. Transcribed from the published table, not computed.
const ALIGN: [&[usize]; 13] = [
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

/// Format-information bit strings for EC level M, masks 0..7, MSB first
/// (ISO/IEC 18004 table 25). Masks 0 and 1 were re-derived by hand from
/// the BCH(15,5) generator 0x537 and the 0x5412 XOR mask.
const FORMAT_M: [&str; 8] = [
    "101010000010010",
    "101000100100101",
    "101111001111100",
    "101101101001011",
    "100010111111001",
    "100000011001110",
    "100111110010111",
    "100101010100000",
];

// ---------------------------------------------------------------------------
// Independent function-module map and decoder
// ---------------------------------------------------------------------------

fn side(version: u8) -> usize {
    17 + 4 * version as usize
}

/// Rebuild the set of function modules for `version` from first
/// principles + the published alignment table.
fn function_map(version: u8) -> Vec<Vec<bool>> {
    let size = side(version);
    let mut f = vec![vec![false; size]; size];

    // Finder patterns, separators and the reserved format-information
    // areas together occupy a 9x9 block at each of three corners.
    for y in 0..9 {
        for x in 0..9 {
            f[y][x] = true; // top-left
        }
    }
    for y in 0..9 {
        for x in (size - 8)..size {
            f[y][x] = true; // top-right
        }
    }
    for y in (size - 8)..size {
        for x in 0..9 {
            f[y][x] = true; // bottom-left (includes the dark module)
        }
    }

    // Timing patterns.
    for i in 0..size {
        f[6][i] = true;
        f[i][6] = true;
    }

    // Alignment patterns, minus the three that collide with finders.
    let centres = ALIGN[version as usize - 1];
    let n = centres.len();
    for (j, &cx) in centres.iter().enumerate() {
        for (k, &cy) in centres.iter().enumerate() {
            if (j == 0 && k == 0) || (j == 0 && k == n - 1) || (j == n - 1 && k == 0) {
                continue;
            }
            for dy in 0..5usize {
                for dx in 0..5usize {
                    f[cy + dy - 2][cx + dx - 2] = true;
                }
            }
        }
    }

    // Version information blocks.
    if version >= 7 {
        for i in 0..18usize {
            let a = size - 11 + i % 3;
            let b = i / 3;
            f[b][a] = true;
            f[a][b] = true;
        }
    }
    f
}

/// The 15 module coordinates of format-information copy 1, bit 0 first.
fn format_positions_copy1() -> Vec<(usize, usize)> {
    let mut v: Vec<(usize, usize)> = (0..=5).map(|i| (8usize, i)).collect();
    v.push((8, 7));
    v.push((8, 8));
    v.push((7, 8));
    for i in 9..15usize {
        v.push((14 - i, 8));
    }
    v
}

/// The 15 module coordinates of format-information copy 2, bit 0 first.
fn format_positions_copy2(size: usize) -> Vec<(usize, usize)> {
    let mut v: Vec<(usize, usize)> = (0..8).map(|i| (size - 1 - i, 8usize)).collect();
    for i in 8..15usize {
        v.push((8, size - 15 + i));
    }
    v
}

/// Read a 15-bit format value (bit 0 = LSB) from a coordinate list.
fn read_format(m: &Matrix, pos: &[(usize, usize)]) -> u32 {
    let mut bits = 0u32;
    for (i, &(x, y)) in pos.iter().enumerate() {
        if m.get(x, y) {
            bits |= 1 << i;
        }
    }
    bits
}

/// Encode a format value the way ISO/IEC 18004 §8.9 prescribes; used both
/// to build the decode table and to check the published strings.
fn format_codeword(ec_bits: u32, mask: u32) -> u32 {
    let data = (ec_bits << 3) | mask;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
    }
    ((data << 10) | (rem & 0x3FF)) ^ 0x5412
}

/// BCH-decode a 15-bit format value to `(ec_bits, mask)`, requiring an
/// exact match (zero bit errors).
fn decode_format_exact(bits: u32) -> Option<(u32, u32)> {
    for ec in 0..4u32 {
        for mask in 0..8u32 {
            if format_codeword(ec, mask) == bits {
                return Some((ec, mask));
            }
        }
    }
    None
}

/// Re-read the interleaved codeword stream out of a symbol, undoing the
/// mask, by walking the two-module-wide zigzag.
fn read_codewords(m: &Matrix, version: u8, mask: u32) -> Vec<u8> {
    let size = side(version);
    let func = function_map(version);
    let total = tables::num_total_codewords(version);

    let mut bits: Vec<bool> = Vec::with_capacity(total * 8 + 8);
    // Column pairs, right to left, skipping the vertical timing column.
    let mut cols: Vec<usize> = Vec::new();
    let mut c = size - 1;
    loop {
        cols.push(c);
        if c < 2 {
            break;
        }
        c -= 2;
        if c == 6 {
            c = 5;
        }
    }
    for (pair_idx, &right) in cols.iter().enumerate() {
        // Pairs alternate direction, starting upward at the right edge.
        let upward = pair_idx % 2 == 0;
        for step in 0..size {
            let y = if upward { size - 1 - step } else { step };
            for j in 0..2usize {
                let x = right - j;
                if func[y][x] {
                    continue;
                }
                let raw = m.get(x, y);
                bits.push(raw ^ mask_bit(mask, x, y));
            }
        }
    }

    // The zigzag must visit exactly the modules the closed-form count says
    // are available, leaving only the (0 or 7) remainder bits over.
    assert_eq!(
        bits.len(),
        tables::num_raw_data_modules(version),
        "zigzag must cover every data module (v{version})"
    );
    assert_eq!(
        bits.len() - total * 8,
        tables::num_remainder_bits(version),
        "remainder bits (v{version})"
    );
    // The encoder never writes the remainder bits, so they must still be
    // light before masking.
    for &b in &bits[total * 8..] {
        assert!(!b, "remainder bits must be unset (v{version})");
    }

    let mut out = Vec::with_capacity(total);
    for chunk in bits.chunks(8).take(total) {
        let mut b = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                b |= 0x80 >> i;
            }
        }
        out.push(b);
    }
    out
}

fn mask_bit(mask: u32, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
    }
}

/// Split the interleaved stream back into blocks, verify every block's
/// Reed-Solomon syndromes vanish, and return the concatenated data
/// codewords.
fn deinterleave_and_verify(all: &[u8], version: u8, gf: &Gf) -> Vec<u8> {
    let ecc_len = tables::ecc_per_block(version);
    let ndata = tables::num_data_codewords(version);

    // One shared derivation with the encoder, pinned element-wise against
    // the published group-1/group-2 table by
    // `tables::tests::block_lengths_match_published_table` — previously
    // this was a second copy of the same formula, so an error in it would
    // have cancelled out on the round trip.
    let mut lens_buf = [0usize; 9];
    let blocks = tables::block_lengths(version, &mut lens_buf);
    let lens: Vec<usize> = lens_buf[..blocks].to_vec();
    let max_len = *lens.iter().max().expect("at least one block");

    let mut data_blocks: Vec<Vec<u8>> = vec![Vec::new(); blocks];
    let mut idx = 0usize;
    for i in 0..max_len {
        for b in 0..blocks {
            if i < lens[b] {
                data_blocks[b].push(all[idx]);
                idx += 1;
            }
        }
    }
    let mut ecc_blocks: Vec<Vec<u8>> = vec![Vec::new(); blocks];
    for _ in 0..ecc_len {
        for b in 0..blocks {
            ecc_blocks[b].push(all[idx]);
            idx += 1;
        }
    }
    assert_eq!(idx, tables::num_total_codewords(version), "stream consumed");

    let mut data = Vec::new();
    for b in 0..blocks {
        // Independent parity check, two ways: recompute, and syndromes.
        let expect = gf.parity(&data_blocks[b], ecc_len);
        assert_eq!(expect, ecc_blocks[b], "block {b} parity (v{version})");
        let mut cw = data_blocks[b].clone();
        cw.extend_from_slice(&ecc_blocks[b]);
        assert!(gf.syndromes_vanish(&cw, ecc_len), "block {b} syndromes");
        data.extend_from_slice(&data_blocks[b]);
    }
    assert_eq!(data.len(), ndata);
    data
}

/// Parse a byte-mode segment out of the data codewords.
fn parse_payload(data: &[u8], version: u8) -> Vec<u8> {
    let mut bitpos = 0usize;
    let take = |n: usize, bitpos: &mut usize| -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = data[*bitpos / 8];
            let bit = (byte >> (7 - (*bitpos % 8))) & 1;
            v = (v << 1) | bit as u32;
            *bitpos += 1;
        }
        v
    };
    let mode = take(4, &mut bitpos);
    assert_eq!(mode, 0b0100, "byte mode indicator");
    let count = take(tables::char_count_bits(version), &mut bitpos) as usize;
    (0..count).map(|_| take(8, &mut bitpos) as u8).collect()
}

/// Full independent decode: matrix in, payload out.
fn decode(m: &Matrix, gf: &Gf) -> (u8, Vec<u8>) {
    let size = m.side();
    assert!(size >= 21 && size <= MAX_SIDE && (size - 17) % 4 == 0, "side {size}");
    let version = ((size - 17) / 4) as u8;

    let f1 = read_format(m, &format_positions_copy1());
    let f2 = read_format(m, &format_positions_copy2(size));
    assert_eq!(f1, f2, "the two format copies must agree");
    let (ec, mask) = decode_format_exact(f1).expect("format info must be a valid BCH codeword");
    assert_eq!(ec, 0b00, "error-correction level must be M");
    assert_eq!(
        FORMAT_M[mask as usize],
        format!("{f1:015b}"),
        "format string must match the published table"
    );

    let all = read_codewords(m, version, mask);
    let data = deinterleave_and_verify(&all, version, gf);
    (version, parse_payload(&data, version))
}

// ---------------------------------------------------------------------------
// Structural invariants
// ---------------------------------------------------------------------------

fn assert_structure(m: &Matrix, version: u8) {
    let size = side(version);
    assert_eq!(m.side(), size, "side == 17 + 4 * version");

    // Finder patterns: 7x7 concentric rings at three corners, each with a
    // one-module light separator on its inner sides.
    for &(ox, oy) in &[(0usize, 0usize), (size - 7, 0), (0, size - 7)] {
        for dy in 0..7usize {
            for dx in 0..7usize {
                // Chebyshev ring from the 7x7 centre: rings 0,1,3 dark,
                // ring 2 light.
                let ring = dx.max(6 - dx).max(dy).max(6 - dy) - 3;
                let want = ring != 2;
                assert_eq!(
                    m.get(ox + dx, oy + dy),
                    want,
                    "finder at ({ox},{oy}) module ({dx},{dy})"
                );
            }
        }
    }
    // Separators: the row/column just inside each finder must be light.
    for i in 0..8usize {
        assert!(!m.get(i, 7), "top-left separator row");
        assert!(!m.get(7, i), "top-left separator column");
        assert!(!m.get(size - 1 - i, 7), "top-right separator row");
        assert!(!m.get(size - 8, i), "top-right separator column");
        assert!(!m.get(i, size - 8), "bottom-left separator row");
        assert!(!m.get(7, size - 1 - i), "bottom-left separator column");
    }

    // Timing patterns alternate, starting and ending dark.
    for i in 8..(size - 8) {
        assert_eq!(m.get(i, 6), i % 2 == 0, "horizontal timing at x={i}");
        assert_eq!(m.get(6, i), i % 2 == 0, "vertical timing at y={i}");
    }

    // The always-dark module.
    assert!(m.get(8, 4 * version as usize + 9), "dark module");
    assert_eq!(4 * version as usize + 9, size - 8);

    // Alignment patterns from the published table.
    let centres = ALIGN[version as usize - 1];
    let n = centres.len();
    for (j, &cx) in centres.iter().enumerate() {
        for (k, &cy) in centres.iter().enumerate() {
            if (j == 0 && k == 0) || (j == 0 && k == n - 1) || (j == n - 1 && k == 0) {
                continue;
            }
            for dy in 0..5usize {
                for dx in 0..5usize {
                    let ring = dx.max(4 - dx).max(dy).max(4 - dy) - 2;
                    assert_eq!(
                        m.get(cx + dx - 2, cy + dy - 2),
                        ring != 1,
                        "alignment at ({cx},{cy})"
                    );
                }
            }
        }
    }

    // The independently-built function map must have exactly as many
    // modules as the crate's closed-form count says are unavailable.
    let f = function_map(version);
    let func_count: usize = f.iter().flatten().filter(|&&b| b).count();
    assert_eq!(
        size * size - func_count,
        tables::num_raw_data_modules(version),
        "function-module count (v{version})"
    );
}

// ---------------------------------------------------------------------------
// Acceptance test 1 — "HELLO WORLD"
// ---------------------------------------------------------------------------

/// The byte-mode bit stream for `"HELLO WORLD"` at version 1, derived by
/// hand: mode `0100`, count `00001011` (11), the eleven ASCII bytes, a
/// four-bit terminator, then `EC 11 EC` padding to 16 data codewords.
const HELLO_DATA_CODEWORDS: [u8; 16] = [
    0x40, 0xB4, 0x84, 0x54, 0xC4, 0xC4, 0xF2, 0x05, 0x74, 0xF5, 0x24, 0xC4, 0x40, 0xEC, 0x11, 0xEC,
];

#[test]
fn hello_world_codewords_and_structure() {
    let gf = Gf::new();
    let mut m = Matrix::new();
    let version = encode(b"HELLO WORLD", &mut m).expect("must fit in version 1");
    assert_eq!(version, 1);
    assert_eq!(m.side(), 21);

    assert_structure(&m, version);

    // Recover the format info and the codeword stream from the matrix.
    let f1 = read_format(&m, &format_positions_copy1());
    let (ec, mask) = decode_format_exact(f1).expect("valid BCH format codeword");
    assert_eq!(ec, 0b00, "EC level M");
    assert_eq!(FORMAT_M[mask as usize], format!("{f1:015b}"));
    // Both copies, module by module, against the published bit string.
    for pos in [format_positions_copy1(), format_positions_copy2(m.side())] {
        for (i, &(x, y)) in pos.iter().enumerate() {
            let want = FORMAT_M[mask as usize].as_bytes()[14 - i] == b'1';
            assert_eq!(m.get(x, y), want, "format bit {i} at ({x},{y})");
        }
    }

    let all = read_codewords(&m, version, mask);
    assert_eq!(all.len(), 26, "v1 total codewords");

    // Known answer BEFORE error correction.
    assert_eq!(
        &all[..16],
        &HELLO_DATA_CODEWORDS,
        "hand-derived byte-mode codeword sequence"
    );

    // Known answer for the parity, from the independent implementation.
    let expected_parity = gf.parity(&HELLO_DATA_CODEWORDS, 10);
    assert_eq!(&all[16..], &expected_parity[..], "Reed-Solomon parity");
    assert!(gf.syndromes_vanish(&all, 10), "syndromes must vanish");

    // Round-trip.
    let (v, payload) = decode(&m, &gf);
    assert_eq!(v, 1);
    assert_eq!(payload, b"HELLO WORLD");
}

/// The first data codeword occupies the bottom-right 2x4 block, read
/// upward, right column first — directly readable off ISO/IEC 18004
/// figure 19. Pin those eight modules to the bits of `0x40`.
#[test]
fn first_codeword_lands_in_the_bottom_right_corner() {
    let mut m = Matrix::new();
    assert_eq!(encode(b"HELLO WORLD", &mut m).unwrap(), 1);
    let f1 = read_format(&m, &format_positions_copy1());
    let (_, mask) = decode_format_exact(f1).unwrap();

    let coords = [
        (20usize, 20usize),
        (19, 20),
        (20, 19),
        (19, 19),
        (20, 18),
        (19, 18),
        (20, 17),
        (19, 17),
    ];
    for (i, &(x, y)) in coords.iter().enumerate() {
        let unmasked = m.get(x, y) ^ mask_bit(mask, x, y);
        let want = (0x40u8 >> (7 - i)) & 1 != 0;
        assert_eq!(unmasked, want, "codeword-0 bit {i} at ({x},{y})");
    }
}

/// The crate's shift-register Reed-Solomon must agree with the
/// independent table-driven long division for every supported block size.
#[test]
fn reed_solomon_matches_independent_implementation() {
    let gf = Gf::new();
    for degree in [10usize, 16, 18, 22, 24, 26, 30] {
        let mut g_crate = [0u8; 30];
        seed_qr::gf256::generator(degree, &mut g_crate);
        let g_ref = gf.generator(degree);
        // The crate omits the leading 1 and stores `degree` coefficients.
        assert_eq!(&g_crate[..degree], &g_ref[1..], "generator degree {degree}");

        let msg: Vec<u8> = (0..60u16).map(|i| (i * 37 + 11) as u8).collect();
        let mut parity = [0u8; 30];
        seed_qr::gf256::remainder(&msg, 0, msg.len(), &g_crate, degree, &mut parity);
        assert_eq!(
            &parity[..degree],
            &gf.parity(&msg, degree)[..],
            "parity degree {degree}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance test 2 — descriptor-shaped payload
// ---------------------------------------------------------------------------

#[test]
fn descriptor_shaped_156_chars() {
    let gf = Gf::new();
    let s = "wpkh([f0f0f0f0/84h/0h/100h]xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/<0;1>/*)#abcdefgh";
    assert_eq!(s.len(), 156, "fixture must be 156 chars");

    let mut m = Matrix::new();
    let version = encode(s.as_bytes(), &mut m).expect("156 bytes must fit");
    assert!(version <= MAX_VERSION, "version {version} <= 13");
    assert_eq!(version, 9, "smallest version holding 156 byte-mode chars");
    assert_eq!(m.side(), 17 + 4 * version as usize);

    assert_structure(&m, version);
    let (v, payload) = decode(&m, &gf);
    assert_eq!(v, version);
    assert_eq!(payload, s.as_bytes());
}

// ---------------------------------------------------------------------------
// Acceptance test 3 — capacity limit
// ---------------------------------------------------------------------------

/// The task brief listed "300 bytes -> `TooLong`". That is arithmetically
/// wrong for EC level M at version 13: the published byte-mode capacity is
/// **331** bytes (data codewords 334, minus the 4-bit mode indicator and
/// 16-bit character count). 300 bytes therefore *must* encode successfully.
/// This test pins the real boundary on both sides.
#[test]
fn capacity_boundary_is_331_bytes() {
    let gf = Gf::new();
    let mut m = Matrix::new();

    let three_hundred = vec![b'A'; 300];
    let v = encode(&three_hundred, &mut m).expect("300 bytes fits version 13 at EC-M");
    assert_eq!(v, 13);
    let (_, payload) = decode(&m, &gf);
    assert_eq!(payload, three_hundred);

    let at_limit = vec![b'A'; 331];
    assert_eq!(encode(&at_limit, &mut m), Ok(13));
    assert_eq!(m.side(), 69);
    assert_eq!(m.side(), MAX_SIDE);
    let (_, payload) = decode(&m, &gf);
    assert_eq!(payload, at_limit);

    let over_limit = vec![b'A'; 332];
    assert_eq!(encode(&over_limit, &mut m), Err(QrError::TooLong));

    let way_over = vec![b'A'; 4096];
    assert_eq!(encode(&way_over, &mut m), Err(QrError::TooLong));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn encoding_is_deterministic() {
    let inputs: [&[u8]; 4] = [
        b"HELLO WORLD",
        b"",
        b"xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz",
        &[0u8; 200],
    ];
    for input in inputs {
        let mut a = Matrix::new();
        let mut b = Matrix::new();
        let va = encode(input, &mut a).unwrap();
        let vb = encode(input, &mut b).unwrap();
        assert_eq!(va, vb);
        assert_eq!(a.side(), b.side());
        for y in 0..a.side() {
            for x in 0..a.side() {
                assert_eq!(a.get(x, y), b.get(x, y), "module ({x},{y})");
            }
        }
    }
    // Re-using a matrix must fully overwrite it, not leave stale modules.
    let mut reused = Matrix::new();
    encode(&[0xFFu8; 300], &mut reused).unwrap();
    encode(b"HELLO WORLD", &mut reused).unwrap();
    let mut fresh = Matrix::new();
    encode(b"HELLO WORLD", &mut fresh).unwrap();
    for y in 0..fresh.side() {
        for x in 0..fresh.side() {
            assert_eq!(reused.get(x, y), fresh.get(x, y), "stale module ({x},{y})");
        }
    }
}

// ---------------------------------------------------------------------------
// Every version, every payload length boundary
// ---------------------------------------------------------------------------

/// Round-trip a payload at each version's exact capacity, and one byte
/// past it (which must roll over to the next version). This exercises the
/// alignment-pattern layout, the 8- vs 16-bit character count, the
/// multi-block interleave and the version-information blocks (v >= 7).
#[test]
fn round_trip_at_every_version_boundary() {
    let gf = Gf::new();
    for version in 1..=MAX_VERSION {
        let cap = tables::max_payload_bytes(version);
        let payload: Vec<u8> = (0..cap).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();

        let mut m = Matrix::new();
        let v = encode(&payload, &mut m).expect("capacity payload must fit");
        assert_eq!(v, version, "exact-capacity payload must select this version");
        assert_structure(&m, version);
        let (dv, decoded) = decode(&m, &gf);
        assert_eq!(dv, version);
        assert_eq!(decoded, payload, "round trip at version {version}");

        if version < MAX_VERSION {
            let mut over = payload.clone();
            over.push(0xA5);
            let v2 = encode(&over, &mut m).expect("must roll to next version");
            assert_eq!(v2, version + 1, "capacity + 1 must bump the version");
            let (_, decoded2) = decode(&m, &gf);
            assert_eq!(decoded2, over);
        }
    }
}

/// Round-trip a spread of arbitrary lengths, including all-zero and
/// all-0xFF payloads which stress the mask-penalty balance rule.
#[test]
fn round_trip_assorted_payloads() {
    let gf = Gf::new();
    for len in [0usize, 1, 2, 13, 14, 15, 26, 27, 100, 152, 153, 180, 181, 213, 250, 331] {
        for fill in [0x00u8, 0xFF, 0x5A] {
            let payload = vec![fill; len];
            let mut m = Matrix::new();
            let version = encode(&payload, &mut m).expect("must fit");
            assert_structure(&m, version);
            let (v, decoded) = decode(&m, &gf);
            assert_eq!(v, version);
            assert_eq!(decoded, payload, "len {len} fill {fill:#04x}");
        }
    }
}

/// Every symbol must select some mask 0..7 and the format info must be
/// self-consistent. Also sanity-check that mask selection is actually
/// exercising more than one mask across a range of inputs.
#[test]
fn mask_selection_is_valid_and_varied() {
    let mut seen = [false; 8];
    for i in 0..64u32 {
        let payload: Vec<u8> = (0..(i as usize % 60 + 1))
            .map(|j| (j as u32 * 7 + i * 13) as u8)
            .collect();
        let mut m = Matrix::new();
        encode(&payload, &mut m).unwrap();
        let f1 = read_format(&m, &format_positions_copy1());
        let f2 = read_format(&m, &format_positions_copy2(m.side()));
        assert_eq!(f1, f2);
        let (ec, mask) = decode_format_exact(f1).expect("valid format codeword");
        assert_eq!(ec, 0);
        seen[mask as usize] = true;
    }
    let count = seen.iter().filter(|&&b| b).count();
    assert!(count >= 4, "expected several masks to be chosen, saw {count}");
}

/// Literal truth values evaluated off ISO/IEC 18004 table 10:
/// `(x, y, [mask 0 .. mask 7])`, with the table's `i` as the row (`y`) and
/// `j` as the column (`x`). Same constants the crate's own unit test pins
/// `mask_condition` against — asserted here for this file's independent
/// `mask_bit`, so encoder and decoder are each tied to the published table
/// rather than to each other.
const MASK_TABLE_10: [(usize, usize, [bool; 8]); 20] = [
    (0, 0, [true, true, true, true, true, true, true, true]),
    (0, 1, [false, false, true, false, true, true, true, false]),
    (1, 0, [false, true, false, false, true, true, true, false]),
    (1, 1, [true, false, false, false, true, false, true, false]),
    (2, 3, [false, false, false, false, false, true, true, false]),
    (3, 2, [false, true, true, false, true, true, true, false]),
    (2, 2, [true, true, false, false, false, false, false, false]),
    (3, 3, [true, false, true, true, true, false, false, true]),
    (4, 6, [true, true, false, false, true, true, true, true]),
    (6, 4, [true, true, true, false, true, true, true, true]),
    (5, 7, [true, false, false, true, true, false, false, true]),
    (7, 5, [true, false, false, true, true, false, false, true]),
    (6, 6, [true, true, true, true, false, true, true, true]),
    (9, 4, [false, true, true, false, false, true, true, false]),
    (4, 9, [false, false, false, false, false, true, true, false]),
    (11, 13, [true, false, false, true, false, false, false, true]),
    (13, 11, [true, false, false, true, false, false, false, true]),
    (8, 3, [false, false, false, false, false, true, true, false]),
    (3, 8, [false, true, true, false, false, true, true, false]),
    (12, 12, [true, true, true, true, true, true, true, true]),
];

#[test]
fn decoder_mask_bit_matches_published_table_10() {
    for &(x, y, expected) in MASK_TABLE_10.iter() {
        for (mask, &want) in expected.iter().enumerate() {
            assert_eq!(mask_bit(mask as u32, x, y), want, "mask {mask} at ({x},{y})");
        }
    }
    // Every pair of masks must differ somewhere in the sample, or the
    // assertion above would not detect a swap.
    for a in 0..8usize {
        for b in (a + 1)..8usize {
            assert!(
                MASK_TABLE_10.iter().any(|&(_, _, e)| e[a] != e[b]),
                "masks {a} and {b} are indistinguishable"
            );
        }
    }
}

/// The published format strings must be exactly what the BCH construction
/// produces, and the code must have minimum distance 7 (BCH(15,5)).
#[test]
fn published_format_table_is_consistent() {
    for (mask, want) in FORMAT_M.iter().enumerate() {
        assert_eq!(format!("{:015b}", format_codeword(0, mask as u32)), *want);
    }
    let all: Vec<u32> = (0..4)
        .flat_map(|ec| (0..8).map(move |m| format_codeword(ec, m)))
        .collect();
    let mut min = u32::MAX;
    for (i, &a) in all.iter().enumerate() {
        for &b in &all[i + 1..] {
            min = min.min((a ^ b).count_ones());
        }
    }
    assert_eq!(min, 7, "BCH(15,5) minimum distance");
}
