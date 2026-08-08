//! `seed-qr` — a self-contained QR Code encoder for air-gapped export
//! screens (account xpubs, output descriptors).
//!
//! Scope is deliberately minimal, which is what makes an allocation-free
//! `no_std` implementation tractable:
//!
//! * **Byte mode only** (ISO/IEC 18004 §8.4.4). No numeric/alphanumeric/
//!   kanji modes, no ECI, no structured append.
//! * **Error-correction level M only** (~15% recovery).
//! * **Versions 1..=13** — up to 69x69 modules, 331 payload bytes, which
//!   covers every descriptor and extended public key this project emits.
//! * **Data mask auto-selected** by the ISO/IEC 18004 §8.8.2 penalty score.
//!
//! # Non-goals / guarantees
//!
//! * `#![no_std]`, no `alloc`, **no dependencies**. All working state is
//!   fixed-size arrays sized for version 13; the caller owns the output
//!   [`Matrix`].
//! * No panic is reachable from [`encode`]: there is no `unwrap`, `expect`,
//!   `panic!`, slicing by range, or unchecked arithmetic on any path. Every
//!   buffer access goes through `get`/`get_mut` or a bounds-guarded helper,
//!   and every index is additionally bounded by construction.
//! * Deterministic: the same input always produces the same matrix.
//!
//! # Provenance
//!
//! This is an independent implementation written against the ISO/IEC 18004
//! specification; it follows the structure popularised by Nayuki's
//! public-domain `qrcodegen` (function-pattern drawing order, the
//! run-history finder-penalty formulation, the closed-form module count).
//! No third-party source file is vendored.
//!
//! # Example
//!
//! ```
//! let mut m = seed_qr::Matrix::new();
//! let version = seed_qr::encode(b"HELLO WORLD", &mut m).unwrap();
//! assert_eq!(version, 1);
//! assert_eq!(m.side(), 21);
//! assert!(m.get(0, 0)); // top-left finder pattern
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// `gf256` and `tables` are implementation detail plus test-support
// surface: they are `pub` so the acceptance vectors can cross-check the
// Reed-Solomon routines and rebuild version geometry independently, but
// they are not part of the supported API. The supported surface is
// [`encode`], [`Matrix`], [`QrError`] and [`max_payload_bytes`].
#[doc(hidden)]
pub mod gf256;
#[doc(hidden)]
pub mod tables;

use core::sync::atomic::{compiler_fence, fence, Ordering as AtomicOrdering};

use tables::{
    alignment_positions, block_lengths, char_count_bits, ecc_per_block, num_data_codewords,
    num_total_codewords, side_for, ECC_FORMAT_BITS_M, MAX_ALIGN_POSITIONS, MAX_BLOCKS,
    MAX_DATA_CODEWORDS, MAX_ECC_PER_BLOCK, MAX_TOTAL_CODEWORDS, MIN_VERSION, MODE_BYTE,
};

/// Largest byte-mode payload, in bytes, that the given version can hold at
/// EC level M. `max_payload_bytes(MAX_VERSION)` is 331 — the limit above
/// which [`encode`] returns [`QrError::TooLong`].
pub use tables::max_payload_bytes;

pub use tables::{MAX_SIDE, MAX_VERSION};

/// Bytes of bitmap backing a [`Matrix`], one bit per module.
const BITS_LEN: usize = (MAX_SIDE * MAX_SIDE + 7) / 8;

/// Penalty weight for runs of five or more same-coloured modules.
const PENALTY_N1: i32 = 3;
/// Penalty weight for 2x2 blocks of one colour.
const PENALTY_N2: i32 = 3;
/// Penalty weight for finder-lookalike 1:1:3:1:1 patterns.
const PENALTY_N3: i32 = 40;
/// Penalty weight per 5% deviation from an even dark/light balance.
const PENALTY_N4: i32 = 10;

/// Why a payload could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    /// The payload does not fit in a version-13 byte-mode EC-M symbol
    /// (the limit is 331 bytes).
    TooLong,
}

/// A rendered QR symbol: a square bitmap of `side` x `side` modules.
///
/// The backing storage is always sized for [`MAX_SIDE`]; `side` records how
/// much of it the last [`encode`] used. `true` means a dark module.
#[derive(Clone)]
pub struct Matrix {
    /// Side length in modules of the symbol currently held, or 0 if empty.
    /// Private so it can never drift out of step with [`Matrix::bits`]: only
    /// [`encode`]/[`Matrix::clear`] write it, and readers go through
    /// [`Matrix::side`].
    side: usize,
    bits: [u8; BITS_LEN],
}

impl Default for Matrix {
    fn default() -> Self {
        Self::new()
    }
}

impl Matrix {
    /// An empty matrix (`side == 0`, all modules light).
    pub const fn new() -> Self {
        Matrix {
            side: 0,
            bits: [0u8; BITS_LEN],
        }
    }

    /// Side length in modules of the symbol currently held, or 0 if empty.
    #[must_use]
    pub fn side(&self) -> usize {
        self.side
    }

    /// Is the module at `(x, y)` dark?
    ///
    /// Coordinates outside the current symbol read as light (the quiet
    /// zone), so callers may over-scan without bounds checks of their own.
    pub fn get(&self, x: usize, y: usize) -> bool {
        if x >= self.side || y >= self.side {
            return false;
        }
        bit_get(&self.bits, x, y)
    }

    fn set(&mut self, x: usize, y: usize, dark: bool) {
        bit_set(&mut self.bits, x, y, dark);
    }

    /// Zeroize the whole bitmap and reset `side` to 0, so this matrix
    /// renders nothing and retains no trace of the symbol it held.
    ///
    /// # Why this exists
    ///
    /// A QR symbol here always encodes a *public* value — an account
    /// extended public key or an output descriptor, never a secret (see
    /// this crate's only consumer, `seed_flow::screens::export`). Public
    /// is not the same as harmless: an account key links every address in
    /// that account forever, so its display buffers are wiped when the
    /// screen showing them is left, under the same policy address buffers
    /// follow. Wiping the bitmap here is therefore privacy-hygiene
    /// defense-in-depth over public payload copies — not secret-scrubbing.
    /// Setting `side = 0` alone would leave the bitmap bytes intact in
    /// memory, and assigning a fresh `Matrix` over an old one is an
    /// ordinary store the optimizer is free to elide, so the wipe is
    /// performed here explicitly and forced to actually happen.
    ///
    /// # Discipline, and one documented difference from `scrub_slice`
    ///
    /// This mirrors `seed_core::arena::scrub_slice`'s shape (SPEC §20.3):
    /// zero the region, force the stores to be observable, and fence at
    /// both compile time and run time.
    ///
    /// It differs in exactly one respect, deliberately. `scrub_slice`
    /// zeroes through `core::ptr::write_volatile`, which requires
    /// `unsafe`, and this crate is `#![forbid(unsafe_code)]` — a property
    /// worth keeping on a from-scratch encoder that does a great deal of
    /// index arithmetic. Instead the zeroing stores are made non-elidable
    /// by passing the buffer through [`core::hint::black_box`], which the
    /// optimizer must treat as having escaped to opaque code that may
    /// read it; the stores therefore cannot be proven dead, which is
    /// exactly the property `write_volatile` is relied on for in
    /// `seed-core`. The `black_box`-folded read-back loop below is part of
    /// that anti-elision mechanism — it makes the optimizer assume the
    /// just-written bytes are observed, which is what forces the wipe to
    /// occur; it does not runtime-*verify* that the bytes are zero.
    /// [`Self::bitmap_is_zero`] lets callers and tests assert the bytes
    /// directly instead of inferring them from `side`.
    ///
    /// This is not a proof of erasure: like the primitive SPEC §20.3
    /// mandates, it observes only *this* address space's view of memory.
    pub fn clear(&mut self) {
        for byte in self.bits.iter_mut() {
            *byte = 0;
        }
        self.side = 0;

        // Force the stores above to be observable: `black_box` hands a
        // pointer to the buffer to code the optimizer knows nothing
        // about, so it cannot conclude the writes are dead.
        let _ = core::hint::black_box(&mut self.bits);

        // Compiler fence, then architecture memory fence: no reordering
        // past this point at compile time or at run time.
        compiler_fence(AtomicOrdering::SeqCst);
        fence(AtomicOrdering::SeqCst);

        // Read every byte back and fold the result through `black_box`.
        // This is anti-elision, not verification: forcing the optimizer to
        // treat the just-cleared bytes as observed is what keeps the wipe
        // above from being proven dead. The folded value is intentionally
        // discarded (there is no assert — this crate stays panic-free).
        let mut observed = 0u8;
        for &byte in self.bits.iter() {
            observed |= byte;
        }
        let _ = core::hint::black_box(observed);
    }

    /// Is every byte of the backing bitmap zero?
    ///
    /// Exposed so a caller that wipes a matrix can *assert* the wipe
    /// happened rather than infer it from `side == 0` — the bitmap is
    /// private, and a scrub nobody can check is a scrub nobody should
    /// trust. Reads the whole backing store, not just the current
    /// `side x side` window, so a stale symbol left outside a smaller
    /// window is still caught.
    #[must_use]
    pub fn bitmap_is_zero(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }
}

/// Read a module from a raw bitmap, clamped to the backing store.
fn bit_get(bits: &[u8; BITS_LEN], x: usize, y: usize) -> bool {
    if x >= MAX_SIDE || y >= MAX_SIDE {
        return false;
    }
    let idx = y * MAX_SIDE + x;
    match bits.get(idx >> 3) {
        Some(b) => (b >> (idx & 7)) & 1 != 0,
        None => false,
    }
}

/// Write a module to a raw bitmap; out-of-range writes are dropped.
fn bit_set(bits: &mut [u8; BITS_LEN], x: usize, y: usize, dark: bool) {
    if x >= MAX_SIDE || y >= MAX_SIDE {
        return;
    }
    let idx = y * MAX_SIDE + x;
    if let Some(b) = bits.get_mut(idx >> 3) {
        let mask = 1u8 << (idx & 7);
        if dark {
            *b |= mask;
        } else {
            *b &= !mask;
        }
    }
}

/// Encode `data` as a byte-mode, EC-level-M QR symbol into `out`.
///
/// Picks the smallest version 1..=13 that fits, generates Reed-Solomon
/// parity, interleaves the blocks, draws the symbol and selects the data
/// mask with the lowest penalty score. Returns the chosen version;
/// `out.side` is then `17 + 4 * version`.
///
/// # Errors
///
/// [`QrError::TooLong`] if `data` exceeds 331 bytes.
pub fn encode(data: &[u8], out: &mut Matrix) -> Result<u8, QrError> {
    let version = pick_version(data.len())?;

    // 1. Payload -> data codewords (mode, count, bytes, terminator, pad).
    let mut data_cw = [0u8; MAX_DATA_CODEWORDS];
    build_data_codewords(data, version, &mut data_cw);

    // 2. Data codewords -> Reed-Solomon blocks -> interleaved codewords.
    let mut all_cw = [0u8; MAX_TOTAL_CODEWORDS];
    add_ecc_and_interleave(&data_cw, version, &mut all_cw);

    // 3. Draw the symbol.
    out.side = side_for(version);
    out.bits = [0u8; BITS_LEN];
    let mut func = [0u8; BITS_LEN];
    draw_function_patterns(version, out, &mut func);
    draw_codewords(&all_cw, num_total_codewords(version), out, &func);

    // 4. Choose the mask with the lowest penalty. XOR is an involution, so
    //    each trial is undone by reapplying it.
    let mut best_mask: u8 = 0;
    let mut best_penalty: i32 = i32::MAX;
    let mut mask: u8 = 0;
    while mask < 8 {
        apply_mask(out, &func, mask);
        draw_format_bits(mask, out, &mut func);
        let p = penalty_score(out);
        if p < best_penalty {
            best_penalty = p;
            best_mask = mask;
        }
        apply_mask(out, &func, mask);
        mask += 1;
    }
    apply_mask(out, &func, best_mask);
    draw_format_bits(best_mask, out, &mut func);

    Ok(version)
}

/// Smallest version whose byte-mode EC-M capacity holds `len` bytes.
fn pick_version(len: usize) -> Result<u8, QrError> {
    let mut version = MIN_VERSION;
    while version <= MAX_VERSION {
        if len <= max_payload_bytes(version) {
            return Ok(version);
        }
        version += 1;
    }
    Err(QrError::TooLong)
}

// ---------------------------------------------------------------------------
// Bit-stream assembly
// ---------------------------------------------------------------------------

/// Append the low `count` bits of `value` (most significant first) to the
/// bit stream held in `buf`, advancing `bit_len`.
fn push_bits(buf: &mut [u8; MAX_DATA_CODEWORDS], bit_len: &mut usize, value: u32, count: usize) {
    let mut i = count;
    while i > 0 {
        i -= 1;
        let bit = if i < 32 { (value >> i) & 1 != 0 } else { false };
        let byte_idx = *bit_len >> 3;
        if bit {
            if let Some(b) = buf.get_mut(byte_idx) {
                *b |= 0x80u8 >> (*bit_len & 7);
            }
        }
        *bit_len += 1;
    }
}

/// Build the data-codeword sequence for `data` at `version`.
///
/// Caller must have established `data.len() <= max_payload_bytes(version)`.
fn build_data_codewords(data: &[u8], version: u8, buf: &mut [u8; MAX_DATA_CODEWORDS]) {
    *buf = [0u8; MAX_DATA_CODEWORDS];
    let capacity_bits = num_data_codewords(version) * 8;
    let mut bit_len = 0usize;

    push_bits(buf, &mut bit_len, MODE_BYTE, 4);
    push_bits(buf, &mut bit_len, data.len() as u32, char_count_bits(version));
    for &b in data.iter() {
        push_bits(buf, &mut bit_len, b as u32, 8);
    }

    // Terminator: up to four zero bits, truncated at capacity.
    let remaining = capacity_bits.saturating_sub(bit_len);
    let term = if remaining < 4 { remaining } else { 4 };
    push_bits(buf, &mut bit_len, 0, term);

    // Pad to a codeword boundary, then alternate 0xEC / 0x11 filler.
    let to_boundary = (8 - (bit_len & 7)) & 7;
    push_bits(buf, &mut bit_len, 0, to_boundary);

    let mut pad: u32 = 0xEC;
    while bit_len < capacity_bits {
        push_bits(buf, &mut bit_len, pad, 8);
        pad ^= 0xEC ^ 0x11;
    }
}

// ---------------------------------------------------------------------------
// Error correction
// ---------------------------------------------------------------------------

/// Split the data codewords into blocks, append Reed-Solomon parity to
/// each, and interleave the result into the final codeword sequence.
fn add_ecc_and_interleave(
    data_cw: &[u8; MAX_DATA_CODEWORDS],
    version: u8,
    out: &mut [u8; MAX_TOTAL_CODEWORDS],
) {
    *out = [0u8; MAX_TOTAL_CODEWORDS];
    let ecc_len = ecc_per_block(version);
    if ecc_len == 0 || ecc_len > MAX_ECC_PER_BLOCK {
        return;
    }

    // Blocks are as equal as possible with the shorter ones first. This is
    // the single shared derivation, pinned against the published
    // group-1/group-2 table by `tables::tests`.
    let mut lens = [0usize; MAX_BLOCKS];
    let blocks = block_lengths(version, &mut lens);
    if blocks == 0 {
        return;
    }
    let mut max_len = 0usize;
    let mut b = 0usize;
    while b < blocks {
        if let Some(l) = lens.get(b) {
            if *l > max_len {
                max_len = *l;
            }
        }
        b += 1;
    }

    let mut gen_poly = [0u8; MAX_ECC_PER_BLOCK];
    gf256::generator(ecc_len, &mut gen_poly);

    let mut ecc = [[0u8; MAX_ECC_PER_BLOCK]; MAX_BLOCKS];
    let mut starts = [0usize; MAX_BLOCKS];

    let mut offset = 0usize;
    let mut b = 0usize;
    while b < blocks {
        let len = match lens.get(b) {
            Some(v) => *v,
            None => 0,
        };
        if let Some(s) = starts.get_mut(b) {
            *s = offset;
        }
        if let Some(dst) = ecc.get_mut(b) {
            gf256::remainder(data_cw, offset, len, &gen_poly, ecc_len, dst);
        }
        offset += len;
        b += 1;
    }

    let mut o = 0usize;

    // Interleave data codewords column-wise across blocks. Short blocks
    // simply have no entry at the final index.
    let mut i = 0usize;
    while i < max_len {
        let mut b = 0usize;
        while b < blocks {
            let len = match lens.get(b) {
                Some(v) => *v,
                None => 0,
            };
            if i < len {
                let start = match starts.get(b) {
                    Some(v) => *v,
                    None => 0,
                };
                let byte = match data_cw.get(start + i) {
                    Some(v) => *v,
                    None => 0,
                };
                if let Some(slot) = out.get_mut(o) {
                    *slot = byte;
                }
                o += 1;
            }
            b += 1;
        }
        i += 1;
    }

    // Then the parity codewords, likewise column-wise.
    let mut i = 0usize;
    while i < ecc_len {
        let mut b = 0usize;
        while b < blocks {
            let byte = match ecc.get(b).and_then(|blk| blk.get(i)) {
                Some(v) => *v,
                None => 0,
            };
            if let Some(slot) = out.get_mut(o) {
                *slot = byte;
            }
            o += 1;
            b += 1;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Function patterns
// ---------------------------------------------------------------------------

/// Set a module and mark it as a function module (not maskable, not
/// available to codeword placement).
fn set_function(out: &mut Matrix, func: &mut [u8; BITS_LEN], x: usize, y: usize, dark: bool) {
    out.set(x, y, dark);
    bit_set(func, x, y, true);
}

/// Draw finders, separators, timing, alignment, and reserve the format /
/// version information areas.
fn draw_function_patterns(version: u8, out: &mut Matrix, func: &mut [u8; BITS_LEN]) {
    let size = side_for(version);

    // Timing patterns along row 6 and column 6.
    let mut i = 0usize;
    while i < size {
        let dark = i % 2 == 0;
        set_function(out, func, 6, i, dark);
        set_function(out, func, i, 6, dark);
        i += 1;
    }

    // Three finder patterns (with separators), drawn from their centres.
    // Drawn after timing so the overlap at the corners is finder-owned.
    draw_finder(out, func, 3, 3, size);
    draw_finder(out, func, size - 4, 3, size);
    draw_finder(out, func, 3, size - 4, size);

    // Alignment patterns, skipping the three that would collide with the
    // finder patterns.
    let mut pos = [0usize; MAX_ALIGN_POSITIONS];
    let n = alignment_positions(version, &mut pos);
    let mut j = 0usize;
    while j < n {
        let mut k = 0usize;
        while k < n {
            let corner = (j == 0 && k == 0) || (j == 0 && k == n - 1) || (j == n - 1 && k == 0);
            if !corner {
                let cx = match pos.get(j) {
                    Some(v) => *v,
                    None => 0,
                };
                let cy = match pos.get(k) {
                    Some(v) => *v,
                    None => 0,
                };
                draw_alignment(out, func, cx, cy, size);
            }
            k += 1;
        }
        j += 1;
    }

    // Reserve the format area (rewritten with the real mask later) and
    // write the version information for versions 7 and up.
    draw_format_bits(0, out, func);
    draw_version_bits(version, out, func);
}

/// Draw a 7x7 finder plus its 1-module separator, centred at `(cx, cy)`.
fn draw_finder(out: &mut Matrix, func: &mut [u8; BITS_LEN], cx: usize, cy: usize, size: usize) {
    let mut dy: isize = -4;
    while dy <= 4 {
        let mut dx: isize = -4;
        while dx <= 4 {
            let adx = dx.unsigned_abs();
            let ady = dy.unsigned_abs();
            let dist = if adx > ady { adx } else { ady };
            let x = cx as isize + dx;
            let y = cy as isize + dy;
            if x >= 0 && y >= 0 && (x as usize) < size && (y as usize) < size {
                // Chebyshev rings: 0,1 dark; 2 light; 3 dark; 4 separator.
                set_function(out, func, x as usize, y as usize, dist != 2 && dist != 4);
            }
            dx += 1;
        }
        dy += 1;
    }
}

/// Draw a 5x5 alignment pattern centred at `(cx, cy)`.
fn draw_alignment(out: &mut Matrix, func: &mut [u8; BITS_LEN], cx: usize, cy: usize, size: usize) {
    let mut dy: isize = -2;
    while dy <= 2 {
        let mut dx: isize = -2;
        while dx <= 2 {
            let adx = dx.unsigned_abs();
            let ady = dy.unsigned_abs();
            let dist = if adx > ady { adx } else { ady };
            let x = cx as isize + dx;
            let y = cy as isize + dy;
            // Centres are always within `2..=size - 3`, so this guard never
            // fires; it mirrors `draw_finder`'s so neither routine can ever
            // write outside the symbol.
            if x >= 0 && y >= 0 && (x as usize) < size && (y as usize) < size {
                set_function(out, func, x as usize, y as usize, dist != 1);
            }
            dx += 1;
        }
        dy += 1;
    }
}

/// Extract bit `i` of `value`.
fn get_bit(value: u32, i: usize) -> bool {
    if i >= 32 {
        return false;
    }
    (value >> i) & 1 != 0
}

/// Write the 15-bit format information (EC level M + `mask`), both copies,
/// plus the always-dark module (ISO/IEC 18004 §8.9).
fn draw_format_bits(mask: u8, out: &mut Matrix, func: &mut [u8; BITS_LEN]) {
    let size = out.side;
    if size < 21 {
        return;
    }
    let data = (ECC_FORMAT_BITS_M << 3) | (mask & 7) as u32;

    // BCH(15,5) with generator 0x537.
    let mut rem = data;
    let mut i = 0;
    while i < 10 {
        rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
        i += 1;
    }
    let bits = ((data << 10) | (rem & 0x3FF)) ^ 0x5412;

    // Copy 1: down the left of the top-left finder, then leftwards below it.
    let mut i = 0usize;
    while i <= 5 {
        set_function(out, func, 8, i, get_bit(bits, i));
        i += 1;
    }
    set_function(out, func, 8, 7, get_bit(bits, 6));
    set_function(out, func, 8, 8, get_bit(bits, 7));
    set_function(out, func, 7, 8, get_bit(bits, 8));
    let mut i = 9usize;
    while i < 15 {
        set_function(out, func, 14 - i, 8, get_bit(bits, i));
        i += 1;
    }

    // Copy 2: right of the top-right finder, then below the bottom-left.
    let mut i = 0usize;
    while i < 8 {
        set_function(out, func, size - 1 - i, 8, get_bit(bits, i));
        i += 1;
    }
    let mut i = 8usize;
    while i < 15 {
        set_function(out, func, 8, size - 15 + i, get_bit(bits, i));
        i += 1;
    }

    // The dark module at (8, 4 * version + 9).
    set_function(out, func, 8, size - 8, true);
}

/// Write the 18-bit version information blocks (versions 7 and up only).
fn draw_version_bits(version: u8, out: &mut Matrix, func: &mut [u8; BITS_LEN]) {
    if version < 7 {
        return;
    }
    let size = out.side;
    if size < 45 {
        return;
    }

    // BCH(18,6) with generator 0x1F25.
    let mut rem = version as u32;
    let mut i = 0;
    while i < 12 {
        rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1F25);
        i += 1;
    }
    let bits = ((version as u32) << 12) | (rem & 0xFFF);

    let mut i = 0usize;
    while i < 18 {
        let bit = get_bit(bits, i);
        let a = size - 11 + i % 3;
        let b = i / 3;
        set_function(out, func, a, b, bit);
        set_function(out, func, b, a, bit);
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Codeword placement, masking, penalty
// ---------------------------------------------------------------------------

/// Place `len` codewords into the symbol along the two-module-wide
/// upward/downward zigzag, skipping function modules.
fn draw_codewords(all_cw: &[u8; MAX_TOTAL_CODEWORDS], len: usize, out: &mut Matrix, func: &[u8; BITS_LEN]) {
    let size = out.side as isize;
    let total_bits = len * 8;
    let mut i = 0usize; // bit index into the codeword stream

    let mut right: isize = size - 1;
    while right >= 1 {
        // Column 6 is the vertical timing pattern; the pair shifts left.
        if right == 6 {
            right = 5;
        }
        let mut vert: isize = 0;
        while vert < size {
            let mut j: isize = 0;
            while j < 2 {
                let x = right - j;
                // Column pairs alternate scan direction.
                let upward = (right + 1) & 2 == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if x >= 0 && y >= 0 {
                    let xu = x as usize;
                    let yu = y as usize;
                    if !bit_get(func, xu, yu) && i < total_bits {
                        let byte = match all_cw.get(i >> 3) {
                            Some(v) => *v,
                            None => 0,
                        };
                        let bit = (byte >> (7 - (i & 7))) & 1 != 0;
                        out.set(xu, yu, bit);
                        i += 1;
                    }
                }
                j += 1;
            }
            vert += 1;
        }
        right -= 2;
    }
}

/// Is the mask condition true at `(x, y)` for mask pattern `mask`?
fn mask_condition(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3) % 2 == 0,
        _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
    }
}

/// XOR the mask pattern over every non-function module. Involutive.
fn apply_mask(out: &mut Matrix, func: &[u8; BITS_LEN], mask: u8) {
    let size = out.side;
    let mut y = 0usize;
    while y < size {
        let mut x = 0usize;
        while x < size {
            if !bit_get(func, x, y) && mask_condition(mask, x, y) {
                let cur = out.get(x, y);
                out.set(x, y, !cur);
            }
            x += 1;
        }
        y += 1;
    }
}

/// Shift a completed run length into the 7-entry run history, prepending
/// the implicit light quiet-zone border ahead of the first run.
fn finder_history_push(history: &mut [i32; 7], run_len: i32, size: i32) {
    let head = match history.get(0) {
        Some(v) => *v,
        None => 0,
    };
    let value = if head == 0 { run_len + size } else { run_len };
    let mut i = history.len();
    while i > 1 {
        i -= 1;
        let prev = match history.get(i - 1) {
            Some(v) => *v,
            None => 0,
        };
        if let Some(slot) = history.get_mut(i) {
            *slot = prev;
        }
    }
    if let Some(slot) = history.get_mut(0) {
        *slot = value;
    }
}

/// Count 1:1:3:1:1 finder-lookalike patterns ending at the current run
/// history position (0, 1 or 2 of them).
fn finder_history_count(history: &[i32; 7]) -> i32 {
    let at = |i: usize| -> i32 {
        match history.get(i) {
            Some(v) => *v,
            None => 0,
        }
    };
    let n = at(1);
    let core = n > 0 && at(2) == n && at(3) == n * 3 && at(4) == n && at(5) == n;
    (core && at(0) >= n * 4 && at(6) >= n) as i32 + (core && at(6) >= n * 4 && at(0) >= n) as i32
}

/// Terminate the current run (adding the trailing quiet-zone border) and
/// count any finder-lookalikes it completes.
fn finder_history_terminate(
    history: &mut [i32; 7],
    run_color: bool,
    run_len: i32,
    size: i32,
) -> i32 {
    let mut len = run_len;
    if run_color {
        finder_history_push(history, len, size);
        len = 0;
    }
    finder_history_push(history, len + size, size);
    finder_history_count(history)
}

/// ISO/IEC 18004 §8.8.2 mask penalty score: lower is better.
fn penalty_score(out: &Matrix) -> i32 {
    let size = out.side;
    let sizei = size as i32;
    let mut result: i32 = 0;

    // Rules 1 and 3, row-wise then column-wise.
    let mut y = 0usize;
    while y < size {
        let mut history = [0i32; 7];
        let mut color = false;
        let mut run_len: i32 = 0;
        let mut x = 0usize;
        while x < size {
            let c = out.get(x, y);
            if c == color {
                run_len += 1;
                if run_len == 5 {
                    result += PENALTY_N1;
                } else if run_len > 5 {
                    result += 1;
                }
            } else {
                finder_history_push(&mut history, run_len, sizei);
                if !color {
                    result += finder_history_count(&history) * PENALTY_N3;
                }
                color = c;
                run_len = 1;
            }
            x += 1;
        }
        result += finder_history_terminate(&mut history, color, run_len, sizei) * PENALTY_N3;
        y += 1;
    }
    let mut x = 0usize;
    while x < size {
        let mut history = [0i32; 7];
        let mut color = false;
        let mut run_len: i32 = 0;
        let mut y = 0usize;
        while y < size {
            let c = out.get(x, y);
            if c == color {
                run_len += 1;
                if run_len == 5 {
                    result += PENALTY_N1;
                } else if run_len > 5 {
                    result += 1;
                }
            } else {
                finder_history_push(&mut history, run_len, sizei);
                if !color {
                    result += finder_history_count(&history) * PENALTY_N3;
                }
                color = c;
                run_len = 1;
            }
            y += 1;
        }
        result += finder_history_terminate(&mut history, color, run_len, sizei) * PENALTY_N3;
        x += 1;
    }

    // Rule 2: 2x2 blocks of a single colour.
    let mut y = 1usize;
    while y < size {
        let mut x = 1usize;
        while x < size {
            let c = out.get(x, y);
            if c == out.get(x - 1, y) && c == out.get(x, y - 1) && c == out.get(x - 1, y - 1) {
                result += PENALTY_N2;
            }
            x += 1;
        }
        y += 1;
    }

    // Rule 4: deviation of the dark-module proportion from 50%.
    let mut dark: i32 = 0;
    let mut y = 0usize;
    while y < size {
        let mut x = 0usize;
        while x < size {
            if out.get(x, y) {
                dark += 1;
            }
            x += 1;
        }
        y += 1;
    }
    let total = sizei * sizei;
    if total > 0 {
        // Smallest k >= 0 with (45 - 5k)% <= dark/total <= (55 + 5k)%.
        let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
        result += k * PENALTY_N4;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_boundary() {
        let mut m = Matrix::new();
        let big = [b'x'; 331];
        assert_eq!(encode(&big, &mut m), Ok(13));
        let too_big = [b'x'; 332];
        assert_eq!(encode(&too_big, &mut m), Err(QrError::TooLong));
    }

    #[test]
    fn empty_payload_encodes() {
        let mut m = Matrix::new();
        assert_eq!(encode(b"", &mut m), Ok(1));
        assert_eq!(m.side(), 21);
    }

    #[test]
    fn reads_outside_the_symbol_are_light() {
        let mut m = Matrix::new();
        let _ = encode(b"hi", &mut m);
        assert!(!m.get(m.side(), 0));
        assert!(!m.get(0, m.side()));
        assert!(!m.get(usize::MAX, usize::MAX));
    }

    /// Literal truth values evaluated off ISO/IEC 18004 table 10, one row
    /// per sample point: `(x, y, [mask 0 .. mask 7])`, where the table's
    /// `i` is the row (`y`) and `j` is the column (`x`).
    ///
    /// Restating the eight formulas in the test would be a tautology, so
    /// these are constants instead. The points are chosen so that **every
    /// one of the 28 mask pairs differs on at least one of them**
    /// (asserted below), which means no formula can be swapped for
    /// another without a failure here.
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
    fn mask_conditions_match_published_table_10() {
        for &(x, y, expected) in MASK_TABLE_10.iter() {
            for (mask, &want) in expected.iter().enumerate() {
                assert_eq!(
                    mask_condition(mask as u8, x, y),
                    want,
                    "mask {mask} at (x={x}, y={y})"
                );
            }
        }
    }

    /// Guards the test above: if the sample points ever stopped
    /// discriminating between two masks, a swap could slip through.
    #[test]
    fn mask_sample_points_discriminate_every_pair() {
        for a in 0..8usize {
            for b in (a + 1)..8usize {
                let differs = MASK_TABLE_10
                    .iter()
                    .any(|&(_, _, e)| e[a] != e[b]);
                assert!(differs, "masks {a} and {b} are indistinguishable");
            }
        }
    }

    /// Mask 8 and above is not a thing; the fallback arm must be mask 7.
    #[test]
    fn mask_condition_falls_back_to_mask_7() {
        for &(x, y, expected) in MASK_TABLE_10.iter() {
            assert_eq!(mask_condition(7, x, y), expected[7]);
            assert_eq!(mask_condition(200, x, y), expected[7]);
        }
    }

    // -- Matrix::clear ---------------------------------------------------

    #[test]
    fn clear_zeroizes_every_bitmap_byte_not_just_the_side() {
        let mut m = Matrix::new();
        // A payload large enough to set bits across most of the backing
        // store, so "the bytes really were wiped" is a meaningful claim.
        let payload = [b'A'; 300];
        encode(&payload, &mut m).unwrap();
        assert!(m.side() > 0);
        assert!(!m.bitmap_is_zero(), "sanity: the encoded symbol sets bits");

        m.clear();

        assert_eq!(m.side(), 0, "a cleared matrix must render nothing");
        assert!(m.bitmap_is_zero(), "clear() must zeroize the whole backing bitmap");
        assert!(m.bits.iter().all(|&b| b == 0), "checked directly, not only via the accessor");
        // Every module reads light, at every coordinate, including
        // outside the former symbol.
        for y in 0..MAX_SIDE {
            for x in 0..MAX_SIDE {
                assert!(!m.get(x, y), "module ({x},{y}) survived clear()");
            }
        }
    }

    #[test]
    fn clear_is_idempotent_and_matches_a_fresh_matrix() {
        let mut m = Matrix::new();
        encode(b"a public descriptor would go here", &mut m).unwrap();
        m.clear();
        let fresh = Matrix::new();
        assert_eq!(m.side(), fresh.side());
        assert_eq!(m.bits, fresh.bits);

        m.clear();
        assert!(m.bitmap_is_zero());
        assert_eq!(m.side(), 0);
    }

    #[test]
    fn a_cleared_matrix_can_be_re_encoded() {
        let mut m = Matrix::new();
        encode(b"first", &mut m).unwrap();
        m.clear();
        encode(b"second", &mut m).unwrap();

        let mut expected = Matrix::new();
        encode(b"second", &mut expected).unwrap();
        assert_eq!(m.side(), expected.side());
        assert_eq!(m.bits, expected.bits, "a cleared matrix must not leave residue behind");
    }

    #[test]
    fn bitmap_is_zero_reports_a_fresh_and_an_encoded_matrix_correctly() {
        let m = Matrix::new();
        assert!(m.bitmap_is_zero());
        let mut m = Matrix::new();
        encode(b"x", &mut m).unwrap();
        assert!(!m.bitmap_is_zero());
    }
}
