//! GF(2^8) arithmetic and Reed-Solomon parity generation for QR Codes.
//!
//! Field: GF(256) modulo the QR primitive polynomial
//! `x^8 + x^4 + x^3 + x^2 + 1` (0x11D), with 0x02 as the generator
//! element (ISO/IEC 18004 §8.5.2).
//!
//! No lookup tables, no allocation, no panics: every routine is a fixed
//! loop over `const`-bounded arrays, indexed through `get`/`get_mut`.

use crate::tables::MAX_ECC_PER_BLOCK;

/// Multiply two GF(256) elements.
///
/// Bit-by-bit "Russian peasant" multiplication with reduction folded in.
/// Total: defined for all inputs, no branches on data, no indexing.
pub const fn mul(x: u8, y: u8) -> u8 {
    let mut z: u8 = 0;
    let mut i: u32 = 8;
    while i > 0 {
        i -= 1;
        // Double `z` in the field: shift, and reduce by 0x11D when the
        // shifted-out bit was set. `z << 1` truncates (no overflow trap),
        // and `(z >> 7) & 1` is 0 or 1 so the product fits in a u8.
        z = (z << 1) ^ (((z >> 7) & 1) * 0x1D);
        // Add `x` when bit `i` of `y` is set.
        z ^= ((y >> i) & 1) * x;
    }
    z
}

/// Compute the Reed-Solomon generator polynomial of the given degree,
/// i.e. the product of `(x - 2^i)` for `i` in `0..degree`.
///
/// Coefficients are stored in `out[0..degree]` from the highest non-leading
/// term down to the constant term; the leading coefficient (always 1) is
/// omitted, matching the layout [`remainder`] expects. A degree outside
/// `1..=MAX_ECC_PER_BLOCK` leaves `out` all-zero.
pub fn generator(degree: usize, out: &mut [u8; MAX_ECC_PER_BLOCK]) {
    *out = [0u8; MAX_ECC_PER_BLOCK];
    if degree == 0 || degree > MAX_ECC_PER_BLOCK {
        return;
    }
    // Start from the polynomial "1" (constant term in the last slot).
    if let Some(slot) = out.get_mut(degree - 1) {
        *slot = 1;
    }
    let mut root: u8 = 1;
    let mut step = 0usize;
    while step < degree {
        // Multiply the current polynomial by (x - root), in place.
        let mut j = 0usize;
        while j < degree {
            let cur = match out.get(j) {
                Some(v) => *v,
                None => 0,
            };
            let next = if j + 1 < degree {
                match out.get(j + 1) {
                    Some(v) => *v,
                    None => 0,
                }
            } else {
                0
            };
            let v = mul(cur, root) ^ next;
            if let Some(slot) = out.get_mut(j) {
                *slot = v;
            }
            j += 1;
        }
        root = mul(root, 0x02);
        step += 1;
    }
}

/// Compute the Reed-Solomon parity codewords for `data[start..start+len]`.
///
/// This is polynomial division of the message (shifted up by `degree`) by
/// the generator polynomial; the remainder is written to `out[0..degree]`.
/// Out-of-range indices are skipped rather than panicking.
pub fn remainder(
    data: &[u8],
    start: usize,
    len: usize,
    gen_poly: &[u8; MAX_ECC_PER_BLOCK],
    degree: usize,
    out: &mut [u8; MAX_ECC_PER_BLOCK],
) {
    *out = [0u8; MAX_ECC_PER_BLOCK];
    if degree == 0 || degree > MAX_ECC_PER_BLOCK {
        return;
    }
    let mut k = 0usize;
    while k < len {
        let b = match data.get(start + k) {
            Some(v) => *v,
            None => 0,
        };
        let head = match out.get(0) {
            Some(v) => *v,
            None => 0,
        };
        let factor = b ^ head;
        // Shift the remainder register left by one coefficient.
        let mut i = 0usize;
        while i + 1 < degree {
            let v = match out.get(i + 1) {
                Some(v) => *v,
                None => 0,
            };
            if let Some(slot) = out.get_mut(i) {
                *slot = v;
            }
            i += 1;
        }
        if let Some(slot) = out.get_mut(degree - 1) {
            *slot = 0;
        }
        // Subtract factor * generator (subtraction is XOR in GF(2^8)).
        let mut i = 0usize;
        while i < degree {
            let g = match gen_poly.get(i) {
                Some(v) => *v,
                None => 0,
            };
            let cur = match out.get(i) {
                Some(v) => *v,
                None => 0,
            };
            if let Some(slot) = out.get_mut(i) {
                *slot = cur ^ mul(g, factor);
            }
            i += 1;
        }
        k += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplicative_identity_and_zero() {
        for x in 0..=255u8 {
            assert_eq!(mul(x, 1), x);
            assert_eq!(mul(1, x), x);
            assert_eq!(mul(x, 0), 0);
            assert_eq!(mul(0, x), 0);
        }
    }

    #[test]
    fn multiplication_is_commutative_and_associative() {
        // Sampled rather than exhaustive over all 2^24 triples.
        for x in (0..=255u8).step_by(7) {
            for y in (0..=255u8).step_by(11) {
                assert_eq!(mul(x, y), mul(y, x));
                for z in (0..=255u8).step_by(29) {
                    assert_eq!(mul(mul(x, y), z), mul(x, mul(y, z)));
                }
            }
        }
    }

    /// 0x02 generates the whole multiplicative group: its powers must
    /// cycle with period exactly 255.
    #[test]
    fn two_is_a_primitive_element() {
        let mut seen = [false; 256];
        let mut v: u8 = 1;
        for i in 0..255 {
            assert!(!seen[v as usize], "repeat at power {i}");
            seen[v as usize] = true;
            v = mul(v, 0x02);
        }
        assert_eq!(v, 1, "period must be 255");
        assert!(!seen[0]);
    }

    /// Known values of the reduction polynomial 0x11D.
    #[test]
    fn known_products() {
        assert_eq!(mul(0x80, 0x02), 0x1D); // x^7 * x = x^8 = x^4+x^3+x^2+1
        assert_eq!(mul(0x02, 0x02), 0x04);
        assert_eq!(mul(0x40, 0x04), 0x1D); // x^6 * x^2 = x^8
        assert_eq!(mul(0x81, 0x02), 0x1F); // (x^7+1)*x = x^8 + x = 0x1D^0x02
    }

    /// Every nonzero element must have exactly one multiplicative inverse
    /// (a field, not merely a ring).
    #[test]
    fn every_nonzero_element_is_invertible() {
        for x in 1..=255u8 {
            let mut inverses = 0;
            for y in 1..=255u8 {
                if mul(x, y) == 1 {
                    inverses += 1;
                }
            }
            assert_eq!(inverses, 1, "element {x:#04x}");
        }
    }

    /// The generator polynomial's roots must be 2^0..2^(degree-1).
    #[test]
    fn generator_roots_vanish() {
        for degree in 1..=MAX_ECC_PER_BLOCK {
            let mut g = [0u8; MAX_ECC_PER_BLOCK];
            generator(degree, &mut g);
            let mut root: u8 = 1;
            for i in 0..degree {
                // Evaluate the monic polynomial (leading 1 then g[0..degree]).
                let mut acc: u8 = 1;
                for j in 0..degree {
                    acc = mul(acc, root) ^ g[j];
                }
                assert_eq!(acc, 0, "degree {degree} root 2^{i}");
                root = mul(root, 0x02);
            }
        }
    }

    /// Appending the parity to the message must produce a polynomial that
    /// is divisible by the generator, i.e. all syndromes vanish.
    #[test]
    fn syndromes_of_codeword_vanish() {
        let msg: [u8; 16] = [
            0x40, 0xB4, 0x84, 0x54, 0xC4, 0xC4, 0xF2, 0x05, 0x74, 0xF5, 0x24, 0xC4, 0x40, 0xEC,
            0x11, 0xEC,
        ];
        let degree = 10usize;
        let mut g = [0u8; MAX_ECC_PER_BLOCK];
        generator(degree, &mut g);
        let mut parity = [0u8; MAX_ECC_PER_BLOCK];
        remainder(&msg, 0, msg.len(), &g, degree, &mut parity);

        let mut root: u8 = 1;
        for i in 0..degree {
            let mut acc: u8 = 0;
            for &b in msg.iter() {
                acc = mul(acc, root) ^ b;
            }
            for &b in parity.iter().take(degree) {
                acc = mul(acc, root) ^ b;
            }
            assert_eq!(acc, 0, "syndrome {i} must vanish");
            root = mul(root, 0x02);
        }
    }
}
