//! Small scalar- and field-element helpers needed to assemble Ed25519
//! verification around syscalls.

use crate::constants::{BASEPOINT_ORDER_LIMBS, FIELD_MODULUS};

/// Returns `true` if `encoding` is a canonical compressed Edwards point.
///
/// A compressed point stores the `y`-coordinate in the low 255 bits and the
/// sign of `x` in the top bit. An encoding is canonical when the masked
/// `y`-coordinate is a reduced field element (`y < p`). Non-canonical encodings
/// (`y >= p`) still decompress — they reduce modulo `p` first — but represent a
/// point with an alternative, non-reduced serialization.
pub(crate) fn is_canonical_point_encoding(encoding: &[u8; 32]) -> bool {
    let mut y = *encoding;
    y[31] &= 0x7f;
    cmp_le(&y, &FIELD_MODULUS).is_lt()
}

/// Reduces a 64-byte little-endian integer modulo the Ed25519 group order.
///
/// Uses radix `2^21` limbs and the relation `2^252 = -c (mod L)`, where
/// `L = 2^252 + c`. After folding, `-L < r < L`; adding `L` when `r` is
/// negative produces a canonical scalar.
pub(crate) fn reduce_wide_into(wide: &[u8; 64], reduced: &mut [u8; 32]) {
    #[inline(always)]
    fn fold(limbs: &mut [i64; 24], index: usize) {
        // The radix-2^21 expansion of -c.
        const COEFFICIENTS: [i64; 6] = [666643, 470296, 654183, -997805, 136657, -683901];

        let high = limbs[index];
        limbs[index] = 0;
        for (j, &coefficient) in COEFFICIENTS.iter().enumerate() {
            limbs[index - 12 + j] += high * coefficient;
        }
    }

    let mut limbs = [0i64; 24];
    for (i, limb) in limbs.iter_mut().enumerate().take(23) {
        let bit = i * 21;
        let byte = bit / 8;
        let word = u32::from_le_bytes(wide[byte..byte + 4].try_into().unwrap());
        *limb = i64::from((word >> (bit % 8)) & 0x1f_ffff);
    }
    limbs[23] = i64::from(u32::from_le_bytes(wide[60..64].try_into().unwrap()) >> 3);

    // Fold the highest six limbs before propagating their carries.
    fold(&mut limbs, 23);
    fold(&mut limbs, 22);
    fold(&mut limbs, 21);
    fold(&mut limbs, 20);
    fold(&mut limbs, 19);
    fold(&mut limbs, 18);

    // Normalize through limb 16 before folding limb 17.
    // Stop before limb 18, which has already been folded.
    for i in 6..17 {
        let carry = limbs[i] >> 21;
        limbs[i] &= 0x1f_ffff;
        limbs[i + 1] += carry;
    }

    fold(&mut limbs, 17);
    fold(&mut limbs, 16);
    fold(&mut limbs, 15);
    fold(&mut limbs, 14);
    fold(&mut limbs, 13);
    fold(&mut limbs, 12);

    for i in 0..12 {
        let carry = limbs[i] >> 21;
        limbs[i] &= 0x1f_ffff;
        limbs[i + 1] += carry;
    }

    // Here limbs[12] is in [-1, 28], and the lower twelve limbs encode
    // a value below 2^252. Folding once more gives -28*c <= r < L.
    // Since 28*c < L, a negative remainder needs exactly one addition of L.
    fold(&mut limbs, 12);
    for i in 0..11 {
        let carry = limbs[i] >> 21;
        limbs[i] &= 0x1f_ffff;
        limbs[i + 1] += carry;
    }

    // Pack r modulo 2^256. The top limb retains the sign of r.
    let mut remainder = [
        (limbs[0] as u64)
            | ((limbs[1] as u64) << 21)
            | ((limbs[2] as u64) << 42)
            | ((limbs[3] as u64) << 63),
        ((limbs[3] as u64) >> 1)
            | ((limbs[4] as u64) << 20)
            | ((limbs[5] as u64) << 41)
            | ((limbs[6] as u64) << 62),
        ((limbs[6] as u64) >> 2)
            | ((limbs[7] as u64) << 19)
            | ((limbs[8] as u64) << 40)
            | ((limbs[9] as u64) << 61),
        ((limbs[9] as u64) >> 3) | ((limbs[10] as u64) << 18) | ((limbs[11] as u64) << 39),
    ];

    let mask = 0u64.wrapping_sub(remainder[3] >> 63);
    let mut carry = 0u64;
    for i in 0..4 {
        let (partial, carry_from_order) =
            remainder[i].overflowing_add(BASEPOINT_ORDER_LIMBS[i] & mask);
        let (limb, carry_from_carry) = partial.overflowing_add(carry);
        remainder[i] = limb;
        carry = u64::from(carry_from_order | carry_from_carry);
    }

    for (chunk, limb) in reduced.chunks_exact_mut(8).zip(remainder) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
}

#[cfg(test)]
pub(crate) fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    let mut reduced = [0u8; 32];
    reduce_wide_into(wide, &mut reduced);
    reduced
}

pub(crate) fn cmp_le(left: &[u8; 32], right: &[u8; 32]) -> core::cmp::Ordering {
    for index in (0..4).rev() {
        let left_limb = u64::from_le_bytes(left[index * 8..index * 8 + 8].try_into().unwrap());
        let right_limb = u64::from_le_bytes(right[index * 8..index * 8 + 8].try_into().unwrap());
        match left_limb.cmp(&right_limb) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::BASEPOINT_ORDER};

    fn wide_from_low_32(low: &[u8; 32]) -> [u8; 64] {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(low);
        wide
    }

    #[test]
    fn reduces_group_order_to_zero() {
        assert_eq!(reduce_wide(&wide_from_low_32(&BASEPOINT_ORDER)), [0; 32]);
    }

    #[test]
    fn reduces_order_boundaries() {
        // L - 1 is already reduced and must pass through unchanged.
        let mut order_minus_one = BASEPOINT_ORDER;
        order_minus_one[0] -= 1;
        assert_eq!(
            reduce_wide(&wide_from_low_32(&order_minus_one)),
            order_minus_one
        );

        // L + 1 must come back as 1.
        let mut order_plus_one = BASEPOINT_ORDER;
        order_plus_one[0] += 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(reduce_wide(&wide_from_low_32(&order_plus_one)), one);
    }

    // `reduce_wide` is hand-rolled modular arithmetic with a branch-free carry
    // chain, so it is cross-checked against curve25519-dalek's own wide
    // reduction rather than against a second copy of the same reasoning.
    #[test]
    fn matches_curve25519_dalek_wide_reduction() {
        let mut wide = [0u8; 64];

        for round in 0..32u32 {
            for (index, byte) in wide.iter_mut().enumerate() {
                *byte = (index as u32).wrapping_mul(31).wrapping_add(round * 7) as u8;
            }

            let expected =
                curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide).to_bytes();
            assert_eq!(reduce_wide(&wide), expected, "round {round}");
        }

        // Saturated input exercises the widest possible quotient.
        let saturated = [0xff; 64];
        let expected =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&saturated).to_bytes();
        assert_eq!(reduce_wide(&saturated), expected);
    }

    #[test]
    fn matches_dalek_on_wide_reduction_boundaries_and_random_inputs() {
        fn check(wide: &[u8; 64]) {
            let expected =
                curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(wide).to_bytes();
            assert_eq!(reduce_wide(wide), expected, "wide input: {wide:02x?}");
        }

        fn check_neighbors(wide: [u8; 64]) {
            check(&wide);

            let mut below = wide;
            for byte in &mut below {
                let (value, borrow) = byte.overflowing_sub(1);
                *byte = value;
                if !borrow {
                    break;
                }
            }
            check(&below);

            let mut above = wide;
            for byte in &mut above {
                let (value, carry) = byte.overflowing_add(1);
                *byte = value;
                if !carry {
                    break;
                }
            }
            check(&above);
        }

        check(&[0; 64]);
        check(&[0xff; 64]);

        // Powers of two and their neighbors across every bit position.
        for bit in 0..512usize {
            let mut wide = [0u8; 64];
            wide[bit / 8] = 1u8 << (bit % 8);
            check_neighbors(wide);
        }

        // L * 2^shift and its neighbors, through the highest fitting shift.
        let mut shifted_order = wide_from_low_32(&BASEPOINT_ORDER);
        for _ in 0..=259 {
            check_neighbors(shifted_order);

            let mut carry = 0u8;
            for byte in &mut shifted_order {
                let next_carry = *byte >> 7;
                *byte = (*byte << 1) | carry;
                carry = next_carry;
            }
        }

        // Deterministic test inputs; this PRNG is not used by the verifier.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..4096 {
            let mut wide = [0u8; 64];
            for chunk in wide.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            check(&wide);
        }
    }

    #[test]
    fn accepts_reduced_encodings() {
        // y = 0
        assert!(is_canonical_point_encoding(&[0; 32]));

        // y = p - 1 (the small-order point (0, -1)), with and without sign bit.
        let mut y = FIELD_MODULUS;
        y[0] -= 1;
        assert!(is_canonical_point_encoding(&y));
        y[31] |= 0x80;
        assert!(is_canonical_point_encoding(&y));
    }

    #[test]
    fn rejects_unreduced_encodings() {
        // y = p
        assert!(!is_canonical_point_encoding(&FIELD_MODULUS));

        // y = p, sign bit set (the sign bit must be ignored, so still rejected).
        let mut y = FIELD_MODULUS;
        y[31] |= 0x80;
        assert!(!is_canonical_point_encoding(&y));

        // y = 2^255 - 1 (largest value the 255 bits can hold, > p).
        let mut y = [0xff; 32];
        y[31] = 0x7f;
        assert!(!is_canonical_point_encoding(&y));
    }
}
