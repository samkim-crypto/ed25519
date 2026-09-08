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

/// Reduces a 64-byte little-endian integer modulo the ed25519 base point order.
///
/// Bit-serial long division: shift the remainder left, shift in the next bit of
/// the dividend, and subtract `L` whenever the result reaches it. The remainder
/// is carried as 64-bit limbs rather than bytes, so each step touches four words
/// instead of thirty-two.
pub(crate) fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    let mut remainder = [0u64; 4];

    for bit_index in (0..512).rev() {
        shl1(&mut remainder);
        remainder[0] |= u64::from((wide[bit_index / 8] >> (bit_index % 8)) & 1);
        conditional_sub_order(&mut remainder);
    }

    let mut reduced = [0u8; 32];
    for (chunk, limb) in reduced.chunks_exact_mut(8).zip(remainder) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    reduced
}

/// Doubles `value` in place, discarding the bit shifted out of the top.
///
/// The caller keeps `value < L < 2^253` between iterations, so the discarded bit
/// is always zero.
fn shl1(value: &mut [u64; 4]) {
    let mut carry = 0u64;
    for limb in value {
        let next_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

/// Subtracts `L` from `value` when `value >= L`, without branching on the input.
fn conditional_sub_order(value: &mut [u64; 4]) {
    let mut difference = [0u64; 4];
    let mut borrow = 0u64;

    for index in 0..4 {
        let (partial, borrow_from_order) =
            value[index].overflowing_sub(BASEPOINT_ORDER_LIMBS[index]);
        let (limb, borrow_from_carry) = partial.overflowing_sub(borrow);
        difference[index] = limb;
        borrow = u64::from(borrow_from_order | borrow_from_carry);
    }

    // A borrow out of the top limb means `value < L`, so the difference is
    // discarded. `mask` is all-ones exactly when the subtraction should apply.
    let mask = borrow.wrapping_sub(1);
    for index in 0..4 {
        value[index] = (value[index] & !mask) | (difference[index] & mask);
    }
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
