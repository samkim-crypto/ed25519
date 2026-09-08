use {
    crate::{
        constants::{
            ED25519_BASEPOINT_NEGATED_COMPRESSED, EDWARDS_IDENTITY_COMPRESSED,
            PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
        },
        error::Ed25519VerifyError,
        points::{compute_challenge_into, is_small_order, multiply_by_8},
        scalar, VerificationCriteria,
    },
    solana_curve25519::{
        edwards::{multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
};

/// Stateless, zero-allocation Ed25519 verifier.
///
/// Behavior is selected by [`VerificationCriteria`]; [`Ed25519Verifier::new`]
/// uses the [ZIP-215] preset.
///
/// [ZIP-215]: VerificationCriteria::zip215
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Verifier {
    criteria: VerificationCriteria,
}

impl Default for Ed25519Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Ed25519Verifier {
    /// Initializes a verifier using the default [ZIP-215] criteria.
    ///
    /// [ZIP-215]: VerificationCriteria::zip215
    pub const fn new() -> Self {
        Self {
            criteria: VerificationCriteria::zip215(),
        }
    }

    /// Initializes a verifier with explicit [`VerificationCriteria`].
    pub const fn with_criteria(criteria: VerificationCriteria) -> Self {
        Self { criteria }
    }

    /// Returns the criteria this verifier enforces.
    pub const fn criteria(&self) -> VerificationCriteria {
        self.criteria
    }

    /// Verifies one Ed25519 signature against the configured criteria.
    ///
    /// Checks `S*B - H(R || A || M)*A - R == identity`, multiplied by the
    /// cofactor 8 when [`VerificationCriteria::cofactored`] is set.
    /// Canonical-encoding and small-order rejections run first.
    #[inline(always)]
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), Ed25519VerifyError> {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().unwrap();
        let s_bytes: &[u8; 32] = s_bytes.try_into().unwrap();

        // `S < L` is enforced by the multiscalar-mul syscall, not here; see
        // `VerificationCriteria` for why there is no knob.

        if self.criteria.require_canonical_a && !scalar::is_canonical_point_encoding(public_key) {
            return Err(Ed25519VerifyError::NonCanonicalPublicKey);
        }
        if self.criteria.require_canonical_r && !scalar::is_canonical_point_encoding(r_bytes) {
            return Err(Ed25519VerifyError::NonCanonicalR);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        if self.criteria.reject_small_order_a && is_small_order(&public_key_point)? {
            return Err(Ed25519VerifyError::SmallOrderPublicKey);
        }
        if self.criteria.reject_small_order_r && is_small_order(&r_point)? {
            return Err(Ed25519VerifyError::SmallOrderR);
        }

        let mut scalars = [PodScalar(*s_bytes), PodScalar([0u8; 32])];
        compute_challenge_into(r_bytes, public_key, message, &mut scalars[1].0);

        // `S*(-B) + H*A` is `-(S*B - H*A)`, the negation of the value the
        // verification equation compares against `R`.
        let neg_lhs = multiscalar_multiply_edwards(
            &scalars,
            &[ED25519_BASEPOINT_NEGATED_COMPRESSED, public_key_point],
        )
        .ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // Flipping the sign bit recovers the left-hand side's encoding.
        // `neg_lhs` is canonical, so the flip is too — except at `x = 0`, where
        // it yields negative zero, which can only miss, never falsely match. A
        // byte match implies `R == lhs`, satisfying both equations, and skips
        // `subtract_edwards` on the happy path.
        let mut lhs_bytes = neg_lhs.0;
        lhs_bytes[31] ^= 0x80;
        if lhs_bytes == *r_bytes {
            return Ok(());
        }

        let lhs = PodEdwardsPoint(lhs_bytes);
        // `lhs` is valid by construction, so a `None` here means `r_point`,
        // built from caller-supplied bytes, failed to decode.
        let difference =
            subtract_edwards(&lhs, &r_point).ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // Exact identity satisfies both equations, so accept before paying for
        // the cofactor multiplication.
        if difference == EDWARDS_IDENTITY_COMPRESSED {
            return Ok(());
        }
        // Cofactorless requires exact identity, now ruled out; cofactored also
        // accepts a difference that clears to identity under multiplication by
        // 8 — the mixed-order points ZIP-215 tolerates.
        if !self.criteria.cofactored {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }
        // `difference` came from `subtract_edwards`, so `None` should be
        // unreachable; `InvalidEncoding` is defensive.
        if multiply_by_8(&difference).ok_or(Ed25519VerifyError::InvalidEncoding)?
            != EDWARDS_IDENTITY_COMPRESSED
        {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }

        Ok(())
    }
}
