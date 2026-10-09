mod batch;
pub(crate) mod small_scalar_msm;
pub(crate) mod srs;
pub mod structs;
use crate::arithmetic::mat_poly::mle::MLEStorage;
use crate::errors::SnarkError;
use crate::errors::SnarkResult;
use crate::pcs::errors::PCSError;
use crate::pcs::pst13::PCSError::EvaluationPointSizeMismatch;
use crate::pcs::pst13::PCSError::TooLargePolynomial;
use crate::pcs::pst13::SnarkError::PCSErrors;
use crate::pcs::pst13::structs::PST13BatchProof;
use crate::pcs::pst13::structs::PST13Commitment;
use crate::pcs::pst13::structs::PST13Proof;
use crate::{
    arithmetic::mat_poly::mle::MLE,
    pcs::{PCS, StructuredReferenceString},
    transcript::Tr,
};
use ark_ec::{
    AffineRepr, CurveGroup, ScalarMul, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{One, Zero};
use ark_poly::Polynomial;
use ark_std::rand::Rng;
use srs::{PST13ProverParam, PST13UniversalParams, PST13VerifierParam};
use std::{borrow::Borrow, marker::PhantomData, ops::Mul, sync::Arc};

/// Shared commit path for all `Sparse*` storage variants: rewrites `MSM(bases, values)` as
/// `default * Σ bases[..inner_len] + Σ bases[idx] * (val - default)` over the exceptions.
/// With `default == 0` only `|exceptions|` scalar-muls are paid; otherwise the baseline sum
/// costs `Ω(inner_len)` group additions but still avoids materializing a `Vec<F>`.
/// Callers pass F-lifted values so `F::from` is paid once per exception, not per element.
fn sparse_commit<E: Pairing>(
    bases: &[E::G1Affine],
    committed_nv: usize,
    default: E::ScalarField,
    exceptions: impl Iterator<Item = (u32, E::ScalarField)>,
) -> E::G1Affine {
    let inner_len = 1usize << committed_nv;
    let mut acc: E::G1 = if default.is_zero() {
        E::G1::zero()
    } else {
        let mut sum_bases: E::G1 = E::G1::zero();
        for base in bases.iter().take(inner_len) {
            sum_bases += base;
        }
        if default.is_one() {
            sum_bases
        } else {
            sum_bases.mul(default)
        }
    };
    for (idx, val) in exceptions {
        let delta = val - default;
        if !delta.is_zero() {
            acc += bases[idx as usize].mul(delta);
        }
    }
    acc.into_affine()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PST13<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PCS<E::ScalarField> for PST13<E> {
    // Parameters
    type ProverParam = PST13ProverParam<E>;
    type VerifierParam = PST13VerifierParam<E>;
    type SRS = PST13UniversalParams<E>;
    // Polynomial and its associated types
    type Poly = MLE<E::ScalarField>;
    // comitments and proofs
    type Commitment = PST13Commitment<E>;
    type Proof = PST13Proof<E>;
    type BatchProof = PST13BatchProof<E, Self>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing_inner<R: Rng>(rng: &mut R, log_size: usize) -> SnarkResult<Self::SRS> {
        PST13UniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_log_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    fn trim_impl_inner(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        if supported_degree.is_some() {
            panic!("supported_degree must be None for multilinear polynomials");
        }
        let supported_num_vars = match supported_num_vars {
            Some(p) => p,
            None => {
                panic!("supported_num_vars should be provided for multilinear polynomials")
            }
        };
        let (ml_ck, ml_vk) = srs.borrow().trim(supported_num_vars)?;

        Ok((ml_ck, ml_vk))
    }

    /// Generate a commitment for a polynomial (`2^num_vars` G1 scalar muls).
    ///
    /// Compressed backings (`Bit`/`U8`/`U32`/`U64`) feed the raw small-scalar slice
    /// straight to [`small_scalar_msm`], avoiding both the dense `Vec<F>`
    /// materialization and a full-width Pippenger MSM.
    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        let prover_param = prover_param.borrow();
        // Commit over the physically-stored hypercube only — never over virtual
        // padding, which is a cyclic repetition the SRS must not consume.
        let committed_nv = poly.storage().inner_num_vars();
        if prover_param.num_vars < committed_nv {
            return Err(PCSErrors(TooLargePolynomial(
                committed_nv,
                prover_param.num_vars,
            )));
        }
        let ignored = prover_param.num_vars - committed_nv;
        let bases = &prover_param.powers_of_g[ignored].evals;

        let com = match poly.storage() {
            MLEStorage::Field(m) => E::G1::msm_unchecked(bases, &m.evaluations).into_affine(),
            MLEStorage::Bit { bits, .. } => {
                // Unpack on the fly (little-endian per byte, per `MLEStorage::Bit`'s
                // contract); the tail beyond `inner_len` is cut by `msm_u1`'s length-min.
                let inner_len = 1usize << committed_nv;
                let scalars: Vec<bool> = (0..inner_len)
                    .map(|i| (bits[i >> 3] >> (i & 7)) & 1 == 1)
                    .collect();
                small_scalar_msm::msm_u1::<E::G1>(bases, &scalars).into_affine()
            }
            MLEStorage::U8 { bytes, .. } => {
                small_scalar_msm::msm_u8::<E::G1>(bases, bytes).into_affine()
            }
            MLEStorage::U32 { words, .. } => {
                small_scalar_msm::msm_u32::<E::G1>(bases, words).into_affine()
            }
            MLEStorage::U64 { words, .. } => {
                small_scalar_msm::msm_u64::<E::G1>(bases, words).into_affine()
            }
            MLEStorage::Constant { value, .. } => {
                // `value * Σ bases[..2^committed_nv]`, summed on the fly (no Vec<F>);
                // short-circuits for value 0 and skips the scalar mul for value 1.
                if value.is_zero() {
                    E::G1::zero().into_affine()
                } else {
                    let inner_len = 1usize << committed_nv;
                    let mut sum: E::G1 = E::G1::zero();
                    for base in bases.iter().take(inner_len) {
                        sum += base;
                    }
                    if value.is_one() {
                        sum.into_affine()
                    } else {
                        sum.mul(*value).into_affine()
                    }
                }
            }
            MLEStorage::Rle { runs, .. } => {
                // Each run `(v, count)` contributes `v * Σ bases[cursor..cursor+count]`;
                // zero-value runs are skipped.
                let mut acc: E::G1 = E::G1::zero();
                let mut cursor: usize = 0;
                for (value, count) in runs.iter() {
                    let count = *count as usize;
                    if !value.is_zero() {
                        let mut run_sum: E::G1 = E::G1::zero();
                        for base in bases.iter().skip(cursor).take(count) {
                            run_sum += base;
                        }
                        if value.is_one() {
                            acc += run_sum;
                        } else {
                            acc += run_sum.mul(*value);
                        }
                    }
                    cursor += count;
                }
                acc.into_affine()
            }
            MLEStorage::Sparse {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                bases,
                committed_nv,
                *default,
                exceptions.iter().map(|(i, v)| (*i, *v)),
            ),
            MLEStorage::SparseU8 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                bases,
                committed_nv,
                E::ScalarField::from(*default as u64),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v as u64))),
            ),
            MLEStorage::SparseU32 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                bases,
                committed_nv,
                E::ScalarField::from(*default as u64),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v as u64))),
            ),
            MLEStorage::SparseU64 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                bases,
                committed_nv,
                E::ScalarField::from(*default),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v))),
            ),
            // `value[i] = (high[i] << 64) | low[i]`, so the commit is
            // `msm_u64(bases, low) + 2^64 * msm_u64(bases, high)`. `scale` is
            // fixed-point decoding metadata, not part of the polynomial value,
            // so it does not participate in the commit (see mle.rs).
            MLEStorage::PackedDecimal { high, low, .. } => {
                let lo_msm = small_scalar_msm::msm_u64::<E::G1>(bases, low);
                let hi_msm = small_scalar_msm::msm_u64::<E::G1>(bases, high);
                let two_pow_64 = E::ScalarField::from(1u128 << 64);
                (lo_msm + hi_msm.mul(two_pow_64)).into_affine()
            }
            // Lazy variants are registered only after their dense form was committed
            // and dropped; committing one directly is a caller bug, and materializing
            // here (O(2^nv) inversions) would defeat the memory optimization.
            MLEStorage::LazyInverseShifted { .. } | MLEStorage::LazyInverseShiftedSum { .. } => {
                panic!(
                    "PST13::commit: cannot commit an MLE with lazy inverse-shifted storage. \
                     Lazy backings are for post-commit re-registration only; commit the dense \
                     source-based MLE first, then swap in the lazy backing via \
                     `register_mat_mv_poly`."
                );
            }
        };

        Ok(PST13Commitment {
            com,
            nv: committed_nv as u8,
        })
    }

    /// Produce an opening proof for `polynomial` at `point` (the evaluation is
    /// computed internally). Costs ~`2^{num_var+1}` G1 scalar muls over `num_var` rounds.
    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        _commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, E::ScalarField)> {
        let prover_param = prover_param.borrow();

        // The polynomial as it was committed: over its own hypercube. The
        // variables it is padded to are ones it repeats along, so of a
        // longer point it reads the first coordinates only.
        let nv = polynomial.storage().inner_num_vars();
        if nv > prover_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(nv, prover_param.num_vars)));
        }
        if point.len() < nv {
            return Err(PCSErrors(EvaluationPointSizeMismatch(point.len(), nv)));
        }
        let point = &point[..nv];

        let open_span = tracing::span!(
            tracing::Level::DEBUG,
            "pst13.open",
            nv = nv,
            total_msm_scalars = (1usize << nv).saturating_sub(1),
        );
        let _open_enter = open_span.enter();
        // The first `ignored` SRS vectors are unused for opening.
        let ignored = prover_param.num_vars - nv + 1;
        let mut f = polynomial.storage().to_evaluations_vec();

        let mut proofs = Vec::new();

        for (i, (&point_at_k, gi)) in point
            .iter()
            .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
            .enumerate()
        {
            let k = nv - 1 - i;
            let cur_dim = 1 << k;
            let round_span = tracing::span!(
                tracing::Level::DEBUG,
                "pst13.open.round",
                round = i,
                msm_size = cur_dim,
            );
            let _round_enter = round_span.enter();
            let mut q = vec![E::ScalarField::zero(); cur_dim];
            let mut r = vec![E::ScalarField::zero(); cur_dim];

            {
                let qr_span =
                    tracing::span!(tracing::Level::DEBUG, "pst13.open.round.qr", size = cur_dim,);
                let _qr_enter = qr_span.enter();
                for b in 0..(1 << k) {
                    // q[b] = f[1, b] - f[0, b]
                    q[b] = f[(b << 1) + 1] - f[b << 1];

                    // r[b] = f[0, b] + q[b] * p
                    r[b] = f[b << 1] + (q[b] * point_at_k);
                }
            }
            f = r;

            // this is a MSM over G1 and is likely to be the bottleneck
            let msm_span = tracing::span!(
                tracing::Level::DEBUG,
                "pst13.open.round.msm",
                size = cur_dim,
            );
            let _msm_enter = msm_span.enter();
            proofs.push(E::G1::msm_unchecked(&gi.evals, &q).into_affine());
        }
        // Every variable is bound: what is left is the evaluation.
        let eval = f[0];
        Ok((PST13Proof { proofs }, eval))
    }

    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Arc<Self::Poly>],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<PST13BatchProof<E, Self>> {
        #[cfg(feature = "honest-prover")]
        {
            use ark_poly::MultilinearExtension;
            // Check the claimed evaluations are actually correct.
            for (i, ((poly, point), eval)) in polynomials
                .iter()
                .zip(points.iter())
                .zip(evals.iter())
                .enumerate()
            {
                // A polynomial reads as many coordinates as it has variables.
                let read = &point[..poly.storage().inner_num_vars().min(point.len())];
                let computed_eval = poly.fix_variables(read).evaluations()[0];
                if computed_eval != *eval {
                    return Err(SnarkError::PCSErrors(PCSError::HonestProver(i)));
                }
            }
        }
        batch::open_batch(
            prover_param.borrow(),
            polynomials,
            points,
            evals,
            transcript,
        )
    }

    /// Verifies that `value` is the evaluation at `point` of the polynomial committed
    /// inside `commitment`. Costs `num_var` pairing products and `num_var` MSMs.
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        // A commitment is to a polynomial of its own number of variables,
        // which reads the first coordinates of a longer point.
        let num_var = commitment.nv as usize;
        if point.len() < num_var {
            return Err(PCSErrors(EvaluationPointSizeMismatch(point.len(), num_var)));
        }
        let point = &point[..num_var];

        if num_var > verifier_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(
                num_var,
                verifier_param.num_vars,
            )));
        }

        // One quotient per variable. With fewer the pairing below would be
        // taken over the ones that are there.
        if proof.proofs.len() != num_var {
            return Ok(false);
        }

        let h_mul: Vec<E::G2Affine> = verifier_param.h.into_group().batch_mul(point);

        let ignored = verifier_param.num_vars - num_var;
        let h_vec: Vec<_> = (0..num_var)
            .map(|i| verifier_param.h_mask[ignored + i].into_group() - h_mul[i])
            .collect();
        let h_vec: Vec<E::G2Affine> = E::G2::normalize_batch(&h_vec);

        let mut pairings: Vec<_> = proof
            .proofs
            .iter()
            .map(|&x| E::G1Prepared::from(x))
            .zip(h_vec.into_iter().take(num_var).map(E::G2Prepared::from))
            .collect();

        pairings.push((
            E::G1Prepared::from(
                (verifier_param.g.mul(*value) - commitment.com.into_group()).into_affine(),
            ),
            E::G2Prepared::from(verifier_param.h),
        ));

        let ps = pairings.iter().map(|(p, _)| p.clone());
        let hs = pairings.iter().map(|(_, h)| h.clone());

        let res = E::multi_pairing(ps, hs) == ark_ec::pairing::PairingOutput(E::TargetField::one());

        Ok(res)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify_inner(
        verifier_param: &Self::VerifierParam,
        comitments: &[Self::Commitment],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        batch::verify_batch(
            verifier_param,
            comitments,
            points,
            evals,
            batch_proof,
            transcript,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_poly::MultilinearExtension;
    use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};

    type E = ark_bn254::Bn254;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &PST13UniversalParams<E>,
        poly: &Arc<MLE<Fr>>,
        rng: &mut R,
    ) -> SnarkResult<()> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = PST13::trim(params, None, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = PST13::commit(&ck, poly)?;
        let (proof, value) = PST13::open(&ck, poly, &point, None)?;

        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);

        let value = Fr::rand(rng);
        assert!(!PST13::verify(&vk, &com, &point, &value, &proof)?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> SnarkResult<()> {
        let mut rng = test_rng();

        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = Arc::new(MLE::rand(8, &mut rng));
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = Arc::new(MLE::rand(1, &mut rng));
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    /// A polynomial padded to more variables than it was committed with,
    /// and a point longer than it: both read the first coordinates only,
    /// and the opening is the one of the committed polynomial.
    #[test]
    fn opening_reads_as_many_coordinates_as_the_commitment_has_variables() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 8)?;
        let (ck, vk) = PST13::trim(&params, None, Some(8))?;
        let inner = MLE::rand(3, &mut rng);
        let padded = Arc::new(MLE::new(inner.mat_mle().into_owned(), Some(6)));
        let inner = Arc::new(inner);
        let point: Vec<Fr> = (0..6).map(|_| Fr::rand(&mut rng)).collect();

        let com = PST13::commit(&ck, &padded)?;
        assert_eq!(com.nv, 3);
        let (proof, value) = PST13::open(&ck, &padded, &point, None)?;
        assert_eq!(
            (proof.clone(), value),
            PST13::open(&ck, &inner, &point[..3].to_vec(), None)?
        );
        assert_eq!(value, inner.evaluate(&point[..3].to_vec()));
        assert_eq!(proof.proofs.len(), 3);
        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);
        assert!(PST13::verify(
            &vk,
            &com,
            &point[..3].to_vec(),
            &value,
            &proof
        )?);

        // Another coordinate the polynomial reads, another value, a point
        // too short, and a proof with a quotient missing.
        let mut moved = point.clone();
        moved[2] += Fr::from(1u64);
        assert!(!PST13::verify(&vk, &com, &moved, &value, &proof)?);
        assert!(!PST13::verify(
            &vk,
            &com,
            &point,
            &(value + Fr::from(1u64)),
            &proof
        )?);
        assert!(PST13::verify(&vk, &com, &point[..2].to_vec(), &value, &proof).is_err());
        assert!(PST13::open(&ck, &padded, &point[..2].to_vec(), None).is_err());
        let mut short = proof.clone();
        short.proofs.pop();
        assert!(!PST13::verify(&vk, &com, &point, &value, &short)?);
        Ok(())
    }

    #[test]
    fn test_wrapped_commit_matches_inner_commit() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;
        let (ck, _) = PST13::trim(&params, None, Some(6))?;

        let inner = MLE::rand(3, &mut rng);
        let wrapped = Arc::new(MLE::new(inner.mat_mle().into_owned(), Some(6)));
        let inner = Arc::new(inner);

        let wrapped_commit = PST13::commit(&ck, &wrapped)?;
        let inner_commit = PST13::commit(&ck, &inner)?;

        assert_eq!(wrapped_commit, inner_commit);
        assert_eq!(wrapped_commit.nv, inner.num_vars() as u8);

        Ok(())
    }
}
