pub(crate) mod srs;
pub(crate) mod util;
use crate::{
    arithmetic::{
        ark_ff::PrimeField,
        ark_poly::{MultilinearExtension, Polynomial},
        f_short_str, f_vec_short_str,
        mat_poly::{mle::MLE, utils::evaluate_opt},
    },
    pcs::{PCS, PCSError, StructuredReferenceString, batching::batch_verify_internal},
    transcript::Tr,
    util::display::short_vec_str,
};
use ark_ec::{
    AffineRepr, CurveGroup, ScalarMul, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, rand::Rng, start_timer};
use macros::timed;
use std::{borrow::Borrow, marker::PhantomData, ops::Mul, sync::Arc};
// use batching::{batch_verify_internal, multi_open_internal};
use super::batching::MlBatchProof;
use crate::pcs::{batching::multi_open_internal, structs::Commitment};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
/// KZG Polynomial Commitment Scheme on multilinear polynomials.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PST13<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct PST13Proof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for PST13Proof<E> {
    fn default() -> Self {
        Self { proofs: vec![] }
    }
}

impl<E: Pairing> PCS<E::ScalarField> for PST13<E> {
    // Parameters
    type ProverParam = MultilinearProverParam<E>;
    type VerifierParam = MultilinearVerifierParam<E>;
    type SRS = MultilinearUniversalParams<E>;
    // Polynomial and its associated types
    type Poly = MLE<E::ScalarField>;
    // Commitments and proofs
    type Commitment = Commitment<E>;
    type Proof = PST13Proof<E>;
    type BatchProof = MlBatchProof<E, Self>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        MultilinearUniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_log_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        assert!(supported_degree.is_none());

        let supported_num_vars = match supported_num_vars {
            Some(p) => p,
            None => {
                return Err(PCSError::InvalidParameters(
                    "multilinear should receive a num_var param".to_string(),
                ));
            }
        };
        let (ml_ck, ml_vk) = srs.borrow().trim(supported_num_vars)?;

        Ok((ml_ck, ml_vk))
    }

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    #[timed("nv:",poly.num_vars())]
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        if prover_param.num_vars < poly.num_vars() {
            return Err(PCSError::InvalidParameters(format!(
                "MlE length ({}) exceeds param limit ({})",
                poly.num_vars(),
                prover_param.num_vars
            )));
        }
        let ignored = prover_param.num_vars - poly.num_vars();
        let scalars: Vec<_> = poly.to_evaluations();
        let commitment =
            E::G1::msm_unchecked(&prover_param.powers_of_g[ignored].evals, scalars.as_slice())
                .into_affine();

        Ok(Commitment {
            com: commitment,
            nv: poly.num_vars(),
        })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same. This function does not need to take the evaluation value as an
    /// input.
    ///
    /// This function takes 2^{num_var +1} number of scalar multiplications over
    /// G1:
    /// - it prodceeds with `num_var` number of rounds,
    /// - at round i, we compute an MSM for `2^{num_var - i + 1}` number of G2
    ///   elements.
    #[timed("nv:", polynomial.num_vars())]
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
    ) -> Result<(Self::Proof, E::ScalarField), PCSError> {
        open_internal(prover_param.borrow(), polynomial, point)
    }

    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    #[timed("nv:", polynomials.iter().map(|p| p.num_vars()).collect::<Vec<usize>>())]
    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Arc<Self::Poly>],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        transcript: &mut Tr<E::ScalarField>,
    ) -> Result<MlBatchProof<E, Self>, PCSError> {
        // First check if the evaluations are actually correct
        debug_assert!(
            polynomials
                .iter()
                .zip(points.iter())
                .zip(evals.iter())
                .all(|((poly, point), eval)| { poly.evaluate(point) == *eval }),
        );

        multi_open_internal(
            prover_param.borrow(),
            polynomials,
            points,
            evals,
            transcript,
        )
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    ///
    /// This function takes
    /// - num_var number of pairing product.
    /// - num_var number of MSM
    #[timed("nv:", commitment.nv)]
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        verify_internal(verifier_param, commitment, point, value, proof)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    #[timed("comms:", short_vec_str(commitments))]
    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        batch_proof: &Self::BatchProof,
        transcript: &mut Tr<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        batch_verify_internal(verifier_param, commitments, points, batch_proof, transcript)
    }
}

/// On input a polynomial `p` and a point `point`, outputs a proof for the
/// same. This function does not need to take the evaluation value as an
/// input.
///
/// This function takes 2^{num_var} number of scalar multiplications over
/// G1:
/// - it proceeds with `num_var` number of rounds,
/// - at round i, we compute an MSM for `2^{num_var - i}` number of G1 elements.
#[timed("point: ", f_vec_short_str(point))]
fn open_internal<E: Pairing>(
    prover_param: &MultilinearProverParam<E>,
    polynomial: &MLE<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(PST13Proof<E>, E::ScalarField), PCSError> {
    if polynomial.num_vars() > prover_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} exceed the limit {}",
            polynomial.num_vars(),
            prover_param.num_vars
        )));
    }

    if polynomial.num_vars() != point.len() {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} does not match point len {}",
            polynomial.num_vars(),
            point.len()
        )));
    }

    let nv = polynomial.num_vars();
    // the first `ignored` SRS vectors are unused for opening.
    let ignored = prover_param.num_vars - nv + 1;
    let mut f = polynomial.to_evaluations();

    let mut proofs = Vec::new();

    for (i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
        .enumerate()
    {
        let k = nv - 1 - i;
        let cur_dim = 1 << k;
        let mut q = vec![E::ScalarField::zero(); cur_dim];
        let mut r = vec![E::ScalarField::zero(); cur_dim];

        for b in 0..(1 << k) {
            // q[b] = f[1, b] - f[0, b]
            q[b] = f[(b << 1) + 1] - f[b << 1];

            // r[b] = f[0, b] + q[b] * p
            r[b] = f[b << 1] + (q[b] * point_at_k);
        }
        f = r;

        // this is a MSM over G1 and is likely to be the bottleneck

        proofs.push(E::G1::msm_unchecked(&gi.evals, &q).into_affine());
    }
    let eval = evaluate_opt(polynomial, point);
    Ok((PST13Proof { proofs }, eval))
}

/// Verifies that `value` is the evaluation at `x` of the polynomial
/// committed inside `comm`.
///
/// This function takes
/// - num_var number of pairing product.
/// - num_var number of MSM
#[timed("point: ", f_vec_short_str(point), ",value: ", f_short_str(*value))]
fn verify_internal<E: Pairing>(
    verifier_param: &MultilinearVerifierParam<E>,
    commitment: &Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &PST13Proof<E>,
) -> Result<bool, PCSError> {
    let num_var = point.len();

    if num_var > verifier_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "point length ({}) exceeds param limit ({})",
            num_var, verifier_param.num_vars
        )));
    }

    let scalar_size = E::ScalarField::MODULUS_BIT_SIZE as usize;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};

    type E = ark_test_curves::bls12_381::Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &MultilinearUniversalParams<E>,
        poly: &Arc<MLE<Fr>>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = PST13::trim(params, None, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = PST13::commit(&ck, poly)?;
        let (proof, value) = PST13::open(&ck, poly, &point)?;

        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);

        let value = Fr::rand(rng);
        assert!(!PST13::verify(&vk, &com, &point, &value, &proof)?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> Result<(), PCSError> {
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

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(PST13::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
