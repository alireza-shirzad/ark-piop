pub(crate) mod srs;
pub mod structs;
use crate::arithmetic::mat_poly::utils::build_eq_x_r_vec;
use crate::arithmetic::mat_poly::utils::eq_eval;
use crate::arithmetic::virt_poly::hp_interface::HPVirtualPolynomial;
use crate::arithmetic::virt_poly::hp_interface::VPAuxInfo;
use crate::errors::SnarkError;
use crate::errors::SnarkResult;
use crate::pcs::errors::PCSError;
use crate::pcs::pst13::PCSError::EvaluationPointSizeMismatch;
use crate::pcs::pst13::PCSError::TooLargePolynomial;
use crate::pcs::pst13::PCSError::{ProverError, VerifierError};
use crate::pcs::pst13::SnarkError::PCSErrors;
use crate::pcs::pst13::structs::PST13BatchProof;
use crate::pcs::pst13::structs::PST13Commitment;
use crate::pcs::pst13::structs::PST13Proof;
use crate::piop::sum_check::SumCheck;
use crate::{
    arithmetic::mat_poly::{mle::MLE, utils::evaluate_opt},
    pcs::{PCS, StructuredReferenceString},
    transcript::Tr,
};
use ark_ec::{
    AffineRepr, CurveGroup, ScalarMul, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{One, Zero};
use ark_poly::MultilinearExtension;
use ark_poly::Polynomial;
use ark_std::log2;
use ark_std::rand::Rng;
use std::collections::BTreeMap;
use std::iter;
use std::ops::Deref;
use std::{borrow::Borrow, marker::PhantomData, ops::Mul, sync::Arc};
// use batching::{batch_verify_internal, multi_open_internal};
use srs::{PST13ProverParam, PST13UniversalParams, PST13VerifierParam};
/// KZG Polynomial Commitment Scheme on multilinear polynomials.

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

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        let prover_param = prover_param.borrow();
        if prover_param.num_vars < poly.num_vars() {
            return Err(PCSErrors(TooLargePolynomial(
                poly.num_vars(),
                prover_param.num_vars,
            )));
        }
        let ignored = prover_param.num_vars - poly.num_vars();
        let scalars: Vec<_> = poly.to_evaluations();
        let commitment =
            E::G1::msm_unchecked(&prover_param.powers_of_g[ignored].evals, scalars.as_slice())
                .into_affine();

        Ok(PST13Commitment {
            com: commitment,
            nv: poly.num_vars() as u8,
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
    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        _commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, E::ScalarField)> {
        let prover_param = prover_param.borrow();

        // There are two possible errors in opening:
        if polynomial.num_vars() > prover_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(
                polynomial.num_vars(),
                prover_param.num_vars,
            )));
        }

        if polynomial.num_vars() != point.len() {
            return Err(PCSErrors(EvaluationPointSizeMismatch(
                point.len(),
                polynomial.num_vars(),
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
            // First check if the evaluations are actually correct

            for (i, ((poly, point), eval)) in polynomials
                .iter()
                .zip(points.iter())
                .zip(evals.iter())
                .enumerate()
            {
                let computed_eval = evaluate_opt(poly, point);
                if computed_eval != *eval {
                    return Err(SnarkError::PCSErrors(PCSError::HonestProver(i)));
                }
            }
        }
        let prover_param = prover_param.borrow();
        let num_var = polynomials[0].num_vars();
        let k = polynomials.len();
        let ell = log2(k) as usize;

        // challenge point t
        let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

        // eq(t, i) for i in [0..k]
        let eq_t_i_list = build_eq_x_r_vec(t.as_ref())?;
        // combine the polynomials that have same opening point first to reduce the
        // cost of sum check later.
        let point_indices = points
            .iter()
            .fold(BTreeMap::<_, _>::new(), |mut indices, point| {
                let idx = indices.len();
                indices.entry(point).or_insert(idx);
                indices
            });
        let deduped_points =
            BTreeMap::from_iter(point_indices.iter().map(|(point, idx)| (*idx, *point)))
                .into_values()
                .collect::<Vec<_>>();
        let merged_tilde_gs = polynomials
            .iter()
            .zip(points.iter())
            .zip(eq_t_i_list.iter())
            .fold(
                iter::repeat_with(MLE::zero)
                    .map(Arc::new)
                    .take(point_indices.len())
                    .collect::<Vec<_>>(),
                |mut merged_tilde_gs, ((poly, point), coeff)| {
                    *Arc::make_mut(&mut merged_tilde_gs[point_indices[point]]) +=
                        (*coeff, poly.deref());
                    merged_tilde_gs
                },
            );

        let tilde_eqs: Vec<_> = deduped_points
            .iter()
            .map(|point| {
                let eq_b_zi = build_eq_x_r_vec(point).unwrap();
                Arc::new(MLE::from_evaluations_vec(num_var, eq_b_zi))
            })
            .collect();

        // built the virtual polynomial for SumCheck

        let mut sum_check_vp = HPVirtualPolynomial::new(num_var);
        for (merged_tilde_g, tilde_eq) in merged_tilde_gs.iter().zip(tilde_eqs.into_iter()) {
            sum_check_vp.add_mle_list([merged_tilde_g.clone(), tilde_eq], E::ScalarField::one())?;
        }

        let proof = match SumCheck::<E::ScalarField>::prove(&sum_check_vp, transcript) {
            Ok(p) => p,
            Err(_e) => {
                // cannot wrap IOPError with PCSError due to cyclic dependency
                return Err(PCSErrors(ProverError(
                    "Sumcheck in batch proving Failed".to_string(),
                )));
            }
        };

        // a2 := sumcheck's point
        let a2 = &proof.point[..num_var];

        // build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is the
        // sumcheck's point \tilde eq_i(a2) = eq(a2, point_i)
        let mut g_prime = Arc::new(MLE::zero());
        for (merged_tilde_g, point) in merged_tilde_gs.iter().zip(deduped_points.iter()) {
            let eq_i_a2 = eq_eval(a2, point)?;
            *Arc::make_mut(&mut g_prime) += (eq_i_a2, merged_tilde_g.deref());
        }

        let (g_prime_proof, _g_prime_eval) =
            Self::open(prover_param, &g_prime, a2.to_vec().as_ref(), None)?;
        // assert_eq!(g_prime_eval, tilde_g_eval);

        Ok(PST13BatchProof {
            sum_check_proof: proof,
            f_i_eval_at_point_i: evals.to_vec(),
            g_prime_proof,
        })
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    ///
    /// This function takes
    /// - num_var number of pairing product.
    /// - num_var number of MSM
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        let num_var = point.len();

        if num_var > verifier_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(
                num_var,
                verifier_param.num_vars,
            )));
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
        _evals: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        let k = comitments.len();
        let ell = log2(k) as usize;
        let num_var = batch_proof.sum_check_proof.point.len();
        // challenge point t
        let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

        // sum check point (a2)
        let a2 = &batch_proof.sum_check_proof.point[..num_var];

        // build g' commitment
        let eq_t_list = build_eq_x_r_vec(t.as_ref())?;

        let mut scalars = vec![];
        let mut bases = vec![];

        for (i, point) in points.iter().enumerate() {
            let eq_i_a2 = eq_eval(a2, point)?;
            scalars.push(eq_i_a2 * eq_t_list[i]);
            bases.push(comitments[i].com);
        }
        let g_prime_commit = E::G1::msm_unchecked(&bases, &scalars);

        // ensure \sum_i eq(t, <i>) * f_i_evals matches the sum via SumCheck
        let mut sum = E::ScalarField::zero();
        for (i, &e) in eq_t_list.iter().enumerate().take(k) {
            sum += e * batch_proof.f_i_eval_at_point_i[i];
        }
        let aux_info = VPAuxInfo {
            max_degree: 2,
            num_variables: num_var,
            phantom: PhantomData,
        };
        let subclaim = match SumCheck::<E::ScalarField>::verify(
            sum,
            &batch_proof.sum_check_proof,
            &aux_info,
            transcript,
        ) {
            Ok(p) => p,
            Err(_e) => {
                // cannot wrap IOPError with PCSError due to cyclic dependency
                return Err(PCSErrors(VerifierError(
                    "Sumcheck in batch verifying Failed".to_string(),
                )));
            }
        };
        let tilde_g_eval = subclaim.expected_evaluation;

        // verify commitment
        let res = Self::verify(
            verifier_param,
            &PST13Commitment {
                com: g_prime_commit.into_affine(),
                nv: num_var as u8,
            },
            a2.to_vec().as_ref(),
            &tilde_g_eval,
            &batch_proof.g_prime_proof,
        )?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ark_ec::pairing::Pairing;
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
}
