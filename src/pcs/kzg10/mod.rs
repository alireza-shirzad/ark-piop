use super::PCS;
use crate::{
    arithmetic::mat_poly::lde::LDE,
    errors::{SnarkError, SnarkResult},
    pcs::{
        errors::PCSError,
        kzg10::structs::{KZG10BatchProof, KZG10Proof},
    },
};

use crate::pcs::kzg10::PCSError::TooLargePolynomial;
use crate::pcs::kzg10::SnarkError::PCSErrors;
use crate::{
    pcs::{Rng, StructuredReferenceString},
    transcript::Tr,
};
use ark_ec::{
    AffineRepr, CurveGroup, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{One, PrimeField};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::marker::PhantomData;
use srs::{KZG10ProverParam, KZG10UniversalParams, KZG10VerifierParam};
use std::{borrow::Borrow, ops::Mul, sync::Arc};
use structs::KZG10Commitment;
pub(crate) mod srs;
pub mod structs;
/// KZG Polynomial Commitment Scheme on univariate polynomial.
#[derive(Clone)]
pub struct KZG10<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PCS<E::ScalarField> for KZG10<E> {
    // Parameters
    type ProverParam = KZG10ProverParam<E::G1Affine>;
    type VerifierParam = KZG10VerifierParam<E>;
    type SRS = KZG10UniversalParams<E>;
    // Polynomial and its associated types
    type Poly = LDE<E::ScalarField>;
    // Polynomial and its associated types
    type Commitment = KZG10Commitment<E>;
    type Proof = KZG10Proof<E>;

    // We do not implement batch univariate KZG at the current version.
    type BatchProof = KZG10BatchProof<E>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing_inner<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> SnarkResult<Self::SRS> {
        Self::SRS::gen_srs_for_testing(rng, supported_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input `max_degree` for univariate.
    /// `supported_num_vars` must be None or an error is returned.
    fn trim_impl_inner(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        if supported_num_vars.is_some() {
            panic!("supported_num_vars must be None for univariate polynomials");
        }
        let supported_degree = match supported_degree {
            Some(p) => p,
            None => {
                panic!("supported_degree should be provided for univariate polynomials")
            }
        };
        let (ml_ck, ml_vk) = srs.borrow().trim(supported_degree)?;

        Ok((ml_ck, ml_vk))
    }

    /// Generate a commitment for a polynomial
    /// Note that the scheme is not hiding
    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        let prover_param = prover_param.borrow();
        if poly.degree() >= prover_param.powers_of_g.len() {
            return Err(PCSErrors(TooLargePolynomial(
                poly.degree(),
                prover_param.powers_of_g.len(),
            )));
        };

        let (num_leading_zeros, plain_coeffs) = skip_leading_zeros(&**poly);

        let commitment =
            E::G1::msm_unchecked(&prover_param.powers_of_g[num_leading_zeros..], plain_coeffs)
                .into_affine();

        Ok(KZG10Commitment {
            com: commitment,
            nv: poly.degree() as u8,
        })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        _commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, E::ScalarField)> {
        let divisor = Self::Poly::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);

        let witness_polynomial = &**polynomial / &divisor;

        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros(&witness_polynomial);

        let proof = E::G1::msm_unchecked(
            &prover_param.borrow().powers_of_g[num_leading_zeros..],
            witness_coeffs,
        )
        .into_affine();

        let eval = polynomial.evaluate(point);

        Ok((Self::Proof { proof }, eval))
    }

    fn multi_open_inner(
        _prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Arc<Self::Poly>],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        _transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<Self::BatchProof> {
        #[cfg(feature = "honest-prover")]
        {
            for (i, ((poly, point), eval)) in polynomials
                .iter()
                .zip(points.iter())
                .zip(evals.iter())
                .enumerate()
            {
                let computed_eval = poly.evaluate(point);
                if computed_eval != *eval {
                    return Err(SnarkError::PCSErrors(PCSError::HonestProver(i)));
                }
            }
        }
        let mut batch_proof = KZG10BatchProof::default();
        polynomials
            .iter()
            .zip(points.iter())
            .zip(evals.iter())
            .for_each(|((poly, point), _)| {
                let (proof, _) = Self::open(_prover_param.borrow(), poly, point, None).unwrap();
                batch_proof.0.push(proof);
            });
        Ok(batch_proof)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify_inner(
        _verifier_param: &Self::VerifierParam,
        _comitments: &[Self::Commitment],
        _points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        _evals: &[E::ScalarField],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        // The output bool is the and of all the individual verifications.
        let mut aggr_res = true;
        _comitments
            .iter()
            .zip(_points.iter())
            .zip(_batch_proof.0.iter())
            .zip(_evals.iter())
            .for_each(|(((commitment, point), proof), value)| {
                let res = Self::verify(_verifier_param, commitment, point, value, proof).unwrap();
                if !res {
                    aggr_res = false;
                }
            });
        Ok(aggr_res)
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        let pairing_inputs: Vec<(E::G1Prepared, E::G2Prepared)> = vec![
            (
                (verifier_param.g.mul(value)
                    - proof.proof.mul(point)
                    - commitment.com.into_group())
                .into_affine()
                .into(),
                verifier_param.h.into(),
            ),
            (proof.proof.into(), verifier_param.beta_h.into()),
        ];

        let p1 = pairing_inputs.iter().map(|(a, _)| a.clone());
        let p2 = pairing_inputs.iter().map(|(_, a)| a.clone());

        let res = E::multi_pairing(p1, p2).0.is_one();

        Ok(res)
    }
}

fn skip_leading_zeros<F: PrimeField, P: DenseUVPolynomial<F>>(p: &P) -> (usize, &[F]) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    (num_leading_zeros, &p.coeffs()[num_leading_zeros..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use ark_std::test_rng;
    use ark_bn254::Bn254;
    fn end_to_end_test_template<E>() -> SnarkResult<()>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = KZG10::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = pp.trim(degree)?;
            let p = <LDE<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(degree, rng);
            let p_arc = Arc::new(p);
            let comm = KZG10::<E>::commit(&ck, &p_arc)?;
            let point = E::ScalarField::rand(rng);
            let (proof, value) = KZG10::<E>::open(&ck, &p_arc, &point, None)?;
            assert!(
                KZG10::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                (*p_arc).degree(),
            );
        }
        Ok(())
    }

    fn linear_polynomial_test_template<E>() -> SnarkResult<()>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let degree = 50;

            let pp = KZG10::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = pp.trim(degree)?;
            let p = <LDE<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(degree, rng);
            let p_arc = Arc::new(p);
            let comm = KZG10::<E>::commit(&ck, &p_arc)?;
            let point = E::ScalarField::rand(rng);
            let (proof, value) = KZG10::<E>::open(&ck, &p_arc, &point, None)?;
            assert!(
                KZG10::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                (*p_arc).degree(),
            );
        }
        Ok(())
    }

    #[test]
    fn end_to_end_test() {
        end_to_end_test_template::<Bn254>().expect("test failed for bn254");
    }

    #[test]
    fn linear_polynomial_test() {
        linear_polynomial_test_template::<Bn254>().expect("test failed for bn254");
    }
}
