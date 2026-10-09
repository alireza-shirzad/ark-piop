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
    type Commitment = KZG10Commitment<E>;
    type Proof = KZG10Proof<E>;

    // Batch univariate KZG is not implemented; this is a vector of single proofs.
    type BatchProof = KZG10BatchProof<E>;

    /// Build SRS for testing; `supported_size` is the maximum degree.
    ///
    /// WARNING: TESTING ONLY — the output SRS must not be used in production.
    fn gen_srs_for_testing_inner<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> SnarkResult<Self::SRS> {
        Self::SRS::gen_srs_for_testing(rng, supported_size)
    }

    /// Trim the universal parameters to `supported_degree`.
    /// Panics if `supported_num_vars` is Some or `supported_degree` is None.
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

    /// Generate a commitment for a polynomial. The scheme is not hiding.
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

    /// Produce an opening proof for `polynomial` at `point`.
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

    /// Verifies each `value_i` against the corresponding commitment at `point_i`;
    /// returns the AND of the individual verifications.
    fn batch_verify_inner(
        _verifier_param: &Self::VerifierParam,
        _comitments: &[Self::Commitment],
        _points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        _evals: &[E::ScalarField],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        // One proof per claim: a shorter list would leave claims unchecked.
        let claims = _comitments.len();
        if _points.len() != claims || _evals.len() != claims || _batch_proof.0.len() != claims {
            return Ok(false);
        }
        for (((commitment, point), proof), value) in _comitments
            .iter()
            .zip(_points)
            .zip(&_batch_proof.0)
            .zip(_evals)
        {
            if !Self::verify(_verifier_param, commitment, point, value, proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verifies that `value` is the evaluation at `point` of the committed polynomial.
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
    use ark_bn254::Bn254;
    use ark_std::UniformRand;
    use ark_std::test_rng;
    /// A batch is one proof per claim, each checked: a list that is short
    /// of a proof, or holds a wrong one, is not a proof of the batch.
    #[test]
    fn batch_verify_checks_every_claim() -> SnarkResult<()> {
        type E = Bn254;
        let rng = &mut test_rng();
        let degree = 12;
        let pp = KZG10::<E>::gen_srs_for_testing(rng, degree)?;
        let (ck, vk) = pp.trim(degree)?;
        let mut transcript = Tr::new(b"kzg batch test");
        let polys: Vec<_> = (0..3)
            .map(|_| Arc::new(<LDE<_> as DenseUVPolynomial<_>>::rand(degree, rng)))
            .collect();
        let comms: Vec<_> = polys
            .iter()
            .map(|p| KZG10::<E>::commit(&ck, p))
            .collect::<SnarkResult<_>>()?;
        let points: Vec<_> = (0..3)
            .map(|_| <E as Pairing>::ScalarField::rand(rng))
            .collect();
        let evals: Vec<_> = polys
            .iter()
            .zip(&points)
            .map(|(p, x)| p.evaluate(x))
            .collect();
        let proof = KZG10::<E>::multi_open(&ck, &polys, &points, &evals, &mut transcript)?;
        let mut verify = |evals: &[_], proof: &KZG10BatchProof<E>| {
            KZG10::<E>::batch_verify(&vk, &comms, &points, evals, proof, &mut transcript)
        };
        assert!(verify(&evals, &proof)?);

        let mut short = proof.clone();
        short.0.pop();
        assert!(!verify(&evals, &short)?);
        let mut swapped = proof.clone();
        swapped.0.swap(0, 2);
        assert!(!verify(&evals, &swapped)?);
        let mut wrong = evals.clone();
        wrong[2] += <E as Pairing>::ScalarField::from(1u64);
        assert!(!verify(&wrong, &proof)?);
        assert!(!verify(&evals[..2], &proof)?);
        Ok(())
    }

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
