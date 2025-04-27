use super::PCS;
use crate::arithmetic::mat_poly::lde::LDE;
use crate::{
    arithmetic::{
        ark_ff::PrimeField,
        ark_poly::{DenseUVPolynomial, Polynomial},
    },
    pcs::PCSError,
};
use ark_ec::{
    AffineRepr, CurveGroup, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::start_timer;
use macros::timed;
use srs::{UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam};
use std::{borrow::Borrow, ops::Mul, sync::Arc};
pub(crate) mod srs;
use crate::{
    pcs::{Rng, StructuredReferenceString, structs::Commitment},
    transcript::Tr,
};
use ark_std::{end_timer, marker::PhantomData};
/// KZG Polynomial Commitment Scheme on univariate polynomial.
pub struct KZG10<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct KZG10Proof<E: Pairing> {
    /// Evaluation of quotients
    pub proof: E::G1Affine,
}
impl<E: Pairing> Default for KZG10Proof<E> {
    fn default() -> Self {
        Self {
            proof: E::G1Affine::zero(),
        }
    }
}
/// batch proof
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct KZG10BatchProof<E: Pairing>(Vec<KZG10Proof<E>>);

impl<E: Pairing> Default for KZG10BatchProof<E> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<E: Pairing> PCS<E::ScalarField> for KZG10<E> {
    // Parameters
    type ProverParam = UnivariateProverParam<E::G1Affine>;
    type VerifierParam = UnivariateVerifierParam<E>;
    type SRS = UnivariateUniversalParams<E>;
    // Polynomial and its associated types
    type Poly = LDE<E::ScalarField>;
    // Polynomial and its associated types
    type Commitment = Commitment<E>;
    type Proof = KZG10Proof<E>;

    // We do not implement batch univariate KZG at the current version.
    type BatchProof = KZG10BatchProof<E>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::gen_srs_for_testing(rng, supported_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input `max_degree` for univariate.
    /// `supported_num_vars` must be None or an error is returned.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        assert!(supported_num_vars.is_none());
        if supported_num_vars.is_some() {
            return Err(PCSError::InvalidParameters(
                "univariate should not receive a num_var param".to_string(),
            ));
        }
        srs.borrow().trim(supported_degree.unwrap())
    }

    /// Generate a commitment for a polynomial
    /// Note that the scheme is not hiding
    #[timed]
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_time = if poly.degree() >= prover_param.powers_of_g.len() {
            return Err(PCSError::InvalidParameters(format!(
                "uni poly degree {} is larger than allowed {}",
                poly.degree(),
                prover_param.powers_of_g.len()
            )));
        };

        let (num_leading_zeros, plain_coeffs) = skip_leading_zeros(&**poly);

        let commitment =
            E::G1::msm_unchecked(&prover_param.powers_of_g[num_leading_zeros..], plain_coeffs)
                .into_affine();

        Ok(Commitment {
            com: commitment,
            nv: poly.degree(),
        })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    #[timed]
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
    ) -> Result<(Self::Proof, E::ScalarField), PCSError> {
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

    fn multi_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: &[Arc<Self::Poly>],
        _points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        _evals: &[E::ScalarField],
        _transcript: &mut Tr<E::ScalarField>,
    ) -> Result<Self::BatchProof, PCSError> {
        let mut batch_proof = KZG10BatchProof::default();
        _polynomials
            .iter()
            .zip(_points.iter())
            .zip(_evals.iter())
            .for_each(|((poly, point), eval)| {
                let (proof, eval) = Self::open(_prover_param.borrow(), poly, point).unwrap();
                batch_proof.0.push(proof);
            });
        Ok(batch_proof)
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    #[timed]
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
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
    use crate::arithmetic::ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Bls12_381;

    fn end_to_end_test_template<E>() -> Result<(), PCSError>
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
            let (proof, value) = KZG10::<E>::open(&ck, &p_arc, &point)?;
            assert!(
                KZG10::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                (*p_arc).degree(),
            );
        }
        Ok(())
    }

    fn linear_polynomial_test_template<E>() -> Result<(), PCSError>
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
            let (proof, value) = KZG10::<E>::open(&ck, &p_arc, &point)?;
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
        end_to_end_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn linear_polynomial_test() {
        linear_polynomial_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }
}
