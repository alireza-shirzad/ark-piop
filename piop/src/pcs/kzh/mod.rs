pub(crate) mod srs;
pub mod structs;
#[cfg(test)]
mod tests;
use crate::arithmetic::mat_poly::utils::build_eq_x_r;
use crate::errors::SnarkError;
use crate::errors::SnarkResult;
use crate::pcs::errors::PCSError;
use crate::pcs::kzh::srs::KZH2ProverParam;
use crate::pcs::kzh::srs::KZH2UniversalParams;
use crate::pcs::kzh::srs::KZH2VerifierParam;
use crate::pcs::pst13::batching::MlBatchProof;
use crate::pcs::pst13::batching::batch_verify_internal;
use crate::pcs::pst13::structs::Commitment;
use crate::prover;
use crate::{
    arithmetic::{f_short_str, f_vec_short_str, mat_poly::utils::evaluate_opt},
    pcs::{PCS, StructuredReferenceString},
    transcript::Tr,
    util::display::short_vec_str,
};
use ark_ec::{
    AffineRepr, CurveGroup, ScalarMul, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::{One, Zero};
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::cfg_chunks;
use ark_std::cfg_iter_mut;
use ark_std::{end_timer, rand::Rng, start_timer};
use macros::timed;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelSlice;
use std::ops::Neg;
use std::{borrow::Borrow, marker::PhantomData, ops::Mul, sync::Arc};
use structs::KZH2AuxInfo;
use structs::KZH2Commitment;
use structs::KZH2OpeningProof;
// use batching::{batch_verify_internal, multi_open_internal};
/// KZG Polynomial Commitment Scheme on multilinear polynomials.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZH2<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PCS<E::ScalarField> for KZH2<E> {
    // Parameters
    type ProverParam = KZH2ProverParam<E>;
    type VerifierParam = KZH2VerifierParam<E>;
    type SRS = KZH2UniversalParams<E>;
    // Polynomial and its associated types
    type Poly = DenseMultilinearExtension<E::ScalarField>;
    // Commitments and proofs
    type Commitment = KZH2Commitment<E>;
    type Proof = KZH2OpeningProof<E>;
    type BatchProof = MlBatchProof<E, Self>;

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> SnarkResult<Self::SRS> {
        KZH2UniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        _supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        let srs = srs.borrow();
        let supp_nv = supported_num_vars.unwrap();
        assert_eq!(srs.nu() + srs.mu(), supp_nv);
        Ok((
            srs.extract_prover_param(supp_nv),
            srs.extract_verifier_param(supp_nv),
        ))
    }

    #[timed("nv:",poly.num_vars())]
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        let com = E::G1::msm_unchecked(prover_param.h_mat(), &poly.to_evaluations());
        Ok(KZH2Commitment::new(com.into(), poly.num_vars()))
    }

    #[timed("nv:", polynomial.num_vars())]
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        _commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(KZH2OpeningProof<E>, E::ScalarField)> {
        let aux = comp_aux(prover_param.borrow(), polynomial, point)?;
        let (f_star, z0) = open_internal(prover_param.borrow(), polynomial, point)?;
        Ok((KZH2OpeningProof::new(f_star, aux), z0))
    }

    #[timed("nv:", polynomials.iter().map(|p| p.num_vars()).collect::<Vec<usize>>())]
    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Arc<Self::Poly>],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<MlBatchProof<E, Self>> {
        todo!()
    }

    #[timed]
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        let (x0, y0) = point.split_at(verifier_param.nu());
        // Check 1: Pairing check for commitment switching
        let g1_pairing_elements =
            std::iter::once(commitment.commitment()).chain(proof.aux().d());
        let g2_pairing_elements = std::iter::once(verifier_param.minus_v_prime())
            .chain(verifier_param.v_vec().iter().copied());
        assert!(E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero());

        // Check 2: Hyrax Check
        let eq_x0_mle = build_eq_x_r(x0).unwrap();

        let scalars: Vec<E::ScalarField> = proof
            .f_star()
            .evaluations
            .iter()
            .copied()
            .chain(eq_x0_mle.evaluations().iter().map(|&x| -x))
            .collect();
        let bases: Vec<E::G1Affine> = verifier_param
            .h_vec()
            .iter()
            .copied()
            .chain(proof.aux().d())
            .rev()
            .collect();

        assert!(E::G1::msm_unchecked(&bases, &scalars).is_zero());

        // Check 3: Evaluate polynomial at point
        assert_eq!(proof.f_star().evaluate(&y0.to_vec()), *value);
        Ok(true)
    }

    #[timed("comms:", short_vec_str(commitments))]
    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        todo!()
    }
}

#[timed("point: ", f_vec_short_str(point))]
fn comp_aux<E: Pairing>(
    prover_param: &KZH2ProverParam<E>,
    polynomial: &DenseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> SnarkResult<KZH2AuxInfo<E>> {
    let mut d = vec![E::G1Affine::zero(); 1 << prover_param.nu()];
    let evaluations = polynomial.evaluations.clone();
    cfg_iter_mut!(d)
        .zip(cfg_chunks!(evaluations, 1 << prover_param.mu()))
        .for_each(|(d, f)| {
            *d = E::G1::msm_unchecked(prover_param.h_vec(), f).into_affine();
        });
    Ok(KZH2AuxInfo::new(d))
}

#[timed("point: ", f_vec_short_str(point))]
fn open_internal<E: Pairing>(
    prover_param: &KZH2ProverParam<E>,
    polynomial: &DenseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> SnarkResult<(DenseMultilinearExtension<E::ScalarField>, E::ScalarField)> {
    let (x0, y0) = point.split_at(prover_param.nu());
    let poly_fixed_at_x0 = polynomial.fix_variables(x0);
    let z0 = poly_fixed_at_x0.evaluate(&y0.to_vec());
    Ok((poly_fixed_at_x0, z0))
}

#[timed("point: ", f_vec_short_str(point), ",value: ", f_short_str(*value))]
fn verify_internal<E: Pairing>(
    verifier_param: &KZH2VerifierParam<E>,
    commitment: &Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &KZH2OpeningProof<E>,
) -> SnarkResult<bool> {
    todo!()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqPolynomial<F: Field + Copy> {
    pub r: Vec<F>,
}

impl<F: Field + Copy> EqPolynomial<F> {
    /// Creates a new EqPolynomial from a vector `w`
    pub fn new(r: Vec<F>) -> Self {
        EqPolynomial { r }
    }

    /// Evaluates the polynomial eq_w(r) = prod_{i} (w_i * r_i + (F::ONE - w_i) * (F::ONE - r_i))
    pub fn evaluate(&self, rx: &[F]) -> F {
        assert_eq!(self.r.len(), rx.len());
        (0..rx.len())
            .map(|i| self.r[i] * rx[i] + (F::one() - self.r[i]) * (F::one() - rx[i]))
            .product()
    }

    pub fn evals(&self) -> Vec<F> {
        let ell = self.r.len();

        let mut evals: Vec<F> = vec![F::one(); 1 << ell];
        let mut size = 1;
        for j in 0..ell {
            // in each iteration, we double the size of chis
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                // copy each element from the prior iteration twice
                let scalar = evals[i / 2];
                evals[i] = scalar * self.r[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }

    pub fn compute_factored_lens(ell: usize) -> (usize, usize) {
        (ell / 2, ell - ell / 2)
    }

    pub fn compute_factored_evals(&self) -> (Vec<F>, Vec<F>) {
        let ell = self.r.len();
        let (left_num_vars, _right_num_vars) = Self::compute_factored_lens(ell);

        let L = EqPolynomial::new(self.r[..left_num_vars].to_vec()).evals();
        let R = EqPolynomial::new(self.r[left_num_vars..ell].to_vec()).evals();

        (L, R)
    }
}
