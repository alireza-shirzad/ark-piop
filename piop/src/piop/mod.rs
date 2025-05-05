use std::{cell::RefCell, rc::Rc};

use ark_ff::PrimeField;

use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
    verifier::Verifier,
};
pub mod errors;
pub mod structs;
pub mod sum_check;

pub trait PIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    type ProverInput: DeepClone<F, MvPCS, UvPCS>;
    type ProverOutput;
    type VerifierOutput;
    type VerifierInput;
    fn prove(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        #[cfg(feature = "honest-prover")]
        {
            let new_prover = prover.deep_copy();
            Self::honest_prover_check(input.deep_clone(new_prover))?;
        }
        Self::prove_inner(prover, input)
    }

    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput>;

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput>;

    #[cfg(feature = "honest-prover")]
    #[allow(unused_variables)]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        unimplemented!()
    }
}

/// A trait for deep cloning objects. This is only implemented for ProverInputs so that the honest-prover checks do not interefer with the prover state.
pub trait DeepClone<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self;
}
