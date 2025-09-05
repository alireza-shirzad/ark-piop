use std::{cell::RefCell, rc::Rc};

use ark_ff::PrimeField;
use tracing::instrument;

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

    /// Instrumented default wrapper; all impls get this span for free.
    #[instrument(
        level = "debug",
        name = "piop.prove",
        skip(prover, input),
        fields(
            piop = %std::any::type_name::<Self>(),
            mv_pcs = %std::any::type_name::<MvPCS>(),
            uv_pcs = %std::any::type_name::<UvPCS>()
        ),
        err
    )]
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

    /// Make `verify` a default wrapper as well, so we can instrument it once.
    #[instrument(
        level = "debug",
        name = "piop.verify",
        skip(verifier, input),
        fields(
            piop = %std::any::type_name::<Self>(),
            mv_pcs = %std::any::type_name::<MvPCS>(),
            uv_pcs = %std::any::type_name::<UvPCS>()
        ),
        err
    )]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Self::verify_inner(verifier, input)
    }

    // required cores; implement these in each PIOP
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput>;

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput>;

    #[cfg(feature = "honest-prover")]
    #[allow(unused_variables)]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        unimplemented!()
    }
}

/// unchanged
pub trait DeepClone<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self;
}