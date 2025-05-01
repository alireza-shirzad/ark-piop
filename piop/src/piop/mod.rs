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
    type ProverInput;
    type ProverOutput;
    type VerifierOutput;
    type VerifierInput;
    fn prove(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        #[cfg(feature = "honest-prover")]
        {
            Self::honest_prover_check(&input)?;
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
    fn honest_prover_check(input: &Self::ProverInput) -> SnarkResult<()> {
        unimplemented!()
    }
}
