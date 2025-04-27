use errors::PolyIOPErrors;

use crate::{
    arithmetic::{
        ark_ff::PrimeField,
        mat_poly::{lde::LDE, mle::MLE},
    },
    errors::DbSnResult,
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
    ) -> DbSnResult<Self::ProverOutput> {
        #[cfg(feature = "honest-prover")]
        {
            Self::honest_prover_check(&input)?;
        }
        Self::prove_inner(prover, input)
    }

    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> DbSnResult<Self::VerifierOutput>;

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> DbSnResult<Self::ProverOutput>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: &Self::ProverInput) -> DbSnResult<()> {
        unimplemented!()
    }
}
