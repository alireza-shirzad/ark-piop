use ark_ff::PrimeField;
#[cfg(feature = "honest-prover")]
use tracing::instrument;
use tracing::{Level, span};

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
pub trait PIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>:
    Sized
{
    type ProverInput: DeepClone<F, MvPCS, UvPCS> + std::fmt::Debug;
    type ProverOutput;
    type VerifierOutput;
    type VerifierInput;
    fn type_name_without_generics<T>() -> &'static str {
        let full = std::any::type_name::<T>();
        match full.split_once('<') {
            Some((before, _)) => before,
            None => full,
        }
    }
    /// Instrumented default wrapper; all impls get this span for free.
    fn prove(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let span = if tracing::level_enabled!(Level::TRACE) {
            span!(
                Level::TRACE,
                "piop.prove",
                piop = Self::type_name_without_generics::<Self>(),
                ?input
            )
        } else {
            let struct_name = Self::type_name_without_generics::<Self>();
            // span name must be a string literal; record dynamic type name as a field instead
            span!(Level::DEBUG, "piop.prove", piop = struct_name)
        };
        let _guard = span.enter();
        #[cfg(feature = "honest-prover")]
        {
            // Nested span for honest prover check so it's visible alongside prove/verify.
            let _hp_guard = span!(Level::TRACE, "piop.honest_prover_check",).entered();
            let new_prover = prover.deep_copy();
            let res = Self::honest_prover_check(input.deep_clone(new_prover));
            if let Err(ref e) = res {
                tracing::error!(parent: &span, error = %e, "honest prover check failed");
            }
            drop(_hp_guard);
            res?
        }
        let res = Self::prove_inner(prover, input);

        // Optional: record errors on the span without spamming trace
        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "prove failed");
        }
        res
    }

    /// Make `verify` a default wrapper as well, so we can instrument it once.
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let span = if tracing::level_enabled!(Level::TRACE) {
            span!(
                Level::TRACE,
                "piop.verify",
                piop = Self::type_name_without_generics::<Self>(),
            )
        } else {
            let struct_name = Self::type_name_without_generics::<Self>();
            span!(Level::DEBUG, "piop.verify", piop = struct_name)
        };
        let _guard = span.enter();
        let res = Self::verify_inner(verifier, input);

        // Optional: record errors on the span without spamming trace
        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "verify failed");
        }
        res
    }

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
