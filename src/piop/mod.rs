//! A General Purpose PIOP abstraction.

use ark_ff::PrimeField;
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
/// Any PIOP must implement this trait.
/// Helper to get a type name without generic parameters.
#[inline]
pub(crate) fn type_name_without_generics<T>() -> &'static str {
    let full = std::any::type_name::<T>();
    match full.split_once('<') {
        Some((before, _)) => before,
        None => full,
    }
}
/// Any PIOP must implement this trait.
pub trait PIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>:
    Sized
{
    type ProverInput: DeepClone<F, MvPCS, UvPCS> + std::fmt::Debug;
    type ProverOutput;
    type VerifierOutput;
    type VerifierInput;
    /// Proves the PIOP.
    ///
    /// This is a default wrapper that adds tracing instrumentation and (optionally) honest prover checks for any PIOP.
    fn prove(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let struct_name = type_name_without_generics::<Self>();
        let span = if tracing::level_enabled!(Level::TRACE) {
            span!(Level::TRACE, "piop.prove", piop = struct_name, ?input)
        } else {
            // span name must be a string literal; record dynamic type name as a field instead
            span!(Level::DEBUG, "piop.prove", piop = struct_name)
        };
        let _guard = span.enter();
        #[cfg(feature = "honest-prover")]
        {
            // Nested span for honest prover check so it's visible alongside prove/verify.
            let _hp_guard =
                span!(Level::TRACE, "piop.honest_prover_check", piop = struct_name).entered();
            let new_prover = prover.deep_copy();
            let res = Self::honest_prover_check(input.deep_clone(new_prover));
            if let Err(ref e) = res {
                tracing::error!(
                    parent: &span,
                    piop = struct_name,
                    error = %e,
                    "honest prover check failed"
                );
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

    /// Verifies the PIOP.
    ///
    /// This is a default wrapper that adds automatic tracing instrumentation for any PIOP.
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let struct_name = type_name_without_generics::<Self>();
        let span = if tracing::level_enabled!(Level::TRACE) {
            span!(Level::TRACE, "piop.verify", piop = struct_name,)
        } else {
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

    /// The actual implementation of the prover logic.
    ///
    /// This will be wrapped by `prove`, which adds tracing instrumentation and (optionally) honest prover checks for any PIOP.
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput>;

    /// The actual implementation of the verifier logic.
    ///
    /// This will be wrapped by `verify`, which adds automatic tracing instrumentation for any PIOP.
    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput>;

    /// An optional honest prover check that runs the prover logic in a fresh prover instance and checks that it succeeds.
    ///
    /// This is useful for testing and debugging, but is costly and should not be enabled in production. The prover passed to the honest prover check is a deep copy of the original prover, so it won't interfere with the actual protocol state.
    #[cfg(feature = "honest-prover")]
    #[allow(unused_variables)]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        unimplemented!()
    }
}

/// This trait only used for deep cloning PIOP prover inputs.
///
/// Simply cloning the prover input interferes with the actual state of the prover in the protocol. Hence for honest prover checks we need to create a new prover instance and deep clone the input with this new prover instance.
pub trait DeepClone<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> {
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self;
}
