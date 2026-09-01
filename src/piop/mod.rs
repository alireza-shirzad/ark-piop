//! Polynomial Interactive Oracle Proof (PIOP) trait and sub-protocols.
//!
//! The [`PIOP`] trait is the main abstraction for implementing custom
//! interactive proof protocols.  Sub-protocols like sumcheck and lookup-check
//! are provided as reusable building blocks.

use tracing::{Level, span};

use crate::{SnarkBackend, errors::SnarkResult, prover::ArgProver, verifier::ArgVerifier};
pub mod errors;
pub mod keyed_sumcheck;
pub mod lookup_check;
pub mod structs;
pub mod sum_check;
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
pub trait PIOP<B: SnarkBackend>: Sized {
    type ProverInput: DeepClone<B> + std::fmt::Debug;
    type ProverOutput;
    type VerifierOutput;
    type VerifierInput;
    /// Proves the PIOP: a default wrapper around [`Self::prove_inner`] adding tracing
    /// and (optionally) honest-prover checks.
    fn prove(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let struct_name = type_name_without_generics::<Self>();
        let span = if tracing::level_enabled!(Level::TRACE) {
            span!(Level::TRACE, "piop.prove", piop = struct_name, ?input)
        } else {
            // Span names must be string literals; the dynamic type name is a field.
            span!(Level::DEBUG, "piop.prove", piop = struct_name)
        };
        let _guard = span.enter();
        #[cfg(feature = "honest-prover")]
        {
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

        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "prove failed");
        }
        res
    }

    /// Verifies the PIOP: a default wrapper around [`Self::verify_inner`] adding
    /// tracing instrumentation.
    fn verify(
        verifier: &mut ArgVerifier<B>,
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

        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "verify failed");
        }
        res
    }

    /// The actual prover logic, wrapped by [`Self::prove`].
    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput>;

    /// The actual verifier logic, wrapped by [`Self::verify`].
    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput>;

    /// Optional honest-prover check, run on a deep copy of the prover so it cannot
    /// interfere with protocol state. Costly — for testing/debugging only.
    #[cfg(feature = "honest-prover")]
    #[allow(unused_variables)]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        unimplemented!()
    }
}

/// Deep-clones PIOP prover inputs against a fresh prover instance — a plain clone
/// would interfere with the real prover's protocol state during honest-prover checks.
pub trait DeepClone<B: SnarkBackend> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self;
}
