//! A PIOP checking that two unions of multiset columns (each weighted by optional
//! multiplicity polynomials) are equal — a generalization of
//! [Logup](https://eprint.iacr.org/2022/1530.pdf), used heavily by other PIOPs.
//!
//! The sums of fractions are proved with LogUp-GKR, which needs no helper
//! commitment. A column and its multiplicity need not have the same size:
//! their term runs over the larger hypercube, the smaller one repeating.

mod honest_prover;
pub(crate) mod reduction;
#[cfg(test)]
mod tests;
use crate::{
    SnarkBackend,
    errors::{
        InputShapeError::{EmptyInput, InputLengthMismatch},
        SnarkError, SnarkResult,
    },
    piop::PIOP,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        ArgVerifier, errors::VerifierError::VerifierInputShapeError, structs::oracle::TrackedOracle,
    },
};
use derivative::Derivative;
use either::Either;
use reduction::{ColumnEvals, KeyedSumRelation, KeyedTerm, prove_keyed_sums, verify_keyed_sums};
use std::marker::PhantomData;
pub struct KeyedSumcheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct KeyedSumcheckProverInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedPoly<B>>,
    pub gxs: Vec<TrackedPoly<B>>,
    pub mfxs: Vec<Option<TrackedPoly<B>>>,
    pub mgxs: Vec<Option<TrackedPoly<B>>>,
}

pub struct KeyedSumcheckVerifierInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedOracle<B>>,
    pub gxs: Vec<TrackedOracle<B>>,
    pub mfxs: Vec<Option<TrackedOracle<B>>>,
    pub mgxs: Vec<Option<TrackedOracle<B>>>,
}

impl<B: SnarkBackend> PIOP<B> for KeyedSumcheck<B> {
    type ProverInput = KeyedSumcheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = KeyedSumcheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        Self::honest_prover_check_helper(&input)
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let relation = KeyedSumRelation {
            fxs: input.fxs.iter().map(KeyedTerm::from).collect(),
            mfxs: input.mfxs.iter().map(optional_term).collect(),
            gxs: input.gxs.iter().map(KeyedTerm::from).collect(),
            mgxs: input.mgxs.iter().map(optional_term).collect(),
        };
        prove_keyed_sums(prover, &[relation], ColumnEvals::new())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // check input shapes are correct
        if input.fxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }
        if input.fxs.len() != input.mfxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.fxs.len(),
                    actual: input.mfxs.len(),
                },
            )));
        }
        if input.gxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }

        if input.gxs.len() != input.mgxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.gxs.len(),
                    actual: input.mgxs.len(),
                },
            )));
        }

        let relation = KeyedSumRelation {
            fxs: input.fxs.iter().map(KeyedTerm::from).collect(),
            mfxs: input.mfxs.iter().map(optional_term).collect(),
            gxs: input.gxs.iter().map(KeyedTerm::from).collect(),
            mgxs: input.mgxs.iter().map(optional_term).collect(),
        };
        verify_keyed_sums(verifier, &[relation])
    }
}

// A constant handle is taken by value and never asked for an id: `id()` on
// one tracks a polynomial, which would move the id counter of whichever side
// happened to ask. Its size is the handle's, the only one it has.
impl<B: SnarkBackend> From<&TrackedPoly<B>> for KeyedTerm<B::F> {
    fn from(poly: &TrackedPoly<B>) -> Self {
        match poly.id_or_const() {
            Either::Left(id) => KeyedTerm::Poly(id),
            Either::Right(value) => KeyedTerm::Constant {
                value,
                nv: poly.log_size(),
            },
        }
    }
}

impl<B: SnarkBackend> From<&TrackedOracle<B>> for KeyedTerm<B::F> {
    fn from(oracle: &TrackedOracle<B>) -> Self {
        match oracle.id_or_const() {
            Either::Left(id) => KeyedTerm::Poly(id),
            Either::Right(value) => KeyedTerm::Constant {
                value,
                nv: oracle.log_size(),
            },
        }
    }
}

fn optional_term<'a, T, F>(term: &'a Option<T>) -> Option<KeyedTerm<F>>
where
    KeyedTerm<F>: From<&'a T>,
{
    term.as_ref().map(KeyedTerm::from)
}
