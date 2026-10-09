//! A PIOP checking that two unions of multiset columns (each weighted by optional
//! multiplicity polynomials) are equal — a generalization of
//! [Logup](https://eprint.iacr.org/2022/1530.pdf), used heavily by other PIOPs.
//!
//! The sums of fractions are proved by the lookup protocol the two sides
//! are configured for ([`LookupProtocol`](crate::types::LookupProtocol)):
//! LogUp-GKR, which needs no helper commitment, or LogUp with a committed
//! helper per column. Under either, a column and its multiplicity need not
//! have the same size: their term runs over the larger hypercube, the
//! smaller one repeating.
//!
//! Proving the PIOP reduces its relation on the spot, in a batch of its
//! own. [`ArgProver::add_mv_keyed_sum_claim`] and its verifier counterpart
//! take the same inputs and leave the relation to the one batch the proof
//! reduces its lookup claims in.

mod honest_prover;
mod logup;
pub(crate) mod reduction;
#[cfg(test)]
mod tests;
use crate::{
    SnarkBackend,
    errors::{
        InputShapeError::{self, EmptyInput, InputLengthMismatch},
        SnarkError, SnarkResult,
    },
    piop::PIOP,
    prover::{
        ArgProver,
        errors::{HonestProverError::WrongInputShape, ProverError},
        structs::polynomial::TrackedPoly,
    },
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
        // The verifier refuses these shapes before it reads the proof, and
        // so does the deferred claim: nothing is written for them here.
        input
            .check_shape()
            .map_err(|shape| ProverError::HonestProverError(WrongInputShape(shape)))?;
        prove_keyed_sums(prover, &[input.relation()], ColumnEvals::new())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        input
            .check_shape()
            .map_err(|shape| SnarkError::VerifierError(VerifierInputShapeError(shape)))?;
        verify_keyed_sums(verifier, &[input.relation()])
    }
}

/// Each side of a keyed sum needs a column, and a multiplicity slot per
/// column. The lengths are those of `fxs`, `mfxs`, `gxs` and `mgxs`.
fn check_shape([fxs, mfxs, gxs, mgxs]: [usize; 4]) -> Result<(), InputShapeError> {
    for (cols, mults) in [(fxs, mfxs), (gxs, mgxs)] {
        if cols == 0 {
            return Err(EmptyInput);
        }
        if cols != mults {
            return Err(InputLengthMismatch {
                expected: cols,
                actual: mults,
            });
        }
    }
    Ok(())
}

impl<B: SnarkBackend> KeyedSumcheckProverInput<B> {
    pub(crate) fn check_shape(&self) -> Result<(), InputShapeError> {
        check_shape([
            self.fxs.len(),
            self.mfxs.len(),
            self.gxs.len(),
            self.mgxs.len(),
        ])
    }

    /// The relation the input states, by tracker id.
    pub(crate) fn relation(&self) -> KeyedSumRelation<B::F> {
        KeyedSumRelation {
            fxs: self.fxs.iter().map(KeyedTerm::from).collect(),
            mfxs: self.mfxs.iter().map(optional_term).collect(),
            gxs: self.gxs.iter().map(KeyedTerm::from).collect(),
            mgxs: self.mgxs.iter().map(optional_term).collect(),
        }
    }
}

impl<B: SnarkBackend> KeyedSumcheckVerifierInput<B> {
    pub(crate) fn check_shape(&self) -> Result<(), InputShapeError> {
        check_shape([
            self.fxs.len(),
            self.mfxs.len(),
            self.gxs.len(),
            self.mgxs.len(),
        ])
    }

    /// The relation the input states, by tracker id.
    pub(crate) fn relation(&self) -> KeyedSumRelation<B::F> {
        KeyedSumRelation {
            fxs: self.fxs.iter().map(KeyedTerm::from).collect(),
            mfxs: self.mfxs.iter().map(optional_term).collect(),
            gxs: self.gxs.iter().map(KeyedTerm::from).collect(),
            mgxs: self.mgxs.iter().map(optional_term).collect(),
        }
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
