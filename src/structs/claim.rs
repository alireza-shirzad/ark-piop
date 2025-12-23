/////////// Imports ///////////
use super::TrackerID;
use crate::pcs::PCS;
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use derivative::Derivative;

/////////// Structs ///////////

/// A claim that a polynomial evaluates to a certain value at a certain point.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct TrackerEvalClaim<F: PrimeField, PC: PCS<F>> {
    pub label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub point: <PC::Poly as Polynomial<F>>::Point,
    pub eval: F,
}

impl<F: PrimeField, PC: PCS<F>> TrackerEvalClaim<F, PC> {
    pub fn new(label: TrackerID, point: <PC::Poly as Polynomial<F>>::Point, eval: F) -> Self {
        Self { label, point, eval }
    }
}

/// A claim that the sum of the evaluations of a polynomial on the boolean
/// hypercube is equal to a certain value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerSumcheckClaim<F: PrimeField> {
    id: TrackerID,
    claim: F,
}

impl<F: PrimeField> TrackerSumcheckClaim<F> {
    pub(crate) fn new(id: TrackerID, claim: F) -> Self {
        Self { id, claim }
    }
    pub(crate) fn claim(&self) -> F {
        self.claim
    }
    pub(crate) fn id(&self) -> TrackerID {
        self.id
    }
    pub(crate) fn set_claim(&mut self, claim: F) {
        self.claim = claim;
    }
}

/// A claim that a polynomial is zero at a certain point.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerZerocheckClaim {
    id: TrackerID,
}

impl TrackerZerocheckClaim {
    pub(crate) fn new(id: TrackerID) -> Self {
        Self { id }
    }
    pub(crate) fn id(&self) -> TrackerID {
        self.id
    }
}

/// A claim that a super polynomial contains all the entries of a sub polynomial.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerLookupClaim {
    super_poly: TrackerID,
    sub_poly: TrackerID,
}

impl TrackerLookupClaim {
    pub(crate) fn new(super_poly: TrackerID, sub_poly: TrackerID) -> Self {
        Self {
            super_poly,
            sub_poly,
        }
    }
    pub(crate) fn super_poly(&self) -> TrackerID {
        self.super_poly
    }
    pub(crate) fn sub_poly(&self) -> TrackerID {
        self.sub_poly
    }
}
