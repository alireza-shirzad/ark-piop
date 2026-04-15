//! Symbolic representation of virtual (sum-of-products) polynomials.
//!
//! A [`VirtualPoly`] stores a polynomial expression of the form
//!
//! ```text
//!   sum_i  c_i * prod_j  p_{i,j}
//! ```
//!
//! where each `c_i` is a scalar coefficient and each `p_{i,j}` is identified
//! by its [`TrackerID`].  The actual polynomial data (evaluations, commitments,
//! oracle closures) lives in the prover or verifier tracker; `VirtualPoly`
//! only records the *structure* of the expression.
//!
//! This type is used on **both** the prover side (where factors are MLEs) and
//! the verifier side (where factors are oracle handles).  It was historically
//! called `VirtualOracle` on the verifier side; that name is kept as a type
//! alias for backward compatibility.

use crate::types::TrackerID;

pub mod hp_interface;
use derivative::Derivative;
use std::ops::{Deref, DerefMut};
use std::slice;

/// A symbolic sum-of-products polynomial expression.
///
/// Each entry `(coefficient, factors)` represents a product term:
/// `coefficient * factors[0] * factors[1] * ...` where each factor is a
/// [`TrackerID`] referencing a tracked polynomial or oracle.
///
/// The full polynomial is the sum of all such terms.
///
/// Used identically on both the prover and verifier sides of the protocol.
#[derive(Derivative)]
#[derivative(Clone(bound = "F: Clone"))]
#[derivative(Default(bound = ""))]
#[derivative(Debug(bound = "F: std::fmt::Debug"))]
pub struct VirtualPoly<F>(Vec<(F, Vec<TrackerID>)>);

impl<F> VirtualPoly<F> {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
}

impl<F> Deref for VirtualPoly<F> {
    type Target = Vec<(F, Vec<TrackerID>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> DerefMut for VirtualPoly<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, F> IntoIterator for &'a VirtualPoly<F> {
    type Item = &'a (F, Vec<TrackerID>);
    type IntoIter = slice::Iter<'a, (F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, F> IntoIterator for &'a mut VirtualPoly<F> {
    type Item = &'a mut (F, Vec<TrackerID>);
    type IntoIter = slice::IterMut<'a, (F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<F> IntoIterator for VirtualPoly<F> {
    type Item = (F, Vec<TrackerID>);
    type IntoIter = std::vec::IntoIter<(F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
