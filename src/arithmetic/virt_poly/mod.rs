//! Symbolic representation of virtual (sum-of-products) polynomials.
//!
//! A [`VirtualPoly`] records only the *structure* `sum_i c_i * prod_j p_{i,j}`,
//! each factor identified by its [`TrackerID`]; the actual polynomial data
//! lives in the prover or verifier tracker. Used on both sides (prover factors
//! are MLEs, verifier factors are oracle handles).

use crate::types::TrackerID;

pub mod hp_interface;
use derivative::Derivative;
use std::ops::{Deref, DerefMut};
use std::slice;

/// A symbolic sum-of-products polynomial expression: each entry
/// `(coefficient, factors)` is one product term, with factors given as
/// [`TrackerID`]s referencing tracked polynomials or oracles.
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
