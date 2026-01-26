use crate::structs::TrackerID;

pub mod hp_interface;
use derivative::Derivative;
use std::ops::{Deref, DerefMut};
use std::slice;
/////////////////// Types ///////////////////
#[derive(Derivative)]
#[derivative(Clone(bound = "F: Clone"))]
#[derivative(Default(bound = ""))]
#[derivative(Debug(bound = "F: std::fmt::Debug"))]
pub(crate) struct VirtualPoly<F>(Vec<(F, Vec<TrackerID>)>);

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
