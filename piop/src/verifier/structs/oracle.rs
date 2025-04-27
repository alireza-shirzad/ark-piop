use ark_ff::PrimeField;
use ark_std::fmt::Debug;
use derivative::Derivative;
use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::DbSnResult,
    pcs::PCS,
    structs::TrackerID,
    verifier::tracker::VerifierTracker,
};

////////////////////////////// Structs & Enums //////////////////////////////

pub trait CloneableFn<F: 'static, In>: Fn(In) -> DbSnResult<F> + Send + Sync {
    fn clone_box(&self) -> Box<dyn CloneableFn<F, In>>;
}

impl<F: 'static, In: 'static, T> CloneableFn<F, In> for T
where
    T: Fn(In) -> DbSnResult<F> + Clone + Send + Sync + 'static,
{
    fn clone_box(&self) -> Box<dyn CloneableFn<F, In>> {
        Box::new(self.clone())
    }
}

impl<F: 'static, In: 'static> Clone for Box<dyn CloneableFn<F, In>> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub enum Oracle<F: 'static> {
    Univariate(Arc<dyn CloneableFn<F, F>>),
    Multivariate(Arc<dyn CloneableFn<F, Vec<F>>>),
}
impl<F: 'static> Clone for Oracle<F> {
    fn clone(&self) -> Self {
        match self {
            Oracle::Univariate(f) => Oracle::Univariate(f.clone()),
            Oracle::Multivariate(f) => Oracle::Multivariate(f.clone()),
        }
    }
}
////////////////////////////////////////////

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"))]
#[derivative(Clone(bound = "UvPCS: PCS<F>"))]
pub struct TrackedOracle<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub id: TrackerID,
    pub tracker: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>,
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Debug for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedOracle")
            .field("id", &self.id)
            .finish()
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS> PartialEq for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS> TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(id: TrackerID, tracker: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>) -> Self {
        let new_comm: TrackedOracle<F, MvPCS, UvPCS> = Self { id, tracker };
        new_comm
    }

    pub fn same_tracker(&self, other: &TrackedOracle<F, MvPCS, UvPCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedOracle<F, MvPCS, UvPCS>) {
        assert!(
            self.same_tracker(other),
            "TrackedOracles are not from the same tracker"
        );
    }

    pub fn add_oracles(&self, other: &TrackedOracle<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        let res_id = self.tracker.borrow_mut().add_oracles(self.id, other.id);
        TrackedOracle::new(res_id, self.tracker.clone())
    }

    pub fn sub_oracles(&self, other: &TrackedOracle<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        let res_id = self.tracker.borrow_mut().sub_oracles(self.id, other.id);
        TrackedOracle::new(res_id, self.tracker.clone())
    }

    pub fn mul_oracles(&self, other: &TrackedOracle<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        let res_id = self.tracker.borrow_mut().mul_oracles(self.id, other.id);
        TrackedOracle::new(res_id, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: F) -> TrackedOracle<F, MvPCS, UvPCS> {
        let res_id = self.tracker.borrow_mut().add_scalar(self.id, c);
        TrackedOracle::new(res_id, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: F) -> TrackedOracle<F, MvPCS, UvPCS> {
        let res_id = self.tracker.borrow_mut().mul_scalar(self.id, c);
        TrackedOracle::new(res_id, self.tracker.clone())
    }
}
