use crate::impl_assign_oracle;
use crate::impl_assign_scalar;
use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    structs::TrackerID,
    verifier::tracker::VerifierTracker,
};
use ark_ff::PrimeField;
use ark_std::fmt::Debug;
use derivative::Derivative;
use std::ops::MulAssign;
use std::{
    cell::RefCell,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
    rc::Rc,
    sync::Arc,
};

////////////////////////////// Structs & Enums //////////////////////////////

pub trait CloneableFn<F: 'static, In>: Fn(In) -> SnarkResult<F> + Send + Sync {
    fn clone_box(&self) -> Box<dyn CloneableFn<F, In>>;
}

impl<F: 'static, In: 'static, T> CloneableFn<F, In> for T
where
    T: Fn(In) -> SnarkResult<F> + Clone + Send + Sync + 'static,
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

impl<F, MvPCS, UvPCS> Neg for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;
    #[inline]
    fn neg(self) -> Self::Output {
        let id = self.tracker.borrow_mut().mul_scalar(self.id, -F::one());
        TrackedOracle::new(id, self.tracker)
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
}

#[macro_export]
macro_rules! impl_assign_oracle {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<F, MvPCS, UvPCS> $trait_<&Self> for TrackedOracle<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            #[inline]
            fn $fn_(&mut self, rhs: &Self) {
                self.assert_same_tracker(rhs);
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs.id);
                self.id = new_id;
            }
        }
    };
}
#[macro_export]
macro_rules! impl_assign_scalar {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<F, MvPCS, UvPCS> std::ops::$trait_<F> for TrackedOracle<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            #[inline]
            fn $fn_(&mut self, rhs: F) {
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs);
                self.id = new_id;
            }
        }
    };
}

macro_rules! impl_binop_oracle {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<'a, F, MvPCS, UvPCS> std::ops::$trait_<&'a TrackedOracle<F, MvPCS, UvPCS>>
            for &'a TrackedOracle<F, MvPCS, UvPCS>
        where
            F: ark_ff::PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            type Output = TrackedOracle<F, MvPCS, UvPCS>;
            #[inline]
            fn $fn_(self, rhs: &'a TrackedOracle<F, MvPCS, UvPCS>) -> Self::Output {
                self.assert_same_tracker(rhs);
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs.id);
                TrackedOracle::new(new_id, self.tracker.clone())
            }
        }
    };
}

macro_rules! impl_binop_scalar {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<'a, F, MvPCS, UvPCS> std::ops::$trait_<F> for &'a TrackedOracle<F, MvPCS, UvPCS>
        where
            F: ark_ff::PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            type Output = TrackedOracle<F, MvPCS, UvPCS>;
            #[inline]
            fn $fn_(self, rhs: F) -> Self::Output {
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs);
                TrackedOracle::new(new_id, self.tracker.clone())
            }
        }
    };
}

impl_binop_oracle!(Add, add, add_oracles);
impl_binop_oracle!(Sub, sub, sub_oracles);
impl_binop_oracle!(Mul, mul, mul_oracles);
impl_binop_scalar!(Add, add, add_scalar);
impl_binop_scalar!(Sub, sub, sub_scalar);
impl_binop_scalar!(Mul, mul, mul_scalar);
impl_assign_oracle!(AddAssign, add_assign, add_oracles);
impl_assign_oracle!(SubAssign, sub_assign, sub_oracles);
impl_assign_oracle!(MulAssign, mul_assign, mul_oracles);
impl_assign_scalar!(AddAssign, add_assign, add_scalar);
impl_assign_scalar!(MulAssign, mul_assign, mul_scalar);
