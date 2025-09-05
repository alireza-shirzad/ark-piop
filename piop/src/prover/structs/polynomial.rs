use std::{cell::RefCell, rc::Rc};

use ark_ff::PrimeField;
use derivative::Derivative;

use crate::{arithmetic::mat_poly::{lde::LDE, mle::MLE}, pcs::PCS, piop::DeepClone, prover::{tracker::ProverTracker, Prover}, structs::TrackerID};
use ark_std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};


#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"))]
/// A tracked polynomial that is tracked by the prover tracker
pub struct TrackedPoly<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    id: TrackerID,
    log_size: usize,
    tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
}

/// Debug implementation for TrackedPoly
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Debug for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedPoly")
            .field("id", &self.id)
            .field("num_vars", &self.log_size)
            .finish()
    }
}

/// PartialEq implementation for TrackedPoly
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> PartialEq for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}

/// Other functionalities for TrackedPoly
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Create a new tracked polynomial
    pub fn new(
        id: TrackerID,
        log_size: usize,
        tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            id,
            log_size,
            tracker,
        }
    }

    /// Get the id of the tracked polynomial
    pub fn get_id(&self) -> TrackerID {
        self.id
    }

    /// Get a reference to the underlying tracker
    pub fn get_tracker(&self) -> Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>> {
        self.tracker.clone()
    }

    /// Return the log size of the polynomial
    /// This is the number of variables in multivariate polynomials
    pub fn get_log_size(&self) -> usize {
        self.log_size
    }

    /// Checks if two tracked polynomials are from the same tracker
    pub fn same_tracker(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    //TODO: See if you can remove this function
    pub fn assert_same_tracker(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) {
        assert!(
            self.same_tracker(other),
            "TrackedPolys are not from the same tracker"
        );
    }

    pub fn evaluate(&self, pt: &[F]) -> Option<F> {
        self.tracker.borrow().evaluate_mv(self.id, pt)
    }

    pub fn evaluate_uv(&self, pt: &F) -> Option<F> {
        self.tracker.borrow().evaluate_uv(self.id, pt)
    }

    pub fn evaluations(&self) -> Vec<F> {
        // TODO: Noe that this has to actually clone the evaluations, which can be
        // expensive
        self.tracker.borrow_mut().evaluations(self.id).clone()
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for TrackedPoly<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            id: self.id,
            log_size: self.log_size,
            tracker: new_prover.tracker_rc,
        }
    }
}

// ====================== Operator Trait Implementations via Macros ======================

// Macro to implement assignment ops with another TrackedPoly
macro_rules! impl_assign_poly {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<F, MvPCS, UvPCS> std::ops::$trait_<&Self> for TrackedPoly<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            #[inline]
            fn $fn_(&mut self, rhs: &Self) {
                self.assert_same_tracker(rhs);
                assert_eq!(self.log_size, rhs.log_size);
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs.id);
                self.id = new_id;
            }
        }
    };
}

// Macro to implement assignment ops with scalar F
macro_rules! impl_assign_scalar_poly {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<F, MvPCS, UvPCS> std::ops::$trait_<F> for TrackedPoly<F, MvPCS, UvPCS>
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

// Macro to implement binary ops between &TrackedPoly and &TrackedPoly
macro_rules! impl_binop_poly {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<'a, F, MvPCS, UvPCS> std::ops::$trait_<&'a TrackedPoly<F, MvPCS, UvPCS>>
            for &'a TrackedPoly<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            type Output = TrackedPoly<F, MvPCS, UvPCS>;
            #[inline]
            fn $fn_(self, rhs: &'a TrackedPoly<F, MvPCS, UvPCS>) -> Self::Output {
                self.assert_same_tracker(rhs);
                assert_eq!(self.log_size, rhs.log_size);
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs.id);
                TrackedPoly::new(new_id, self.log_size, self.tracker.clone())
            }
        }
    };
}

// Macro to implement binary ops between &TrackedPoly and scalar F
macro_rules! impl_binop_scalar_poly {
    ($trait_:ident, $fn_:ident, $tracker_fn:ident) => {
        impl<'a, F, MvPCS, UvPCS> std::ops::$trait_<F> for &'a TrackedPoly<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            type Output = TrackedPoly<F, MvPCS, UvPCS>;
            #[inline]
            fn $fn_(self, rhs: F) -> Self::Output {
                let new_id = self.tracker.borrow_mut().$tracker_fn(self.id, rhs);
                TrackedPoly::new(new_id, self.log_size, self.tracker.clone())
            }
        }
    };
}

// Special-case macro for subtracting a scalar (uses add_scalar with negation)
macro_rules! impl_binop_scalar_sub_poly {
    () => {
        impl<'a, F, MvPCS, UvPCS> std::ops::Sub<F> for &'a TrackedPoly<F, MvPCS, UvPCS>
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            type Output = TrackedPoly<F, MvPCS, UvPCS>;
            #[inline]
            fn sub(self, rhs: F) -> Self::Output {
                let new_id = self.tracker.borrow_mut().add_scalar(self.id, -rhs);
                TrackedPoly::new(new_id, self.log_size, self.tracker.clone())
            }
        }
    };
}

// Invoke macros to create the implementations
impl_binop_poly!(Add, add, add_polys);
impl_binop_poly!(Sub, sub, sub_polys);
impl_binop_poly!(Mul, mul, mul_polys);
impl_binop_scalar_poly!(Add, add, add_scalar);
impl_binop_scalar_poly!(Mul, mul, mul_scalar);
impl_binop_scalar_sub_poly!();
impl_assign_poly!(AddAssign, add_assign, add_polys);
impl_assign_poly!(SubAssign, sub_assign, sub_polys);
impl_assign_poly!(MulAssign, mul_assign, mul_polys);
impl_assign_scalar_poly!(AddAssign, add_assign, add_scalar);
impl_assign_scalar_poly!(MulAssign, mul_assign, mul_scalar);
