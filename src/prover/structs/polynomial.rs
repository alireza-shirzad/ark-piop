use std::{cell::RefCell, panic, rc::Rc};

use ark_ff::PrimeField;
use derivative::Derivative;
use either::Either;

use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{Prover, tracker::ProverTracker},
    structs::TrackerID,
};
use ark_std::fmt::Debug;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"))]
/// A tracked polynomial that is tracked by the prover tracker
pub struct TrackedPoly<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub id_or_const: Either<TrackerID, F>,
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
            .field("id_or_const", &self.id_or_const)
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
        self.id_or_const == other.id_or_const && Rc::ptr_eq(&self.tracker, &other.tracker)
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
        id_or_const: Either<TrackerID, F>,
        log_size: usize,
        tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            id_or_const,
            log_size,
            tracker,
        }
    }

    /// Get the id of the tracked polynomial
    pub fn id_or_const(&self) -> Either<TrackerID, F> {
        self.id_or_const
    }

    pub fn id(&self) -> TrackerID {
        match self.id_or_const {
            Either::Left(id) => id,
            Either::Right(_) => panic!("TrackedPoly is a constant"),
        }
    }

    /// Get a reference to the underlying tracker
    pub fn tracker(&self) -> Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>> {
        self.tracker.clone()
    }

    /// Return the log size of the polynomial
    /// This is the number of variables in multivariate polynomials
    pub fn log_size(&self) -> usize {
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
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow().evaluate_mv(*id, pt),
            Either::Right(c) => {
                assert_eq!(pt.len(), 0);
                Some(*c)
            }
        }
    }

    pub fn evaluate_uv(&self, pt: &F) -> Option<F> {
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow().evaluate_uv(*id, pt),
            Either::Right(c) => {
                assert_eq!(pt, &F::zero());
                Some(*c)
            }
        }
    }

    pub fn evaluations(&self) -> Vec<F> {
        // TODO: Noe that this has to actually clone the evaluations, which can be
        // expensive
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow_mut().evaluations(*id).clone(),
            Either::Right(c) => vec![*c; 1 << self.log_size],
        }
    }

    fn combine_log_sizes(lhs: usize, rhs: usize) -> usize {
        if lhs == rhs {
            lhs
        } else if lhs == 0 {
            rhs
        } else if rhs == 0 {
            lhs
        } else {
            panic!("Mismatched log sizes: lhs = {}, rhs = {}", lhs, rhs);
        }
    }

    fn compute_add(&self, rhs: &TrackedPoly<F, MvPCS, UvPCS>) -> (Either<TrackerID, F>, usize) {
        self.assert_same_tracker(rhs);
        let log_size = Self::combine_log_sizes(self.log_size, rhs.log_size);
        let id_or_const = match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().add_polys(*id1, *id2);
                Either::Left(new_id)
            }
            (Either::Left(id1), Either::Right(c2)) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id1, *c2);
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id2, *c1);
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 + *c2),
        };
        (id_or_const, log_size)
    }

    fn compute_sub(&self, rhs: &TrackedPoly<F, MvPCS, UvPCS>) -> (Either<TrackerID, F>, usize) {
        self.assert_same_tracker(rhs);
        let log_size = Self::combine_log_sizes(self.log_size, rhs.log_size);
        let id_or_const = match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().sub_polys(*id1, *id2);
                Either::Left(new_id)
            }
            (Either::Left(id1), Either::Right(c2)) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id1, -*c2);

                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Left(id2)) => {
                let new_id = {
                    let mut tracker = self.tracker.borrow_mut();
                    let neg_id = tracker.mul_scalar(*id2, -F::one());
                    tracker.add_scalar(neg_id, *c1)
                };
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 - *c2),
        };
        (id_or_const, log_size)
    }

    fn compute_mul(&self, rhs: &TrackedPoly<F, MvPCS, UvPCS>) -> (Either<TrackerID, F>, usize) {
        self.assert_same_tracker(rhs);
        let log_size = Self::combine_log_sizes(self.log_size, rhs.log_size);
        let id_or_const = match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().mul_polys(*id1, *id2);
                Either::Left(new_id)
            }
            (Either::Left(id1), Either::Right(c2)) => {
                let new_id = self.tracker.borrow_mut().mul_scalar(*id1, *c2);
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().mul_scalar(*id2, *c1);
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 * *c2),
        };
        (id_or_const, log_size)
    }

    fn compute_add_scalar(&self, scalar: F) -> (Either<TrackerID, F>, usize) {
        let id_or_const = match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(constant) => Either::Right(*constant + scalar),
        };
        (id_or_const, self.log_size)
    }

    fn compute_sub_scalar(&self, scalar: F) -> (Either<TrackerID, F>, usize) {
        let id_or_const = match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, -scalar);
                Either::Left(new_id)
            }
            Either::Right(constant) => Either::Right(*constant - scalar),
        };
        (id_or_const, self.log_size)
    }

    fn compute_mul_scalar(&self, scalar: F) -> (Either<TrackerID, F>, usize) {
        let id_or_const = match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().mul_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(constant) => Either::Right(*constant * scalar),
        };
        (id_or_const, self.log_size)
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for TrackedPoly<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            id_or_const: self.id_or_const,
            log_size: self.log_size,
            tracker: new_prover.tracker_rc,
        }
    }
}

// ====================== Operator Trait Implementations ======================

impl<F, MvPCS, UvPCS> std::ops::AddAssign<&Self> for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let (id_or_const, log_size) = self.compute_add(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<F, MvPCS, UvPCS> std::ops::SubAssign<&Self> for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let (id_or_const, log_size) = self.compute_sub(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<F, MvPCS, UvPCS> std::ops::MulAssign<&Self> for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let (id_or_const, log_size) = self.compute_mul(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<F, MvPCS, UvPCS> std::ops::AddAssign<F> for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn add_assign(&mut self, rhs: F) {
        let (id_or_const, log_size) = self.compute_add_scalar(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<F, MvPCS, UvPCS> std::ops::MulAssign<F> for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: F) {
        let (id_or_const, log_size) = self.compute_mul_scalar(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Add<&'a TrackedPoly<F, MvPCS, UvPCS>>
    for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn add(self, rhs: &'a TrackedPoly<F, MvPCS, UvPCS>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_add(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Sub<&'a TrackedPoly<F, MvPCS, UvPCS>>
    for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn sub(self, rhs: &'a TrackedPoly<F, MvPCS, UvPCS>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_sub(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Mul<&'a TrackedPoly<F, MvPCS, UvPCS>>
    for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn mul(self, rhs: &'a TrackedPoly<F, MvPCS, UvPCS>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_mul(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Add<F> for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn add(self, rhs: F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_add_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Sub<F> for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn sub(self, rhs: F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_sub_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> std::ops::Mul<F> for &'a TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedPoly<F, MvPCS, UvPCS>;

    #[inline]
    fn mul(self, rhs: F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_mul_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}
