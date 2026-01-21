use std::{cell::RefCell, panic, rc::Rc};

use crate::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    piop::DeepClone,
    prover::{ArgProver, tracker::ProverTracker},
    structs::TrackerID,
};
use ark_ff::PrimeField;
use ark_std::One;
use ark_std::Zero;
use ark_std::fmt::Debug;
use derivative::Derivative;
use either::Either;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
/// A tracked polynomial that is tracked by the prover tracker
pub struct TrackedPoly<B>
where
    B: SnarkBackend,
{
    pub id_or_const: Either<TrackerID, B::F>,
    log_size: usize,
    tracker: Rc<RefCell<ProverTracker<B>>>,
}

/// Debug implementation for TrackedPoly
impl<B: SnarkBackend> Debug for TrackedPoly<B>
where
    B: SnarkBackend,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedPoly")
            .field("id_or_const", &self.id_or_const)
            .field("num_vars", &self.log_size)
            .finish()
    }
}

/// PartialEq implementation for TrackedPoly
impl<B: SnarkBackend> PartialEq for TrackedPoly<B>
where
    B: SnarkBackend,
{
    fn eq(&self, other: &Self) -> bool {
        self.id_or_const == other.id_or_const && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}

/// Other functionalities for TrackedPoly
impl<B: SnarkBackend> TrackedPoly<B>
where
    B: SnarkBackend,
{
    /// Create a new tracked polynomial
    pub fn new(
        id_or_const: Either<TrackerID, B::F>,
        log_size: usize,
        tracker: Rc<RefCell<ProverTracker<B>>>,
    ) -> Self {
        Self {
            id_or_const,
            log_size,
            tracker,
        }
    }

    /// Get the id of the tracked polynomial
    pub fn id_or_const(&self) -> Either<TrackerID, B::F> {
        self.id_or_const
    }

    pub fn id(&self) -> TrackerID {
        match self.id_or_const {
            Either::Left(id) => id,
            Either::Right(_) => panic!("TrackedPoly is a constant"),
        }
    }

    /// Get a reference to the underlying tracker
    pub fn tracker(&self) -> Rc<RefCell<ProverTracker<B>>> {
        self.tracker.clone()
    }

    /// Return the log size of the polynomial
    /// This is the number of variables in multivariate polynomials
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Checks if two tracked polynomials are from the same tracker
    pub fn same_tracker(&self, other: &TrackedPoly<B>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    //TODO: See if you can remove this function
    pub fn assert_same_tracker(&self, other: &TrackedPoly<B>) {
        assert!(
            self.same_tracker(other),
            "TrackedPolys are not from the same tracker"
        );
    }

    pub fn evaluate(&self, pt: &[B::F]) -> Option<B::F> {
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow().evaluate_mv(*id, pt),
            Either::Right(c) => {
                assert_eq!(pt.len(), 0);
                Some(*c)
            }
        }
    }

    pub fn evaluate_uv(&self, pt: &B::F) -> Option<B::F> {
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow().evaluate_uv(*id, pt),
            Either::Right(c) => {
                assert_eq!(pt, &B::F::zero());
                Some(*c)
            }
        }
    }

    pub fn evaluations(&self) -> Vec<B::F> {
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

    fn compute_add(&self, rhs: &TrackedPoly<B>) -> (Either<TrackerID, B::F>, usize) {
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

    fn compute_sub(&self, rhs: &TrackedPoly<B>) -> (Either<TrackerID, B::F>, usize) {
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
                    let neg_id = tracker.mul_scalar(*id2, -B::F::one());
                    tracker.add_scalar(neg_id, *c1)
                };
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 - *c2),
        };
        (id_or_const, log_size)
    }

    fn compute_mul(&self, rhs: &TrackedPoly<B>) -> (Either<TrackerID, B::F>, usize) {
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

    fn compute_add_scalar(&self, scalar: B::F) -> (Either<TrackerID, B::F>, usize) {
        let id_or_const = match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(constant) => Either::Right(*constant + scalar),
        };
        (id_or_const, self.log_size)
    }

    fn compute_sub_scalar(&self, scalar: B::F) -> (Either<TrackerID, B::F>, usize) {
        let id_or_const = match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, -scalar);
                Either::Left(new_id)
            }
            Either::Right(constant) => Either::Right(*constant - scalar),
        };
        (id_or_const, self.log_size)
    }

    fn compute_mul_scalar(&self, scalar: B::F) -> (Either<TrackerID, B::F>, usize) {
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

impl<B: SnarkBackend> DeepClone<B> for TrackedPoly<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        Self {
            id_or_const: self.id_or_const,
            log_size: self.log_size,
            tracker: new_prover.tracker_rc,
        }
    }
}

impl<B: SnarkBackend> TrackedPoly<B> {
    /// Return a new tracked polynomial equal to `self * scalar`.
    pub fn mul_scalar_poly(&self, scalar: B::F) -> Self {
        let (id_or_const, log_size) = self.compute_mul_scalar(scalar);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }

    /// Return a new tracked polynomial equal to `self + scalar`.
    pub fn add_scalar_poly(&self, scalar: B::F) -> Self {
        let (id_or_const, log_size) = self.compute_add_scalar(scalar);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }

    /// Return a new tracked polynomial equal to `self - scalar`.
    pub fn sub_scalar_poly(&self, scalar: B::F) -> Self {
        let (id_or_const, log_size) = self.compute_sub_scalar(scalar);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

// ====================== Operator Trait Implementations ======================
impl<'a, 'b, B: SnarkBackend> std::ops::Add<&'b TrackedPoly<B>> for &'a TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn add(self, rhs: &'b TrackedPoly<B>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_add(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, 'b, B: SnarkBackend> std::ops::Sub<&'b TrackedPoly<B>> for &'a TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn sub(self, rhs: &'b TrackedPoly<B>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_sub(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, 'b, B: SnarkBackend> std::ops::Mul<&'b TrackedPoly<B>> for &'a TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn mul(self, rhs: &'b TrackedPoly<B>) -> Self::Output {
        let (id_or_const, log_size) = self.compute_mul(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<B: SnarkBackend> std::ops::Add<B::F> for TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn add(self, rhs: B::F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_add_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<B: SnarkBackend> std::ops::Sub<B::F> for TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn sub(self, rhs: B::F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_sub_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<B: SnarkBackend> std::ops::Mul<B::F> for TrackedPoly<B> {
    type Output = TrackedPoly<B>;

    #[inline]
    fn mul(self, rhs: B::F) -> Self::Output {
        let (id_or_const, log_size) = self.compute_mul_scalar(rhs);
        TrackedPoly::new(id_or_const, log_size, self.tracker.clone())
    }
}

impl<'a, B: SnarkBackend> std::ops::AddAssign<&'a TrackedPoly<B>> for TrackedPoly<B> {
    #[inline]
    fn add_assign(&mut self, rhs: &'a TrackedPoly<B>) {
        let (id_or_const, log_size) = self.compute_add(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<'a, B: SnarkBackend> std::ops::SubAssign<&'a TrackedPoly<B>> for TrackedPoly<B> {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a TrackedPoly<B>) {
        let (id_or_const, log_size) = self.compute_sub(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

impl<'a, B: SnarkBackend> std::ops::MulAssign<&'a TrackedPoly<B>> for TrackedPoly<B> {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a TrackedPoly<B>) {
        let (id_or_const, log_size) = self.compute_mul(rhs);
        self.id_or_const = id_or_const;
        self.log_size = log_size;
    }
}

pub fn get_or_insert_shift_poly<B>(
    prover: &mut ArgProver<B>,
    log_size: usize,
    shift: usize,
    is_right: bool,
) -> TrackedPoly<B>
where
    B: SnarkBackend,
    B::F: PrimeField,
{
    let label = format!("shift_perm_{}_{}_{}", log_size, shift, is_right);
    match prover.indexed_tracked_poly(label.clone()) {
        Ok(poly) => poly,
        Err(_) => {
            let domain_size = 1usize << log_size;
            let normalized_shift = if domain_size == 0 {
                0
            } else {
                shift % domain_size
            };

            let mut evals: Vec<B::F> = (0..domain_size).map(|i| B::F::from(i as u64)).collect();
            if domain_size > 0 {
                if is_right {
                    evals.rotate_right(normalized_shift);
                } else {
                    evals.rotate_left(normalized_shift);
                }
            }

            let poly = prover.track_mat_mv_poly(MLE::from_evaluations_vec(log_size, evals));
            prover.add_indexed_tracked_poly(label, poly.clone());
            poly
        }
    }
}
