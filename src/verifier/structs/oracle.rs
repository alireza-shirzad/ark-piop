use crate::{
    SnarkBackend, errors::SnarkResult, pcs::PCS, structs::TrackerID,
    verifier::tracker::VerifierTracker,
};
use ark_ff::Field;
use ark_std::One;
use ark_std::fmt::Debug;
use derivative::Derivative;
use either::Either;
use std::ops::MulAssign;
use std::{
    cell::RefCell,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
    rc::Rc,
    sync::Arc,
};

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

pub enum InnerOracle<F: Field + 'static> {
    Univariate(Arc<dyn CloneableFn<F, F>>),
    Multivariate(Arc<dyn CloneableFn<F, Vec<F>>>),
    Constant(F),
}

#[derive(Clone)]
pub struct Oracle<F: Field + 'static> {
    log_size: usize,
    inner: InnerOracle<F>,
}

impl<F: 'static + Field> Oracle<F> {
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    pub fn new_univariate(log_size: usize, f: impl CloneableFn<F, F> + 'static) -> Self {
        Self {
            log_size,
            inner: InnerOracle::Univariate(Arc::new(f)),
        }
    }

    pub fn new_multivariate(log_size: usize, f: impl CloneableFn<F, Vec<F>> + 'static) -> Self {
        Self {
            log_size,
            inner: InnerOracle::Multivariate(Arc::new(f)),
        }
    }

    pub fn new_constant(log_size: usize, c: F) -> Self {
        Self {
            log_size,
            inner: InnerOracle::Constant(c),
        }
    }

    //TODO: Remove this inner in the future and replace it with proper APIs
    pub fn inner(&self) -> &InnerOracle<F> {
        &self.inner
    }
}

impl<F: 'static + Field> Clone for InnerOracle<F> {
    fn clone(&self) -> Self {
        match self {
            InnerOracle::Univariate(f) => InnerOracle::Univariate(f.clone()),
            InnerOracle::Multivariate(f) => InnerOracle::Multivariate(f.clone()),
            InnerOracle::Constant(c) => InnerOracle::Constant(*c),
        }
    }
}
////////////////////////////////////////////

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct TrackedOracle<B>
where
    B: SnarkBackend,
{
    id_or_const: Either<TrackerID, B::F>,
    tracker: Rc<RefCell<VerifierTracker<B>>>,
    log_size: usize,
}

impl<B> TrackedOracle<B>
where
    B: SnarkBackend,
{
    /// Returns the number of variables in the tracked oracle
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    pub fn tracker(&self) -> Rc<RefCell<VerifierTracker<B>>> {
        self.tracker.clone()
    }
}

// Serialization for tracked oracle
impl<B> Debug for TrackedOracle<B>
where
    B: SnarkBackend,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedOracle")
            .field("id_or_const", &self.id_or_const)
            .finish()
    }
}

impl<B> PartialEq for TrackedOracle<B>
where
    B: SnarkBackend,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}

impl<B> TrackedOracle<B>
where
    B: SnarkBackend,
{
    /// Return a new tracked oracle equal to `self * scalar`.
    pub fn mul_scalar_oracle(&self, scalar: B::F) -> Self {
        let id_or_const = self.compute_mul_scalar(scalar);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }

    /// Return a new tracked oracle equal to `self + scalar`.
    pub fn add_scalar_oracle(&self, scalar: B::F) -> Self {
        let id_or_const = self.compute_add_scalar(scalar);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }

    /// Return a new tracked oracle equal to `self - scalar`.
    pub fn sub_scalar_oracle(&self, scalar: B::F) -> Self {
        let id_or_const = self.compute_sub_scalar(scalar);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<B> TrackedOracle<B>
where
    B: SnarkBackend,
{
    pub fn new(
        id_or_const: Either<TrackerID, B::F>,
        tracker: Rc<RefCell<VerifierTracker<B>>>,
        log_size: usize,
    ) -> Self {
        Self {
            id_or_const,
            tracker,
            log_size,
        }
    }

    pub fn id(&self) -> TrackerID {
        match &self.id_or_const {
            Either::Left(id) => *id,
            Either::Right(_) => panic!("TrackedOracle is a constant"),
        }
    }

    pub fn same_tracker(&self, other: &TrackedOracle<B>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedOracle<B>) {
        assert!(
            self.same_tracker(other),
            "TrackedOracles are not from the same tracker"
        );
    }

    pub fn commitment(&self) -> <B::MvPCS as PCS<B::F>>::Commitment
    where
        <B::MvPCS as PCS<B::F>>::Commitment: Clone,
    {
        match &self.id_or_const {
            Either::Left(id) => self
                .tracker
                .borrow()
                .mv_commitment(*id)
                .expect("TrackedOracle commitment not found"),
            Either::Right(_) => panic!("TrackedOracle is a constant"),
        }
    }

    fn compute_add(&self, rhs: &TrackedOracle<B>) -> Either<TrackerID, B::F> {
        self.assert_same_tracker(rhs);
        match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().add_oracles(*id1, *id2);
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
        }
    }

    fn compute_sub(&self, rhs: &TrackedOracle<B>) -> Either<TrackerID, B::F> {
        self.assert_same_tracker(rhs);
        match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().sub_oracles(*id1, *id2);
                Either::Left(new_id)
            }
            (Either::Left(id1), Either::Right(c2)) => {
                let new_id = self.tracker.borrow_mut().sub_scalar(*id1, *c2);
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
        }
    }

    fn compute_mul(&self, rhs: &TrackedOracle<B>) -> Either<TrackerID, B::F> {
        self.assert_same_tracker(rhs);
        match (&self.id_or_const, &rhs.id_or_const) {
            (Either::Left(id1), Either::Left(id2)) => {
                let new_id = self.tracker.borrow_mut().mul_oracles(*id1, *id2);
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
        }
    }

    fn compute_add_scalar(&self, scalar: B::F) -> Either<TrackerID, B::F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c + scalar),
        }
    }

    fn compute_sub_scalar(&self, scalar: B::F) -> Either<TrackerID, B::F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().sub_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c - scalar),
        }
    }

    fn compute_mul_scalar(&self, scalar: B::F) -> Either<TrackerID, B::F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().mul_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c * scalar),
        }
    }

    fn compute_add_operand<'a>(&self, rhs: OracleOperand<'a, B>) -> Either<TrackerID, B::F> {
        match rhs {
            OracleOperand::Oracle(oracle) => self.compute_add(oracle),
        }
    }

    fn compute_sub_operand<'a>(&self, rhs: OracleOperand<'a, B>) -> Either<TrackerID, B::F> {
        match rhs {
            OracleOperand::Oracle(oracle) => self.compute_sub(oracle),
        }
    }

    fn compute_mul_operand<'a>(&self, rhs: OracleOperand<'a, B>) -> Either<TrackerID, B::F> {
        match rhs {
            OracleOperand::Oracle(oracle) => self.compute_mul(oracle),
        }
    }
}

/// Helper that lets us unify operator implementations for either another
/// oracle or a scalar field element.
enum OracleOperand<'a, B: SnarkBackend> {
    Oracle(&'a TrackedOracle<B>),
}

trait IntoOracleOperand<B: SnarkBackend> {
    fn into_operand<'a>(self) -> OracleOperand<'a, B>
    where
        Self: 'a;
}

impl<'a, B: SnarkBackend> IntoOracleOperand<B> for &'a TrackedOracle<B> {
    fn into_operand<'b>(self) -> OracleOperand<'b, B>
    where
        Self: 'b,
    {
        OracleOperand::Oracle(self)
    }
}

impl<B, Rhs> AddAssign<Rhs> for TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    #[inline]
    fn add_assign(&mut self, rhs: Rhs) {
        self.id_or_const = self.compute_add_operand(rhs.into_operand());
    }
}

impl<B, Rhs> SubAssign<Rhs> for TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: Rhs) {
        self.id_or_const = self.compute_sub_operand(rhs.into_operand());
    }
}

impl<B, Rhs> MulAssign<Rhs> for TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: Rhs) {
        self.id_or_const = self.compute_mul_operand(rhs.into_operand());
    }
}

impl<'a, B, Rhs> Add<Rhs> for &'a TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    type Output = TrackedOracle<B>;

    #[inline]
    fn add(self, rhs: Rhs) -> Self::Output {
        let id_or_const = self.compute_add_operand(rhs.into_operand());
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<'a, B, Rhs> Sub<Rhs> for &'a TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    type Output = TrackedOracle<B>;

    #[inline]
    fn sub(self, rhs: Rhs) -> Self::Output {
        let id_or_const = self.compute_sub_operand(rhs.into_operand());
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<'a, B, Rhs> Mul<Rhs> for &'a TrackedOracle<B>
where
    B: SnarkBackend,
    Rhs: IntoOracleOperand<B>,
{
    type Output = TrackedOracle<B>;

    #[inline]
    fn mul(self, rhs: Rhs) -> Self::Output {
        let id_or_const = self.compute_mul_operand(rhs.into_operand());
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<B> Neg for TrackedOracle<B>
where
    B: SnarkBackend,
{
    type Output = TrackedOracle<B>;
    #[inline]
    fn neg(self) -> Self::Output {
        let tracker = self.tracker.clone();
        let id_or_const = match self.id_or_const {
            Either::Left(id) => {
                let new_id = tracker.borrow_mut().mul_scalar(id, -B::F::one());
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(-c),
        };
        TrackedOracle::new(id_or_const, tracker, self.log_size)
    }
}
