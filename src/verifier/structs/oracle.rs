use crate::{
    SnarkBackend, errors::SnarkResult, pcs::PCS, structs::TrackerID,
    verifier::{ArgVerifier, tracker::VerifierTracker},
};
use ark_ff::{Field, PrimeField};
use ark_std::{One, Zero};
use ark_std::fmt::Debug;
use derivative::Derivative;
use either::Either;
use std::ops::MulAssign;
use std::{
    cell::RefCell,
    slice,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OracleKind {
    Univariate,
    Multivariate,
    Constant,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "F: Clone"))]
#[derivative(Default(bound = ""))]
#[derivative(Debug(bound = "F: Debug"))]
pub(crate) struct VirtualOracle<F>(Vec<(F, Vec<TrackerID>)>);

impl<F> VirtualOracle<F> {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
}

impl<F> std::ops::Deref for VirtualOracle<F> {
    type Target = Vec<(F, Vec<TrackerID>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> std::ops::DerefMut for VirtualOracle<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, F> IntoIterator for &'a VirtualOracle<F> {
    type Item = &'a (F, Vec<TrackerID>);
    type IntoIter = slice::Iter<'a, (F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, F> IntoIterator for &'a mut VirtualOracle<F> {
    type Item = &'a mut (F, Vec<TrackerID>);
    type IntoIter = slice::IterMut<'a, (F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<F> IntoIterator for VirtualOracle<F> {
    type Item = (F, Vec<TrackerID>);
    type IntoIter = std::vec::IntoIter<(F, Vec<TrackerID>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
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

    /// Return the max multiplicative degree of the tracked oracle.
    pub fn degree(&self) -> usize {
        match &self.id_or_const {
            Either::Left(id) => self.tracker.borrow().virt_oracle_degree(*id),
            Either::Right(_) => 0,
        }
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

    pub fn id_or_const(&self) -> Either<TrackerID, B::F> {
        self.id_or_const
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

}

// ====================== Operator Trait Implementations ======================
impl<'a, 'b, B: SnarkBackend> Add<&'b TrackedOracle<B>> for &'a TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn add(self, rhs: &'b TrackedOracle<B>) -> Self::Output {
        let id_or_const = self.compute_add(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<'a, 'b, B: SnarkBackend> Sub<&'b TrackedOracle<B>> for &'a TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn sub(self, rhs: &'b TrackedOracle<B>) -> Self::Output {
        let id_or_const = self.compute_sub(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<'a, 'b, B: SnarkBackend> Mul<&'b TrackedOracle<B>> for &'a TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn mul(self, rhs: &'b TrackedOracle<B>) -> Self::Output {
        let id_or_const = self.compute_mul(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}


impl<B: SnarkBackend> Add<B::F> for TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn add(self, rhs: B::F) -> Self::Output {
        let id_or_const = self.compute_add_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<B: SnarkBackend> Sub<B::F> for TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn sub(self, rhs: B::F) -> Self::Output {
        let id_or_const = self.compute_sub_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<B: SnarkBackend> Mul<B::F> for TrackedOracle<B> {
    type Output = TrackedOracle<B>;

    #[inline]
    fn mul(self, rhs: B::F) -> Self::Output {
        let id_or_const = self.compute_mul_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone(), self.log_size)
    }
}

impl<'a, B: SnarkBackend> AddAssign<&'a TrackedOracle<B>> for TrackedOracle<B> {
    #[inline]
    fn add_assign(&mut self, rhs: &'a TrackedOracle<B>) {
        self.id_or_const = self.compute_add(rhs);
    }
}

impl<'a, B: SnarkBackend> SubAssign<&'a TrackedOracle<B>> for TrackedOracle<B> {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a TrackedOracle<B>) {
        self.id_or_const = self.compute_sub(rhs);
    }
}

impl<'a, B: SnarkBackend> MulAssign<&'a TrackedOracle<B>> for TrackedOracle<B> {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a TrackedOracle<B>) {
        self.id_or_const = self.compute_mul(rhs);
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

pub fn get_or_insert_shift_oracle<B>(
    verifier: &mut ArgVerifier<B>,
    log_size: usize,
    shift: usize,
    is_right: bool,
) -> TrackedOracle<B>
where
    B: SnarkBackend,
    B::F: PrimeField,
{
    let label = format!("shift_perm_{}_{}_{}", log_size, shift, is_right);
    match verifier.indexed_oracle(label.clone()) {
        Ok(oracle) => oracle,
        Err(_) => {
            let oracle = build_shift_oracle::<B::F>(log_size, shift, is_right);
            let oracle = verifier.track_oracle(oracle);
            verifier.add_indexed_tracked_oracle(label, oracle.clone());
            oracle
        }
    }
}

fn build_shift_oracle<F: PrimeField>(log_size: usize, shift: usize, right: bool) -> Oracle<F> {
    let domain_size = 1usize << log_size;
    let shift_mod = if domain_size == 0 {
        0
    } else {
        shift % domain_size
    };

    let mut weights = Vec::with_capacity(log_size);
    let mut coeff = F::one();
    for _ in 0..log_size {
        weights.push(coeff);
        coeff += coeff;
    }

    let (delta_int, overflow_threshold) = if shift_mod == 0 {
        (0usize, None)
    } else if right {
        ((domain_size - shift_mod) % domain_size, Some(shift_mod))
    } else {
        (shift_mod, Some(domain_size - shift_mod))
    };

    let mut delta_f = F::zero();
    for (i, weight) in weights.iter().enumerate() {
        if ((delta_int >> i) & 1) == 1 {
            delta_f += *weight;
        }
    }

    let domain_f = overflow_threshold.map(|_| {
        let mut value = F::one();
        for _ in 0..log_size {
            value += value;
        }
        value
    });

    let threshold_bits = overflow_threshold.map(|thr| {
        (0..log_size)
            .map(|i| ((thr >> i) & 1) == 1)
            .collect::<Vec<bool>>()
    });

    Oracle::new_multivariate(log_size, move |mut point: Vec<F>| {
        if point.len() > log_size {
            point.truncate(log_size);
        } else if point.len() < log_size {
            point.resize(log_size, F::zero());
        }

        let range_value = point
            .iter()
            .zip(weights.iter())
            .fold(F::zero(), |acc, (bit, weight)| acc + (*bit * *weight));

        let mut result = range_value + delta_f;

        if let (Some(bits), Some(domain)) = (threshold_bits.as_ref(), domain_f) {
            let overflow = evaluate_ge_bits(&point, bits);
            result -= domain * overflow;
        }

        Ok(result)
    })
}

fn evaluate_ge_bits<F: PrimeField>(vars: &[F], threshold_bits: &[bool]) -> F {
    let one = F::one();
    let mut prefix_equal = F::one();
    let mut greater = F::zero();

    for i in (0..vars.len()).rev() {
        let bit_val = vars[i];
        if !threshold_bits[i] {
            greater += prefix_equal * bit_val;
            prefix_equal *= one - bit_val;
        } else {
            prefix_equal *= bit_val;
        }
    }

    greater + prefix_equal
}
