use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    structs::TrackerID,
    verifier::tracker::VerifierTracker,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_std::fmt::Debug;
use derivative::Derivative;
use either::Either;
use serde::{Serialize, Serializer, ser::Error as SerError, ser::SerializeStruct};
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

pub enum Oracle<F: Field + 'static> {
    Univariate(Arc<dyn CloneableFn<F, F>>),
    Multivariate(Arc<dyn CloneableFn<F, Vec<F>>>),
    Constant(F),
}
impl<F: 'static + Field> Clone for Oracle<F> {
    fn clone(&self) -> Self {
        match self {
            Oracle::Univariate(f) => Oracle::Univariate(f.clone()),
            Oracle::Multivariate(f) => Oracle::Multivariate(f.clone()),
            Oracle::Constant(c) => Oracle::Constant(*c),
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
    pub id_or_const: Either<TrackerID, F>,
    pub tracker: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> Serialize for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField + CanonicalSerialize,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    MvPCS::Commitment: CanonicalSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TrackedOracle", 2)?;
        match &self.id_or_const {
            Either::Left(id) => {
                let commitment = self.tracker.borrow().mv_commitment(*id).ok_or_else(|| {
                    S::Error::custom("commitment not found for oracle")
                })?;
                let mut bytes = Vec::new();
                commitment
                    .serialize_with_mode(&mut bytes, Compress::Yes)
                    .map_err(|e: SerializationError| S::Error::custom(e.to_string()))?;
                state.serialize_field("kind", "commitment")?;
                state.serialize_field("data", &bytes)?;
            }
            Either::Right(value) => {
                let mut bytes = Vec::new();
                value
                    .serialize_with_mode(&mut bytes, Compress::Yes)
                    .map_err(|e: SerializationError| S::Error::custom(e.to_string()))?;
                state.serialize_field("kind", "constant")?;
                state.serialize_field("data", &bytes)?;
            }
        }
        state.end()
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Debug for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedOracle")
            .field("id_or_const", &self.id_or_const)
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

impl<F, MvPCS, UvPCS> AddAssign<&Self> for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.id_or_const = self.compute_add(rhs);
    }
}

impl<F, MvPCS, UvPCS> SubAssign<&Self> for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.id_or_const = self.compute_sub(rhs);
    }
}

impl<F, MvPCS, UvPCS> MulAssign<&Self> for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.id_or_const = self.compute_mul(rhs);
    }
}

impl<F, MvPCS, UvPCS> AddAssign<F> for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn add_assign(&mut self, rhs: F) {
        self.id_or_const = self.compute_add_scalar(rhs);
    }
}

impl<F, MvPCS, UvPCS> MulAssign<F> for TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: F) {
        self.id_or_const = self.compute_mul_scalar(rhs);
    }
}

impl<'a, F, MvPCS, UvPCS> Add<&'a TrackedOracle<F, MvPCS, UvPCS>>
    for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn add(self, rhs: &'a TrackedOracle<F, MvPCS, UvPCS>) -> Self::Output {
        let id_or_const = self.compute_add(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> Sub<&'a TrackedOracle<F, MvPCS, UvPCS>>
    for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn sub(self, rhs: &'a TrackedOracle<F, MvPCS, UvPCS>) -> Self::Output {
        let id_or_const = self.compute_sub(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> Mul<&'a TrackedOracle<F, MvPCS, UvPCS>>
    for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn mul(self, rhs: &'a TrackedOracle<F, MvPCS, UvPCS>) -> Self::Output {
        let id_or_const = self.compute_mul(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> Add<F> for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn add(self, rhs: F) -> Self::Output {
        let id_or_const = self.compute_add_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> Sub<F> for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn sub(self, rhs: F) -> Self::Output {
        let id_or_const = self.compute_sub_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
    }
}

impl<'a, F, MvPCS, UvPCS> Mul<F> for &'a TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Output = TrackedOracle<F, MvPCS, UvPCS>;

    #[inline]
    fn mul(self, rhs: F) -> Self::Output {
        let id_or_const = self.compute_mul_scalar(rhs);
        TrackedOracle::new(id_or_const, self.tracker.clone())
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
        let tracker = self.tracker.clone();
        let id_or_const = match self.id_or_const {
            Either::Left(id) => {
                let new_id = tracker.borrow_mut().mul_scalar(id, -F::one());
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(-c),
        };
        TrackedOracle::new(id_or_const, tracker)
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS> TrackedOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        id_or_const: Either<TrackerID, F>,
        tracker: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            id_or_const,
            tracker,
        }
    }

    pub fn id(&self) -> TrackerID {
        match &self.id_or_const {
            Either::Left(id) => *id,
            Either::Right(_) => panic!("TrackedOracle is a constant"),
        }
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

    fn compute_add(&self, rhs: &TrackedOracle<F, MvPCS, UvPCS>) -> Either<TrackerID, F> {
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

    fn compute_sub(&self, rhs: &TrackedOracle<F, MvPCS, UvPCS>) -> Either<TrackerID, F> {
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
                    let neg_id = tracker.mul_scalar(*id2, -F::one());
                    tracker.add_scalar(neg_id, *c1)
                };
                Either::Left(new_id)
            }
            (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 - *c2),
        }
    }

    fn compute_mul(&self, rhs: &TrackedOracle<F, MvPCS, UvPCS>) -> Either<TrackerID, F> {
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

    fn compute_add_scalar(&self, scalar: F) -> Either<TrackerID, F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().add_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c + scalar),
        }
    }

    fn compute_sub_scalar(&self, scalar: F) -> Either<TrackerID, F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().sub_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c - scalar),
        }
    }

    fn compute_mul_scalar(&self, scalar: F) -> Either<TrackerID, F> {
        match &self.id_or_const {
            Either::Left(id) => {
                let new_id = self.tracker.borrow_mut().mul_scalar(*id, scalar);
                Either::Left(new_id)
            }
            Either::Right(c) => Either::Right(*c * scalar),
        }
    }
}
