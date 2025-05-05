/////////////////// Modules //////////////////

pub mod proof;

/////////////////// Imports //////////////////
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::Arc,
};

use super::{Prover, tracker::ProverTracker};
use crate::{
    arithmetic::{
        mat_poly::{lde::LDE, mle::MLE},
        virt_poly::VirtualPoly,
    },
    pcs::PCS,
    piop::DeepClone,
    setup::structs::ProvingKey,
    structs::{
        TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
    transcript::Tr,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_std::fmt::Debug;
use derivative::Derivative;

/// A claim that the sum of the evaluations of a polynomial on the boolean
/// hypercube is equal to a certain value.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derive(Debug, PartialEq, Eq, PartialOrd)]
pub struct TrackerEvalClaim<F: PrimeField, PC: PCS<F>> {
    id: TrackerID,
    point: <PC::Poly as Polynomial<F>>::Point,
}

impl<F: PrimeField, PC: PCS<F>> TrackerEvalClaim<F, PC> {
    pub fn new(id: TrackerID, point: <PC::Poly as Polynomial<F>>::Point) -> Self {
        Self { id, point }
    }
    pub fn get_id(&self) -> TrackerID {
        self.id
    }
    pub fn get_point(&self) -> &<PC::Poly as Polynomial<F>>::Point {
        &self.point
    }
    pub fn set_point(&mut self, point: <PC::Poly as Polynomial<F>>::Point) {
        self.point = point;
    }
}

// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct ProverState<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The transcript for the PIOP
    pub transcript: Tr<F>,

    /// number of the tracked polynomials (Univariate and Multivariate)
    // TODO: See if we should split this into two fields
    pub num_tracked_polys: usize,

    /// A map from TrackerID to a virtual polynomials, i.e. polynomials of the
    /// form `sum_i c_i * prod_j p_ij` where `p_ij` points to another
    /// materialized or virtual polynomials
    pub virtual_polys: BTreeMap<TrackerID, VirtualPoly<F>>,

    pub mv_pcs_substate: ProverPCSubstate<F, MvPCS>,
    pub uv_pcs_substate: ProverPCSubstate<F, UvPCS>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct ProverPCSubstate<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub materialized_polys: BTreeMap<TrackerID, Arc<PC::Poly>>,
    pub materialized_comms: BTreeMap<TrackerID, PC::Commitment>,
    pub eval_claims: Vec<TrackerEvalClaim<F, PC>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedProvingKey<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub log_db_size: usize,
    pub mv_pcs_param: MvPCS::ProverParam,
    pub uv_pcs_param: UvPCS::ProverParam,
    pub indexed_mles: BTreeMap<String, TrackedPoly<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProcessedProvingKey<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new_from_pk(pk: &ProvingKey<F, MvPCS, UvPCS>) -> Self {
        Self {
            log_db_size: pk.log_db_size,
            mv_pcs_param: pk.mv_pcs_param.clone(),
            uv_pcs_param: pk.uv_pcs_param.clone(),
            indexed_mles: BTreeMap::new(),
        }
    }
}

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

    pub fn add_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.log_size, other.log_size);
        let res_id = self.tracker.borrow_mut().add_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.log_size, self.tracker.clone())
    }

    pub fn sub_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.log_size, other.log_size);
        let res_id = self.tracker.borrow_mut().sub_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.log_size, self.tracker.clone())
    }

    pub fn mul_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.log_size, other.log_size);
        let res_id = self.tracker.borrow_mut().mul_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.log_size, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: F) -> Self {
        let res_id = self.tracker.borrow_mut().add_scalar(self.id, c);
        TrackedPoly::new(res_id, self.log_size, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: F) -> Self {
        let res_id = self.tracker.borrow_mut().mul_scalar(self.id, c);
        TrackedPoly::new(res_id, self.log_size, self.tracker.clone())
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
