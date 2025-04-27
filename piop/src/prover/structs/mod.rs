/////////////////// Modules //////////////////

pub mod proof;

/////////////////// Imports //////////////////
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use super::{Prover, tracker::ProverTracker};
use crate::{
    arithmetic::{
        mat_poly::{lde::LDE, mle::MLE},
        virt_poly::{VirtualPoly, hp_interface::HPVirtualPolynomial},
    },
    pcs::PCS,
    setup::structs::ProvingKey,
    structs::{
        EvalClaimMap, TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
    transcript::Tr,
};
use ark_ff::PrimeField;
use ark_std::fmt::Debug;
use derivative::Derivative;

//////////////////// Structs & Enums //////////////////

pub enum Poly {
    MLE,
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
    pub eval_claims: EvalClaimMap<F, PC>,
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
pub struct TrackedPoly<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub id: TrackerID,
    // TODO: For unvariate polynomials, this is the log_2(deg)
    pub num_vars: usize,
    pub tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Debug for TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedPoly")
            .field("id", &self.id)
            .field("num_vars", &self.num_vars)
            .finish()
    }
}

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
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> TrackedPoly<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        id: TrackerID,
        num_vars: usize,
        tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            id,
            num_vars,
            tracker,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn same_tracker(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) {
        assert!(
            self.same_tracker(other),
            "TrackedPolys are not from the same tracker"
        );
    }

    pub fn add_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.num_vars, other.num_vars);
        let res_id = self.tracker.borrow_mut().add_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn sub_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.num_vars, other.num_vars);
        let res_id = self.tracker.borrow_mut().sub_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_poly(&self, other: &TrackedPoly<F, MvPCS, UvPCS>) -> Self {
        self.assert_same_tracker(other);
        assert_eq!(self.num_vars, other.num_vars);
        let res_id = self.tracker.borrow_mut().mul_polys(self.id, other.id);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: F) -> Self {
        let res_id = self.tracker.borrow_mut().add_scalar(self.id, c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: F) -> Self {
        let res_id = self.tracker.borrow_mut().mul_scalar(self.id, c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
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
        let output = self.tracker.borrow_mut().evaluations(self.id).clone();
        output
    }

    pub fn to_hp_virtual_poly(&self) -> HPVirtualPolynomial<F> {
        self.tracker.borrow().to_hp_virtual_poly(self.id)
    }
}
