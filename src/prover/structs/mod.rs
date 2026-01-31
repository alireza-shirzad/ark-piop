/////////////////// Modules //////////////////

pub mod polynomial;
pub mod proof;
/////////////////// Imports //////////////////
use std::{collections::BTreeMap, sync::Arc};

use crate::structs::claim::TrackerNoZerocheckClaim;
use crate::{
    SnarkBackend,
    arithmetic::virt_poly::VirtualPoly,
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
    setup::structs::SNARKPk,
    structs::{
        TrackerID,
        claim::{TrackerLookupClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
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
    pub fn id(&self) -> TrackerID {
        self.id
    }
    pub fn point(&self) -> &<PC::Poly as Polynomial<F>>::Point {
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
pub struct ProverState<B>
where
    B: SnarkBackend,
{
    /// The transcript for the PIOP
    pub transcript: Tr<B::F>,

    /// number of the tracked polynomials (Univariate and Multivariate)
    // TODO: See if we should split this into two fields
    pub num_tracked_polys: usize,

    /// A map from TrackerID to a virtual polynomials, i.e. polynomials of the
    /// form `sum_i c_i * prod_j p_ij` where `p_ij` points to another
    /// materialized or virtual polynomials
    pub virtual_polys: BTreeMap<TrackerID, VirtualPoly<B::F>>,

    /// Mutable indexed tracked polynomials for protocol-time updates.
    pub indexed_tracked_polys: BTreeMap<String, TrackedPoly<B>>,

    pub mv_pcs_substate: ProverPCSubstate<B::F, B::MvPCS>,
    pub uv_pcs_substate: ProverPCSubstate<B::F, B::UvPCS>,
    pub miscellaneous_field_elements: BTreeMap<String, B::F>,
    pub num_vars: BTreeMap<TrackerID, usize>,
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
    pub no_zero_check_claims: Vec<TrackerNoZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
    pub lookup_claims: Vec<TrackerLookupClaim>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedSNARKPk<B>
where
    B: SnarkBackend,
{
    pub log_size: usize,
    pub mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    pub uv_pcs_param: Arc<<B::UvPCS as PCS<B::F>>::ProverParam>,
}

impl<B> ProcessedSNARKPk<B>
where
    B: SnarkBackend,
{
    pub fn new_from_pk(pk: &SNARKPk<B>) -> Self {
        Self {
            log_size: pk.log_size,
            mv_pcs_param: Arc::clone(&pk.mv_pcs_param),
            uv_pcs_param: Arc::clone(&pk.uv_pcs_param),
        }
    }
}
